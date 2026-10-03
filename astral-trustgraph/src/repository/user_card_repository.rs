//! 用户卡数据访问 — UserCardRepository
//!
//! 对齐 Java `UserCardMapper` 边界（user_card + card_rule_set_ref + 快照读取）。
//! delete 的级联清理（permission_rule / card_rule_set_ref +
//! 软删卡）收口为单一事务聚合方法（permission_rule_snapshot 维度已随迁移
//! 20260827000002 退役，级联不再触碰）。
//! action_codes 摘要不再进入正式卡查询的 LEFT JOIN；卡行（仅身份/平台目录展示
//! 字段）先按页加载，再经共享 `astral_db::load_card_permission_summaries` 以页内
//! 卡 id 一次批量回填 —— 摘要读统一收口到共享 fail-closed 投影门禁（CARD head
//! 缺失 / 非 READY / source != projected 的卡不产生摘要），查询错误必须传播，
//! 绝不降级为空授权视图。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::{AstralError, ProjectionAggregate, EVENT_TYPE_RULE_SET_UPDATE, SYSTEM_ACTOR_ID};

use crate::repository::audit_log_repository::{
    insert_rule_set_projection_audit_in_tx, insert_user_card_cascade_audit_in_tx,
    validated_request_operation_id, RuleSetMutationContext, RuleSetProjectionAuditEntry,
    UserCardCascadeAuditEntry, UserCardCascadeRulesetAudit,
};
use crate::repository::authorization_source_transaction::{
    append_eligibility_projection_with_invalidation_in_tx, AuthorizationSourceTransaction,
};
use crate::repository::delegation_repository::{
    require_provable_expiry, DelegationRecord, DELEGATION_SELECT,
};
use crate::repository::grant_ledger_adapter::{
    append_approval_remove_in_tx, append_delegation_grant_delta_in_tx,
    append_direct_grant_delta_in_tx, build_approval_remove_draft, build_delegation_revoke_draft,
    build_direct_remove_draft, derive_approval_contribution_event_id, derive_approval_identity,
    derive_delegation_contribution_event_id, derive_delegation_identity,
    derive_direct_contribution_event_id, derive_direct_identity, derive_direct_tenant,
    map_grant_repository_error, ApprovalContributionKind, ApprovalRemoveLedgerFacts,
    DelegationContributionKind, DelegationLedgerFacts, DirectRuleLedgerFacts,
    DirectRuleOperationKind, APPROVAL_AGGREGATE_TYPE, DELEGATION_AGGREGATE_TYPE,
    DIRECT_AGGREGATE_TYPE,
};
use crate::repository::projection_repository::{
    append_card_projection_in_tx, append_card_projection_with_metadata_in_tx,
    append_rule_set_projection_in_tx,
};
use crate::repository::rule_repository::{LockedRuleRow, SqlxRuleRepository};
use crate::repository::rule_set_repository::{
    append_card_cascade_ruleset_removals_in_tx, append_card_create_ruleset_entry_adds_in_tx,
    ensure_rule_set_projection_in_tx, validate_binding_tenants,
};

/// 用户卡记录（含 LEFT JOIN 展示字段 + action_codes 摘要）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserCardRecord {
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub card_type: String,
    pub card_status: String,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub tenant_id: Option<i64>,
    pub card_name: Option<String>,
    pub template_code: Option<String>,
    pub template_name: Option<String>,
    pub level_code: Option<String>,
    pub level_name: Option<String>,
    pub level_no: Option<i32>,
    pub action_codes: Option<String>,
}

/// 列表过滤
#[derive(Debug, Default)]
pub struct UserCardFilter {
    pub user_id: Option<i64>,
    pub template_id: Option<i64>,
    pub card_status: Option<String>,
    /// 管理范围过滤（对齐 Java CardManagementScopeServiceImpl：列表必须限定在操作者 tenant/domain）
    pub tenant_id: Option<i64>,
    pub domain_id: Option<i64>,
}

/// 新建卡参数
#[derive(Debug)]
pub struct NewUserCard {
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub card_type: String,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub priority: i32,
    pub is_primary: bool,
    pub tenant_id: Option<i64>,
    /// 可选的请求级 operation id（Gateway `x-request-id`）。
    ///
    /// 显式携带时先通过统一持久化安全校验（不安全 header Validation fail-closed），
    /// 通过后作为本次创建全部账本/投影/审计事件的 stable operation id；缺失或空白
    /// 时以锁定中的 durable 代次确定性派生（见
    /// [`derive_create_card_template_operation_id`]），随机 fallback 永不允许进入
    /// 账本事件链。identity starter 的无模板路径只用它做 legacy correlation。
    pub request_operation_id: Option<String>,
}

/// 部分更新补丁
///
/// `card_status` 是对有效授权的 source mutation 面（`perm:card:active` 资格与
/// CARD 投影 REVOKE 语义都随它变化），因此任何携带状态的更新都必须同时携带
/// 可证明的调用者身份与 operation 身份；缺失一律 fail-closed（见
/// [`UserCardRepository::update_card`]）。priority/is_primary/level_id 不改变
/// 资格语义，不强制身份上下文。
#[derive(Debug, Default)]
pub struct UserCardPatch {
    pub card_status: Option<String>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
    pub level_id: Option<i64>,
    /// Gateway 已验证的操作者（HTTP `x-user-id`），由 handler 传播。
    ///
    /// 携带 `card_status` 的更新要求正数 actor；缺失或非正数在进入任何
    /// durable 写入前整体拒绝，绝不以 SYSTEM_ACTOR 冒充人类操作者。
    pub actor_id: Option<i64>,
    /// 可选的请求级 operation id（Gateway `x-request-id`），契约与
    /// [`NewUserCard::request_operation_id`] 一致：显式携带时先过统一持久化
    /// 安全校验（不安全 header Validation fail-closed），缺失/空白时以锁定中
    /// 的 durable CARD head 代次确定性派生，随机 fallback 永不进入事件链。
    pub request_operation_id: Option<String>,
}

/// 删除结果（级联清理计数）
#[derive(Debug, Clone, Copy)]
pub struct DeleteCascadeResult {
    pub exists: bool,
    pub permission_rule_deleted: u64,
    pub snapshot_deleted: u64,
    pub rule_set_ref_deleted: u64,
}

/// 模板关联的规则集（create 时绑定）
#[derive(Debug, Clone)]
pub struct TemplateRuleSet {
    pub rule_set_id: i64,
}

/// 部分更新是否影响卡资格（仅 card_status 改变 `perm:card:active`；
/// priority / is_primary / level_id 不改变资格，无需 ELIGIBILITY 事件）。
fn patch_affects_eligibility(patch: &UserCardPatch) -> bool {
    patch.card_status.is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// 卡状态迁移状态机（通用 update_card 入口的唯一合法迁移面）
//
// 目标：通用部分更新只能让卡**离开** ACTIVE（停用/吊销/挂起），绝不能把任何
// 非 ACTIVE 卡**送回** ACTIVE —— 回到 ACTIVE 的每一条路径都必须经过带守卫的
// 专用入口：
//   - DISABLED（软删）→ ACTIVE 只能走 `restore_card`（`/user-cards/{id}/restore`，
//     Java 侧同契约：仅 DISABLED 可恢复）；
//   - PENDING/INACTIVE → ACTIVE 只能走带归属/贡献 fail-closed 守卫的
//     `bind_card`（`/user-cards/{id}/bind`）；
//   - 其余进入 ACTIVE 的迁移（含 SUSPENDED → ACTIVE）没有守卫入口，一律
//     fail-closed 拒绝，绝不为本入口新开授权恢复旁路。
// 迁移判定以事务内 FOR UPDATE 锁定行的当前状态为准，不信任请求携带的旧读。
// ─────────────────────────────────────────────────────────────────────────────

/// update_card 可写入的 canonical 状态字母表（对齐 handler 白名单与 Java
/// canonical 状态；超出集合的值在本入口一律 Validation fail-closed）。
const CARD_STATUS_ALPHABET: [&str; 4] = ["ACTIVE", "INACTIVE", "DISABLED", "SUSPENDED"];

/// 纯校验：请求携带的目标状态必须在 canonical 字母表内并归一为大写。
/// 非法/未知状态拒绝（不静默改写、不 passthrough 任意字符串进 SQL）。
fn normalize_requested_card_status(raw: &str) -> Result<String, AstralError> {
    let upper = raw.trim().to_uppercase();
    if CARD_STATUS_ALPHABET.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(AstralError::Validation(format!(
            "card_status must be one of {CARD_STATUS_ALPHABET:?}, got {raw:?}"
        )))
    }
}

/// 卡状态迁移状态机（纯逻辑，fail-closed）。
///
/// 以锁定行证明的当前状态 `current` 为准判定请求目标 `requested`（两者均应为
/// canonical 大写，见 [`normalize_requested_card_status`]）：
/// - 同状态：无迁移（允许随其他字段一起回显，事件语义为 CARD_UPDATE）；
/// - ACTIVE → {INACTIVE, SUSPENDED, DISABLED}：离开 ACTIVE 的停用面，允许
///   （走加固路径：REVOKE 投影 + actor/operation 元数据 + 同事务审计关联）；
/// - 其余一切迁移：拒绝，并指明唯一合法专用入口（restore/bind）。
fn validate_card_status_transition(current: &str, requested: &str) -> Result<(), AstralError> {
    if current == requested {
        return Ok(());
    }
    if current == "ACTIVE" && requested != "ACTIVE" {
        return Ok(());
    }
    let guidance = match (current, requested) {
        ("DISABLED", _) => {
            "DISABLED (revoked) cards may only leave that state through the restore path \
             (PUT /user-cards/{id}/restore)"
        }
        (_, "ACTIVE") => {
            "re-entering ACTIVE is only allowed through its guarded dedicated paths \
             (bind for PENDING/INACTIVE, restore for DISABLED)"
        }
        _ => "generic update may only move a card out of ACTIVE (INACTIVE/SUSPENDED/DISABLED)",
    };
    Err(AstralError::Validation(format!(
        "card status transition {current} -> {requested} is not permitted through the generic \
         update path: {guidance}"
    )))
}

/// update_card 状态维度的投影语义（纯判定，无 IO；唯一事实来源是事务内
/// `FOR UPDATE` 锁定行证明的当前状态）：
/// - `exits_active`：ACTIVE → 任何非 ACTIVE 目标是离开 ACTIVE 的停用/吊销面
///   （带元数据 CARD REVOKE + ELIGIBILITY + 同事务审计）。同状态回显（含
///   INACTIVE → INACTIVE）与未携带状态的纯字段更新都不是吊销，也绝不因回显
///   失效 `perm:card:active` 资格；
/// - `status_changed`：锁定状态与目标状态真实不同（ELIGIBILITY 的前提）。
///   状态机只放行同状态与离开 ACTIVE 两族迁移，因此非退出分支内它必然为
///   false；保留该字段是防止未来合法迁移面扩张时悄悄丢失 ELIGIBILITY 事件
///   的第二道防线。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CardStatusUpdateSemantics {
    exits_active: bool,
    status_changed: bool,
}

/// 纯分类器：以锁定行当前状态为基准，把请求目标状态映射为
/// [`CardStatusUpdateSemantics`]。不读任何 IO、不构造任何错误 —— 与
/// [`validate_card_status_transition`]（迁移合法性）正交，只回答"这是不是
/// 吊销 + 资格失效"。
fn classify_card_status_update(
    locked_status: &str,
    requested_status: Option<&str>,
) -> CardStatusUpdateSemantics {
    let requested = requested_status.unwrap_or(locked_status);
    CardStatusUpdateSemantics {
        exits_active: locked_status == "ACTIVE" && requested != "ACTIVE",
        status_changed: requested != locked_status,
    }
}

/// update_card 离开 ACTIVE 路径的稳定 operation id 纯派生：
/// `user-card:update:{card_id}:gen:{locked CARD head generation}`。
///
/// 与 [`derive_card_cascade_operation_id`] / [`derive_create_card_template_operation_id`]
/// 同一契约：缺失 header 的路径必须以**锁定中的 durable 代次**确定性派生，
/// 随机 fallback 绝不允许进入账本/事件链。card id 与代次任一非法即
/// Validation fail-closed。
fn derive_update_card_operation_id(
    card_id: i64,
    locked_generation: i64,
) -> Result<String, AstralError> {
    if card_id <= 0 || locked_generation < 0 {
        return Err(AstralError::Validation(format!(
            "update-card operation identity requires a positive card id and a non-negative \
             locked CARD head generation, got card_id={card_id}, generation={locked_generation}"
        )));
    }
    Ok(format!(
        "user-card:update:{card_id}:gen:{locked_generation}"
    ))
}

/// 防御性 ELIGIBILITY 路径的确定性 operation id（纯逻辑，fail-closed）。
///
/// update_card 的非退出分支目前不可达（状态机只放行同状态回显与离开 ACTIVE）；
/// 保留为未来合法迁移面扩张时的第二道防线。若触发，其资格失效身份以锁定行
/// 证明的迁移前后 canonical 状态限定：`user-card:update:{card_id}:status:{from}:{to}`。
/// 随机 fallback 绝不进入事件链；outbox 唯一性由每事件的 ELIGIBILITY 投影
/// 事件 id（messageId）承担，本 id 只做源 mutation 关联。
fn derive_update_card_eligibility_operation_id(
    card_id: i64,
    from_status: &str,
    to_status: &str,
) -> Result<String, AstralError> {
    if card_id <= 0
        || !CARD_STATUS_ALPHABET.contains(&from_status)
        || !CARD_STATUS_ALPHABET.contains(&to_status)
    {
        return Err(AstralError::Validation(format!(
            "update-card eligibility operation identity requires a positive card id and \
             canonical from/to statuses from {CARD_STATUS_ALPHABET:?}, got card_id={card_id}, \
             {from_status} -> {to_status}"
        )));
    }
    Ok(format!(
        "user-card:update:{card_id}:status:{from_status}:{to_status}"
    ))
}

/// bind 换主（PENDING/INACTIVE → ACTIVE）的确定性 operation id（纯逻辑，
/// fail-closed）：卡行已在同事务 `FOR UPDATE` 锁定、目标用户已过正数校验，
/// 身份 `user-card:bind:{card_id}:user:{user_id}` 只绑定锁定 durable 事实。
/// 连续 rebind 的 outbox 唯一性由每事件的 ELIGIBILITY 投影事件 id（messageId）
/// 承担，本 id 只做源 mutation 关联；随机 fallback 绝不进入事件链。
fn derive_bind_card_operation_id(card_id: i64, user_id: i64) -> Result<String, AstralError> {
    if card_id <= 0 || user_id <= 0 {
        return Err(AstralError::Validation(format!(
            "bind-card eligibility operation identity requires positive card and user ids, \
             got card_id={card_id}, user_id={user_id}"
        )));
    }
    Ok(format!("user-card:bind:{card_id}:user:{user_id}"))
}

/// 卡状态变更（离开 ACTIVE）的 durable 审计关联输入。
///
/// 与 [`UserCardCascadeAuditEntry`]（`insert_user_card_cascade_audit_in_tx`）同一
/// 机制：与 source UPDATE、CARD head/outbox（REVOKE）、ELIGIBILITY 事件共享同一
/// 稳定 operation_id，使一次停用/吊销在审计、source 与投影链上可相互关联。
/// `user_id` 列记 Gateway 验证的操作者（delegation 家族同一契约）；卡属主、
/// 前后状态与父事件号进 detail JSON，双向可追溯。
struct UserCardStatusAuditEntry<'a> {
    /// Gateway 已验证的操作者 id（正数；由 [`UserCardRepository::update_card`]
    /// 的 Phase 0 校验保证）。
    actor_id: i64,
    /// 卡属主 user id（锁定行读取；无主持卡记 0，仅进 detail）。
    owner_user_id: i64,
    target_card_id: i64,
    /// 本 mutation 的稳定 operation id（贯穿 CARD REVOKE outbox 与本审计行）。
    operation_id: &'a str,
    /// 父级带 metadata 的 CARD REVOKE 投影事件号（generation/fence 关联）。
    parent_event_id: &'a str,
    /// 锁定行证明的迁移前状态（canonical 大写）。
    from_status: &'a str,
    /// 迁移后状态（canonical 大写）。
    to_status: &'a str,
    /// 目标卡租户/域边界（锁定行读取，用于租户隔离的审计关联）。
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

impl UserCardStatusAuditEntry<'_> {
    /// 结构化详情；序列化失败必须阻止事务提交（与级联删除审计同一门禁）。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "actorId": self.actor_id,
            "ownerUserId": self.owner_user_id,
            "targetCardId": self.target_card_id,
            "operationId": self.operation_id,
            "parentEventId": self.parent_event_id,
            "fromStatus": self.from_status,
            "toStatus": self.to_status,
            "action": "status_revoke",
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "user card status audit detail serialization failed: {error}"
            ))
        })
    }
}

/// 纯校验：状态变更审计必须携带正数操作者/目标卡、可关联 operation 与父事件
/// 身份、以及前后两个 canonical 状态；缺失或错位拒绝落库。
fn validate_user_card_status_audit_entry(
    entry: &UserCardStatusAuditEntry<'_>,
) -> Result<(), AstralError> {
    if entry.actor_id <= 0 || entry.target_card_id <= 0 {
        return Err(AstralError::Validation(
            "user card status audit requires a positive actor id and target card id".into(),
        ));
    }
    if entry.operation_id.trim().is_empty() || entry.parent_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "user card status audit requires operation and parent event correlation".into(),
        ));
    }
    for status in [entry.from_status, entry.to_status] {
        if !CARD_STATUS_ALPHABET.contains(&status) {
            return Err(AstralError::Validation(format!(
                "user card status audit requires canonical statuses from {CARD_STATUS_ALPHABET:?}, \
                 got {status:?}"
            )));
        }
    }
    Ok(())
}

/// 把用户卡状态变更（离开 ACTIVE）的审计关联写入同一个 InnoDB 事务。
///
/// 沿用 `insert_user_card_cascade_audit_in_tx` 的既有机制：与 source UPDATE、
/// head/outbox 同事务落 `audit_log`，任何失败回滚整个 mutation。不能复用
/// MQ-first AuditDualWrite：它可能在事务提交后异步落库。
async fn insert_user_card_status_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    entry: &UserCardStatusAuditEntry<'_>,
) -> Result<(), AstralError> {
    validate_user_card_status_audit_entry(entry)?;
    let detail = entry.detail_json()?;
    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
          domain_id, tenant_id, detail) \
         VALUES (?, ?, 'card_status_change', 'user_card', ?, NULL, 'USER_CARD_MUTATION', ?, ?, ?, ?)",
    )
    .bind(entry.actor_id)
    .bind(entry.target_card_id)
    // decision 与父 CARD REVOKE 投影事件的语义对齐（撤销事实贯穿两条链）。
    .bind("CARD_REVOKED")
    .bind(entry.operation_id)
    .bind(entry.domain_id)
    .bind(entry.tenant_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("user card status audit insert failed: {error}"))
    })?;
    Ok(())
}

/// 卡恢复（DISABLED → ACTIVE）的 durable 审计关联输入。
///
/// 与 [`UserCardStatusAuditEntry`]（`insert_user_card_status_audit_in_tx`）同一
/// 机制（`audit_log` 同表同事务），但语义相反：restore 是资格恢复而非吊销。
/// repository 入口不携带 Gateway 操作者上下文，actor 固定为
/// [`SYSTEM_ACTOR_ID`]（与 `insert_rule_set_projection_audit_in_tx` 同一系统
/// actor 门禁：非正且非 SYSTEM 一律拒绝落库）；`user_id` 列与级联删除审计同一
/// 契约记卡属主（无主持卡记 0）。
struct UserCardRestoreAuditEntry<'a> {
    /// 本路径固定为 SYSTEM_ACTOR_ID；未来若 API 层传入真实操作者必须为正数。
    actor_id: i64,
    /// 卡属主 user id（锁定行读取；无主持卡记 0，仅进审计 user_id 列与 detail）。
    owner_user_id: i64,
    target_card_id: i64,
    /// 本 mutation 的稳定 operation id（贯穿 CARD_RESTORED outbox 与本审计行）。
    operation_id: &'a str,
    /// 父级带 metadata 的 CARD_RESTORED 投影事件号（generation 关联锚）。
    parent_event_id: &'a str,
    /// 目标卡租户/域边界（锁定行读取，用于租户隔离的审计关联）。
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

impl UserCardRestoreAuditEntry<'_> {
    /// 结构化详情；序列化失败必须阻止事务提交（与状态变更/级联删除审计同一
    /// 门禁）。前后状态由 UPDATE 谓词固定（DISABLED → ACTIVE）；`reauthorization`
    /// 显式声明 ALLOW-only 语义 —— 恢复不复活任何授权，重新授权必须走显式新
    /// revision/mutation。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "actorId": self.actor_id,
            "ownerUserId": self.owner_user_id,
            "targetCardId": self.target_card_id,
            "operationId": self.operation_id,
            "parentEventId": self.parent_event_id,
            "fromStatus": "DISABLED",
            "toStatus": "ACTIVE",
            "action": "card_restore",
            "reauthorization": "EXPLICIT_MUTATION_REQUIRED",
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "user card restore audit detail serialization failed: {error}"
            ))
        })
    }
}

/// 纯校验：恢复审计必须携带系统或正数 actor、正数目标卡、可关联 operation 与
/// 父事件身份；缺失或错位拒绝落库。
fn validate_user_card_restore_audit_entry(
    entry: &UserCardRestoreAuditEntry<'_>,
) -> Result<(), AstralError> {
    if (entry.actor_id != SYSTEM_ACTOR_ID && entry.actor_id <= 0) || entry.target_card_id <= 0 {
        return Err(AstralError::Validation(
            "user card restore audit requires a positive or system actor id and a positive \
             target card id"
                .into(),
        ));
    }
    if entry.operation_id.trim().is_empty() || entry.parent_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "user card restore audit requires operation and parent event correlation".into(),
        ));
    }
    Ok(())
}

/// 把用户卡恢复（DISABLED → ACTIVE）的审计关联写入同一个 InnoDB 事务。
///
/// 沿用 `insert_user_card_status_audit_in_tx` 的既有机制：与 source UPDATE、
/// CARD_RESTORED head/outbox、ELIGIBILITY 事件同事务落 `audit_log`，任何失败
/// 回滚整个 mutation。不能复用 MQ-first AuditDualWrite：它可能在事务提交后
/// 异步落库。decision 与父 CARD_RESTORED 投影事件语义对齐（恢复事实贯穿两条
/// 链）；审计行记录的是资格恢复事实而非授权恢复 —— 级联删除时该卡全部贡献已
/// 版本化 REMOVE，恢复不自动复活任何授权。
async fn insert_user_card_restore_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    entry: &UserCardRestoreAuditEntry<'_>,
) -> Result<(), AstralError> {
    validate_user_card_restore_audit_entry(entry)?;
    let detail = entry.detail_json()?;
    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
          domain_id, tenant_id, detail) \
         VALUES (?, ?, 'card_restore', 'user_card', ?, NULL, 'USER_CARD_MUTATION', ?, ?, ?, ?)",
    )
    .bind(entry.owner_user_id)
    .bind(entry.target_card_id)
    // decision 与父 CARD_RESTORED 投影事件的语义对齐（恢复事实贯穿两条链）。
    .bind("CARD_RESTORED")
    .bind(entry.operation_id)
    .bind(entry.domain_id)
    .bind(entry.tenant_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("user card restore audit insert failed: {error}"))
    })?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 卡创建 × 版本化授权账本（ALLOW-only + 全增量）模板 BASE 绑定接线
//
// 目标：create_card 在同一 source transaction 内插入 user_card 后，把每个模板
// RuleSet 的 enabled+ALLOW 条目通过 rule_set_repository 的共享 ADD 物化核心写进
// grant revision/delta 账本，消除与标准 bind_card 的语义分叉。旧读链语义不变：
// CARD_CREATED + ELIGIBILITY_UPDATE 仍同事务落库，且各绑定不再追加重复的 CARD
// RULE_SET_BOUND 父事件（复用单张 CARD_CREATED 作为全部贡献的 generation/fence
// 锚点，避免旧 worker 对同一张新建卡做额外重建）。
//
// 锁序（binding-side 全局契约方向，与 bind/unbind 家族一致，无反向取锁）：
//   user_card 行（本 tx INSERT X 锁，此卡行由本事务拥有）
//   → [单语句] rule_set 行升序锁定 + 各 RuleSet 投影 head FOR UPDATE
//   → card_rule_set_ref 严格插入（新卡不存在旧 ref；重复命中即不变量冲突回滚）
//   → rule_set_entry 条目锁定读取（ORDER BY entry_id）
//   → CARD parent 投影（CARD_CREATED，带 actor/operation 元数据）
//   → grant revision head → delta version（每 entry×ref 独立贡献）
//   → legacy 投影/审计。
//
// operation identity 单一契约：显式 x-request-id 通过统一安全校验后原样贯穿全部
// 写入；缺失时以锁定的 durable RULE_SET 代次 + card/template/mutation-kind 确定性
// 派生，随机 fallback 绝不允许进入账本。任一绑定失败整体回滚（含新建 user_card /
// ref / 投影 / 账本 / 审计），绝不只写旧链。
// ─────────────────────────────────────────────────────────────────────────────

/// 模板绑定卡创建的稳定 operation id 派生（纯函数）：
/// `user-card:create:{card_id}:tpl:{template_id}:ruleset-gen:{locked_generation}`。
///
/// 与 rule set 的 `stabilize_rule_set_operation_context`、卡删除的
/// [`derive_card_cascade_operation_id`] 同一契约：缺失 header 的路径必须以**锁定中
/// 的 durable 代次**确定性派生。locked_generation 取模板下全部升序锁定 RuleSet 投影
/// head 的最大 source_generation（缺失 head 按 0 计）；事务回滚后重试时 source 插入
/// 与 head 代次一并还原，派生值逐字节一致，重放得到同一身份；提交成功后不可能为
/// 同一 card 再次执行，AUTO_INCREMENT 回滚不复用保证不同请求必然分叉。
fn derive_create_card_template_operation_id(
    card_id: i64,
    template_id: i64,
    locked_ruleset_generation: i64,
) -> String {
    format!("user-card:create:{card_id}:tpl:{template_id}:ruleset-gen:{locked_ruleset_generation}")
}

/// 无模板绑定路径的稳定 operation id（纯函数）：`user-card:create:{card_id}`。
/// 该路径不物化任何账本贡献，id 只用于 CARD_CREATED / ELIGIBILITY outbox 元数据
/// 与后续审计 correlation。
fn derive_create_card_plain_operation_id(card_id: i64) -> String {
    format!("user-card:create:{card_id}")
}

/// restore 路径的稳定 operation id（纯函数）：`user-card:restore:{card_id}`。
/// 该路径不物化任何账本贡献（恢复绝不隐式复活授权，语义见 `restore_card`），
/// id 只用于 CARD_RESTORED / ELIGIBILITY outbox 元数据与后续审计 correlation，
/// 与 [`derive_create_card_plain_operation_id`] 同一契约。
fn derive_restore_card_operation_id(card_id: i64) -> String {
    format!("user-card:restore:{card_id}")
}

/// create_card 的最小 ledger scope 合同校验（纯逻辑，先于任何 durable 写入）：
/// 仅当创建**模板绑定卡**（即新账本 ALLOW 贡献的物化目标）时强制 —— tenant 必须
/// 非空正数、属主 user 必须非空正数、domain/template 携带时必须正数，任何无法
/// 证明 scope 的请求整卡创建失败，不降级只写旧链。identity 注册 starter 的
/// tenantless 无模板路径不产生账本贡献，保持既有语义放行，明确不在本片修改。
fn validate_create_card_ledger_scope(new: &NewUserCard) -> Result<(), AstralError> {
    let Some(template_id) = new.template_id else {
        return Ok(());
    };
    if template_id <= 0 {
        return Err(AstralError::Validation(format!(
            "create card requires a positive template id, got {template_id}"
        )));
    }
    if new.user_id.is_none_or(|user_id| user_id <= 0) {
        return Err(AstralError::Validation(format!(
            "template-bound card creation requires a positive owner user id, got {:?}",
            new.user_id
        )));
    }
    if new.tenant_id.is_none_or(|tenant_id| tenant_id <= 0) {
        return Err(AstralError::Validation(format!(
            "template-bound card creation requires a positive tenant scope, got {:?}; \
             refusing to materialize ledger grants for a tenantless card",
            new.tenant_id
        )));
    }
    if let Some(domain_id) = new.domain_id {
        if domain_id <= 0 {
            return Err(AstralError::Validation(format!(
                "create card requires a positive domain id when scoped, got {domain_id}"
            )));
        }
    }
    Ok(())
}

/// create_card 租户绑定写点的租户行锁定语句（参数化 + FOR UPDATE）。
///
/// `user_card.tenant_id`（及同事务 `card_rule_set_ref.tenant_id`）是本文件唯一的
/// 租户绑定写入：必须在锁定并证明存在的 tenant 行之后落 source 行。取锁方向为
/// tenant 行 → user_card source 行，与 tenant_repository（delete_tenant 的
/// tenant 行锁 → user_card 引用计数守卫、状态/域 mutation 的 tenant → mapping →
/// user_card）同向，本文件其余路径不访问 tenant 表，不存在反向锁边。
/// 这闭合了与硬删除租户的竞态：create 持 tenant 行锁期间 delete 的守卫计数
/// 必然包含（或阻塞于）本事务，"守卫见 0 行后提交出孤儿卡"不再可能。
const CREATE_CARD_TENANT_LOCK_SQL: &str =
    "SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE";

/// create_card 租户绑定的纯校验（fail-closed，可单测）：绑定租户必须为正数。
/// 该门禁覆盖全部创建路径（含无模板路径）；tenantless（`None`，identity
/// starter）不经过本门禁，保持既有语义放行。存在性证明由调用方在事务内以
/// [`CREATE_CARD_TENANT_LOCK_SQL`] 锁定行完成，缺失即整体 Validation 拒绝。
fn validate_create_card_tenant_binding(tenant_id: i64) -> Result<(), AstralError> {
    if tenant_id <= 0 {
        return Err(AstralError::Validation(format!(
            "create card requires a positive tenant scope, got {tenant_id}"
        )));
    }
    Ok(())
}

/// 锁定的模板 RuleSet 行：source 行与投影 head 由同一条升序 FOR UPDATE 捕获，
/// 是 tenant 校验、operation identity 派生与绑定物化的唯一事实来源。
#[derive(Debug, Clone, sqlx::FromRow)]
struct LockedTemplateRuleSetRow {
    rule_set_id: i64,
    tenant_id: Option<i64>,
    /// 该 RuleSet 当前的 durable 投影代次（head 缺失按 0 处理）。
    source_generation: Option<i64>,
}

/// 模板 RuleSet 集合的不变量复核（纯逻辑）：主键查询天然唯一，结果集出现重复
/// 说明 template→rule_set 映射或读取被破坏 —— 新卡事务内整体 fail-closed 拒绝，
/// 绝不静默跳过任何一个绑定（否则会留下只写部分绑定的半完成状态）。
fn ensure_unique_template_rule_set_ids(
    rows: &[LockedTemplateRuleSetRow],
) -> Result<(), AstralError> {
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if !seen.insert(row.rule_set_id) {
            return Err(AstralError::Internal(format!(
                "template lookup returned duplicate template rule_set mapping {} in a single new-card transaction; refusing to materialize a partially bound card",
                row.rule_set_id
            )));
        }
        // 负代次属于持久层不变式破坏，禁止作为 identity 派生输入。
        if row
            .source_generation
            .is_some_and(|generation| generation < 0)
        {
            return Err(AstralError::Validation(
                "RULE_SET projection head carries a negative generation; refusing to derive a create-card operation identity from it"
                    .into(),
            ));
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 卡级联删除 × 版本化授权账本（ALLOW-only + 全增量）撤销接线
//
// 目标：delete_with_cascade 在同一 source transaction 内把新读链可见的
// DIRECT / APPROVAL / RULE_SET / DELEGATION 账本贡献一并写成 REMOVE/REVOKE
// tombstone，避免 source 行被清掉后账本里残留 ACTIVE ghost。旧读路径
// （snapshot/legacy 事件）语义保持不变：CARD REVOKE + ELIGIBILITY_UPDATE 仍然
// 同事务落库。
//
// 锁序（全局契约，与 delegation_repository 的 create/update/revoke 同一方向）：
//   [受影响委托端点卡 plain 预读（{被删卡} ∪ 全部委托行两端卡），仅用于确定锁集合]
//   → user_card 全部参与卡一次性 IN 锁定、card_id 升序 —— 单语句完成全部
//     user_card 行锁，不再先单锁被删卡再逐张补锁：互链委托（A→B 且 B→A）
//     并发级联的 ABBA 环由统一升序方向消除
//   → permission_delegation 受影响行升序（delegation_id）＋ 预读-锁定集合
//     一致性复核（端点越界或集合漂移即冲突回滚）
//   → permission_rule 升序（被删卡全部来源 + 远端承载卡上的 DELEGATION 规则）
//   → [rule_set 升序逐个] rule_set → card_rule_set_ref → entries（既有顺序）
//   → projection head/outbox（被删卡一次父事件；每个远端承载卡各一次专用 REVOKE 父事件）
//   → grant head → delta version → tombstone
//   → source cleanup（delegation REVOKED → 规则/快照/引用删除 → DISABLED）
//   → legacy 投影 + audit。
//
// 绑定侧 mutation（unbind/级联删除）先取卡锁；delegation 生命周期 mutation 现在
// 也先锁两端 user_card 再锁 permission_delegation —— 双方共同遵守"user_card 行 →
// permission_delegation 行"方向，家族之间不存在 ABBA 环。绝不先删 source 再查询。
// ─────────────────────────────────────────────────────────────────────────────

/// FOR UPDATE 捕获的参与卡身份事实（全部字段来自锁定行；删除动作的用户/
/// 租户/域边界都以这里为准，不回读任何缓存或快照）。被删卡与全部远端
/// 参与卡共用同一行形状，一次 IN 查询捕获。
#[derive(Debug, Clone, sqlx::FromRow)]
struct CascadeLockedCardRow {
    card_id: i64,
    user_id: Option<i64>,
    domain_id: Option<i64>,
    card_status: String,
    tenant_id: Option<i64>,
}

/// 远端承载卡（被删卡作为 delegator 时 grant 所在 delegate 卡）的锁定身份事实。
/// 由 `lock_cascade_participant_cards_in_tx` 的锁定行派生，不再单独加锁。
#[derive(Debug, Clone, sqlx::FromRow)]
struct CascadeCarrierCardRow {
    card_id: i64,
    user_id: Option<i64>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
}

/// 卡删除共用的稳定 batch operation id 纯派生：
/// `user-card:delete:{card_id}:gen:{locked CARD head generation}`。
///
/// 与 rule set 的 `stabilize_rule_set_operation_context` 同一契约：缺失 header 的
/// 路径必须以**锁定中的 durable 代次**确定性派生，随机 fallback 绝不允许进入
/// 账本。card id 与代次任一非法即 Validation fail-closed。
fn derive_card_cascade_operation_id(card_id: i64, locked_generation: i64) -> String {
    format!("user-card:delete:{card_id}:gen:{locked_generation}")
}

/// 去重并升序排列待锁定的卡集合（非正 id 一律 Validation fail-closed）。
///
/// 与 delegation_repository 的同名 helper 同一契约：一次级联涉及的全部
/// user_card 行按 card_id 升序锁定，跨家族保持一致方向（防 ABBA 环）。
fn ordered_unique_positive_card_ids(
    cards: impl IntoIterator<Item = i64>,
) -> Result<Vec<i64>, AstralError> {
    let mut seen = std::collections::BTreeSet::new();
    for card_id in cards {
        if card_id <= 0 {
            return Err(AstralError::Validation(format!(
                "cascade deletion requires positive user_card ids, got {card_id}"
            )));
        }
        seen.insert(card_id);
    }
    Ok(seen.into_iter().collect())
}

/// 分类结果：需要为该规则写新账本 tombstone 的来源通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CascadeRuleLedgerKind {
    /// permission_rule.source_type ∈ {CARD_ONLY, MANUAL}
    Direct,
    /// permission_rule.source_type = PERMISSION_REQUEST
    Approval,
    /// permission_rule.source_type = DELEGATION（source_id = delegation 主键）。
    /// 写统一 REVOKE tombstone（与 delegation 生命周期撤权语义一致），provenance
    /// 保持 DELEGATION/delegation_id/layer NONE —— 绝不归类 DIRECT/APPROVAL，
    /// 也绝不写成普通 DENY。
    Delegation,
}

/// 物化候选分类（纯逻辑，ALLOW-only 语义与 rule set classifier 一致）：
/// - enabled=1 且 effect=ALLOW 的 direct/approval/delegation 规则是已入账授权来源
///   → 必须撤销（delegation 为 M3 接线：删除 delegator/delegate 任一卡都不得
///   留下 ACTIVE 委托账本 ghost）；
/// - DENY（任何大小写）/禁用行从未进入 ALLOW-only 账本 → 安全跳过（不存在
///   ghost；未入账的 legacy delegation 同理不得伪造 tombstone）；
/// - 其余未知 effect 值 fail-closed；
/// - 其他未知 source_type 在破坏性删除前一律 fail-closed，绝不猜测来源语义。
///
/// APPROVAL/DELEGATION 命中时返回其稳定 source 主键（request id / delegation id）。
fn classify_permission_rule_for_ledger(
    row: &LockedRuleRow,
) -> Result<Option<(CascadeRuleLedgerKind, Option<i64>)>, AstralError> {
    match row.source_type.trim() {
        "CARD_ONLY" | "MANUAL" => classify_allow_only(row)
            .map(|relevant| relevant.map(|_| (CascadeRuleLedgerKind::Direct, None))),
        "PERMISSION_REQUEST" => {
            let relevant = classify_allow_only(row)?;
            let request_id = row.source_id.filter(|id| *id > 0);
            if relevant.is_some() && request_id.is_none() {
                return Err(AstralError::Validation(format!(
                    "approval rule {} carries an unusable permission_request source id; \
                     refusing to revoke an approval contribution without a provable request",
                    row.rule_id
                )));
            }
            Ok(relevant.map(|_| (CascadeRuleLedgerKind::Approval, request_id)))
        }
        "DELEGATION" => {
            // source_id 必须是可证明的正数 delegation 主键（无论该规则是否已入账，
            // pairing 阶段都要求它指向锁定中的委托行）。
            let delegation_id = row.source_id.filter(|id| *id > 0);
            if delegation_id.is_none() {
                return Err(AstralError::Validation(format!(
                    "delegation rule {} carries an unusable permission_delegation source id; \
                     refusing to cascade-delete a delegation clause without a provable aggregate",
                    row.rule_id
                )));
            }
            let relevant = classify_allow_only(row)?;
            Ok(relevant.map(|_| (CascadeRuleLedgerKind::Delegation, delegation_id)))
        }
        other => Err(AstralError::Validation(format!(
            "permission rule {} under card {} carries unknown source_type {other:?}; \
             refusing to cascade-delete a grant of unprovable provenance",
            row.rule_id, row.card_id
        ))),
    }
}

/// enabled=1 + effect 白名单判定（direct/approval 共用）。
fn classify_allow_only(row: &LockedRuleRow) -> Result<Option<&LockedRuleRow>, AstralError> {
    if row.enabled.unwrap_or(1) != 1 {
        // 禁用行从不代表账本内活跃授权；按既有语义留在旧链之外。
        return Ok(None);
    }
    let effect = row.effect.trim();
    if effect.eq_ignore_ascii_case("ALLOW") {
        Ok(Some(row))
    } else if effect.eq_ignore_ascii_case("DENY") {
        // Legacy deny 行从未作为 ALLOW 入账；跳过即无 ghost 可留。
        Ok(None)
    } else {
        Err(AstralError::Validation(format!(
            "permission rule {} carries unknown effect {effect:?}; refusing to classify it as an authorization contribution",
            row.rule_id
        )))
    }
}

/// direct 身份 facts（与 rule_repository 批量删除路径完全一致的 identity 形状：
/// resource/action/effect 不进入身份，REMOVE delta 无 payload，无需有效期解析）。
fn direct_remove_identity_facts(row: &LockedRuleRow) -> DirectRuleLedgerFacts<'static> {
    DirectRuleLedgerFacts {
        tenant_id: row.tenant_id,
        domain_id: row.domain_id,
        card_id: row.card_id,
        user_id: row.user_id,
        rule_id: row.rule_id,
        resource: "",
        resource_id: None,
        action: "",
        condition_json: None,
        valid_from: None,
        valid_to: None,
    }
}

/// 被删卡参与的委托行集合：两端任一命中即受影响，按 delegation_id 升序
/// FOR UPDATE（全局锁序：user_card 行锁之后、permission_rule 之前）。
async fn lock_affected_delegations_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
) -> Result<Vec<DelegationRecord>, AstralError> {
    sqlx::query_as::<_, DelegationRecord>(&format!(
        "SELECT {DELEGATION_SELECT} FROM permission_delegation \
         WHERE delegator_card_id = ? OR delegate_card_id = ? \
         ORDER BY delegation_id FOR UPDATE"
    ))
    .bind(card_id)
    .bind(card_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)
}

/// 完整参与卡的 plain 预读（不带锁）：受影响委托行的
/// （delegator_card_id, delegate_card_id）端点对 —— 两端任一命中被删卡即受影响。
/// 只用于确定锁集合与随后的预读-锁定一致性复核，结果绝不当作授权事实；
/// 真实身份/scope 以随后的 FOR UPDATE 复读为准。非正端点 id 是持久层不变式
/// 破坏，构造锁集合前即 Validation fail-closed。
async fn probe_cascade_delegation_endpoint_pairs_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
) -> Result<Vec<(i64, i64)>, AstralError> {
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT DISTINCT delegator_card_id, delegate_card_id FROM permission_delegation \
         WHERE delegator_card_id = ? OR delegate_card_id = ?",
    )
    .bind(card_id)
    .bind(card_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?
    .into_iter()
    .map(|pair| {
        if pair.0 <= 0 || pair.1 <= 0 {
            return Err(AstralError::Validation(format!(
                "permission_delegation carries non-positive card endpoints {pair:?}; refusing to build a cascade lock set from invalid identifiers"
            )));
        }
        Ok(pair)
    })
    .collect()
}

/// 从预读端点对构造完整参与卡集合 `{deleted_card_id} ∪ 全部两端卡`（纯逻辑）：
/// 非正 id 一律 Validation fail-closed，去重 + 升序由
/// `ordered_unique_positive_card_ids` 保证。互链委托（A→B 且 B→A）的两端在
/// 此合并为同一升序集合，是消除并发级联 ABBA 环的前提。
fn collect_cascade_participant_ids(
    deleted_card_id: i64,
    pairs: impl IntoIterator<Item = (i64, i64)>,
) -> Result<Vec<i64>, AstralError> {
    let mut ids = vec![deleted_card_id];
    for (delegator_card_id, delegate_card_id) in pairs {
        ids.push(delegator_card_id);
        ids.push(delegate_card_id);
    }
    ordered_unique_positive_card_ids(ids)
}

/// 全部参与卡一次性按 card_id 升序 FOR UPDATE（全局锁序第 1 步：先于任何
/// permission_delegation / permission_rule / source mutation）。
///
/// 单个 `IN (...) ORDER BY card_id ASC FOR UPDATE` 完成全部 user_card 行锁，
/// 绝不在形成锁集合之后再按任意顺序逐张补锁 —— MySQL 按同一升序方向取锁，
/// 家族内/家族间都不再构成等待环。IN 值全部经 QueryBuilder push_bind 绑定，
/// 不拼接任何用户输入。输入必须是已去重升序的 id 集合。
async fn lock_cascade_participant_cards_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    ascending_card_ids: &[i64],
) -> Result<Vec<CascadeLockedCardRow>, AstralError> {
    debug_assert!(!ascending_card_ids.is_empty());
    debug_assert!(
        ascending_card_ids
            .windows(2)
            .all(|window| window[0] < window[1]),
        "cascade participant card ids must arrive deduplicated and ascending"
    );
    let mut builder = QueryBuilder::<sqlx::MySql>::new(
        "SELECT card_id, user_id, domain_id, card_status, tenant_id \
         FROM user_card WHERE card_id IN (",
    );
    let mut first = true;
    for card_id in ascending_card_ids {
        if !first {
            builder.push(", ");
        }
        builder.push_bind(*card_id);
        first = false;
    }
    builder.push(") ORDER BY card_id ASC FOR UPDATE");
    builder
        .build_query_as::<CascadeLockedCardRow>()
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)
}

/// 预读-锁定一致性判定（纯逻辑）：预读观测到的委托端点对必须与锁定后的实际
/// 委托行完全一致。缺行由锁定阶段的参与者存在性门禁处理；本门禁覆盖：
/// - 锁定后的每条委托行端点对必须在预读集合内（否则该聚合的另一端卡未进入
///   本事务参与卡锁，撤销链不可证明）；
/// - 两集合相等：新增、删除或换端都视为漂移，说明预读与加锁之间存在绕过
///   全局锁序的并发委托变更 —— 冲突回滚重试，绝不在陈旧集合上继续删除。
fn verify_cascade_participant_consistency(
    pre_read_pairs: &std::collections::BTreeSet<(i64, i64)>,
    locked_delegations: &[DelegationRecord],
) -> Result<(), AstralError> {
    let mut locked_pairs = std::collections::BTreeSet::new();
    for record in locked_delegations {
        let pair = (record.delegator_card_id, record.delegate_card_id);
        if !pre_read_pairs.contains(&pair) {
            return Err(AstralError::Internal(format!(
                "permission_delegation {} endpoints {pair:?} were not part of the pre-locked cascade participant set; refusing to proceed on an unstable endpoint set",
                record.delegation_id
            )));
        }
        locked_pairs.insert(pair);
    }
    if &locked_pairs != pre_read_pairs {
        return Err(AstralError::Internal(format!(
            "cascade delegation endpoint set drifted between the plain pre-read and the locked re-read ({locked_pairs:?} vs {pre_read_pairs:?}); conflicting concurrent delegation mutation detected, refusing to cascade-delete against a stale set"
        )));
    }
    Ok(())
}

/// 远端承载卡上、delegator 侧 ACTIVE 委托的 DELEGATION 规则行：按 rule_id 升序
/// FOR UPDATE（delegation 行锁之后）。每个入账委托必须恰好对应一条规则，由
/// 配对/计划阶段复核。
async fn lock_remote_delegation_rules_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    delegations: &[DelegationRecord],
    deleted_card_id: i64,
) -> Result<Vec<LockedRuleRow>, AstralError> {
    // delegator 侧委托的规则位于其 delegate 卡上（远端卡）。
    let mut delegation_ids: Vec<i64> = delegations
        .iter()
        .filter(|record| {
            record.delegator_card_id == deleted_card_id
                && record.delegate_card_id != deleted_card_id
        })
        .map(|record| record.delegation_id)
        .collect();
    if delegation_ids.is_empty() {
        return Ok(Vec::new());
    }
    delegation_ids.sort_unstable();
    delegation_ids.dedup();

    let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
        "SELECT {LOCKED_RULE_SELECT_LOCAL} FROM permission_rule pr \
         INNER JOIN user_card uc ON uc.card_id = pr.card_id \
         WHERE pr.source_type = 'DELEGATION' AND pr.source_id IN ("
    ));
    let mut first = true;
    for delegation_id in &delegation_ids {
        if !first {
            builder.push(", ");
        }
        builder.push_bind(*delegation_id);
        first = false;
    }
    builder.push(") ORDER BY pr.rule_id ASC FOR UPDATE");
    builder
        .build_query_as::<LockedRuleRow>()
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)
}

/// `rule_repository::LOCKED_RULE_SELECT` 的本地引用（同一列清单经别名映射；
/// 保持 FromRow 字段一致，避免重复维护列名漂移）。
const LOCKED_RULE_SELECT_LOCAL: &str = crate::repository::rule_repository::LOCKED_RULE_SELECT;

/// 从合并后的锁定规则集中按主键取回一行（Internal fail-closed —— 锁定集在
/// 同一事务内不可能减少）。
fn locked_rule_of(
    combined_rules: &[LockedRuleRow],
    rule_id: i64,
) -> Result<&LockedRuleRow, AstralError> {
    combined_rules
        .iter()
        .find(|row| row.rule_id == rule_id)
        .ok_or_else(|| {
            AstralError::Internal(format!(
                "locked cascade rule set drift: expected rule {rule_id} inside the acquired set"
            ))
        })
}

/// DELEGATION 规则 × 锁定委托行的配对解析（纯判定）。
///
/// 每条捕获的 DELEGATION 规则必须指向一个**锁定中且 ACTIVE** 的委托行：
/// - 记录缺失 → Validation（规则来源指向不存在的聚合）；
/// - 非 ACTIVE 委托仍持有规则行 → Validation（生命周期残留 drift）；
/// - 被删卡是 delegate → 规则必须落在被删卡上；被删卡是 delegator → 规则必须
///   恰好落在远端 delegate 卡上。位置不符即 scope drift；
/// - resource/action 与委托行不一致 → drift；
/// - 有效期不可证明 → repair required（fail-closed）。
///
/// 全部通过时返回该委托行引用。
fn resolve_delegation_pairing<'d>(
    rule_row: &LockedRuleRow,
    delegations: &'d [DelegationRecord],
    deleted_card_id: i64,
) -> Result<&'d DelegationRecord, AstralError> {
    let delegation_id = rule_row.source_id.filter(|id| *id > 0).ok_or_else(|| {
        AstralError::Validation(format!(
            "delegation rule {} carries no usable source id; refusing to pair it with a delegation aggregate",
            rule_row.rule_id
        ))
    })?;
    let record = delegations.iter().find(|d| d.delegation_id == delegation_id).ok_or_else(|| {
        AstralError::Validation(format!(
            "DELEGATION rule {} references permission_delegation {} outside the locked cascade scope; refusing to delete a clause of unprovable provenance",
            rule_row.rule_id, delegation_id
        ))
    })?;
    if record.status != "ACTIVE" {
        return Err(AstralError::Validation(format!(
            "non-ACTIVE permission_delegation {} still owns DELEGATION rule {}; lifecycle residue must be repaired before the cascade deletes it",
            record.delegation_id, rule_row.rule_id
        )));
    }
    if record.delegate_card_id == deleted_card_id {
        if rule_row.card_id != deleted_card_id {
            return Err(AstralError::Validation(format!(
                "DELEGATION rule {} sits on card {} but delegation {} marks this cascade target as the delegate; scope drift detected",
                rule_row.rule_id, rule_row.card_id, record.delegation_id
            )));
        }
    } else if record.delegator_card_id == deleted_card_id {
        if rule_row.card_id != record.delegate_card_id {
            return Err(AstralError::Validation(format!(
                "DELEGATION rule {} sits on card {} but delegation {} expects its clause on remote delegate card {}; scope drift detected",
                rule_row.rule_id, rule_row.card_id, record.delegation_id, record.delegate_card_id
            )));
        }
    } else {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} does not link to cascade target card {} through delegation {}; provenance is unprovable",
            rule_row.rule_id, deleted_card_id, record.delegation_id
        )));
    }
    if rule_row.resource_type.trim() != record.resource_type.trim()
        || rule_row.action_code.trim() != record.action_code.trim()
    {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} resource/action drifted from permission_delegation {}; refusing to revoke a mismatched grant",
            rule_row.rule_id, record.delegation_id
        )));
    }
    require_provable_expiry(record)?;
    Ok(record)
}

const USER_CARD_SELECT_COLUMNS: &str =
    "uc.card_id, uc.user_id, uc.domain_id, uc.card_type, uc.card_status, \
         uc.template_id, uc.level_id, uc.priority, uc.is_primary, \
         DATE_FORMAT(uc.valid_from, '%Y-%m-%dT%H:%i:%sZ') as valid_from, \
         DATE_FORMAT(uc.valid_until, '%Y-%m-%dT%H:%i:%sZ') as valid_until, \
         DATE_FORMAT(uc.created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
         DATE_FORMAT(uc.updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at, \
         uc.tenant_id, \
         CONCAT(IFNULL(t.template_name,''), ' · ', IFNULL(l.level_name,'')) as card_name, \
         t.template_code, t.template_name, l.level_code, l.level_name, l.level_no, \
         NULL as action_codes";

/// FROM + LEFT JOIN（只保留身份/平台目录展示字段 JOIN；action_codes 摘要不再在
/// 此 JOIN `permission_rule_snapshot` 的 MAX(version_no) 子查询 —— 统一由
/// `attach_card_permission_summaries` 在行加载后经共享
/// `astral_db::load_card_permission_summaries` 按页批量回填）
const USER_CARD_FROM_JOINS: &str = "user_card uc \
         LEFT JOIN user_card_template t ON t.template_id = uc.template_id \
         LEFT JOIN user_card_level_definition l ON l.level_id = uc.level_id";

#[async_trait]
pub trait UserCardRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_cards(&self, filter: &UserCardFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY user_id, card_id）
    async fn list_cards(
        &self,
        filter: &UserCardFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserCardRecord>, AstralError>;
    async fn get_card(&self, card_id: i64) -> Result<Option<UserCardRecord>, AstralError>;
    /// 新建卡 + 绑定模板规则集（BASE），返回新 card_id
    async fn create_card(&self, new: &NewUserCard) -> Result<i64, AstralError>;
    /// 部分更新（card_status / priority / is_primary / level_id）
    ///
    /// 状态变更是授权 source mutation：补丁必须携带 Gateway 已验证的正数
    /// `actor_id` 与可选的请求级 operation id（契约同 [`NewUserCard`]），且
    /// 只能离开 ACTIVE（状态机见 `validate_card_status_transition`）——
    /// 任何把卡送回 ACTIVE 的迁移、未知状态或不可归属的调用者一律
    /// fail-closed 拒绝；离开 ACTIVE 时同事务落带元数据的 CARD REVOKE 投影
    /// 与审计关联行。
    async fn update_card(&self, card_id: i64, patch: &UserCardPatch) -> Result<(), AstralError>;
    /// 级联删除（事务：清理规则/快照/规则集引用 + 软删卡）
    async fn delete_with_cascade(&self, card_id: i64) -> Result<DeleteCascadeResult, AstralError>;
    /// 恢复已删除卡（DISABLED → ACTIVE），返回是否命中
    ///
    /// 恢复是资格恢复而非授权恢复：级联删除时该卡全部授权贡献已版本化 REMOVE，
    /// restore 绝不隐式复活任何 grant（ALLOW-only，重新授权需要显式的新
    /// revision/mutation）；同事务落带 metadata 的 CARD_RESTORED 投影、
    /// ELIGIBILITY 事件与恢复审计关联行。
    async fn restore_card(&self, card_id: i64) -> Result<bool, AstralError>;
    /// 绑定单卡（PENDING/INACTIVE → ACTIVE + user_id），返回是否命中。
    ///
    /// 与 [`Self::bind_card_async_one`] 共享 [`bind_card_with_reassignment_guard`]
    /// 同一受守卫核心：正目标用户校验、锁卡证明候选状态、归属/贡献 fail-closed
    /// 守卫全部先于换主 UPDATE（详见核心函数文档）。
    async fn bind_card(&self, card_id: i64, user_id: i64) -> Result<bool, AstralError>;
    /// 异步绑定单卡（PENDING/INACTIVE → ACTIVE + user_id），返回是否命中。
    ///
    /// 与 [`Self::bind_card`] 共享同一受守卫核心；异步批量入口没有任何绕过
    /// 归属/贡献守卫的旁路。
    async fn bind_card_async_one(&self, card_id: i64, user_id: i64) -> Result<bool, AstralError>;
    /// 冲突检测：同一用户下同 card_type 不同 template_id 的 ACTIVE 卡（限定管理范围）
    async fn find_conflicts(
        &self,
        filter: &UserCardFilter,
    ) -> Result<Vec<UserCardRecord>, AstralError>;
    /// 用户第一张活跃卡（personal_permissions grant 用）
    async fn find_active_card_for_user(&self, user_id: i64) -> Result<Option<i64>, AstralError>;
}

/// FOR UPDATE 捕获的更新目标卡身份事实（`update_card` 迁移判定与审计关联的
/// 唯一事实来源：当前状态、属主与租户/域边界都以锁定行为准，不信任请求侧
/// 旧读，也不回读任何缓存或快照）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct LockedUpdateCardRow {
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

pub struct SqlxUserCardRepository {
    db: MySqlPool,
}

impl SqlxUserCardRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }

    /// 行加载后的 action_codes 批量回填（页内一次 `IN (...)` 查询，无 N+1）。
    ///
    /// 权限摘要统一走共享 `astral_db::load_card_permission_summaries`：其内置
    /// fail-closed 投影门禁（CARD head 缺失 / 非 READY / source != projected 的卡
    /// 不读快照、不产生摘要）。查询错误必须原样传播为 `AstralError::Database`，
    /// 绝不降级为“空 action_codes 授权视图”或吞错继续返回卡行。
    async fn attach_card_permission_summaries(
        &self,
        records: &mut [UserCardRecord],
    ) -> Result<(), AstralError> {
        let card_ids: Vec<i64> = records.iter().map(|record| record.card_id).collect();
        let summaries = astral_db::load_card_permission_summaries(&self.db, &card_ids)
            .await
            .map_err(|e| AstralError::Database(format!("User card summaries failed: {e}")))?;
        apply_card_permission_summaries(records, &summaries);
        Ok(())
    }
}

/// 把共享摘要查询结果回填到本页卡记录（纯逻辑，无 IO）。
///
/// 摘要缺失（投影门禁剔除 / 无 ALLOW 快照行）的卡保持 `action_codes = None`：
/// 绝不为它伪造空 CSV 授权，也不保留 SQL 阶段的占位残留 —— 摘要是该字段的
/// 唯一事实来源。
fn apply_card_permission_summaries(
    records: &mut [UserCardRecord],
    summaries: &std::collections::HashMap<i64, astral_db::CardPermissionSummary>,
) {
    for record in records {
        let summary = summaries.get(&record.card_id);
        record.action_codes = summary.and_then(|s| s.action_codes.clone());
    }
}

/// 追加过滤条件（列表与总数共用）
fn push_filter<'args>(builder: &mut QueryBuilder<'args, sqlx::MySql>, filter: &UserCardFilter) {
    if let Some(user_id) = filter.user_id {
        builder.push(" AND user_id = ").push_bind(user_id);
    }
    if let Some(template_id) = filter.template_id {
        builder.push(" AND template_id = ").push_bind(template_id);
    }
    if let Some(status) = &filter.card_status {
        builder
            .push(" AND card_status = ")
            .push_bind(status.to_uppercase());
    }
    if let Some(tenant_id) = filter.tenant_id {
        builder.push(" AND tenant_id = ").push_bind(tenant_id);
    }
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
}

#[async_trait]
impl UserCardRepository for SqlxUserCardRepository {
    async fn count_cards(&self, filter: &UserCardFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM user_card WHERE 1=1");
        push_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_cards(
        &self,
        filter: &UserCardFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserCardRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {USER_CARD_SELECT_COLUMNS} FROM {USER_CARD_FROM_JOINS} WHERE 1=1"
        ));
        push_filter(&mut builder, filter);
        builder
            .push(" ORDER BY uc.user_id, uc.card_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let mut records = builder
            .build_query_as::<UserCardRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        self.attach_card_permission_summaries(&mut records).await?;
        Ok(records)
    }

    async fn get_card(&self, card_id: i64) -> Result<Option<UserCardRecord>, AstralError> {
        let mut record = sqlx::query_as::<_, UserCardRecord>(&format!(
            "SELECT {USER_CARD_SELECT_COLUMNS} FROM {USER_CARD_FROM_JOINS} WHERE uc.card_id = ?"
        ))
        .bind(card_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        if let Some(record) = record.as_mut() {
            self.attach_card_permission_summaries(std::slice::from_mut(record))
                .await?;
        }
        Ok(record)
    }

    async fn create_card(&self, new: &NewUserCard) -> Result<i64, AstralError> {
        // ── Phase 0: 纯校验先于任何 durable 写入 ─────────────────────────────
        // 可选 x-request-id 复用为 durable operation id：不安全 header fail-closed
        // （与审批/direct 规则路径同一条统一门禁），缺失/空白走确定性派生。
        let request_operation_id =
            validated_request_operation_id(new.request_operation_id.as_deref())?;
        validate_create_card_ledger_scope(new)?;
        // 租户绑定纯门禁（正数）先于事务：任一创建路径绑定非正数租户一律拒绝。
        if let Some(tenant_id) = new.tenant_id {
            validate_create_card_tenant_binding(tenant_id)?;
        }

        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;

        // 租户绑定存在性证明（fail-closed，先于任何 source 写入）：tenant 行
        // FOR UPDATE 缺失即 Validation 整体回滚，绝不把 user_card.tenant_id 绑到
        // 不存在的租户上，也绝不与 delete_tenant 的守卫产生孤儿卡竞态（锁序
        // tenant 行 → user_card source 行，与 tenant_repository 同向）。
        if let Some(tenant_id) = new.tenant_id {
            let locked_tenant: Option<(i64,)> = sqlx::query_as(CREATE_CARD_TENANT_LOCK_SQL)
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_error)?;
            if locked_tenant.is_none() {
                return Err(AstralError::Validation(format!(
                    "create card requires an existing tenant: tenant {tenant_id} not found; \
                     refusing to bind user_card.tenant_id to a missing tenant"
                )));
            }
        }
        let result = sqlx::query(
            "INSERT INTO user_card \
             (user_id, domain_id, card_type, card_status, template_id, level_id, priority, is_primary, tenant_id) \
             VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)",
        )
        .bind(new.user_id)
        .bind(new.domain_id)
        .bind(&new.card_type)
        .bind(new.template_id)
        .bind(new.level_id)
        .bind(new.priority)
        .bind(new.is_primary)
        .bind(new.tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        // 新建卡主键是本事务拥有的 source 身份事实；不可用即持久层异常，整体拒绝。
        if result.last_insert_id() == 0 {
            return Err(AstralError::Internal(
                "user_card insert returned an unusable id".into(),
            ));
        }
        let new_id = result.last_insert_id() as i64;

        // 模板绑定失败必须回滚创建，避免卡片处于无授权规则集的半完成状态。
        // 模板路径贯穿账本/审计的 operation id 捕获到外层变量，供同事务的
        // ELIGIBILITY durable invalidation intent 复用同一源 mutation 身份。
        let mut template_path_operation_id: Option<String> = None;
        if let Some(template_id) = new.template_id {
            // 锁定集合与代次捕获（单语句，rule_set_id 升序）：source 行与其投影 head
            // 一并 FOR UPDATE —— 与后续 ensure/rebuild 写入同一取锁方向，binding-side
            // 家族（user_card → rule_set/head → refs/entries）之间无反向锁序。
            let locked_rule_sets: Vec<LockedTemplateRuleSetRow> = sqlx::query_as(
                "SELECT rs.rule_set_id AS rule_set_id, rs.tenant_id AS tenant_id, \
                 h.source_generation AS source_generation \
                 FROM rule_set rs \
                 LEFT JOIN authorization_projection_head h \
                   ON h.aggregate_type = 'RULE_SET' AND h.aggregate_id = rs.rule_set_id \
                 WHERE rs.source_type = 'TEMPLATE' AND rs.source_id = ? AND rs.enabled = 1 \
                 ORDER BY rs.rule_set_id ASC FOR UPDATE",
            )
            .bind(template_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(db_error)?;
            ensure_unique_template_rule_set_ids(&locked_rule_sets)?;
            for row in &locked_rule_sets {
                // Reject one-sided tenant scopes before any durable write; the
                // enclosing transaction rolls back the new card if any template
                // RuleSet is not in the same scope.
                validate_binding_tenants(row.tenant_id, new.tenant_id)?;
            }
            // Operation identity（首个 ledger/outbox/audit 写之前确定）：显式请求
            // id 原样贯穿，否则以锁定的最大 RULE_SET 代次确定性派生。
            let operation_id = request_operation_id.unwrap_or_else(|| {
                let locked_ruleset_generation = locked_rule_sets
                    .iter()
                    .filter_map(|row| row.source_generation)
                    .max()
                    .unwrap_or(0);
                derive_create_card_template_operation_id(
                    new_id,
                    template_id,
                    locked_ruleset_generation,
                )
            });
            template_path_operation_id = Some(operation_id.clone());
            let context = RuleSetMutationContext::system(&operation_id)?;

            // ── CARD parent：单张带 actor/operation 元数据的 CARD_CREATED 事件 ──
            // 其 durable 身份作为本卡全部模板绑定 ADD 贡献的 generation/fence 锚点；
            // 不再逐绑定追加 RULE_SET_BOUND 父事件（避免旧 worker 额外重建）。
            let parent_projection = append_card_projection_with_metadata_in_tx(
                &mut tx,
                new_id,
                "CARD_CREATED",
                astral_db::ProjectionEventMetadata {
                    actor_id: SYSTEM_ACTOR_ID,
                    operation_id: &operation_id,
                },
            )
            .await?;

            for row in &locked_rule_sets {
                // Sources are locked by RuleSet id; prove each RuleSet before its reference.
                ensure_rule_set_projection_in_tx(
                    &mut tx,
                    row.rule_set_id,
                    row.tenant_id,
                    SYSTEM_ACTOR_ID,
                    &operation_id,
                )
                .await?;
                // 严格 ref 主键捕获：普通 INSERT（非 IGNORE）。新卡在本事务内不可能
                // 已有 ref —— IGNORE 命中旧行或拿不到可用主键都说明不变量已被破坏，
                // 必须整体失败而不是猜测 ref_id=0 或静默复用未知旧绑定。
                let inserted_ref = sqlx::query(
                    "INSERT INTO card_rule_set_ref \
                     (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, 'BASE', ?)",
                )
                .bind(new_id)
                .bind(row.rule_set_id)
                .bind(new.tenant_id)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?;
                let ref_id = i64::try_from(inserted_ref.last_insert_id())
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        AstralError::Internal(
                            "card_rule_set_ref insert returned an unusable id".into(),
                        )
                    })?;
                // 绑定本身是一次 RuleSet 授权语义变更：RULE_SET 投影事件 + BIND_CARD
                // 审计与标准 bind_card 同语义（缓存失效/快照重建契约一致）。
                let rule_projection = append_rule_set_projection_in_tx(
                    &mut tx,
                    row.rule_set_id,
                    EVENT_TYPE_RULE_SET_UPDATE,
                    astral_db::ProjectionEventMetadata {
                        actor_id: SYSTEM_ACTOR_ID,
                        operation_id: &operation_id,
                    },
                )
                .await?;
                // enabled+ALLOW 条目的标准 ADD 物化（rev1 base0→target1）；空 RuleSet
                // 合法返回空贡献集。贡献以 entry×card×ref 维度派生独立稳定事件号，
                // 不复用父事件号触发 uk_ade_event。
                let addition = append_card_create_ruleset_entry_adds_in_tx(
                    &mut tx,
                    row.rule_set_id,
                    &parent_projection,
                    &context,
                    ref_id,
                    new_id,
                    new.user_id.unwrap_or_default(),
                    new.tenant_id.unwrap_or_default(),
                    new.domain_id,
                    "BASE",
                )
                .await?;

                // BIND_CARD 审计关联面（同事务、序列化/DB 错误一律上抛回滚）：
                // parent CARD 事件、模板/租户/卡/ref 维度与全部贡献事件号可追溯。
                let addition_detail = serde_json::json!({
                    "cardId": new_id,
                    "tenantId": new.tenant_id,
                    "templateId": template_id,
                    "refId": ref_id,
                    "refType": "BASE",
                    "parentSourceEventId": parent_projection.event_id,
                    "contributionEventIds": addition
                        .added_entries
                        .iter()
                        .map(|entry| entry.event_id.as_str())
                        .collect::<Vec<_>>(),
                    "ruleSetEntryIds": addition
                        .added_entries
                        .iter()
                        .map(|entry| entry.entry_id)
                        .collect::<Vec<_>>(),
                    "boundCardIds": [new_id],
                    "bindingRefIds": [ref_id],
                });
                insert_rule_set_projection_audit_in_tx(
                    &mut tx,
                    &RuleSetProjectionAuditEntry {
                        rule_set_id: row.rule_set_id,
                        entry_id: None,
                        aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                        aggregate_id: row.rule_set_id,
                        event_id: &rule_projection.event_id,
                        source_generation: rule_projection.source_generation,
                        operation_id: &operation_id,
                        actor_id: SYSTEM_ACTOR_ID,
                        change_type: "BIND_CARD",
                        old_value_json: None,
                        new_value_json: Some(&addition_detail.to_string()),
                        tenant_id: rule_projection.tenant_id,
                    },
                )
                .await?;
            }
        }

        // 无模板路径：不物化任何账本贡献，但仍写一张带 operation 元数据的
        // CARD_CREATED 父事件（outbox correlation 契约对全部创建路径一致）。
        // 模板路径的 CARD_CREATED 已在上方绑定循环前写入，这里不再重复。
        if new.template_id.is_none() {
            let plain_operation_id = derive_create_card_plain_operation_id(new_id);
            append_card_projection_with_metadata_in_tx(
                &mut tx,
                new_id,
                "CARD_CREATED",
                astral_db::ProjectionEventMetadata {
                    actor_id: SYSTEM_ACTOR_ID,
                    operation_id: &plain_operation_id,
                },
            )
            .await?;
        }
        // 既有 ELIGIBILITY 语义保持：独立轻量资格通道（推进 ELIGIBILITY head，
        // 不重建规则快照、不发 CARD refresh）与其 durable invalidation intent
        // （ELIGIBILITY_INVALIDATED 同事务落 al_message_outbox）成对落库；
        // commit 证明后直投失效通知，commit 未知绝不发送。失效身份与其所属
        // create 路径贯穿同一稳定 operation id（模板路径 = 账本/审计身份，
        // 无模板路径 = plain 派生），确定性派生，随机 fallback 绝不进入事件链。
        let eligibility_operation_id = template_path_operation_id
            .unwrap_or_else(|| derive_create_card_plain_operation_id(new_id));
        append_eligibility_projection_with_invalidation_in_tx(
            &mut tx,
            new_id,
            &eligibility_operation_id,
        )
        .await?;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    /// 部分更新（card_status / priority / is_primary / level_id）。
    ///
    /// 加固契约（授权 source mutation，五链审查见模块内状态机文档）：
    /// - Phase 0 纯校验先于任何 durable 写入：目标状态 canonical 字母表、显式
    ///   `x-request-id` 统一安全门禁、携带状态的补丁必须带正数 actor
    ///   （Gateway 已验证的 `x-user-id`，由 handler 传播；缺失/非正数整体拒绝，
    ///   绝不以系统身份冒充人类操作者）；
    /// - 状态迁移只认事务内 `FOR UPDATE` 锁定行的当前状态，经
    ///   `validate_card_status_transition` 状态机判定 —— 本入口只能离开
    ///   ACTIVE，任何把卡送回 ACTIVE 的请求整体拒绝（restore/bind 专用入口
    ///   之外的授权恢复旁路不存在）；
    /// - 离开 ACTIVE 的迁移（停用/吊销/挂起）走加固路径：以锁定 CARD head
    ///   代次确定性派生（或复用已校验的显式）稳定 operation id，CARD REVOKE
    ///   投影事件带 actor/operation 元数据落库，ELIGIBILITY 资格事件同事务，
    ///   审计关联行（`audit_log`，event_type `USER_CARD_MUTATION`）同事务落库
    ///   —— 任一失败整体回滚，绝不只写旧链或只写审计；
    /// - 非状态字段更新保持既有语义：legacy `CARD_UPDATE` 投影 +
    ///   条件性 ELIGIBILITY 事件，同一事务。
    async fn update_card(&self, card_id: i64, patch: &UserCardPatch) -> Result<(), AstralError> {
        // ── Phase 0: 纯校验先于任何 durable 写入 ─────────────────────────────
        // 目标状态字母表（不信任 handler 白名单：本 trait 为 pub 入口，自包含
        // fail-closed，未知字符串绝不进入 SQL 绑定值）。
        let requested_status = match patch.card_status.as_deref() {
            Some(raw) => Some(normalize_requested_card_status(raw)?),
            None => None,
        };
        // 显式 x-request-id 复用为 durable operation id：不安全 header
        // fail-closed（与 create/审批/direct 规则路径同一条统一门禁）。
        let request_operation_id =
            validated_request_operation_id(patch.request_operation_id.as_deref())?;
        // 状态变更是授权 source mutation：必须携带 Gateway 已验证的正数 actor。
        if requested_status.is_some() && patch.actor_id.is_none_or(|actor_id| actor_id <= 0) {
            return Err(AstralError::Auth(
                "user card status mutation requires a verified positive actor id propagated \
                 from the HTTP handler (x-user-id); refusing an unattributable authorization \
                 mutation"
                    .into(),
            ));
        }
        let status_mutation = requested_status.is_some();
        if !status_mutation
            && patch.priority.is_none()
            && patch.is_primary.is_none()
            && patch.level_id.is_none()
        {
            return Ok(());
        }

        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;

        // ── Phase 1: 锁定行身份事实（迁移判定只认锁定状态，不信任请求旧读）──
        let locked: Option<LockedUpdateCardRow> = sqlx::query_as(
            "SELECT card_status, user_id, tenant_id, domain_id \
             FROM user_card WHERE card_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
        let locked = locked.ok_or_else(|| {
            AstralError::NotFound(format!("user card {card_id} not found or unchanged"))
        })?;

        // The transition must be derived from the locked current state, not from
        // the requested target alone. A no-op update on an already inactive card
        // is not a new revoke mutation.
        let CardStatusUpdateSemantics {
            exits_active,
            status_changed,
        } = classify_card_status_update(&locked.card_status, requested_status.as_deref());

        // ── Phase 2: 状态机判定（先于 UPDATE；迁移非法则零副作用回滚）────────
        if let Some(requested) = &requested_status {
            validate_card_status_transition(&locked.card_status, requested)?;
        }

        // 离开 ACTIVE：先锁定 CARD head 并稳定 operation 身份（capture-before-
        // write，与级联删除 Phase 2 同一纪律；身份失败时不残留任何 source 变更）。
        let operation_id = if exits_active {
            let locked_generation: i64 = sqlx::query_scalar::<_, Option<i64>>(
                "SELECT source_generation FROM authorization_projection_head \
                 WHERE aggregate_type = 'CARD' AND aggregate_id = ? FOR UPDATE",
            )
            .bind(card_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?
            .flatten()
            .unwrap_or(0);
            match request_operation_id {
                Some(explicit) => explicit,
                None => derive_update_card_operation_id(card_id, locked_generation)?,
            }
        } else {
            // 非退出路径不消费 operation 身份（保持占位，避免分支携带 Option）。
            String::new()
        };

        // ── Phase 3: source UPDATE（全部绑定参数；锁定状态下 status 谓词作为
        // 第二道防线，与 bind 核心的候选状态谓词同一模式）────────────────────
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE user_card SET ");
        let mut first = true;
        if let Some(status) = &requested_status {
            builder.push("card_status = ").push_bind(status);
            first = false;
        }
        if let Some(priority) = patch.priority {
            if !first {
                builder.push(", ");
            }
            builder.push("priority = ").push_bind(priority);
            first = false;
        }
        if let Some(is_primary) = patch.is_primary {
            if !first {
                builder.push(", ");
            }
            builder.push("is_primary = ").push_bind(is_primary);
            first = false;
        }
        if let Some(level_id) = patch.level_id {
            if !first {
                builder.push(", ");
            }
            builder.push("level_id = ").push_bind(level_id);
        }
        builder
            .push(" WHERE card_id = ")
            .push_bind(card_id)
            .push(" AND card_status = ")
            .push_bind(locked.card_status.clone());
        let result = builder.build().execute(&mut **tx).await.map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(AstralError::NotFound(format!(
                "user card {card_id} not found or unchanged"
            )));
        }

        // ── Phase 4: 投影 + 审计（与 source UPDATE 同一事务）────────────────
        if exits_active {
            // 停用/吊销/挂起：带 actor/operation 元数据的 CARD REVOKE（替换旧的
            // 丢身份兼容入口），ELIGIBILITY 资格事件同事务（状态变更必然影响
            // `perm:card:active`），审计关联行同事务落库。
            let parent_projection = append_card_projection_with_metadata_in_tx(
                &mut tx,
                card_id,
                "REVOKE",
                astral_db::ProjectionEventMetadata {
                    actor_id: patch.actor_id.unwrap_or_default(),
                    operation_id: &operation_id,
                },
            )
            .await?;
            // 停用/吊销/挂起：ELIGIBILITY 资格事件（状态变更必然影响
            // `perm:card:active`）与其 durable invalidation intent 同事务成对落库。
            append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, &operation_id)
                .await?;
            insert_user_card_status_audit_in_tx(
                &mut tx,
                &UserCardStatusAuditEntry {
                    actor_id: patch.actor_id.unwrap_or_default(),
                    owner_user_id: locked.user_id.unwrap_or_default(),
                    target_card_id: card_id,
                    operation_id: &operation_id,
                    parent_event_id: &parent_projection.event_id,
                    from_status: &locked.card_status,
                    to_status: requested_status.as_deref().unwrap_or_default(),
                    tenant_id: locked.tenant_id,
                    domain_id: locked.domain_id,
                },
            )
            .await?;
        } else {
            // 既有语义保持：无状态变化/同状态回显走 legacy CARD_UPDATE；
            // 仅状态字段影响资格。
            append_card_projection_in_tx(&mut tx, card_id, "CARD_UPDATE").await?;
            // 同状态回显只更新 source 字段，不产生新的资格失效事件；只有锁定行
            // 证明了真实状态变化时才追加 ELIGIBILITY（与其 durable invalidation
            // intent 成对）。状态机使本分支当前不可达，保留为迁移面扩张的
            // 第二道防线。
            if status_changed && patch_affects_eligibility(patch) {
                let eligibility_operation_id = derive_update_card_eligibility_operation_id(
                    card_id,
                    &locked.card_status,
                    requested_status.as_deref().unwrap_or(&locked.card_status),
                )?;
                append_eligibility_projection_with_invalidation_in_tx(
                    &mut tx,
                    card_id,
                    &eligibility_operation_id,
                )
                .await?;
            }
        }
        tx.commit_consuming().await?;
        Ok(())
    }

    async fn delete_with_cascade(&self, card_id: i64) -> Result<DeleteCascadeResult, AstralError> {
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;

        // ── Phase 1: capture/lock（锁序见模块头注释）──────────────────────────
        // 0) 完整参与卡集合 plain 预读（同连接、不带锁）：{被删卡} ∪ 受影响委托行
        //    的两端卡。集合只用于确定锁集合与随后的漂移复核，绝不当作授权事实。
        let pre_read_pairs: std::collections::BTreeSet<(i64, i64)> =
            probe_cascade_delegation_endpoint_pairs_in_tx(&mut tx, card_id)
                .await?
                .into_iter()
                .collect();
        let probed_participants =
            collect_cascade_participant_ids(card_id, pre_read_pairs.iter().copied())?;

        // 1) 全部参与卡一次性按 card_id 升序 FOR UPDATE（全局锁序第 1 步）：单语句
        //    取得全部 user_card 行锁，先于任何 permission_delegation /
        //    permission_rule / source mutation。不再先单独锁被删卡、再按任意顺序
        //    逐张补锁远端卡 —— 统一升序方向消除互链委托并发级联的 ABBA 环；
        //    IN 值全部经 QueryBuilder 绑定，不拼接用户输入。
        let locked_cards =
            lock_cascade_participant_cards_in_tx(&mut tx, &probed_participants).await?;

        // 被删卡缺行 → 既有 exists=false 短路语义保持（本事务尚未产生任何写入，
        // 返回即回滚释放全部行锁）。
        let Some(card) = locked_cards
            .iter()
            .find(|row| row.card_id == card_id)
            .cloned()
        else {
            return Ok(DeleteCascadeResult {
                exists: false,
                permission_rule_deleted: 0,
                snapshot_deleted: 0,
                rule_set_ref_deleted: 0,
            });
        };
        // 其余参与卡缺行 = 预读到锁定之间承载卡行消失：不可证明状态，整体
        // fail-closed。锁定集来自 IN 集合本身，不存在多余行；重复 id 已在预读去重。
        for expected in &probed_participants {
            if *expected == card_id {
                continue;
            }
            if !locked_cards.iter().any(|row| row.card_id == *expected) {
                return Err(AstralError::Internal(format!(
                    "cascade participant card {expected} vanished between the plain pre-read and the ordered participant lock"
                )));
            }
        }
        // 承载卡视图（被删卡以外的全部远端参与者）；身份/租户事实全部来自锁定行。
        let carrier_rows: Vec<CascadeCarrierCardRow> = locked_cards
            .iter()
            .filter(|row| row.card_id != card_id)
            .map(|row| CascadeCarrierCardRow {
                card_id: row.card_id,
                user_id: row.user_id,
                domain_id: row.domain_id,
                tenant_id: row.tenant_id,
            })
            .collect();

        // 2) 受影响委托聚合行按 delegation_id 升序 FOR UPDATE；随后复核预读-锁定
        //    一致性：端点对越界或集合漂移都说明存在绕过全局锁序的并发委托变更 ——
        //    冲突回滚重试，绝不在陈旧集合上执行破坏性级联删除。
        let delegations = lock_affected_delegations_in_tx(&mut tx, card_id).await?;
        verify_cascade_participant_consistency(&pre_read_pairs, &delegations)?;

        // 3) 被删卡全部来源的 permission_rule 行 + delegator 侧远端 DELEGATION
        //    规则行，统一按 rule_id 升序合并（capture-before-delete 的完整事实面）。
        let rules = SqlxRuleRepository::lock_all_card_rules_in_tx(&mut tx, card_id).await?;
        let remote_rules =
            lock_remote_delegation_rules_in_tx(&mut tx, &delegations, card_id).await?;
        let mut combined_rules = rules.clone();
        for remote in &remote_rules {
            // 与被删卡规则集重叠（例如历史 self-delegation 残留）时去重，
            // 保证每个 rule_id 只处理一次。
            if !combined_rules
                .iter()
                .any(|row| row.rule_id == remote.rule_id)
            {
                combined_rules.push(remote.clone());
            }
        }
        combined_rules.sort_by_key(|row| row.rule_id);

        // ── 幂等短路 ──────────────────────────────────────────────────────────
        // 重复/并发删除（此前同一事务已清空规则+引用、卡已离开 ACTIVE、
        // 且无任何 ACTIVE 委托残留）直接返回既有结果，不追加任何新事件 —— 每次
        // 重放都从锁定 CARD 代次重新派生 operation id 会制造新事件号，被此门禁
        // 阻断。ACTIVE 委托仍然存在时不得短路（必须继续走全量撤销路径）。
        // （旧实现还要求旧链快照行已清空；该表已随迁移
        // 20260827000002 删除，快照维度整体退役。）
        if card.card_status != "ACTIVE"
            && combined_rules.is_empty()
            && !delegations.iter().any(|record| record.status == "ACTIVE")
        {
            let leftover_refs: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM card_rule_set_ref WHERE card_id = ?")
                    .bind(card_id)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(db_error)?;
            if leftover_refs == 0 {
                return Ok(DeleteCascadeResult {
                    exists: true,
                    permission_rule_deleted: 0,
                    snapshot_deleted: 0,
                    rule_set_ref_deleted: 0,
                });
            }
            // 非空残留 ref 走完整清理路径（orphan 清理 + 审计），不静默通过。
        }

        // ── Phase 2: 校验全部贡献 identity（纯计算先于任何 durable 写入）──────
        let locked_generation: i64 = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT source_generation FROM authorization_projection_head \
             WHERE aggregate_type = 'CARD' AND aggregate_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .flatten()
        .unwrap_or(0);
        if locked_generation < 0 {
            return Err(AstralError::Validation(
                "CARD projection head carries a negative generation; refusing to derive a cascade operation identity from it"
                    .into(),
            ));
        }
        // proven operation id：绑定 card id + mutation kind + 锁定 source 代次；
        // direct/approval/delegation 全部贡献共享这一个稳定 operation id。
        let operation_id = derive_card_cascade_operation_id(card_id, locked_generation);

        // 配对（先于分类）：每条捕获的 DELEGATION 规则都必须指向锁定中的 ACTIVE
        // 委托聚合；未配对/漂移/非 ACTIVE 残留在此整体 fail-closed —— 已入账行
        // 存在时绝不静默跳过。
        struct DelegationPairing {
            rule_id: i64,
            delegation_index: usize,
        }
        let mut pairings: Vec<DelegationPairing> = Vec::new();
        for row in &combined_rules {
            if row.source_type.trim() != "DELEGATION" {
                continue;
            }
            let record = resolve_delegation_pairing(row, &delegations, card_id)?;
            let delegation_index = delegations
                .iter()
                .position(|d| d.delegation_id == record.delegation_id)
                .expect("resolve_delegation_pairing returned a locked record");
            if pairings
                .iter()
                .any(|pairing| pairing.delegation_index == delegation_index)
            {
                return Err(AstralError::Validation(format!(
                    "ACTIVE permission_delegation {} owns more than one captured DELEGATION rule; repair required before the cascade deletes this aggregate",
                    record.delegation_id
                )));
            }
            pairings.push(DelegationPairing {
                rule_id: row.rule_id,
                delegation_index,
            });
        }
        // 每个 ACTIVE 委托都必须至少拥有一条被捕获的规则行，否则级联后它将
        // 指向一张已删/已禁用的卡却保持 ACTIVE —— 这正是 M3 要消除的 ghost，
        // fail-closed 要求修复而不是静默跳过。
        for (index, record) in delegations.iter().enumerate() {
            if record.status == "ACTIVE"
                && !pairings
                    .iter()
                    .any(|pairing| pairing.delegation_index == index)
            {
                return Err(AstralError::Validation(format!(
                    "ACTIVE permission_delegation {} links to card {card_id} without any capturable DELEGATION rule; repair required instead of a silent skip",
                    record.delegation_id
                )));
            }
        }

        // 逐规则分类并预派生独立 contribution event id；任一 tenantless /
        // missing request / 非法形状失败都在进入删除前整体回滚。
        enum PlannedKind {
            Direct,
            Approval {
                request_id: i64,
            },
            Delegation {
                delegation_id: i64,
                /// 授权承载卡 = 被删卡或远端 delegate 卡（provenance/card 边界）。
                carrier_card_id: i64,
                carrier_user_id: i64,
                facts_tenant_id: i64,
                facts_domain_id: Option<i64>,
                resource: String,
                action: String,
                not_before_unix: Option<i64>,
                expires_at_unix: i64,
            },
        }
        struct CascadePlanEntry {
            rule_id: i64,
            kind: PlannedKind,
            contribution_event_id: String,
        }
        let mut plan: Vec<CascadePlanEntry> = Vec::new();
        for row in &combined_rules {
            let Some((kind, source_id)) = classify_permission_rule_for_ledger(row)? else {
                continue;
            };
            match kind {
                CascadeRuleLedgerKind::Direct => {
                    let facts = direct_remove_identity_facts(row);
                    // tenantless 在计划期 fail-closed（derive_direct_tenant 同一门禁）。
                    derive_direct_tenant(&facts)?;
                    let contribution_event_id = derive_direct_contribution_event_id(
                        &operation_id,
                        &facts,
                        DirectRuleOperationKind::Remove,
                    )?;
                    plan.push(CascadePlanEntry {
                        rule_id: row.rule_id,
                        kind: PlannedKind::Direct,
                        contribution_event_id,
                    });
                }
                CascadeRuleLedgerKind::Approval => {
                    let request_id = source_id.ok_or_else(|| {
                        AstralError::Internal(format!(
                            "approval rule {} was classified without a usable request id",
                            row.rule_id
                        ))
                    })?;
                    let facts = ApprovalRemoveLedgerFacts {
                        tenant_id: card.tenant_id,
                        domain_id: card.domain_id,
                        card_id,
                        user_id: card.user_id.unwrap_or(0),
                        request_id,
                        rule_id: row.rule_id,
                    };
                    // 身份派生即合同校验（正数 id / 租户边界）。
                    derive_approval_identity(&facts)?;
                    let contribution_event_id = derive_approval_contribution_event_id(
                        &operation_id,
                        &facts,
                        ApprovalContributionKind::Remove,
                    )?;
                    plan.push(CascadePlanEntry {
                        rule_id: row.rule_id,
                        kind: PlannedKind::Approval { request_id },
                        contribution_event_id,
                    });
                }
                CascadeRuleLedgerKind::Delegation => {
                    let record = {
                        let pairing = pairings
                            .iter()
                            .find(|pairing| pairing.rule_id == row.rule_id)
                            .ok_or_else(|| {
                                AstralError::Internal(format!(
                                    "classified DELEGATION rule {} lacks its pairing result",
                                    row.rule_id
                                ))
                            })?;
                        &delegations[pairing.delegation_index]
                    };
                    // 承载卡：被删卡自身或远端 delegate 卡；tenant/domain/user 全部
                    // 来自锁定行，缺失即计划期 fail-closed。
                    let (carrier_card_id, carrier_user_id, tenant_id, domain_id) = if record
                        .delegate_card_id
                        == card_id
                    {
                        (
                            card_id,
                            card.user_id.unwrap_or(0),
                            card.tenant_id,
                            card.domain_id,
                        )
                    } else {
                        let carrier = carrier_rows
                                .iter()
                                .find(|row| row.card_id == record.delegate_card_id)
                                .ok_or_else(|| {
                                    AstralError::Internal(format!(
                                        "remote delegate card {} for delegation {} is not part of the locked carrier set",
                                        record.delegate_card_id, record.delegation_id
                                    ))
                                })?;
                        (
                            carrier.card_id,
                            carrier.user_id.unwrap_or(0),
                            carrier.tenant_id,
                            carrier.domain_id,
                        )
                    };
                    let expires_at_unix = require_provable_expiry(record)?;
                    let facts = DelegationLedgerFacts {
                        tenant_id: tenant_id.ok_or_else(|| {
                            AstralError::Validation(format!(
                                "carrier card {} of delegation {} has no tenant scope; refusing to revoke a tenantless delegation contribution",
                                record.delegate_card_id, record.delegation_id
                            ))
                        })?,
                        domain_id,
                        card_id: carrier_card_id,
                        user_id: carrier_user_id,
                        delegation_id: record.delegation_id,
                        resource: record.resource_type.as_str(),
                        action: record.action_code.as_str(),
                        not_before_unix: Some(record.effective_from_ts),
                        expires_at_unix,
                    };
                    // 身份派生即合同校验（正数 id / 租户边界 / 有效期窗口）。
                    derive_delegation_identity(&facts)?;
                    let contribution_event_id = derive_delegation_contribution_event_id(
                        &operation_id,
                        &facts,
                        DelegationContributionKind::Revoke,
                    )?;
                    plan.push(CascadePlanEntry {
                        rule_id: row.rule_id,
                        kind: PlannedKind::Delegation {
                            delegation_id: record.delegation_id,
                            carrier_card_id,
                            carrier_user_id,
                            facts_tenant_id: facts.tenant_id,
                            facts_domain_id: facts.domain_id,
                            resource: record.resource_type.clone(),
                            action: record.action_code.clone(),
                            not_before_unix: Some(record.effective_from_ts),
                            expires_at_unix,
                        },
                        contribution_event_id,
                    });
                }
            }
        }
        // 计划期唯一性复核：一个委托聚合只允许一个 tombstone 条目。
        {
            let mut seen = std::collections::BTreeSet::new();
            for entry in &plan {
                if let PlannedKind::Delegation { delegation_id, .. } = entry.kind {
                    if !seen.insert(delegation_id) {
                        return Err(AstralError::Internal(format!(
                            "cascade plan produced duplicate tombstones for delegation {delegation_id}"
                        )));
                    }
                }
            }
        }

        // 规则集分组：绑定写入方都被 user_card 行锁挡住，卡锁定后绑定集合不再
        // 变化，DISTINCT 规则集 id 无需 FOR UPDATE 即可安全分组（升序遍历）。
        let rule_set_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT rule_set_id FROM card_rule_set_ref WHERE card_id = ? \
             ORDER BY rule_set_id ASC",
        )
        .bind(card_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
        let expected_user_id = card.user_id.filter(|id| *id > 0);
        if !plan.is_empty() || !rule_set_ids.is_empty() {
            // 存在新链贡献物化目标时必须有可证明的属主/租户边界。
            if expected_user_id.is_none() {
                return Err(AstralError::Validation(format!(
                    "card {card_id} has no positive owner user id; refusing to materialize ledger revocations without a provable owner"
                )));
            }
            if card.tenant_id.is_none() || card.tenant_id.is_some_and(|tenant| tenant <= 0) {
                return Err(AstralError::Validation(format!(
                    "card {card_id} has a NULL/non-positive tenant_id; refusing to materialize ledger revocations without a tenant scope"
                )));
            }
        }

        // ── Phase 3: 父事件（被删卡一次 CARD REVOKE；每个承载 delegation 贡献的
        // 远端卡各追加一次专用 CARD REVOKE，升序执行）─────────────────────────
        //
        // parent 只提供 generation/fence/source correlation；每个 contribution 都
        // 使用自己派生的独立稳定事件号。远端父事件与 delegation lifecycle revoke
        // 相同：贡献的依赖向量绑定的就是该承载卡自身的 CARD 流代次，因此 parent
        // 必须写在同一个承载卡的流上，不允许跨卡冒用被删卡的代次。
        let parent_projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            card_id,
            "REVOKE",
            astral_db::ProjectionEventMetadata {
                actor_id: SYSTEM_ACTOR_ID,
                operation_id: &operation_id,
            },
        )
        .await?;
        let mut needed_carriers: Vec<i64> = plan
            .iter()
            .filter_map(|entry| match entry.kind {
                PlannedKind::Delegation {
                    carrier_card_id, ..
                } if carrier_card_id != card_id => Some(carrier_card_id),
                _ => None,
            })
            .collect();
        needed_carriers.sort_unstable();
        needed_carriers.dedup();
        let mut delegation_parents: Vec<(i64, astral_db::ProjectionEventIdentity)> = Vec::new();
        for carrier_card_id in &needed_carriers {
            let identity = append_card_projection_with_metadata_in_tx(
                &mut tx,
                *carrier_card_id,
                "REVOKE",
                astral_db::ProjectionEventMetadata {
                    actor_id: SYSTEM_ACTOR_ID,
                    operation_id: &operation_id,
                },
            )
            .await?;
            delegation_parents.push((*carrier_card_id, identity));
        }
        fn parent_for_carrier<'p>(
            parents: &'p [(i64, astral_db::ProjectionEventIdentity)],
            deleted_parent: &'p astral_db::ProjectionEventIdentity,
            card_id: i64,
            carrier_card_id: i64,
        ) -> Result<&'p astral_db::ProjectionEventIdentity, AstralError> {
            if carrier_card_id == card_id {
                return Ok(deleted_parent);
            }
            parents
                .iter()
                .find(|(id, _)| *id == carrier_card_id)
                .map(|(_, identity)| identity)
                .ok_or_else(|| {
                    AstralError::Internal(format!(
                        "no parent projection event was appended for carrier card {carrier_card_id}"
                    ))
                })
        }

        // ── Phase 4: REMOVE/REVOKE ledger deltas（direct/approval/delegation 按
        // rule_id 升序；rule_set 按 id 升序）。head 缺失/stale/gap/CAS 冲突一律
        // 错误上抛，整个事务回滚：不用旧快照/raw source 冒充撤销，不吞错只写
        // 旧链。────────────────────────────────────────────────────────────────
        let mut direct_rule_ids: Vec<i64> = Vec::new();
        let mut direct_contribution_ids: Vec<String> = Vec::new();
        let mut approval_rule_ids: Vec<i64> = Vec::new();
        let mut approval_contribution_ids: Vec<String> = Vec::new();
        struct DelegationAuditRecord {
            delegation_id: i64,
            contribution_event_id: String,
            parent_event_id: String,
        }
        let mut delegation_audit_records: Vec<DelegationAuditRecord> = Vec::new();
        for entry in &plan {
            let row = locked_rule_of(&combined_rules, entry.rule_id)?;
            match &entry.kind {
                PlannedKind::Direct => {
                    let facts = direct_remove_identity_facts(row);
                    let tenant_id = derive_direct_tenant(&facts)?;
                    let grant_id = derive_direct_identity(&facts)?;
                    let head = astral_db::read_grant_head_for_update_in_tx(
                        &mut tx,
                        tenant_id,
                        DIRECT_AGGREGATE_TYPE,
                        card_id,
                        grant_id,
                    )
                    .await
                    .map_err(map_grant_repository_error)?
                    .ok_or_else(|| {
                        AstralError::Validation(format!(
                            "direct grant ledger entry missing for rule {} under card {card_id}; \
                             refusing to cascade-delete an un-versioned authorization",
                            row.rule_id
                        ))
                    })?;
                    let last_target_version =
                        astral_db::read_latest_delta_target_version_for_update_in_tx(
                            &mut tx,
                            tenant_id,
                            DIRECT_AGGREGATE_TYPE,
                            card_id,
                            head.grant_id,
                        )
                        .await
                        .map_err(map_grant_repository_error)?;
                    let (base_version, target_version) =
                        astral_db::next_delta_version(last_target_version)
                            .map_err(map_grant_repository_error)?;
                    let draft = build_direct_remove_draft(
                        &facts,
                        &head,
                        &operation_id,
                        &parent_projection,
                        &entry.contribution_event_id,
                    )?;
                    append_direct_grant_delta_in_tx(&mut tx, &draft, base_version, target_version)
                        .await?;
                    direct_rule_ids.push(row.rule_id);
                    direct_contribution_ids.push(entry.contribution_event_id.clone());
                }
                PlannedKind::Approval { request_id } => {
                    let facts = ApprovalRemoveLedgerFacts {
                        tenant_id: card.tenant_id,
                        domain_id: card.domain_id,
                        card_id,
                        user_id: card.user_id.unwrap_or(0),
                        request_id: *request_id,
                        rule_id: row.rule_id,
                    };
                    let grant_id = derive_approval_identity(&facts)?;
                    let head = astral_db::read_grant_head_for_update_in_tx(
                        &mut tx,
                        card.tenant_id.unwrap_or_default(),
                        APPROVAL_AGGREGATE_TYPE,
                        *request_id,
                        grant_id,
                    )
                    .await
                    .map_err(map_grant_repository_error)?
                    .ok_or_else(|| {
                        AstralError::Validation(format!(
                            "approval grant ledger entry missing for rule {} (request {request_id}) under card {card_id}; \
                             refusing to cascade-delete an un-versioned approval authorization",
                            row.rule_id
                        ))
                    })?;
                    let last_target_version =
                        astral_db::read_latest_delta_target_version_for_update_in_tx(
                            &mut tx,
                            card.tenant_id.unwrap_or_default(),
                            APPROVAL_AGGREGATE_TYPE,
                            *request_id,
                            head.grant_id,
                        )
                        .await
                        .map_err(map_grant_repository_error)?;
                    let (base_version, target_version) =
                        astral_db::next_delta_version(last_target_version)
                            .map_err(map_grant_repository_error)?;
                    let draft = build_approval_remove_draft(
                        &facts,
                        &head,
                        &operation_id,
                        &parent_projection,
                        &entry.contribution_event_id,
                    )?;
                    append_approval_remove_in_tx(&mut tx, &draft, base_version, target_version)
                        .await?;
                    approval_rule_ids.push(row.rule_id);
                    approval_contribution_ids.push(entry.contribution_event_id.clone());
                }
                PlannedKind::Delegation {
                    delegation_id,
                    carrier_card_id,
                    carrier_user_id,
                    facts_tenant_id,
                    facts_domain_id,
                    resource,
                    action,
                    not_before_unix,
                    expires_at_unix,
                } => {
                    let facts = DelegationLedgerFacts {
                        tenant_id: *facts_tenant_id,
                        domain_id: *facts_domain_id,
                        card_id: *carrier_card_id,
                        user_id: *carrier_user_id,
                        delegation_id: *delegation_id,
                        resource: resource.as_str(),
                        action: action.as_str(),
                        not_before_unix: *not_before_unix,
                        expires_at_unix: *expires_at_unix,
                    };
                    let grant_id = derive_delegation_identity(&facts)?;
                    let head = astral_db::read_grant_head_for_update_in_tx(
                        &mut tx,
                        facts.tenant_id,
                        DELEGATION_AGGREGATE_TYPE,
                        facts.delegation_id,
                        grant_id,
                    )
                    .await
                    .map_err(map_grant_repository_error)?
                    .ok_or_else(|| {
                        AstralError::Validation(format!(
                            "delegation grant ledger entry missing for delegation {} under carrier card {}; \
                             refusing to cascade-delete an un-versioned delegation authorization",
                            delegation_id, carrier_card_id
                        ))
                    })?;
                    let last_target_version =
                        astral_db::read_latest_delta_target_version_for_update_in_tx(
                            &mut tx,
                            facts.tenant_id,
                            DELEGATION_AGGREGATE_TYPE,
                            facts.delegation_id,
                            head.grant_id,
                        )
                        .await
                        .map_err(map_grant_repository_error)?;
                    let (base_version, target_version) =
                        astral_db::next_delta_version(last_target_version)
                            .map_err(map_grant_repository_error)?;
                    // 统一 REVOKE tombstone：生命周期撤权语义、成对 before-image/
                    // digest、provenance 保持 DELEGATION/delegation_id/NONE 层。
                    // provenance/grant-id/租户/卡归属对齐由 builder 内部门禁校验。
                    let parent = parent_for_carrier(
                        &delegation_parents,
                        &parent_projection,
                        card_id,
                        *carrier_card_id,
                    )?;
                    let draft = build_delegation_revoke_draft(
                        &facts,
                        &head,
                        &operation_id,
                        parent,
                        &entry.contribution_event_id,
                    )?;
                    append_delegation_grant_delta_in_tx(
                        &mut tx,
                        &draft,
                        base_version,
                        target_version,
                    )
                    .await?;
                    delegation_audit_records.push(DelegationAuditRecord {
                        delegation_id: *delegation_id,
                        contribution_event_id: entry.contribution_event_id.clone(),
                        parent_event_id: parent.event_id.clone(),
                    });
                }
            }
        }

        // RULE_SET 贡献：复用 unbind 的 remove core，整卡共享同一 parent CARD
        // 锚点与 operation id；每个 entry×binding 得到独立稳定 tombstone。
        let mut ruleset_audits: Vec<UserCardCascadeRulesetAudit> = Vec::new();
        for rule_set_id in &rule_set_ids {
            let removal = append_card_cascade_ruleset_removals_in_tx(
                &mut tx,
                card_id,
                card.user_id.unwrap_or_default(),
                card.tenant_id.unwrap_or_default(),
                card.domain_id,
                *rule_set_id,
                &parent_projection,
                &operation_id,
            )
            .await?
            .ok_or_else(|| {
                AstralError::Internal(format!(
                    "rule set bindings under card {card_id} vanished before cascade cleanup; \
                     the frozen binding invariant was violated"
                ))
            })?;
            ruleset_audits.push(UserCardCascadeRulesetAudit {
                rule_set_id: removal.rule_set_id,
                binding_ref_ids: removal.binding_ref_ids,
                removed_entries: removal
                    .removed_entries
                    .into_iter()
                    .map(|contribution| {
                        (
                            contribution.entry_id,
                            contribution.binding_ref_id,
                            contribution.event_id,
                        )
                    })
                    .collect(),
            });
        }

        // ── Phase 5: source cleanup（新链成功后才动 source；计数严格对齐捕获值）
        // 5a) 已撤销的委托聚合置 REVOKED（升序执行；必须在删除规则行之前完成，
        // 使"source 状态 → 删规则 → 禁卡"顺序可审计且失败即回滚）。
        let mut flipped_delegation_ids: Vec<i64> = delegation_audit_records
            .iter()
            .map(|record| record.delegation_id)
            .collect();
        flipped_delegation_ids.sort_unstable();
        flipped_delegation_ids.dedup();
        for delegation_id in &flipped_delegation_ids {
            let revoked_rows = sqlx::query(
                "UPDATE permission_delegation SET status = 'REVOKED', revoked_at = NOW() \
                 WHERE delegation_id = ? AND status = 'ACTIVE'",
            )
            .bind(delegation_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?
            .rows_affected();
            if revoked_rows != 1 {
                return Err(AstralError::Internal(format!(
                    "permission_delegation revoke touched {revoked_rows} rows for delegation {delegation_id} while holding its lock"
                )));
            }
        }

        // 5b) 被删卡上的规则行整批删除（计数对齐捕获值）。
        let pr_deleted = sqlx::query("DELETE FROM permission_rule WHERE card_id = ?")
            .bind(card_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?
            .rows_affected();
        if pr_deleted != rules.len() as u64 {
            return Err(AstralError::Internal(format!(
                "permission_rule cleanup touched {pr_deleted} rows but {count} were locked for card {card_id}",
                count = rules.len()
            )));
        }
        // 5c) 远端承载卡上的 DELEGATION 规则行逐条精确删除（rule_id 白名单）。
        for remote in &remote_rules {
            let removed = sqlx::query("DELETE FROM permission_rule WHERE rule_id = ?")
                .bind(remote.rule_id)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?
                .rows_affected();
            if removed != 1 {
                return Err(AstralError::Internal(format!(
                    "remote DELEGATION rule cleanup missed locked rule {} (delegation side effects would survive)",
                    remote.rule_id
                )));
            }
        }
        // （旧实现在此清理旧链快照行；该表已随迁移 20260827000002 删除，
        // 快照维度整体退役，无需任何清理动作。）
        let rule_set_ref_deleted = sqlx::query("DELETE FROM card_rule_set_ref WHERE card_id = ?")
            .bind(card_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?
            .rows_affected();
        let expected_ref_deletes: u64 = ruleset_audits
            .iter()
            .map(|audit| audit.binding_ref_ids.len() as u64)
            .sum();
        if rule_set_ref_deleted != expected_ref_deletes {
            return Err(AstralError::Internal(format!(
                "card_rule_set_ref cleanup touched {rule_set_ref_deleted} rows but {expected_ref_deletes} were captured for card {card_id}"
            )));
        }

        // 软删卡状态用 Java canonical `DISABLED`（对齐 UserCardServiceImpl：delete 置
        // DISABLED、仅 DISABLED 可恢复）。跨运行时共享 user_card 表，Java 侧恢复只认
        // DISABLED，Rust 必须写入同一状态值。
        let disabled_rows =
            sqlx::query("UPDATE user_card SET card_status = 'DISABLED' WHERE card_id = ?")
                .bind(card_id)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?
                .rows_affected();
        if disabled_rows != 1 {
            return Err(AstralError::Internal(format!(
                "user_card disable touched {disabled_rows} rows for card {card_id} while holding its row lock"
            )));
        }

        // ── Phase 6: ELIGIBILITY 投影事件 + 审计（同一事务）────────────────────
        // 仅保留 ELIGIBILITY_UPDATE 事件及其 durable invalidation intent（worker
        // 存续职责：失效资格缓存）。旧链 CARD REVOKE 二次通知已随迁移
        // 20260827000002 退役：CARD 撤销事实由 Phase 3 父事件与账本 REMOVE delta
        // 承载，且 CARD outbox 事件已无任何重建/刷新消费者（worker 对 CARD 通道
        // 只做终态排水）。
        append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, &operation_id)
            .await?;

        let direct_contribution_refs: Vec<&str> =
            direct_contribution_ids.iter().map(String::as_str).collect();
        let approval_contribution_refs: Vec<&str> = approval_contribution_ids
            .iter()
            .map(String::as_str)
            .collect();
        // 审计数组按 delegation_id 升序输出（确定性 JSON）。
        delegation_audit_records.sort_by_key(|record| record.delegation_id);
        let delegation_id_refs: Vec<i64> = delegation_audit_records
            .iter()
            .map(|record| record.delegation_id)
            .collect();
        let delegation_contribution_refs: Vec<&str> = delegation_audit_records
            .iter()
            .map(|record| record.contribution_event_id.as_str())
            .collect();
        let delegation_parent_refs: Vec<&str> = delegation_audit_records
            .iter()
            .map(|record| record.parent_event_id.as_str())
            .collect();
        insert_user_card_cascade_audit_in_tx(
            &mut tx,
            &UserCardCascadeAuditEntry {
                target_user_id: card.user_id.unwrap_or_default(),
                target_card_id: card_id,
                operation_id: &operation_id,
                parent_event_id: &parent_projection.event_id,
                direct_rule_ids: &direct_rule_ids,
                direct_contribution_event_ids: &direct_contribution_refs,
                approval_rule_ids: &approval_rule_ids,
                approval_contribution_event_ids: &approval_contribution_refs,
                delegation_ids: &delegation_id_refs,
                delegation_contribution_event_ids: &delegation_contribution_refs,
                delegation_parent_event_ids: &delegation_parent_refs,
                rulesets: &ruleset_audits,
            },
        )
        .await?;

        // 任一新链失败均已在上方以 Err 返回使整个事务回滚；此处提交前所有
        // capture/delta/cleanup/disable/legacy/audit 写入均在同一未提交事务内。
        tx.commit_consuming().await?;
        Ok(DeleteCascadeResult {
            exists: true,
            permission_rule_deleted: pr_deleted,
            // 快照维度已随迁移 20260827000002 退役：恒 0，仅为响应形状稳定保留。
            snapshot_deleted: 0,
            rule_set_ref_deleted,
        })
    }

    async fn restore_card(&self, card_id: i64) -> Result<bool, AstralError> {
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        let result = sqlx::query(
            "UPDATE user_card SET card_status = 'ACTIVE' WHERE card_id = ? AND card_status = 'DISABLED'",
        )
        .bind(card_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        // 语义边界（ALLOW-only）：DISABLED 若来自级联删除，该卡全部授权贡献
        // （direct/approval/delegation/规则集 BASE/OVERLAY）已在删除事务内版本化
        // REMOVE 进账本；restore 只把卡行拉回 ACTIVE 并恢复资格面（ELIGIBILITY
        // 事件），绝不隐式 ADD/复活任何 grant —— 重新授权必须走显式的新
        // revision/mutation（bind/grant 家族）。下方审计行记录的是资格恢复事实，
        // 不是授权恢复。
        let (owner_user_id, tenant_id, domain_id): (Option<i64>, Option<i64>, Option<i64>) =
            sqlx::query_as("SELECT user_id, tenant_id, domain_id FROM user_card WHERE card_id = ?")
                .bind(card_id)
                .fetch_one(&mut **tx)
                .await
                .map_err(db_error)?;
        let operation_id = derive_restore_card_operation_id(card_id);
        // CARD_RESTORED 携带 actor/operation 元数据并返回 durable 事件身份，作为
        // 恢复审计 correlation 的父事件锚（与 update_card 退出路径同一带 metadata
        // 投影入口；旧的丢身份兼容入口不得再用于需要审计关联的路径）。
        let parent_projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            card_id,
            "CARD_RESTORED",
            astral_db::ProjectionEventMetadata {
                actor_id: SYSTEM_ACTOR_ID,
                operation_id: &operation_id,
            },
        )
        .await?;
        // 资格恢复事实：ELIGIBILITY 事件与其 durable invalidation intent 同事务
        // 成对落库（commit 证明后直投失效通知）。
        append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, &operation_id)
            .await?;
        insert_user_card_restore_audit_in_tx(
            &mut tx,
            &UserCardRestoreAuditEntry {
                actor_id: SYSTEM_ACTOR_ID,
                owner_user_id: owner_user_id.unwrap_or_default(),
                target_card_id: card_id,
                operation_id: &operation_id,
                parent_event_id: &parent_projection.event_id,
                tenant_id,
                domain_id,
            },
        )
        .await?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn bind_card(&self, card_id: i64, user_id: i64) -> Result<bool, AstralError> {
        // 与 bind_card_async_one 共享同一受守卫绑定核心：锁卡证明 PENDING/INACTIVE
        // 候选状态、正目标用户校验、归属/贡献 fail-closed 守卫全部先于换主 UPDATE。
        bind_card_with_reassignment_guard(&self.db, card_id, user_id).await
    }

    async fn bind_card_async_one(&self, card_id: i64, user_id: i64) -> Result<bool, AstralError> {
        // 共享核心与 bind_card 完全一致 —— 异步批量绑定没有任何绕过归属/贡献
        // 守卫的旁路。
        bind_card_with_reassignment_guard(&self.db, card_id, user_id).await
    }

    async fn find_conflicts(
        &self,
        filter: &UserCardFilter,
    ) -> Result<Vec<UserCardRecord>, AstralError> {
        let user_id = filter
            .user_id
            .ok_or_else(|| AstralError::Validation("user_id is required".into()))?;
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {USER_CARD_SELECT_COLUMNS} FROM {USER_CARD_FROM_JOINS} WHERE 1=1"
        ));
        builder
            .push(" AND uc.user_id = ")
            .push_bind(user_id)
            .push(" AND uc.card_status = 'ACTIVE'");
        push_filter(&mut builder, filter);
        builder.push(" ORDER BY uc.card_type, uc.template_id, uc.card_id");
        let mut records = builder
            .build_query_as::<UserCardRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        self.attach_card_permission_summaries(&mut records).await?;
        Ok(records)
    }

    async fn find_active_card_for_user(&self, user_id: i64) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT card_id FROM user_card WHERE user_id = ? AND card_status = 'ACTIVE' ORDER BY card_id LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }
}

/// bind 换主归属守卫（fail-closed）：拒绝任何会随卡易主却仍归属旧用户（或归属
/// 不明）的既有授权痕迹。不静默转移授权、不删除证据，也不改写 append-only 账本；
/// 全部语句均为绑定参数 SQL，错误为确定性消息。
async fn ensure_bind_card_no_stale_user_evidence_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    target_user_id: i64,
    current_owner: Option<i64>,
) -> Result<(), AstralError> {
    // 1) 规范授权账本（无条件检查）：非 tombstone 修订（DIRECT/APPROVAL/
    //    DELEGATION 贡献与 RULE_SET 绑定派生授权）是 append-only 不可改写证据，
    //    payload 内的 canonical userId 记录了归属用户。归属用户不是本次目标
    //    用户 ⇒ 换主将把该授权留在旧用户名下（授权与持卡人错位）；改写/删除
    //    账本又违反 append-only 证据不变式 —— 两者都不允许，整体拒绝。无法
    //    解析归属的修订按“归属他人”（COALESCE 0）处理，绝不静默放行。
    let ledger_orphans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_grant_revision \
         WHERE card_id = ? AND is_tombstone = 0 \
           AND COALESCE(CAST(JSON_UNQUOTE(JSON_EXTRACT(grant_payload, '$.userId')) AS UNSIGNED), 0) <> ?",
    )
    .bind(card_id)
    .bind(target_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_error)?;
    if ledger_orphans > 0 {
        return Err(AstralError::Validation(format!(
            "user card {card_id} still owns {ledger_orphans} canonical authorization_grant_revision row(s) attributed to another user; refusing to rebind ownership (repair or explicitly remove the grants first)"
        )));
    }
    // 2/3 仅守“换主”：目标用户与当前持卡人相同时归属不变（同用户重绑放行）；
    // 无主持卡存在授权痕迹时归属不明，同样按换主处理（fail-closed）。
    let ownership_changes = match current_owner {
        Some(owner) => owner != target_user_id,
        None => true,
    };
    if !ownership_changes {
        return Ok(());
    }
    // 2) 卡级源贡献：permission_rule 行是卡上用户授权的 source 事实（DIRECT/
    //    APPROVAL/DELEGATION 等）。换主会让这些规则随卡转移而账本无法跟随 ——
    //    拒绝，而不是静默转移或删除证据。
    let source_contributions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM permission_rule WHERE card_id = ?")
            .bind(card_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?;
    if source_contributions > 0 {
        return Err(AstralError::Validation(format!(
            "user card {card_id} still owns {source_contributions} card-scoped permission_rule contribution row(s); refusing to reassign ownership to another user"
        )));
    }
    // 3) 卡级 ACTIVE 委托绑定：委托以卡为端点建立授权通道；换主会让旧用户的
    //    委托授权被新用户静默继承 —— 拒绝。
    let active_delegation_bindings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM permission_delegation \
         WHERE status = 'ACTIVE' AND (delegator_card_id = ? OR delegate_card_id = ?)",
    )
    .bind(card_id)
    .bind(card_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_error)?;
    if active_delegation_bindings > 0 {
        return Err(AstralError::Validation(format!(
            "user card {card_id} is still an endpoint of {active_delegation_bindings} ACTIVE permission_delegation binding(s); refusing to reassign ownership to another user"
        )));
    }
    Ok(())
}

/// [`UserCardRepository::bind_card`] 与 [`UserCardRepository::bind_card_async_one`]
/// 共享的受守卫绑定核心。
///
/// 旧实现只有一条候选状态守卫的条件 UPDATE：卡处于 PENDING/INACTIVE 即可直接
/// 改写 user_id。这在“换主重绑”（已有授权痕迹的卡重新绑到另一用户）时会静默
/// 转移/错置既有授权归属 —— 规范账本修订、卡级源贡献与 ACTIVE 委托绑定仍指向
/// 旧用户，而卡已归属新用户。本核心按序执行：
///
/// 1. 正目标用户校验（先于开事务；纯校验失败不产生任何 durable 副作用）；
/// 2. 锁读卡行（`FOR UPDATE`）并证明 `card_status ∈ {PENDING, INACTIVE}`；卡
///    不存在或不在候选状态保持既有“未命中 → Ok(false)”语义 —— ACTIVE 卡换人
///    绑定是跨用户静默转移，绝不从本入口放行；
/// 3. [`ensure_bind_card_no_stale_user_evidence_in_tx`] 归属/贡献 fail-closed
///    守卫：任何将随卡易主却仍归属旧用户（或归属不明）的规范
///    `authorization_grant_revision` 修订、卡级源贡献与 ACTIVE 委托绑定整体
///    拒绝；
/// 4. 守卫通过后才执行换主 UPDATE（候选状态集条件保留为第二道防线），随后
///    维持既有事务/事件语义：CARD_BOUND 投影 + ELIGIBILITY_UPDATE 同事务提交。
async fn bind_card_with_reassignment_guard(
    db: &MySqlPool,
    card_id: i64,
    user_id: i64,
) -> Result<bool, AstralError> {
    // 1) 正目标用户：绑定语义是“把卡授予某用户”，非正 id 不是合法归属。
    if user_id <= 0 {
        return Err(AstralError::Validation(format!(
            "bind_card target user id must be positive, got {user_id}"
        )));
    }
    let mut tx = AuthorizationSourceTransaction::begin(db).await?;
    // 2) 锁读卡行：候选状态证明与后续换主 UPDATE 同事务持锁，杜绝并发绑定/
    //    状态翻转在守卫与 UPDATE 之间改写卡片归属的竞态窗口。
    let locked: Option<(String, Option<i64>)> =
        sqlx::query_as("SELECT card_status, user_id FROM user_card WHERE card_id = ? FOR UPDATE")
            .bind(card_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
    let Some((card_status, current_owner)) = locked else {
        // 卡不存在：保持既有“未命中”语义（本事务尚未产生任何写入）。
        return Ok(false);
    };
    if card_status != "PENDING" && card_status != "INACTIVE" {
        // 仅允许绑定尚未归属的卡（PENDING/INACTIVE）。ACTIVE 卡绑定到其他用户
        // 是跨用户静默转移（原持卡人的授权随 user_id 换人），必须拒绝。
        return Ok(false);
    }
    // 3) 归属/贡献守卫（fail-closed，见函数文档）。
    ensure_bind_card_no_stale_user_evidence_in_tx(&mut tx, card_id, user_id, current_owner).await?;
    // 4) 守卫通过后才允许换主 UPDATE；候选状态集条件保留为第二道防线。
    let result = sqlx::query(
        "UPDATE user_card SET user_id = ?, card_status = 'ACTIVE' \
         WHERE card_id = ? AND card_status IN ('PENDING', 'INACTIVE')",
    )
    .bind(user_id)
    .bind(card_id)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    append_card_projection_in_tx(&mut tx, card_id, "CARD_BOUND").await?;
    // 换主/绑定同样影响资格：ELIGIBILITY 事件与其 durable invalidation intent
    // 同事务成对落库；身份从锁定卡行与已校验正数目标用户确定性派生。
    let bind_operation_id = derive_bind_card_operation_id(card_id, user_id)?;
    append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, &bind_operation_id)
        .await?;
    tx.commit_consuming().await?;
    Ok(true)
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("User card repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::EVENT_TYPE_ELIGIBILITY_UPDATE;

    /// 资格失效派生身份 fail-closed：非正 id 与非 canonical 状态拒绝，合法输入
    /// 确定性派生（随机 fallback 绝不进入事件链）。
    #[test]
    fn eligibility_operation_identity_derivation_fails_closed() {
        assert!(derive_update_card_eligibility_operation_id(0, "ACTIVE", "DISABLED").is_err());
        assert!(derive_update_card_eligibility_operation_id(-1, "ACTIVE", "DISABLED").is_err());
        assert!(derive_update_card_eligibility_operation_id(42, "active", "DISABLED").is_err());
        assert!(derive_update_card_eligibility_operation_id(42, "ACTIVE", "ACTIVE-X").is_err());
        assert_eq!(
            derive_update_card_eligibility_operation_id(42, "ACTIVE", "DISABLED")
                .expect("canonical transition derives a stable id"),
            "user-card:update:42:status:ACTIVE:DISABLED"
        );

        assert!(derive_bind_card_operation_id(0, 7).is_err());
        assert!(derive_bind_card_operation_id(42, 0).is_err());
        assert!(derive_bind_card_operation_id(42, -7).is_err());
        assert_eq!(
            derive_bind_card_operation_id(42, 7).expect("positive ids derive a stable id"),
            "user-card:bind:42:user:7"
        );
    }

    /// 结构守卫：create_card 的租户绑定写点必须以"纯校验 → 事务开始 → tenant 行
    /// FOR UPDATE → user_card source INSERT"的顺序落库。tenant 行锁与
    /// tenant_repository（delete_tenant 的 tenant 行锁 → user_card 引用计数守卫）
    /// 同向，闭合"create 在途未提交 → delete 守卫见 0 行 → 提交孤儿卡"竞态。
    #[test]
    fn create_card_tenant_binding_locks_tenant_row_before_source_write() {
        // SQL 形状：参数化 + FOR UPDATE，锁定 tenant 行。
        assert!(CREATE_CARD_TENANT_LOCK_SQL.contains("FROM tenant"));
        assert!(CREATE_CARD_TENANT_LOCK_SQL.contains("tenant_id = ?"));
        assert!(CREATE_CARD_TENANT_LOCK_SQL.ends_with("FOR UPDATE"));

        let create_card = implementation_between("async fn create_card", "async fn update_card");
        let tenant_gate = create_card
            .find("validate_create_card_tenant_binding")
            .expect("tenant binding must pass the pure positive-id gate");
        let tx_begin = create_card
            .find("AuthorizationSourceTransaction::begin(&self.db)")
            .expect("transaction begin");
        let tenant_lock = create_card
            .find("CREATE_CARD_TENANT_LOCK_SQL")
            .expect("the tenant row must be locked FOR UPDATE in-tx before the source insert");
        let card_insert = create_card
            .find("INSERT INTO user_card")
            .expect("the card source row insert");
        assert!(
            tenant_gate < tx_begin,
            "pure tenant validation must precede the transaction"
        );
        assert!(
            tx_begin < tenant_lock && tenant_lock < card_insert,
            "tenant row FOR UPDATE must sit between tx begin and the user_card insert \
             (tenant -> user_card order, same direction as delete_tenant)"
        );
        // 缺租户 fail-closed：锁定行缺失即 Validation 整体回滚，绝不静默绑定。
        assert!(
            create_card.contains("refusing to bind user_card.tenant_id to a missing tenant"),
            "a missing tenant row must fail the whole create closed"
        );
    }

    /// 纯守卫：租户绑定正数门禁覆盖全部创建路径（含无模板路径）；
    /// tenantless（None）不经本门禁，保持 identity starter 既有语义。
    #[test]
    fn create_card_tenant_binding_validation_fails_closed() {
        assert!(validate_create_card_tenant_binding(0).is_err());
        assert!(validate_create_card_tenant_binding(-7).is_err());
        assert!(validate_create_card_tenant_binding(7).is_ok());
    }

    /// 只有 card_status 变更需要 ELIGIBILITY 事件（priority/is_primary/level_id
    /// 不影响 perm:card:active 资格缓存）。
    #[test]
    fn only_status_change_requires_eligibility_event() {
        let mut patch = UserCardPatch::default();
        assert!(!patch_affects_eligibility(&patch));

        patch.card_status = Some("ACTIVE".into());
        assert!(patch_affects_eligibility(&patch));

        patch.card_status = Some("DISABLED".into());
        assert!(patch_affects_eligibility(&patch));
        patch.card_status = None;
        assert!(!patch_affects_eligibility(&patch));
    }

    /// 资格事件必须走 ELIGIBILITY 聚合通道与 ELIGIBILITY_UPDATE 事件类型常量，
    /// 禁止散落裸字符串（worker 按常量解析并轻量投影）。
    #[test]
    fn eligibility_event_uses_aggregate_and_event_constants() {
        assert_eq!(ProjectionAggregate::Eligibility.as_str(), "ELIGIBILITY");
        assert_eq!(EVENT_TYPE_ELIGIBILITY_UPDATE, "ELIGIBILITY_UPDATE");
        // ELIGIBILITY_UPDATE 不是 REVOKE，不递增 ELIGIBILITY head 的 revoke_fence。
        assert_ne!(EVENT_TYPE_ELIGIBILITY_UPDATE, "REVOKE");
    }

    /// 结构守卫（保留并强化原门禁）：create_card 的模板 BASE 绑定必须复用标准
    /// RuleSet ADD 物化链 —— 租户校验先于投影证明、证明先于严格 ref 插入、条目
    /// 物化先于 BIND_CARD 审计；单张带元数据 CARD_CREATED 父事件贯穿全部贡献；
    /// 任一失败整体回滚，绝不 INSERT IGNORE 后猜测主键或只写旧链。
    #[test]
    fn template_binding_requires_ruleset_proof_before_reference_insert() {
        let create_card = implementation_between("async fn create_card", "async fn update_card");

        // 原有门禁保持：租户校验 → RuleSet 投影证明 → card_rule_set_ref 插入。
        let tenant_validation = create_card
            .find("validate_binding_tenants")
            .expect("template binding must validate RuleSet/card tenant scope");
        let proof = create_card
            .find("ensure_rule_set_projection_in_tx")
            .expect("template binding must ensure RuleSet projection proof");
        let reference = create_card
            .find("INSERT INTO card_rule_set_ref")
            .expect("template binding must insert card_rule_set_ref");
        assert!(
            tenant_validation < proof && proof < reference,
            "tenant scope must be validated before RuleSet proof and reference insertion"
        );
        assert!(create_card.contains("SYSTEM_ACTOR_ID"));
        assert!(create_card.contains("CARD_CREATED"));
        assert!(create_card.contains("append_eligibility_projection_with_invalidation_in_tx"));

        // 严格 ref 主键：新卡事务内不存在旧 ref —— 普通INSERT、无 IGNORE，
        // 且必须显式校验真实主键 > 0，不猜 last_insert_id=0、不复用未知旧 ref。
        assert!(
            !create_card.contains("INSERT IGNORE INTO card_rule_set_ref"),
            "strict insert is mandatory; IGNORE would silently reuse an unknown old ref"
        );
        assert!(
            create_card.contains("card_rule_set_ref insert returned an unusable id"),
            "the captured ref primary key must be validated before materialization"
        );

        // 请求级 operation id：先过统一安全校验且早于任何 durable 写入（含开事务）。
        let request_id_gate = create_card
            .find("validated_request_operation_id")
            .expect("explicit x-request-id must pass the shared safety gate");
        let tx_begin = create_card
            .find("AuthorizationSourceTransaction::begin(&self.db)")
            .expect("transaction begin");
        assert!(
            request_id_gate < tx_begin,
            "request id validation must precede any durable write"
        );

        // 锁序/身份顺序：scope 校验 → 单语句升序锁定 + 代次捕获 → 重复映射守卫 →
        // operation id 派生 → proven context → CARD_CREATED 父事件 → 绑定循环。
        let scope_validation = create_card
            .find("validate_create_card_ledger_scope(new)")
            .expect("ledger scope validation must gate the whole creation");
        let ordered_lock = create_card
            .find("ORDER BY rs.rule_set_id ASC FOR UPDATE")
            .expect("rule_set rows and projection heads must lock in one ascending statement");
        let duplicate_guard = create_card
            .find("ensure_unique_template_rule_set_ids(&locked_rule_sets)")
            .expect("duplicate template rule_set mappings must fail closed");
        let operation_derive = create_card
            .find("derive_create_card_template_operation_id(")
            .expect("operation identity must be deterministically derived from locked facts");
        let system_context = create_card
            .find("RuleSetMutationContext::system(&operation_id)")
            .expect("binding context must be a proven stable identity");
        let parent_event = create_card
            .find("let parent_projection")
            .expect("a single CARD_CREATED parent projection must anchor all contributions");
        assert!(
            scope_validation < tx_begin
                && tx_begin < ordered_lock
                && ordered_lock < duplicate_guard
                && duplicate_guard < operation_derive
                && operation_derive < system_context
                && system_context < parent_event,
            "identity must stabilize before any ledger/outbox/audit write"
        );

        // 绑定循环内：ref → RULE_SET_UPDATE 投影 → 标准 ADD 物化 → BIND_CARD 审计。
        let rule_set_projection = create_card
            .find("EVENT_TYPE_RULE_SET_UPDATE")
            .expect("each binding appends its RULE_SET stream event (bind_card parity)");
        let adds_materialization = create_card
            .find("append_card_create_ruleset_entry_adds_in_tx(")
            .expect("enabled+ALLOW entries must go through the shared ADD core");
        let bind_audit = create_card
            .find("\"BIND_CARD\"")
            .expect("the binding audit must correlate the whole contribution evidence surface");
        assert!(
            reference < rule_set_projection
                && rule_set_projection < adds_materialization
                && adds_materialization < bind_audit,
            "standard RuleSet ADD materialization sits between source binding and audit"
        );
        for key in [
            "parentSourceEventId",
            "contributionEventIds",
            "ruleSetEntryIds",
            "boundCardIds",
            "bindingRefIds",
            "templateId",
        ] {
            assert!(
                create_card.contains(key),
                "BIND_CARD audit JSON must remain traceable ({key})"
            );
        }

        // 单张父事件语义：模板路径与无模板路径各恰好一次带元数据 CARD_CREATED，
        // 不再逐绑定追加重复的 CARD 父事件（旧 worker 额外重建被禁止）。
        assert_eq!(
            create_card.matches("\"CARD_CREATED\"").count(),
            2,
            "exactly one metadata-bound CARD_CREATED per path (template / plain)"
        );
        assert_eq!(
            create_card.matches("let parent_projection").count(),
            1,
            "one durable parent identity anchors every binding contribution"
        );
        assert!(!create_card.contains("\"RULE_SET_BOUND\""));
        // ELIGIBILITY 必须仍走独立轻量资格通道 helper（CARD 流除外），且与其
        // durable invalidation intent 成对落库；create 路径身份贯穿同一
        // operation id（模板路径账本身份 / 无模板路径 plain 派生）。
        assert!(
            create_card.contains("append_eligibility_projection_with_invalidation_in_tx"),
            "legacy ELIGIBILITY aggregate semantics must stay on its own channel"
        );
        assert!(
            create_card.contains("&eligibility_operation_id,"),
            "create-path eligibility invalidation must reuse the resolved create operation id"
        );
        // 随机 fallback 与旧的临时 correlation 格式绝不允许回流。
        assert!(!create_card.contains("uuid::Uuid"));
        assert!(!create_card.contains("card:create:"));
    }

    #[test]
    fn create_card_operation_identity_is_deterministic_and_scoped() {
        let first = derive_create_card_template_operation_id(31, 7, 12);
        assert_eq!(first, "user-card:create:31:tpl:7:ruleset-gen:12");
        // 重放稳定：同一业务重试（回滚后重放）派生逐字节一致。
        assert_eq!(derive_create_card_template_operation_id(31, 7, 12), first);
        // 卡 / 模板 / 锁定代次任一不同都必然分叉。
        assert_ne!(derive_create_card_template_operation_id(32, 7, 12), first);
        assert_ne!(derive_create_card_template_operation_id(31, 8, 12), first);
        assert_ne!(
            derive_create_card_template_operation_id(31, 7, 13),
            first,
            "锁定的 RULE_SET 代次推进后是新操作身份"
        );
        // 无模板路径独立命名空间，同样重放稳定。
        let plain = derive_create_card_plain_operation_id(31);
        assert_eq!(plain, "user-card:create:31");
        assert_eq!(derive_create_card_plain_operation_id(31), plain);
        assert_ne!(derive_create_card_plain_operation_id(32), plain);
        assert_ne!(plain, first, "两族 op id 不得碰撞");
    }

    fn new_user_card(
        user_id: Option<i64>,
        domain_id: Option<i64>,
        template_id: Option<i64>,
        tenant_id: Option<i64>,
    ) -> NewUserCard {
        NewUserCard {
            user_id,
            domain_id,
            card_type: "STANDARD".into(),
            template_id,
            level_id: None,
            priority: 100,
            is_primary: false,
            tenant_id,
            request_operation_id: None,
        }
    }

    #[test]
    fn create_card_ledger_scope_fails_closed_on_unprovable_scopes() {
        // 可证明 scope 全通过。
        validate_create_card_ledger_scope(&new_user_card(Some(42), Some(11), Some(9), Some(7)))
            .unwrap();
        // 无模板：账本路径不启动，保持既有放行语义（identity starter 路径不动）。
        validate_create_card_ledger_scope(&new_user_card(None, None, None, None)).unwrap();

        // 模板绑定卡是 ALLOW 贡献物化目标：tenantless 整卡失败，不降级只写旧链。
        let error =
            validate_create_card_ledger_scope(&new_user_card(Some(42), Some(11), Some(9), None))
                .unwrap_err();
        assert!(error.to_string().contains("tenantless"));
        for bad_tenant in [Some(0), Some(-3)] {
            assert!(matches!(
                validate_create_card_ledger_scope(&new_user_card(
                    Some(42),
                    Some(11),
                    Some(9),
                    bad_tenant
                )),
                Err(AstralError::Validation(_))
            ));
        }
        // 属主缺失同样无法证明授权归属。
        assert!(matches!(
            validate_create_card_ledger_scope(&new_user_card(None, Some(11), Some(9), Some(7))),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            validate_create_card_ledger_scope(&new_user_card(Some(0), Some(11), Some(9), Some(7))),
            Err(AstralError::Validation(_))
        ));
        // domain/template 仅在携带时要求正数。
        assert!(matches!(
            validate_create_card_ledger_scope(&new_user_card(Some(42), Some(0), Some(9), Some(7))),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            validate_create_card_ledger_scope(&new_user_card(Some(42), Some(-1), Some(9), Some(7))),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            validate_create_card_ledger_scope(&new_user_card(Some(42), Some(11), Some(0), Some(7))),
            Err(AstralError::Validation(_))
        ));
    }

    fn locked_template_rule_set(rule_set_id: i64) -> LockedTemplateRuleSetRow {
        LockedTemplateRuleSetRow {
            rule_set_id,
            tenant_id: Some(7),
            source_generation: Some(4),
        }
    }

    #[test]
    fn duplicate_template_rule_set_mappings_fail_closed_in_new_card_tx() {
        ensure_unique_template_rule_set_ids(&[
            locked_template_rule_set(5),
            locked_template_rule_set(6),
        ])
        .unwrap();
        // head 缺失按 0 代次处理（新建聚合首写窗口），合法。
        ensure_unique_template_rule_set_ids(&[LockedTemplateRuleSetRow {
            rule_set_id: 5,
            tenant_id: None,
            source_generation: None,
        }])
        .unwrap();
        // 重复映射 = 持久层不变量冲突：fail-closed，绝不静默跳过部分绑定。
        let error = ensure_unique_template_rule_set_ids(&[
            locked_template_rule_set(5),
            locked_template_rule_set(6),
            locked_template_rule_set(5),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"));
        // 负代次禁止作为 identity 派生输入。
        let negative_generation = LockedTemplateRuleSetRow {
            rule_set_id: 9,
            tenant_id: Some(7),
            source_generation: Some(-1),
        };
        assert!(matches!(
            ensure_unique_template_rule_set_ids(&[negative_generation]),
            Err(AstralError::Validation(_))
        ));
    }

    #[test]
    fn two_rule_sets_two_entries_yield_distinct_stable_contribution_ids_under_shared_operation() {
        use crate::repository::grant_ledger_adapter::{
            derive_ruleset_contribution_event_id, RuleSetEntryLedgerFacts, RuleSetMutationKind,
        };
        fn facts(rule_set_id: i64, ref_id: i64, entry_id: i64) -> RuleSetEntryLedgerFacts<'static> {
            RuleSetEntryLedgerFacts {
                tenant_id: 7,
                domain_id: Some(11),
                card_id: 77,
                user_id: 42,
                rule_set_id,
                entry_id,
                ref_id,
                ref_type: "BASE",
                resource: "learn_course",
                resource_id: None,
                action: "read",
                condition_json: None,
                valid_from: None,
                valid_to: None,
            }
        }
        // 共享同一 proven operation id 的两次模板绑定（2 个规则集 × 各 2 条 entry）：
        // 每个 entry×卡×绑定行贡献事件号互异 —— uk_ade_event 全局唯一。
        let operation_id = derive_create_card_template_operation_id(77, 9, 3);
        let mut event_ids = Vec::new();
        for (rule_set_id, ref_id) in [(101, 501), (102, 502)] {
            for entry_id in [1_001, 1_002] {
                event_ids.push(
                    derive_ruleset_contribution_event_id(
                        &operation_id,
                        &facts(rule_set_id, ref_id, entry_id),
                        RuleSetMutationKind::Add,
                    )
                    .unwrap(),
                );
            }
        }
        assert_eq!(event_ids.len(), 4);
        let unique: std::collections::BTreeSet<_> = event_ids.iter().collect();
        assert_eq!(
            unique.len(),
            4,
            "Grant/Event 身份在多绑定、多 entry 下不得碰撞"
        );
        // 重放稳定：同一业务重试（回滚后重放）派生逐字节一致。
        assert_eq!(
            derive_ruleset_contribution_event_id(
                &operation_id,
                &facts(101, 501, 1_001),
                RuleSetMutationKind::Add
            )
            .unwrap(),
            event_ids[0]
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 卡级联删除 × 版本化账本撤销（纯逻辑 + 形状守卫）
    // ─────────────────────────────────────────────────────────────────────────

    /// 构造一行锁定规则行（全部字段显式填写，作为分类器的最小可证明输入）。
    fn locked_rule(rule_id: i64, source_type: &str) -> LockedRuleRow {
        LockedRuleRow {
            rule_id,
            card_id: 21,
            user_id: 42,
            tenant_id: Some(7),
            domain_id: Some(11),
            resource_type: "learn_course".into(),
            resource_id: None,
            action_code: "read".into(),
            effect: "ALLOW".into(),
            condition_json: None,
            priority: 100,
            valid_from: None,
            valid_to: None,
            source_type: source_type.into(),
            source_id: None,
            enabled: Some(1),
        }
    }

    #[test]
    fn classifier_wires_only_booked_allow_contributions() {
        // 已入账 ALLOW 来源必须撤销。
        assert_eq!(
            classify_permission_rule_for_ledger(&locked_rule(1, "CARD_ONLY")).unwrap(),
            Some((CascadeRuleLedgerKind::Direct, None))
        );
        assert_eq!(
            classify_permission_rule_for_ledger(&locked_rule(2, "MANUAL")).unwrap(),
            Some((CascadeRuleLedgerKind::Direct, None))
        );
        // 审批规则缺少可证明的 request 主键时，即使 ALLOW 也必须失败，
        // 而不是静默通过或伪造身份。
        assert!(
            classify_permission_rule_for_ledger(&locked_rule(3, "PERMISSION_REQUEST")).is_err()
        );
    }

    #[test]
    fn classifier_maps_approval_source_to_its_request_identity() {
        let mut row = locked_rule(4, "PERMISSION_REQUEST");
        row.source_id = Some(9001);
        assert_eq!(
            classify_permission_rule_for_ledger(&row).unwrap(),
            Some((CascadeRuleLedgerKind::Approval, Some(9001)))
        );
        // 非正数 request 主键无法证明审批来源 → fail-closed。
        row.source_id = Some(0);
        assert!(classify_permission_rule_for_ledger(&row).is_err());
    }

    #[test]
    fn classifier_skips_unbooked_rows_and_fails_closed_on_unknown_provenance() {
        // legacy DENY / 禁用行从未进入 ALLOW-only 账本：跳过即无 ghost。
        let deny = locked_rule(5, "CARD_ONLY");
        let mut deny = deny.clone();
        deny.effect = "DENY".into();
        assert!(classify_permission_rule_for_ledger(&deny)
            .unwrap()
            .is_none());

        let mut disabled = locked_rule(6, "MANUAL");
        disabled.enabled = Some(0);
        assert!(classify_permission_rule_for_ledger(&disabled)
            .unwrap()
            .is_none());

        // 未知 effect 一律 fail-closed，不猜测语义。
        let mut unknown = locked_rule(7, "CARD_ONLY");
        unknown.effect = "PROMOTE".into();
        assert!(classify_permission_rule_for_ledger(&unknown).is_err());

        // DELEGATION（M3 接线）：ALLOW 规则映射到其 delegation 主键；legacy DENY/
        // 禁用行安全跳过（未入账即无 ghost，不伪造 tombstone）。
        let mut delegation = locked_rule(8, "DELEGATION");
        delegation.source_id = Some(7001);
        assert_eq!(
            classify_permission_rule_for_ledger(&delegation).unwrap(),
            Some((CascadeRuleLedgerKind::Delegation, Some(7001)))
        );
        let mut legacy_deny_delegation = delegation.clone();
        legacy_deny_delegation.effect = "DENY".into();
        assert!(classify_permission_rule_for_ledger(&legacy_deny_delegation)
            .unwrap()
            .is_none());
        // 缺失/非正 delegation source id 无法证明聚合归属 → fail-closed。
        assert!(classify_permission_rule_for_ledger(&locked_rule(8, "DELEGATION")).is_err());
        let mut zero_source = delegation.clone();
        zero_source.source_id = Some(0);
        assert!(classify_permission_rule_for_ledger(&zero_source).is_err());

        // 其他未知 source_type 在破坏性删除前拒绝，绝不猜测来源。
        assert!(classify_permission_rule_for_ledger(&locked_rule(9, "TEMPLATE")).is_err());
        assert!(classify_permission_rule_for_ledger(&locked_rule(10, "")).is_err());
    }

    #[test]
    fn cascade_operation_identity_is_deterministic_and_scoped() {
        let first = derive_card_cascade_operation_id(21, 4);
        assert_eq!(first, "user-card:delete:21:gen:4");
        assert_eq!(derive_card_cascade_operation_id(21, 4), first);
        assert_ne!(
            derive_card_cascade_operation_id(22, 4),
            first,
            "不同卡必然分叉"
        );
        assert_ne!(
            derive_card_cascade_operation_id(21, 5),
            first,
            "锁定代次推进后是新操作身份"
        );
    }

    #[test]
    fn cascade_card_lock_sets_are_ascending_unique_and_fail_closed() {
        assert_eq!(
            ordered_unique_positive_card_ids([7, 3, 7, 11]).unwrap(),
            vec![3, 7, 11]
        );
        for bad in [vec![0], vec![-9], vec![4, -1]] {
            assert!(matches!(
                ordered_unique_positive_card_ids(bad),
                Err(AstralError::Validation(_))
            ));
        }
    }

    /// 结构守卫：全部参与卡必须经单个绑定参数化的升序 IN 语句一次锁定，
    /// 不允许字符串拼接 IN 列表，也不按其他顺序逐张补锁。
    #[test]
    fn cascade_participants_lock_once_in_a_single_bound_ascending_statement() {
        let production = include_str!("user_card_repository.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("tests module must be last");
        let lock_helper = production
            .split("async fn lock_cascade_participant_cards_in_tx")
            .nth(1)
            .and_then(|rest| rest.split("\n/// ").next())
            .expect("participant lock helper body must exist");
        assert!(
            lock_helper.contains("FROM user_card WHERE card_id IN ("),
            "the whole participant set locks through one IN statement"
        );
        assert!(
            lock_helper.contains("ORDER BY card_id ASC FOR UPDATE"),
            "participant rows must be acquired ascending under FOR UPDATE"
        );
        assert!(
            lock_helper.contains("push_bind"),
            "every IN value must be bound via QueryBuilder, never interpolated"
        );
        assert!(
            !lock_helper.contains("format!"),
            "IN lists must not be assembled with string formatting"
        );
    }

    /// 互链委托端点（A→B 且 B→A，含被删卡作为 delegate 的 delegator 端点）
    /// 必须并入同一去重升序锁集合：单语句统一方向是消除并发级联 ABBA 环的前提。
    #[test]
    fn interlinked_delegate_endpoints_collapse_into_one_ascending_participant_set() {
        assert_eq!(
            collect_cascade_participant_ids(21, [(21, 88), (88, 21)]).unwrap(),
            vec![21, 88],
            "mutually-linked delegations share one ascending participant set"
        );
        // 被删卡作为 delegate 时，其 delegator 端点卡同样进入锁集合。
        assert_eq!(
            collect_cascade_participant_ids(21, [(55, 21)]).unwrap(),
            vec![21, 55]
        );
        // self-delegation / 方向重复端点去重；无委托时至少包含被删卡自身。
        assert_eq!(
            collect_cascade_participant_ids(21, [(21, 21)]).unwrap(),
            vec![21]
        );
        assert_eq!(
            collect_cascade_participant_ids(21, [(21, 30), (21, 30)]).unwrap(),
            vec![21, 30]
        );
        assert_eq!(collect_cascade_participant_ids(21, []).unwrap(), vec![21]);
        // 非正 id（含委托行携带的非正端点）一律 Validation fail-closed。
        assert!(matches!(
            collect_cascade_participant_ids(21, [(0, 30)]),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            collect_cascade_participant_ids(-5, []),
            Err(AstralError::Validation(_))
        ));
    }

    /// 预读集合与锁定后委托行的一致性判定：一致放行；新增行 / 换端 / 集合缺失
    /// 全部冲突回滚，绝不在陈旧预读集合上执行级联删除。
    #[test]
    fn participant_consistency_fails_closed_on_endpoint_drift() {
        let pre_read: std::collections::BTreeSet<(i64, i64)> = [(21, 88)].into_iter().collect();
        let locked = [delegation_record(9001, 21, 88, "ACTIVE")];
        assert!(verify_cascade_participant_consistency(&pre_read, &locked).is_ok());

        // 锁定后出现预读未见过的委托行 → 端点对不在预锁集合内 → 冲突回滚。
        let extra = [
            delegation_record(9001, 21, 88, "ACTIVE"),
            delegation_record(9002, 30, 21, "ACTIVE"),
        ];
        let error = verify_cascade_participant_consistency(&pre_read, &extra).unwrap_err();
        assert!(error.to_string().contains("unstable endpoint set"));

        // 委托换端（方向翻转也算漂移）→ 冲突回滚。
        let swapped = [delegation_record(9001, 88, 21, "ACTIVE")];
        let swapped_error =
            verify_cascade_participant_consistency(&pre_read, &swapped).unwrap_err();
        assert!(swapped_error.to_string().contains("unstable endpoint set"));

        // 预读到的委托在锁定时消失 → 陈旧集合，冲突回滚。
        let missing = verify_cascade_participant_consistency(&pre_read, &[]).unwrap_err();
        assert!(missing.to_string().contains("drifted"));
        let two_pair_pre: std::collections::BTreeSet<(i64, i64)> =
            [(21, 88), (55, 21)].into_iter().collect();
        let one_row = [delegation_record(9001, 21, 88, "ACTIVE")];
        let removed = verify_cascade_participant_consistency(&two_pair_pre, &one_row).unwrap_err();
        assert!(removed.to_string().contains("drifted"));
    }

    fn delegation_record(
        delegation_id: i64,
        delegator_card_id: i64,
        delegate_card_id: i64,
        status: &str,
    ) -> DelegationRecord {
        DelegationRecord {
            delegation_id,
            delegator_card_id,
            delegate_card_id,
            resource_type: "learn_course".into(),
            action_code: "read".into(),
            effective_from_ts: 1_760_000_000,
            effective_until_ts: Some(1_770_000_000),
            is_revokable: 1,
            status: status.into(),
        }
    }

    #[test]
    fn delegation_pairing_resolves_both_cascade_directions_or_fails_closed() {
        // 被删卡是 delegate：规则必须落在被删卡上。
        let mut delegate_side = locked_rule(11, "DELEGATION");
        delegate_side.card_id = 21;
        delegate_side.source_id = Some(9001);
        let delegations = vec![delegation_record(9001, 55, 21, "ACTIVE")];
        let paired = resolve_delegation_pairing(&delegate_side, &delegations, 21).unwrap();
        assert_eq!(paired.delegation_id, 9001);

        // 被删卡是 delegator：规则必须落在远端 delegate 卡上。
        let mut remote_rule = locked_rule(12, "DELEGATION");
        remote_rule.card_id = 88;
        remote_rule.source_id = Some(9002);
        let delegator_side = vec![delegation_record(9002, 21, 88, "ACTIVE")];
        assert_eq!(
            resolve_delegation_pairing(&remote_rule, &delegator_side, 21)
                .unwrap()
                .delegation_id,
            9002
        );

        // 位置漂移：delegate 侧规则写在别的卡上。
        let mut misplaced = delegate_side.clone();
        misplaced.rule_id = 13;
        misplaced.card_id = 99;
        assert!(resolve_delegation_pairing(&misplaced, &delegations, 21).is_err());

        // delegator 侧规则没有正确挂在远端 delegate 卡上。
        let mut wrong_remote = remote_rule.clone();
        wrong_remote.rule_id = 14;
        wrong_remote.card_id = 21;
        assert!(
            resolve_delegation_pairing(&wrong_remote, &delegator_side, 21).is_err(),
            "delegate-side clause must sit on its carrier card"
        );

        // 委托缺失 / 非 ACTIVE 残留 / resource 漂移 全部 fail-closed。
        let orphan: Vec<DelegationRecord> = Vec::new();
        let missing = resolve_delegation_pairing(&remote_rule, &orphan, 21).unwrap_err();
        assert!(missing.to_string().contains("locked cascade scope"));
        let revoked = vec![delegation_record(9002, 21, 88, "REVOKED")];
        let residue = resolve_delegation_pairing(&remote_rule, &revoked, 21).unwrap_err();
        assert!(residue.to_string().contains("lifecycle residue"));
        let mut drifted_resource = remote_rule.clone();
        drifted_resource.resource_type = "learn_quiz".into();
        let drift = resolve_delegation_pairing(&drifted_resource, &delegator_side, 21).unwrap_err();
        assert!(drift.to_string().contains("drift"));

        // 无可证明有效期的 ACTIVE 委托在配对期就 fail-closed（repair required）。
        let mut expiring_record = delegation_record(9003, 21, 90, "ACTIVE");
        expiring_record.effective_until_ts = None;
        let mut expiring_rule = locked_rule(15, "DELEGATION");
        expiring_rule.card_id = 90;
        expiring_rule.source_id = Some(9003);
        let expiry =
            resolve_delegation_pairing(&expiring_rule, &[expiring_record], 21).unwrap_err();
        assert!(expiry.to_string().contains("positive expiry"));
    }

    #[test]
    fn delegation_tombstones_share_the_batch_operation_but_fork_per_delegation() {
        // 同一 cascade operation id 下两个委托各自派生独立 REVOKE 事件号；
        // 与 direct 家族事件号也互不相同（uk_ade_event 全局唯一的空间互不相交）。
        use crate::repository::grant_ledger_adapter::{
            DelegationContributionKind, DelegationLedgerFacts,
        };
        let op = "user-card:delete:21:gen:9";
        let facts_a = DelegationLedgerFacts {
            tenant_id: 7,
            domain_id: Some(11),
            card_id: 21,
            user_id: 42,
            delegation_id: 8100,
            resource: "",
            action: "",
            not_before_unix: None,
            expires_at_unix: 1_770_000_000,
        };
        let facts_b = DelegationLedgerFacts {
            tenant_id: 7,
            domain_id: Some(11),
            card_id: 21,
            user_id: 42,
            delegation_id: 8101,
            resource: "",
            action: "",
            not_before_unix: None,
            expires_at_unix: 1_770_000_000,
        };
        let event_a = derive_delegation_contribution_event_id(
            op,
            &facts_a,
            DelegationContributionKind::Revoke,
        )
        .unwrap();
        let event_b = derive_delegation_contribution_event_id(
            op,
            &facts_b,
            DelegationContributionKind::Revoke,
        )
        .unwrap();
        assert_ne!(event_a, event_b);
        // 重放稳定（同一业务重试复用同一身份）。
        assert_eq!(
            event_a,
            derive_delegation_contribution_event_id(
                op,
                &facts_a,
                DelegationContributionKind::Revoke,
            )
            .unwrap()
        );
        // 与 direct REMOVE 事件号分离。
        let direct_row = locked_rule(16, "CARD_ONLY");
        let direct_event = derive_direct_contribution_event_id(
            op,
            &direct_remove_identity_facts(&direct_row),
            DirectRuleOperationKind::Remove,
        )
        .unwrap();
        assert_ne!(direct_event, event_a);
        // grant identity 与 contribution event id 分离。
        let grant = derive_delegation_identity(&facts_a).unwrap();
        assert_ne!(event_a, grant.as_str());
    }

    /// 从测试源码切出 SQL 实现块内 `[start_marker, end_marker)` 的方法体区间
    /// （锚定实现块并在 `#[cfg(test)]` 前截断，跳过 trait 声明与本测试模块，
    /// 避免 include_str 自引用切片污染）。
    fn implementation_between(start_marker: &str, end_marker: &str) -> &'static str {
        let source = include_str!("user_card_repository.rs");
        let implementation = source
            .split("impl UserCardRepository for SqlxUserCardRepository")
            .nth(1)
            .and_then(|rest| rest.split("#[cfg(test)]").next())
            .expect("sqlx user card repository implementation must exist");
        let start = implementation
            .find(start_marker)
            .unwrap_or_else(|| panic!("{start_marker} implementation must exist"));
        let tail = &implementation[start..];
        let end = tail
            .find(end_marker)
            .unwrap_or_else(|| panic!("{end_marker} must follow {start_marker}"));
        &tail[..end]
    }

    /// 结构守卫：卡删除必须先 FOR UPDATE 捕获全部事实与身份，再追加 ledger
    /// REMOVE/REVOKE 与任何 DELETE —— capture-before-delete + 新链先于 source 清理。
    #[test]
    fn cascade_delete_capture_and_plan_precede_parent_event_and_cleanup() {
        let body = implementation_between("async fn delete_with_cascade", "async fn restore_card");

        // 统一升序全卡锁：完整参与集合 plain 预读 → 单个 IN 语句一次性锁定全部
        // 参与卡（{被删卡} ∪ 全部委托端点卡）。
        let endpoint_probe = body
            .find("probe_cascade_delegation_endpoint_pairs_in_tx")
            .expect("affected delegation endpoint pairs must be pre-read without locks");
        let participant_lock = body
            .find("lock_cascade_participant_cards_in_tx")
            .expect("the full participant card set must be locked in one ascending IN statement");
        // 不允许回到旧形状：先单独 FOR UPDATE 被删卡，或在锁集合形成后逐张补锁
        // 远端承载卡 —— 互链委托并发级联下该顺序存在可达 ABBA 环。
        assert!(
            !body.contains("FROM user_card WHERE card_id = ? FOR UPDATE"),
            "delete_with_cascade must not single-lock the deleted card outside the participant set"
        );
        assert!(
            !body.contains("lock_cascade_carrier_cards_in_tx"),
            "per-card sequential carrier locking is forbidden; the participant set locks once, ascending"
        );
        // M3 锁序：预读 → 全部 user_card 参与卡一次升序锁定 → 受影响 delegation 行
        // → 规则行。
        let delegations_lock = body
            .find("lock_affected_delegations_in_tx")
            .expect("affected permission_delegation rows must be locked by ascending id");
        let drift_gate = body.find("verify_cascade_participant_consistency").expect(
            "pre-read vs locked delegation endpoint sets must be re-verified after locking",
        );
        let rules_lock = body
            .find("lock_all_card_rules_in_tx")
            .expect("permission_rule rows must be locked (all source types)");
        let remote_rules_lock = body
            .find("lock_remote_delegation_rules_in_tx")
            .expect("remote DELEGATION rules must be locked too");
        let pairing_gate = body
            .find("resolve_delegation_pairing")
            .expect("DELEGATION rules must pair with locked ACTIVE delegations");
        let plan_marker = body
            .find("derive_direct_contribution_event_id")
            .expect("direct contribution identities must be derived in plan phase");
        let parent_marker = body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("parent CARD REVOKE projection must carry metadata");
        // direct/approval/delegation 各自锁定一次账本 head（FOR UPDATE），都在父事件之后。
        let head_reads: Vec<usize> = body
            .match_indices("read_grant_head_for_update_in_tx")
            .map(|(offset, _)| offset)
            .collect();
        assert_eq!(
            head_reads.len(),
            3,
            "exactly one locked head read per ledger family (direct, approval, delegation)"
        );
        assert!(body.contains("DIRECT_AGGREGATE_TYPE"));
        assert!(body.contains("APPROVAL_AGGREGATE_TYPE"));
        assert!(body.contains("DELEGATION_AGGREGATE_TYPE"));
        let rules_delete = body
            .find("DELETE FROM permission_rule WHERE card_id = ?")
            .expect("source cleanup must delete permission_rule");
        let status_flip = body
            .find("SET status = 'REVOKED', revoked_at = NOW()")
            .expect("revoked delegations must flip to REVOKED with a timestamp");
        let remote_delete = body
            .find("DELETE FROM permission_rule WHERE rule_id = ?")
            .expect("remote DELEGATION rules must be deleted exactly per locked set");
        // 快照维度已随迁移 20260827000002 退役：级联清理绝不再触碰
        // permission_rule_snapshot（曾遗留活 DELETE 导致已迁移库上删卡 1146）。
        assert!(
            !body.contains("permission_rule_snapshot"),
            "retired snapshot table must not be touched by the cascade cleanup"
        );
        let refs_delete = body
            .find("DELETE FROM card_rule_set_ref WHERE card_id = ?")
            .expect("source cleanup must delete card_rule_set_ref");
        let disable_marker = body
            .find("SET card_status = 'DISABLED'")
            .expect("card must be soft-disabled");
        let legacy_revoke = body
            .find(
                "append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, \
                 &operation_id)",
            )
            .expect("ELIGIBILITY cache-eviction event must be preserved (worker survival duty)");
        // 旧链二次 CARD REVOKE 已退役（Phase 3 父事件是唯一的 CARD 事件；
        // CARD outbox 已无任何重建/刷新消费者）。
        assert!(
            !body.contains("append_card_projection_in_tx(&mut tx, card_id, \"REVOKE\")"),
            "legacy second CARD REVOKE must not be reintroduced in the cascade"
        );
        let audit_marker = body
            .find("insert_user_card_cascade_audit_in_tx")
            .expect("cascade audit must be written inside the same transaction");
        let commit_marker = body
            .find("tx.commit_consuming()")
            .expect("transaction must commit explicitly");

        assert!(
            endpoint_probe < participant_lock
                && participant_lock < delegations_lock
                && delegations_lock < rules_lock
                && rules_lock < remote_rules_lock,
            "global lock order: plain pre-read -> all participant user_cards in one ascending IN lock -> delegation rows asc -> permission_rule"
        );
        assert!(delegations_lock < drift_gate && drift_gate < pairing_gate);
        assert!(rules_lock < plan_marker);
        // 计划先于 parent 投影事件：身份失败在进入任何 durable 写入前回滚。
        assert!(plan_marker < parent_marker);
        // 父事件只作 generation/fence 锚点，位于全部 REMOVE/REVOKE head 锁之前。
        assert!(
            parent_marker < head_reads[0]
                && parent_marker < head_reads[1]
                && parent_marker < head_reads[2],
            "parent CARD REVOKE events precede every grant head lock"
        );
        assert!(
            body.contains("build_delegation_revoke_draft",),
            "delegation contributions must use the shared lifecycle REVOKE builder"
        );
        assert!(
            body.contains("append_delegation_grant_delta_in_tx"),
            "delegation tombstones must append through the shared transaction wrapper"
        );
        // 新链成功后才执行 source 清理；委托状态翻转先于规则删除。
        assert!(head_reads.iter().all(|head| *head < status_flip));
        assert!(
            head_reads.iter().all(|head| *head < rules_delete),
            "every ledger tombstone must land before any source deletion"
        );
        assert!(
            status_flip < rules_delete && status_flip < remote_delete,
            "delegation REVOKED status must be written before its rule rows are deleted"
        );
        assert!(rules_delete < disable_marker);
        assert!(disable_marker < legacy_revoke && legacy_revoke < audit_marker);
        assert!(refs_delete < disable_marker);
        assert!(audit_marker < commit_marker);
        // 幂等门禁存在：重复删除不再制造新事件；ACTIVE 委托残留时禁止短路。
        assert!(
            body.contains("card_status != \"ACTIVE\""),
            "repeat-delete idempotence gate must be present"
        );
        assert!(
            body.contains("!delegations.iter().any(|record| record.status == \"ACTIVE\")"),
            "repeat-delete short circuit must not skip pending ACTIVE delegations"
        );
        assert!(
            body.contains("delegation_ids: &delegation_id_refs"),
            "cascade audit must correlate the delegation tombstone family"
        );
    }

    /// 结构守卫：三处 missing-head 分支都必须整体拒绝事务（不得静默转换或
    /// 只写旧链），DELEGATION 分类分支有显式映射，ACTIVE 委托无规则捕获即
    /// fail-closed（不在已入账行存在时静默跳过）。
    #[test]
    fn cascade_delete_fails_closed_on_missing_heads_and_skips_delegation_explicitly() {
        let delete_body =
            implementation_between("async fn delete_with_cascade", "async fn restore_card");
        assert_eq!(
            delete_body
                .matches("refusing to cascade-delete an un-versioned authorization\"")
                .count(),
            1,
            "direct missing-head must fail the whole transaction exactly once"
        );
        assert_eq!(
            delete_body
                .matches("un-versioned approval authorization\"")
                .count(),
            1,
            "approval missing-head must fail the whole transaction exactly once"
        );
        assert_eq!(
            delete_body
                .matches("un-versioned delegation authorization\"")
                .count(),
            1,
            "delegation missing-head must fail the whole transaction exactly once"
        );
        // M3：每个 ACTIVE 委托必须能配对到至少一条被捕获的规则，否则要求修复，
        // 绝不静默跳过留下指向已删卡的 ACTIVE ghost。
        assert!(
            delete_body.contains(
                "without any capturable DELEGATION rule; repair required instead of a silent skip",
            ),
            "orphan-ACTIVE-delegation gate must be present"
        );
        assert!(
            include_str!("user_card_repository.rs")
                .split("#[cfg(test)]")
                .next()
                .expect("tests module must be last")
                .contains("\"DELEGATION\" => {"),
            "delegation rules map through an explicit classifier arm"
        );
    }

    /// 结构守卫：restore 不隐式 ADD/复活旧 grant（direct/approval/delegation 同一
    /// 门禁）—— 重新授权仍走显式 bind/grant。
    #[test]
    fn restore_card_never_adds_or_resurrects_grants() {
        let restore_body = implementation_between("async fn restore_card", "async fn bind_card");
        for forbidden in [
            "build_direct_add_draft",
            "build_approval_add_draft",
            "build_delegation_add_draft",
            "append_grant_revision_in_tx",
            "DeltaEventType::Add",
            "GrantDelta::add",
        ] {
            assert!(
                !restore_body.contains(forbidden),
                "restore path must not materialize grants: found {forbidden}"
            );
        }
    }

    /// 结构守卫：restore 必须在同事务落恢复审计关联行（`audit_log` 既有机制），
    /// 次序为 带元数据 CARD_RESTORED → ELIGIBILITY → 恢复审计 → commit；旧的丢
    /// 身份投影入口不得留在被审计的恢复路径上。恢复路径同时保持零账本写入
    /// （见 [`restore_card_never_adds_or_resurrects_grants`]）。
    #[test]
    fn restore_card_audits_eligibility_restore_in_same_tx() {
        let restore_body = implementation_between("async fn restore_card", "async fn bind_card");
        let metadata_projection = restore_body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("restore must use the metadata-bound projection entry for audit correlation");
        let eligibility = restore_body
            .find(
                "append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, \
                 &operation_id)",
            )
            .expect("eligibility restore must stay on the ELIGIBILITY channel");
        let audit = restore_body
            .find("insert_user_card_restore_audit_in_tx")
            .expect("the restore audit correlation row must land in the same transaction");
        let commit = restore_body
            .find("tx.commit_consuming()")
            .expect("transaction must commit explicitly");
        assert!(
            metadata_projection < eligibility && eligibility < audit && audit < commit,
            "identity must stabilize before the metadata CARD_RESTORED, eligibility and same-tx audit"
        );
        assert!(
            !restore_body.contains("append_card_projection_in_tx"),
            "the identity-dropping legacy projection entry must not remain on the audited restore path"
        );
    }

    /// 恢复审计行的纯校验：系统/正数 actor、正数目标卡、operation 与父事件
    /// 关联缺一不可；错位一律拒绝落库。
    #[test]
    fn user_card_restore_audit_entry_validation_fails_closed() {
        fn restore_audit_entry() -> UserCardRestoreAuditEntry<'static> {
            UserCardRestoreAuditEntry {
                actor_id: SYSTEM_ACTOR_ID,
                owner_user_id: 7,
                target_card_id: 12,
                operation_id: "user-card:restore:12",
                parent_event_id: "evt-parent",
                tenant_id: Some(3),
                domain_id: Some(5),
            }
        }
        validate_user_card_restore_audit_entry(&restore_audit_entry()).unwrap();
        for mutate in [
            |e: &mut UserCardRestoreAuditEntry<'_>| e.actor_id = 0,
            |e: &mut UserCardRestoreAuditEntry<'_>| e.target_card_id = -1,
            |e: &mut UserCardRestoreAuditEntry<'_>| e.operation_id = "  ",
            |e: &mut UserCardRestoreAuditEntry<'_>| e.parent_event_id = "",
        ] {
            let mut broken = restore_audit_entry();
            mutate(&mut broken);
            assert!(matches!(
                validate_user_card_restore_audit_entry(&broken),
                Err(AstralError::Validation(_))
            ));
        }
        // 正数 actor 同样放行（未来 API 层传入真实操作者的前置兼容面）。
        let mut positive = restore_audit_entry();
        positive.actor_id = 42;
        validate_user_card_restore_audit_entry(&positive).unwrap();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 卡读取 action_codes 摘要 × 共享批量回填（形状守卫 + 纯逻辑）
    // ─────────────────────────────────────────────────────────────────────────

    fn user_card_record_with(card_id: i64, action_codes: Option<String>) -> UserCardRecord {
        UserCardRecord {
            card_id,
            user_id: None,
            domain_id: None,
            card_type: "STANDARD".into(),
            card_status: "ACTIVE".into(),
            template_id: None,
            level_id: None,
            priority: Some(100),
            is_primary: Some(false),
            valid_from: None,
            valid_until: None,
            created_at: None,
            updated_at: None,
            tenant_id: None,
            card_name: None,
            template_code: None,
            template_name: None,
            level_code: None,
            level_name: None,
            level_no: None,
            action_codes,
        }
    }

    /// 摘要回填只覆盖门禁放行的卡；被 fail-closed 投影门禁剔除的卡保持 None，
    /// 绝不伪造成空 CSV 或保留旧占位值。
    #[test]
    fn summary_backfill_populates_only_gated_cards() {
        let mut records = vec![
            user_card_record_with(1, Some("stale:action".into())),
            user_card_record_with(2, None),
        ];
        let mut summaries = std::collections::HashMap::new();
        summaries.insert(
            1,
            astral_db::CardPermissionSummary {
                action_codes: Some("learn_course:read,learn_course:write".into()),
                base_rule_set_ids: Some("9".into()),
                overlay_rule_set_ids: None,
            },
        );
        // card 2 被投影门禁剔除（head 缺失/非 READY）：不产生摘要条目。
        apply_card_permission_summaries(&mut records, &summaries);
        assert_eq!(
            records[0].action_codes.as_deref(),
            Some("learn_course:read,learn_course:write"),
            "gated-in cards receive their snapshot summary"
        );
        assert!(
            records[1].action_codes.is_none(),
            "gate-omitted cards must stay None, never an empty CSV authorization"
        );
    }

    /// 摘要是 action_codes 的唯一事实来源：门禁剔除时必须清掉 SQL 阶段的任何
    /// 残留值，不得展示未经投影门禁证明的授权摘要。
    #[test]
    fn summary_backfill_clears_stale_values_when_gate_omits_card() {
        let mut records = vec![user_card_record_with(3, Some("legacy:action".into()))];
        let summaries = std::collections::HashMap::new();
        apply_card_permission_summaries(&mut records, &summaries);
        assert!(
            records[0].action_codes.is_none(),
            "missing summary must clear any stale value instead of showing unproven authorization"
        );
    }

    /// 结构守卫：卡正式查询只保留身份/平台目录展示 JOIN；action_codes 摘要不再
    /// 以 LEFT JOIN permission_rule_snapshot/MAX(version_no) 形式进入 SQL，而是
    /// 行加载后经共享 `load_card_permission_summaries` 按页批量回填（无 N+1），
    /// count_cards 保持纯 COUNT。
    #[test]
    fn card_read_queries_use_shared_batch_summary_backfill() {
        let production = include_str!("user_card_repository.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("tests module must be last");

        // FROM/JOIN 形状：不再 JOIN permission_rule_snapshot，元数据 JOIN 保留。
        let from_joins = production
            .split("const USER_CARD_FROM_JOINS: &str = ")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .expect("USER_CARD_FROM_JOINS must exist");
        assert!(
            !from_joins.contains("permission_rule_snapshot"),
            "card metadata queries must not LEFT JOIN permission_rule_snapshot; summaries go through the shared fail-closed gate"
        );
        assert!(
            from_joins.contains("LEFT JOIN user_card_template t")
                && from_joins.contains("LEFT JOIN user_card_level_definition l"),
            "card metadata display joins (template/level) must be preserved"
        );

        // SELECT 形状：action_codes 是 NULL 占位，由 Rust 侧回填。
        let select_columns = production
            .split("const USER_CARD_SELECT_COLUMNS: &str =")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .expect("USER_CARD_SELECT_COLUMNS must exist");
        assert!(
            select_columns.contains("NULL as action_codes"),
            "action_codes must be a NULL placeholder backfilled after row load"
        );
        assert!(
            !select_columns.contains("pr.action_codes"),
            "action_codes must not be selected from a joined snapshot subquery"
        );

        // 三个读路径（list/get/conflicts）都必须走共享批量回填 helper。
        for (method, end_marker) in [
            ("async fn list_cards", "async fn get_card"),
            ("async fn get_card", "async fn create_card"),
            (
                "async fn find_conflicts",
                "async fn find_active_card_for_user",
            ),
        ] {
            let body = implementation_between(method, end_marker);
            assert!(
                body.contains("attach_card_permission_summaries"),
                "{method} must backfill summaries through the shared batch helper (no N+1)"
            );
        }
        // count_cards 不回填（保持纯 COUNT）。
        let count_body = implementation_between("async fn count_cards", "async fn list_cards");
        assert!(
            !count_body.contains("attach_card_permission_summaries"),
            "count_cards stays a pure COUNT and must not load permission summaries"
        );
    }

    /// 结构守卫：bind_card 与 bind_card_async_one 必须共享同一受守卫绑定核心，
    /// 且正目标用户校验、锁卡证明（PENDING/INACTIVE）、归属/贡献 fail-closed
    /// 守卫全部先于换主 UPDATE —— 核心之外不存在任何裸 user_id UPDATE。
    #[test]
    fn bind_card_methods_share_guarded_core_with_ownership_check_before_update() {
        let bind_body =
            implementation_between("async fn bind_card", "async fn bind_card_async_one");
        let async_one_body =
            implementation_between("async fn bind_card_async_one", "async fn find_conflicts");
        for (method, body) in [
            ("bind_card", bind_body),
            ("bind_card_async_one", async_one_body),
        ] {
            assert!(
                body.contains("bind_card_with_reassignment_guard(&self.db, card_id, user_id)"),
                "{method} must delegate to the shared guarded binding core"
            );
            assert!(
                !body.contains("UPDATE user_card SET user_id"),
                "{method} must not own a user reassignment UPDATE; only the guarded core may"
            );
        }

        // 共享核心：正目标用户校验先于开事务；锁读卡行证明候选状态先于守卫，
        // 守卫先于换主 UPDATE；既有事件语义（CARD_BOUND/ELIGIBILITY/commit）保持。
        let core =
            implementation_between("async fn bind_card_with_reassignment_guard", "fn db_error");
        let positive_user = core
            .find("must be positive")
            .expect("target user id must be validated positive");
        let tx_begin = core
            .find("AuthorizationSourceTransaction::begin(db)")
            .expect("guarded core must open its own transaction");
        assert!(
            positive_user < tx_begin,
            "positive target user validation must precede the transaction"
        );
        let lock_read = core
            .find("SELECT card_status, user_id FROM user_card WHERE card_id = ? FOR UPDATE")
            .expect("core must lock-read the card row before deciding");
        let candidate_proof = core
            .find("card_status != \"PENDING\"")
            .expect("core must prove card_status is still PENDING/INACTIVE after locking");
        let guard_call = core
            .find("ensure_bind_card_no_stale_user_evidence_in_tx(&mut tx")
            .expect("ownership/contribution guard must gate the reassignment");
        let guarded_update = core
            .find("UPDATE user_card SET user_id = ?, card_status = 'ACTIVE'")
            .expect("reassignment UPDATE must live inside the guarded core");
        assert!(
            lock_read < candidate_proof
                && candidate_proof < guard_call
                && guard_call < guarded_update,
            "lock/read + candidate proof + ownership/contribution guard must all precede the UPDATE"
        );
        assert!(
            core.contains("AND card_status IN ('PENDING', 'INACTIVE')"),
            "candidate status predicate must stay on the UPDATE as a second line of defense"
        );
        let card_bound = core
            .find("append_card_projection_in_tx(&mut tx, card_id, \"CARD_BOUND\")")
            .expect("CARD_BOUND projection event must be preserved");
        let eligibility = core
            .find(
                "append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, \
                 &bind_operation_id)",
            )
            .expect("legacy ELIGIBILITY event semantics must be preserved");
        let commit = core
            .find("tx.commit_consuming()")
            .expect("guarded core must commit explicitly");
        assert!(
            guarded_update < card_bound && card_bound < eligibility && eligibility < commit,
            "existing transaction/event semantics must be preserved after the guarded UPDATE"
        );

        // 守卫本体：规范账本修订（canonical payload 归属）、卡级源贡献与 ACTIVE
        // 委托绑定三道检查都是绑定参数 SQL，并在确定错误上整体拒绝。
        let guard = implementation_between(
            "async fn ensure_bind_card_no_stale_user_evidence_in_tx",
            "async fn bind_card_with_reassignment_guard",
        );
        assert!(
            guard.contains("FROM authorization_grant_revision")
                && guard.contains("is_tombstone = 0")
                && guard.contains("JSON_EXTRACT(grant_payload, '$.userId')"),
            "guard must check canonical (non-tombstone) ledger revisions attributed via the grant payload"
        );
        assert!(
            guard.contains(".bind(target_user_id)"),
            "ledger attribution check must bind the target user, never interpolate"
        );
        assert!(
            guard.contains("FROM permission_rule WHERE card_id = ?"),
            "guard must refuse card-scoped source contribution rows on reassignment"
        );
        assert!(
            guard.contains("FROM permission_delegation")
                && guard.contains("delegator_card_id = ? OR delegate_card_id = ?"),
            "guard must refuse ACTIVE card-scoped delegation bindings on reassignment"
        );
        assert!(
            guard.contains("refusing to rebind ownership")
                && guard.matches("refusing to reassign ownership").count() == 2,
            "guard refusals must surface deterministic errors"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 卡状态迁移状态机 × 通用 update 加固（纯逻辑 + 形状守卫）
    // ─────────────────────────────────────────────────────────────────────────

    /// 状态机：通用 update 只能离开 ACTIVE 或原地无迁移；任何把卡送回 ACTIVE
    /// 的迁移（DISABLED/PENDING/INACTIVE/SUSPENDED → ACTIVE）与 DISABLED 的
    /// 任何逃逸都 fail-closed，并指明唯一合法专用入口（restore/bind）。
    #[test]
    fn card_status_transition_state_machine_fails_closed() {
        // 合法面：ACTIVE → 三个非 ACTIVE 状态（停用面）。
        for target in ["INACTIVE", "SUSPENDED", "DISABLED"] {
            assert!(
                validate_card_status_transition("ACTIVE", target).is_ok(),
                "ACTIVE -> {target} is the deactivation face and must be allowed"
            );
        }
        // 同状态回显：无迁移（允许随其他字段一起更新）。
        for same in ["ACTIVE", "INACTIVE", "DISABLED", "SUSPENDED"] {
            assert!(validate_card_status_transition(same, same).is_ok());
        }

        // 软删卡逃逸：任何方向都拒绝 —— 回 ACTIVE 只能走 restore。
        for target in ["ACTIVE", "INACTIVE", "SUSPENDED"] {
            let error = validate_card_status_transition("DISABLED", target).unwrap_err();
            assert!(
                error.to_string().contains("restore path"),
                "DISABLED -> {target} must name the restore path, got: {error}"
            );
        }
        // 非 ACTIVE → ACTIVE 的重激活旁路全部封死。
        for current in ["PENDING", "INACTIVE", "SUSPENDED"] {
            let error = validate_card_status_transition(current, "ACTIVE").unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("re-entering ACTIVE"),
                "{current} -> ACTIVE must be rejected as reactivation, got: {message}"
            );
            if current != "SUSPENDED" {
                assert!(
                    message.contains("bind for PENDING/INACTIVE"),
                    "{current} -> ACTIVE must name the bind path, got: {message}"
                );
            }
        }
        // 非 ACTIVE 之间的横跳同样不在通用入口的合法迁移面内（fail-closed）。
        for (current, target) in [("INACTIVE", "SUSPENDED"), ("SUSPENDED", "INACTIVE")] {
            assert!(validate_card_status_transition(current, target).is_err());
        }
    }

    /// 状态语义回归（纯逻辑，无 DB）：同状态 INACTIVE → INACTIVE 回显既不是
    /// 吊销也不产生资格失效 —— 不写 CARD REVOKE、不追加 ELIGIBILITY、审计
    /// decision 不得按 CARD_REVOKED 落库；只允许随其他字段一起走 legacy
    /// CARD_UPDATE 回显。
    #[test]
    fn same_state_inactive_echo_is_non_revoke_and_non_eligibility() {
        let semantics = classify_card_status_update("INACTIVE", Some("INACTIVE"));
        assert!(
            !semantics.exits_active,
            "INACTIVE -> INACTIVE must not classify as the revoke face"
        );
        assert!(
            !semantics.status_changed,
            "same-state echo must not evict the perm:card:active eligibility cache"
        );
        // 状态机放行同状态回显（允许随其他字段一起更新）。
        assert!(validate_card_status_transition("INACTIVE", "INACTIVE").is_ok());
        // patch 携带 card_status 本身会满足 patch_affects_eligibility，但资格
        // 事件的真实前提是 status_changed —— 两者合取后同状态回显不产生
        // ELIGIBILITY（update_card 非 exit 分支的既有门禁）。
        let patch = UserCardPatch {
            card_status: Some("INACTIVE".into()),
            ..UserCardPatch::default()
        };
        assert!(patch_affects_eligibility(&patch));
        assert!(
            !(semantics.status_changed && patch_affects_eligibility(&patch)),
            "same-state echo must not append an ELIGIBILITY event"
        );
    }

    /// 状态语义回归（纯逻辑，无 DB）：ACTIVE → INACTIVE 是离开 ACTIVE 的吊销
    /// 面 —— CARD REVOKE + ELIGIBILITY + 同事务审计，operation 身份走退出路径
    /// （exits_active 驱动 head 锁定与确定性派生）。
    #[test]
    fn active_to_inactive_is_revoke_with_eligibility() {
        let semantics = classify_card_status_update("ACTIVE", Some("INACTIVE"));
        assert!(
            semantics.exits_active,
            "ACTIVE -> INACTIVE is the deactivation/revoke face"
        );
        assert!(semantics.status_changed);
        assert!(validate_card_status_transition("ACTIVE", "INACTIVE").is_ok());
        // 分类跟随锁定行：其余两个离开 ACTIVE 的目标（SUSPENDED/DISABLED）同属
        // 吊销面；反向（INACTIVE → ACTIVE）与纯字段更新（不携带状态）都不是。
        for (current, target, expected_revoke) in [
            ("ACTIVE", Some("SUSPENDED"), true),
            ("ACTIVE", Some("DISABLED"), true),
            ("INACTIVE", Some("ACTIVE"), false),
            ("INACTIVE", None, false),
        ] {
            let probe = classify_card_status_update(current, target);
            assert_eq!(
                probe.exits_active, expected_revoke,
                "{current} -> {target:?} revoke classification must follow the locked row"
            );
        }
        // patch 面对齐：携带 INACTIVE 目标即满足资格判定前提（配合
        // status_changed=true 走退出路径的 ELIGIBILITY 事件）。
        let patch = UserCardPatch {
            card_status: Some("INACTIVE".into()),
            ..UserCardPatch::default()
        };
        assert!(patch_affects_eligibility(&patch));
    }

    /// update 写入的目标状态必须在 canonical 字母表内并归一化；未知/任意字符串
    /// 绝不进入 SQL 绑定值（trait 为 pub 入口，repository 自包含 fail-closed）。
    #[test]
    fn normalize_requested_card_status_gates_the_alphabet() {
        assert_eq!(normalize_requested_card_status("ACTIVE").unwrap(), "ACTIVE");
        assert_eq!(
            normalize_requested_card_status(" disabled ").unwrap(),
            "DISABLED"
        );
        for bad in ["PENDING", "REVOKED", "active;x", ""] {
            assert!(matches!(
                normalize_requested_card_status(bad),
                Err(AstralError::Validation(_))
            ));
        }
    }

    /// update 退出路径的 operation id 契约：锁定代次确定性派生、重放稳定、
    /// 维度分叉；非正卡 id / 负代次拒绝（负代次是持久层不变量破坏）。
    #[test]
    fn update_card_operation_identity_is_deterministic_and_scoped() {
        let first = derive_update_card_operation_id(21, 4).unwrap();
        assert_eq!(first, "user-card:update:21:gen:4");
        assert_eq!(derive_update_card_operation_id(21, 4).unwrap(), first);
        assert_ne!(derive_update_card_operation_id(22, 4).unwrap(), first);
        assert_ne!(
            derive_update_card_operation_id(21, 5).unwrap(),
            first,
            "锁定的 CARD 代次推进后是新操作身份"
        );
        // 与 delete/create 家族命名空间互不相交。
        assert_ne!(first, derive_card_cascade_operation_id(21, 4));
        assert_ne!(first, derive_create_card_plain_operation_id(21));
        for (card_id, generation) in [(0, 4), (-1, 4), (21, -1)] {
            assert!(matches!(
                derive_update_card_operation_id(card_id, generation),
                Err(AstralError::Validation(_))
            ));
        }
    }

    fn status_audit_entry<'a>() -> UserCardStatusAuditEntry<'a> {
        UserCardStatusAuditEntry {
            actor_id: 42,
            owner_user_id: 7,
            target_card_id: 21,
            operation_id: "user-card:update:21:gen:4",
            parent_event_id: "evt-parent",
            from_status: "ACTIVE",
            to_status: "DISABLED",
            tenant_id: Some(3),
            domain_id: Some(5),
        }
    }

    /// 状态变更审计关联输入的纯校验：操作者/目标卡、operation 与父事件关联、
    /// canonical 前后状态缺一不可；错位一律拒绝落库。
    #[test]
    fn user_card_status_audit_entry_validation_fails_closed() {
        validate_user_card_status_audit_entry(&status_audit_entry()).unwrap();
        for mutate in [
            |e: &mut UserCardStatusAuditEntry<'_>| e.actor_id = 0,
            |e: &mut UserCardStatusAuditEntry<'_>| e.target_card_id = -1,
            |e: &mut UserCardStatusAuditEntry<'_>| e.operation_id = "  ",
            |e: &mut UserCardStatusAuditEntry<'_>| e.parent_event_id = "",
            |e: &mut UserCardStatusAuditEntry<'_>| e.from_status = "BROKEN",
            |e: &mut UserCardStatusAuditEntry<'_>| e.to_status = "active",
        ] {
            let mut entry = status_audit_entry();
            mutate(&mut entry);
            assert!(matches!(
                validate_user_card_status_audit_entry(&entry),
                Err(AstralError::Validation(_))
            ));
        }
    }

    /// 形状守卫：update_card 的离开 ACTIVE 路径必须 —— Phase 0 纯校验（字母表
    /// 归一化 / request id 统一门禁 / actor 归属门禁）先于开事务；锁读行先于
    /// 状态机判定；状态机先于 source UPDATE 且 UPDATE 携带锁定状态 CAS 谓词；
    /// 退出路径先锁定 CARD head 并稳定 operation 身份，再落带元数据 CARD
    /// REVOKE + ELIGIBILITY + 同事务审计行（先于 commit）；legacy CARD_UPDATE
    /// 语义保持；随机 fallback 绝不允许回流。
    #[test]
    fn update_card_status_exit_uses_hardened_metadata_projection_and_same_tx_audit() {
        let body = implementation_between("async fn update_card", "async fn delete_with_cascade");

        // Phase 0：纯校验先于任何 durable 写入（含开事务）。
        let status_alphabet = body
            .find("normalize_requested_card_status(raw)")
            .expect("requested status must pass the canonical alphabet gate");
        let request_id_gate = body
            .find("validated_request_operation_id(patch.request_operation_id.as_deref())")
            .expect("explicit x-request-id must pass the shared safety gate");
        let actor_gate = body
            .find("requires a verified positive actor id")
            .expect("status-bearing patches must fail closed without a verified actor");
        let tx_begin = body
            .find("AuthorizationSourceTransaction::begin(&self.db)")
            .expect("transaction begin");
        assert!(
            status_alphabet < tx_begin && request_id_gate < tx_begin && actor_gate < tx_begin,
            "pure validation must precede the transaction"
        );

        // 锁读行 → 状态机 → source UPDATE（锁定状态 CAS 谓词作第二道防线）。
        let lock_read = body
            .find("FROM user_card WHERE card_id = ? FOR UPDATE")
            .expect("the migration decision must be made on a FOR UPDATE locked row");
        let transition_gate = body
            .find("validate_card_status_transition(&locked.card_status, requested)")
            .expect("the state machine must gate the locked current status");
        let status_predicate = body
            .find("AND card_status = ")
            .expect("the UPDATE must carry the locked status CAS predicate");
        assert!(
            tx_begin < lock_read
                && lock_read < transition_gate
                && transition_gate < status_predicate,
            "lock-read, state machine and the status CAS predicate must order strictly"
        );

        // 退出路径：head 锁 + 身份派生 → 带元数据 REVOKE → ELIGIBILITY → 同事务审计 → commit。
        let head_lock = body
            .find("WHERE aggregate_type = 'CARD' AND aggregate_id = ? FOR UPDATE")
            .expect("the exit identity must derive from a locked CARD head generation");
        let identity = body
            .find("derive_update_card_operation_id(card_id, locked_generation)")
            .expect("missing header must derive the operation identity from locked facts");
        let metadata_revoke = body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("the status exit must use the metadata-bound projection entry");
        let eligibility = body
            .find(
                "append_eligibility_projection_with_invalidation_in_tx(&mut tx, card_id, \
                 &operation_id)",
            )
            .expect("eligibility eviction must stay on the ELIGIBILITY channel");
        let audit = body
            .find("insert_user_card_status_audit_in_tx")
            .expect("the audit correlation row must land in the same transaction");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("transaction must commit explicitly");
        assert!(
            head_lock < identity
                && identity < metadata_revoke
                && metadata_revoke < eligibility
                && eligibility < audit
                && audit < commit,
            "identity must stabilize before the metadata REVOKE, eligibility and same-tx audit"
        );
        assert!(
            body.contains("\"REVOKE\""),
            "the exit event keeps REVOKE semantics (revoke fence advancement)"
        );
        // legacy 非状态路径保持：CARD_UPDATE 兼容入口仍在（同状态回显/纯字段更新）。
        assert!(
            body.contains("append_card_projection_in_tx(&mut tx, card_id, \"CARD_UPDATE\")"),
            "non-status updates keep the legacy CARD_UPDATE semantics"
        );
        // 随机 fallback 与旧临时 correlation 绝不允许回流。
        assert!(!body.contains("uuid::Uuid"));
    }

    /// 形状守卫：状态变更审计行必须走 `audit_log` 的既有机制（与级联删除审计
    /// 同表同事务），全部输入绑定参数、无 SQL 字符串拼接，事件族与 decision
    /// 语义和父 CARD REVOKE 对齐。
    #[test]
    fn user_card_status_audit_is_parameterized_same_tx_correlation() {
        let production = include_str!("user_card_repository.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("tests module must be last");
        let helper = production
            .split("async fn insert_user_card_status_audit_in_tx")
            .nth(1)
            .and_then(|rest| {
                rest.split("derive_create_card_template_operation_id")
                    .next()
            })
            .expect("status audit helper body must exist");
        assert!(
            helper.contains("INSERT INTO audit_log"),
            "the audit correlation row must use the shared audit_log mechanism"
        );
        for binding in [
            ".bind(entry.actor_id)",
            ".bind(entry.target_card_id)",
            ".bind(entry.operation_id)",
            ".bind(entry.domain_id)",
            ".bind(entry.tenant_id)",
            ".bind(detail)",
        ] {
            assert!(
                helper.contains(binding),
                "audit inputs must be bound parameters ({binding})"
            );
        }
        // no-format! 门禁只作用于 SQL 调用本体（sqlx::query( 起始到首个绑定输入）：
        // 错误消息映射里的 format!（AstralError::Database 文案）不属于 SQL 组装面，
        // 不得让该守卫误伤 —— SQL 字面量本体必须是不经字符串拼接的 plain literal。
        let sql_call_region = helper
            .split("sqlx::query(")
            .nth(1)
            .and_then(|rest| rest.split(".bind(entry.actor_id)").next())
            .expect("audit SQL call must precede its bound inputs");
        assert!(
            !sql_call_region.contains("format!("),
            "the audit SQL must never be assembled with string formatting"
        );
        assert!(
            helper.contains("'USER_CARD_MUTATION'")
                && helper.contains("'card_status_change'")
                // decision 走绑定参数（.bind("CARD_REVOKED")），不是 SQL 内联字面量。
                && helper.contains(".bind(\"CARD_REVOKED\")"),
            "event family/decision must align with the parent CARD REVOKE projection"
        );
        assert!(
            helper.contains("validate_user_card_status_audit_entry(entry)?"),
            "the audit row must be validated before insert"
        );
    }
}
