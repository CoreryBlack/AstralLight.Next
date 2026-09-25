//! 全局管理员数据访问 — GlobalAdminRepository
//!
//! 对齐 Java `IdentityGlobalAdminMapper` 边界（identity_global_admin 表）。
//! disable 的最后活跃管理员保护封装为单一原子方法（对齐 Java
//! `LAST_GLOBAL_ADMIN_PROTECTED` 语义）。
//!
//! SUPER_ADMIN 授权 mutation（grant/disable）在同一 source transaction 内把
//! `__SUPERADMIN__` 模板 RuleSet 的 BASE 贡献物化进授权账本
//! （`authorization_grant_revision` + `authorization_delta_event`），与既有
//! head/outbox 投影事件并存；身份全部确定性派生（无随机业务 identity），
//! 幂等 enable/grant 不产生重复 Active 贡献，disable 对缺失账本贡献 fail-closed。
//! grant 侧落 `INITIAL_REBUILD`、disable 侧落 `SUPERADMIN_DISABLE` 关联审计行
//! （同一 `rule_set_projection_audit` 表、同一事务），发放与回收两侧的投影/账本
//! 证据均可审计关联。
//!
//! ## is_active_admin 进程级缓存（读链规模化）
//!
//! [`GlobalAdminRepository::is_active_admin`]（管理范围例外判定，非
//! PolicyEngine 评估链）经进程级短窗缓存（TTL [`ACTIVE_ADMIN_CACHE_TTL`]，
//! 5s）。失效方式：本进程的 grant/disable 提交成功后按 user 主动 evict
//! （立即生效）；跨实例（含 Java 侧对同表的写入）无广播，由 TTL 兜底（≤5s）。
//! 缓存 miss/DB 错误一律回源权威查询并原样上抛（fail-closed 不变），错误绝不
//! 入缓存。
//!
//! ### 撤销传播窗口标注（缓存 → 撤销路径 → 兜底层）
//!
//! - **grant 层（兜底为 pointer 对牌，零窗口）**：disable 在同一 source
//!   transaction 内为受影响 SUPER_ADMIN 卡物化 `__SUPERADMIN__` BASE 贡献的
//!   REMOVE tombstone + CARD REVOKE 投影（见
//!   `revoke_superadmin_rule_set_contributions_in_tx`）。这些授权撤销经投影
//!   发布推进指针版本组，由 evidence 缓存的指针双读对牌（读前+读后均真读
//!   DB pointer，零传播窗口）立即失效——PolicyEngine 评估链的 SUPER_ADMIN
//!   特权撤销**不依赖本缓存，延迟 ≈ 0**。
//! - **边界守卫自身（无 pointer 兜底，保持 5s 短窗口）**：
//!   `is_active_admin` 读的是 source 表状态（identity_global_admin），不是
//!   指针派生的授权事实，pointer 对牌无法兜底。stale-true 窗口内已撤销的
//!   管理员仍可通过 `require_platform_admin` 类跨范围例外判定（**放行方向**，
//!   ≤TTL 上限）。其后的业务授权仍须过 PolicyEngine：仅由 `__SUPERADMIN__`
//!   特权支撑的资源已被零窗口拒绝；残余暴露 = 窗口内以其**既有普通授权**
//!   （未被 disable 触及的其它卡/规则）触达跨范围管理操作，且其下所有调用
//!   仍受 PolicyEngine 评估与租户边界约束。反向（新授予/启用延迟 ≤5s 生效）
//!   只会延迟放行，是安全方向。**据此 TTL 保持 5s 不放宽**（与 sod_policy
//!   缓存的 30s 差异：SoD 缓存对象是策略输入而非撤销信号；此处缓存对象是
//!   撤销敏感的管理边界状态）。

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{
    AstralError, DependencyVector, DependencyVersion, GrantContractError, GrantDelta,
    GrantEvidence, GrantState, ProjectionAggregate, EVENT_TYPE_ELIGIBILITY_UPDATE,
    EVENT_TYPE_REVOKE, EVENT_TYPE_RULE_SET_UPDATE, SYSTEM_ACTOR_ID,
};
use policy_engine::COMPILER_VERSION;

use crate::repository::audit_log_repository::{
    insert_rule_set_projection_audit_in_tx, RuleSetProjectionAuditEntry,
};
use crate::repository::grant_ledger_adapter::{
    append_ruleset_grant_delta_in_tx, build_ruleset_add_draft, build_ruleset_remove_draft,
    derive_ruleset_contribution_event_id, derive_ruleset_identity, map_grant_repository_error,
    RuleSetEntryLedgerFacts, RuleSetMutationKind, RULE_SET_AGGREGATE_TYPE,
};
use crate::repository::projection_repository::{
    append_aggregate_projection_in_tx, append_card_projection_with_metadata_in_tx,
    append_rule_set_projection_in_tx,
};

/// 在 source transaction 内追加 ELIGIBILITY 资格投影事件（与 CARD 事件同事务）。
///
/// SUPER_ADMIN 卡的 status / tenant_id / domain_id 变更同样影响资格缓存
/// （`perm:card:active:{card_id}`），必须同事务落 ELIGIBILITY 事件，否则资格缓存
/// 在最长 TTL 内 stale-ALLOW。ELIGIBILITY 通道轻量投影（只 evict 资格缓存 + 推进
/// head），不重建规则快照、不发 CARD refresh，与 CARD 事件并存不会重复改快照语义。
async fn append_eligibility_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
) -> Result<(), AstralError> {
    append_aggregate_projection_in_tx(
        tx,
        ProjectionAggregate::Eligibility,
        card_id,
        EVENT_TYPE_ELIGIBILITY_UPDATE,
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// __SUPERADMIN__ RuleSet BASE 贡献的授权账本物化（共享 ledger adapter helpers）
//
// 身份全部确定性派生，无随机业务 identity：
// - grant 的稳定 operation id：`global-admin:grant:{user_id}:{card_id}:{rule_set_id}`
//   （与 legacy RuleSet 投影共享同一身份）；同一 grant 身份上可能连续成功多次的
//   mutation（disable 后重新 enable 的复活 ADD、多次 disable 的 REMOVE）把锁定
//   head revision 折入 id：`{base}:r{rev}` —— 同业务重试（事务已回滚、head 未
//   推进）重放得到同一 operation/contribution event id，revision 推进后必然分叉，
//   与 delegation 的 identity-bound revision 同一防重放思路。
// - contribution event id 经共享 adapter（derive_ruleset_contribution_event_id）
//   从 operation id + 稳定维度（租户/RULE_SET 聚合/entry×card×ref/kind）派生，
//   满足 `uk_ade_event` 全局唯一且可重放。
//
// 幂等语义：head 已 Active 的贡献直接跳过（不重复物化 Active 授权）；head 缺失
// → 全新 ADD rev1（base 0 → target 1）；head 为 tombstone → 严格 successor 的
// 复活 ADD。disable 侧为 Active 贡献追加 REMOVE tombstone，head 缺失即
// fail-closed，绝不谎报撤销完成。
// ─────────────────────────────────────────────────────────────────────────────

/// `__SUPERADMIN__` 规则集启用条目的账本物化所需字段（enabled=1 在 SQL 过滤）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct SuperadminRuleSetEntryRow {
    entry_id: i64,
    effect: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    action_code: Option<String>,
    condition_json: Option<String>,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

const SUPERADMIN_RULE_SET_ENTRY_SELECT: &str = "entry_id AS entry_id, effect AS effect, \
     resource_type AS resource_type, resource_id AS resource_id, action_code AS action_code, \
     condition_json AS condition_json, \
     DATE_FORMAT(valid_from, '%Y-%m-%dT%H:%i:%s') AS valid_from, \
     DATE_FORMAT(valid_to, '%Y-%m-%dT%H:%i:%s') AS valid_to";

/// 读取 `__SUPERADMIN__` 规则集的启用条目。`lock` 选择 FOR UPDATE（grant 组装
/// ADD 需要 resource/action 事实稳定）或一致性快照读（disable 只消费不可变的
/// entry/ref 主键身份，避免与 rule-set-first 路径形成 entries↔refs 反序锁）。
async fn load_superadmin_rule_set_entries_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    lock: bool,
) -> Result<Vec<SuperadminRuleSetEntryRow>, AstralError> {
    let lock_clause = if lock { " FOR UPDATE" } else { "" };
    sqlx::query_as::<_, SuperadminRuleSetEntryRow>(&format!(
        "SELECT {SUPERADMIN_RULE_SET_ENTRY_SELECT} FROM rule_set_entry \
         WHERE rule_set_id = ? AND enabled = 1 ORDER BY entry_id{lock_clause}"
    ))
    .bind(rule_set_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)
}

/// 条目效果分类（与 rule_set 侧物化分类同一语义）：ALLOW → 授权来源；
/// DENY → 从未进入 canonical 账本，安全跳过；未知值 fail-closed，不猜测语义。
fn superadmin_entry_is_materializable_allow(effect: &str) -> Result<bool, AstralError> {
    let effect = effect.trim();
    if effect.eq_ignore_ascii_case("ALLOW") {
        Ok(true)
    } else if effect.eq_ignore_ascii_case("DENY") {
        Ok(false)
    } else {
        Err(AstralError::Validation(format!(
            "__SUPERADMIN__ rule set entry carries unknown effect {effect:?}; refusing to classify it as an authorization contribution"
        )))
    }
}

/// canonical 授权字段提取：非空 resource/action 才能进入 canonical 合同，
/// 无法证明的 legacy 行显式拒绝而非静默跳过。
fn superadmin_entry_canonical_fields(
    entry: &SuperadminRuleSetEntryRow,
) -> Result<(&str, &str), AstralError> {
    let resource = entry
        .resource_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "__SUPERADMIN__ rule set entry {} lacks a usable resource_type; refusing to materialize a canonical grant",
                entry.entry_id
            ))
        })?;
    let action = entry
        .action_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "__SUPERADMIN__ rule set entry {} lacks a usable action; refusing to materialize a canonical grant",
                entry.entry_id
            ))
        })?;
    Ok((resource, action))
}

/// 组装单条 `__SUPERADMIN__` 条目贡献的稳定事实（全部来自锁定/已证明的 source
/// 行）；`ref_type` 恒为 BASE（本仓库 grant 只创建 BASE 绑定）。
#[allow(clippy::too_many_arguments)]
fn superadmin_entry_facts<'a>(
    rule_set_id: i64,
    tenant_id: i64,
    domain_id: Option<i64>,
    card_id: i64,
    user_id: i64,
    ref_id: i64,
    entry: &'a SuperadminRuleSetEntryRow,
) -> Result<RuleSetEntryLedgerFacts<'a>, AstralError> {
    let (resource, action) = superadmin_entry_canonical_fields(entry)?;
    Ok(RuleSetEntryLedgerFacts {
        tenant_id,
        domain_id,
        card_id,
        user_id,
        rule_set_id,
        entry_id: entry.entry_id,
        ref_id,
        ref_type: "BASE",
        resource,
        resource_id: entry.resource_id,
        action,
        // 条件文本原样传给 adapter：非空值由 canonical ADD 组装门禁 fail-closed
        //（canonical 合同无 condition 槽位）；REMOVE 不消费本字段。
        condition_json: entry.condition_json.as_deref(),
        valid_from: entry.valid_from.as_deref(),
        valid_to: entry.valid_to.as_deref(),
    })
}

/// 账本 actor：系统 mutation（SYSTEM_ACTOR_ID=-1）以 None 表达（canonical 合同
/// 拒绝非正 actor）；用户上下文要求正数；其余非正值 fail-closed。
fn superadmin_ledger_actor(actor_id: i64) -> Result<Option<i64>, AstralError> {
    if actor_id == SYSTEM_ACTOR_ID {
        Ok(None)
    } else if actor_id > 0 {
        Ok(Some(actor_id))
    } else {
        Err(AstralError::Validation(format!(
            "global admin ledger mutation requires a positive actor id or the system actor, got {actor_id}"
        )))
    }
}

/// grant 的稳定 operation id（fresh ADD 与 legacy RuleSet 投影共享同一身份）。
fn superadmin_grant_operation_id(user_id: i64, card_id: i64, rule_set_id: i64) -> String {
    format!("global-admin:grant:{user_id}:{card_id}:{rule_set_id}")
}

/// revision 绑定的 operation id：同一 grant 身份上可能连续成功多次的 mutation
/// 把锁定 head revision 折入 id，重试/推进分叉语义见本节头注释。
fn revision_bound_operation_id(base: &str, revision: u64) -> String {
    format!("{base}:r{revision}")
}

/// disable REMOVE 的 operation id（revision 绑定，防多次 disable 撞唯一事件号）。
fn superadmin_disable_operation_id(admin_row_id: i64, card_id: i64, revision: u64) -> String {
    revision_bound_operation_id(
        &format!("global-admin:disable:{admin_row_id}:card:{card_id}"),
        revision,
    )
}

/// disable 路径关联审计行的 change_type：以 CARD REVOKE 投影事件为锚，与 grant
/// 路径的 `INITIAL_REBUILD` 审计同表（`rule_set_projection_audit`）同机制落库；
/// 唯一键含 change_type，因此与既有 INITIAL_REBUILD/REBUILD_SNAPSHOT 行互不冲突。
const SUPERADMIN_DISABLE_AUDIT_CHANGE_TYPE: &str = "SUPERADMIN_DISABLE";

/// grant 侧账本动作分类（纯逻辑，可单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantLedgerAction {
    /// head 已 Active：贡献已物化，幂等跳过（绝不重复 ADD Active 授权）。
    Skip,
    /// head 缺失：全新 ADD rev1（base 0 → target 1）。
    FreshAdd,
    /// head 为 tombstone：严格 successor 的复活 ADD（locked revision + 1）。
    Resurrect,
}

fn grant_ledger_action(head_state: Option<GrantState>) -> GrantLedgerAction {
    match head_state {
        None => GrantLedgerAction::FreshAdd,
        Some(GrantState::Active) => GrantLedgerAction::Skip,
        Some(_) => GrantLedgerAction::Resurrect,
    }
}

/// disable 侧账本动作分类：Active 贡献必须 REMOVE；已 tombstone（Removed/
/// Revoked）说明撤销证据已在账本中，跳过不重复；其余状态交由账本 transition
/// 规则 fail-closed（冻结/未知状态不允许静默放行）。head 缺失由调用方
/// fail-closed（不谎报撤销完成）。
fn disable_entry_needs_remove(head_state: GrantState) -> bool {
    !matches!(head_state, GrantState::Removed | GrantState::Revoked)
}

/// i64 投影代次/围栏 → 无符号合同域（负值为持久层不变式破坏，归类 Internal）。
fn superadmin_projection_u64(value: i64, field: &'static str) -> Result<u64, AstralError> {
    u64::try_from(value).map_err(|_| {
        AstralError::Internal(format!(
            "__SUPERADMIN__ projection {field} {value} cannot cross the unsigned contract boundary"
        ))
    })
}

fn superadmin_contract_error(error: GrantContractError) -> AstralError {
    AstralError::Validation(format!(
        "__SUPERADMIN__ grant contract rejected payload: {error}"
    ))
}

/// 复活 ADD（head 为 tombstone 时重新 enable）：以锁定 head 的 canonical payload
/// 为基底，revision 严格推进到 successor（账本 transition 规则复核），provenance
/// 重绑本次 mutation；ADD 无 before-image（成对缺席）。delta/evidence 合同校验
/// 全部执行，任何失败 fail-closed 并整体回滚。不 commit、不触碰 Redis/MQ。
#[allow(clippy::too_many_arguments)]
async fn append_ruleset_resurrection_add_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    head: &astral_db::GrantHeadSnapshot,
    facts: &RuleSetEntryLedgerFacts<'_>,
    operation_id: &str,
    actor_user_id: Option<i64>,
    parent: &astral_db::ProjectionEventIdentity,
    contribution_event_id: &str,
    base_version: i64,
    target_version: i64,
) -> Result<(), AstralError> {
    if target_version <= base_version || base_version < 0 {
        return Err(AstralError::Validation(
            "__SUPERADMIN__ resurrection delta version must strictly advance from a non-negative base"
                .into(),
        ));
    }
    let next_revision = head
        .entry
        .revision
        .next()
        .map_err(superadmin_contract_error)?;
    let mut resurrected = head.payload.clone();
    resurrected.revision = next_revision;
    resurrected.state = GrantState::Active;
    resurrected.provenance.operation_id = operation_id.to_owned();
    resurrected.provenance.event_id = Some(contribution_event_id.to_owned());
    resurrected.provenance.actor_user_id = actor_user_id;

    let delta = GrantDelta::add(resurrected.clone());
    delta.validate().map_err(superadmin_contract_error)?;
    // 依赖向量仅做合同级校验 + hash（与 adapter 内 RULE_SET 组装同一形态）。
    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        format!("card:{}", facts.card_id),
        superadmin_projection_u64(parent.source_generation, "source_generation")?,
        superadmin_projection_u64(parent.revoke_fence, "revoke_fence")?,
    )
    .map_err(superadmin_contract_error)?])
    .map_err(superadmin_contract_error)?;
    let evidence = GrantEvidence {
        grant: resurrected.clone(),
        event_id: contribution_event_id.to_owned(),
        operation_id: operation_id.to_owned(),
        source_generation: superadmin_projection_u64(
            parent.source_generation,
            "source_generation",
        )?,
        revoke_fence: superadmin_projection_u64(parent.revoke_fence, "revoke_fence")?,
        dependency_vector: dependency_vector.clone(),
    };
    evidence.validate().map_err(superadmin_contract_error)?;
    let semantic_hash_hex = resurrected
        .canonical_hash()
        .map_err(superadmin_contract_error)?;
    let dependency_hash_hex = dependency_vector
        .canonical_hash()
        .map_err(superadmin_contract_error)?;
    let delta_json = serde_json::to_string(&delta).map_err(|error| {
        AstralError::Internal(format!(
            "__SUPERADMIN__ resurrection delta serialization failed: {error}"
        ))
    })?;

    astral_db::append_grant_revision_in_tx(
        &mut *tx,
        &astral_db::GrantRevisionAppendRequest {
            tenant_id: facts.tenant_id,
            card_id_scope: Some(facts.card_id),
            aggregate_type: RULE_SET_AGGREGATE_TYPE.to_owned(),
            aggregate_id: facts.rule_set_id,
            delta,
            event_id: contribution_event_id.to_owned(),
            operation_id: operation_id.to_owned(),
            semantic_hash_hex: semantic_hash_hex.clone(),
            dependency_hash_hex: dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
        },
    )
    .await
    .map_err(map_grant_repository_error)?;
    astral_db::append_delta_event(
        &mut **tx,
        &astral_db::DeltaEventAppendRequest {
            tenant_id: facts.tenant_id,
            card_id: Some(facts.card_id),
            aggregate_type: RULE_SET_AGGREGATE_TYPE.to_owned(),
            aggregate_id: facts.rule_set_id,
            grant_id: head.grant_id,
            event_id: contribution_event_id.to_owned(),
            operation_id: operation_id.to_owned(),
            event_type: astral_db::DeltaEventType::Add,
            base_version,
            target_version,
            source_generation: superadmin_projection_u64(
                parent.source_generation,
                "source_generation",
            )?,
            revoke_fence: superadmin_projection_u64(parent.revoke_fence, "revoke_fence")?,
            invalidates_published_evidence: false,
            before_image_json: None,
            before_digest_hex: None,
            delta_json,
            semantic_hash_hex,
            dependency_hash_hex,
            compiler_version: COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        },
    )
    .await
    .map_err(map_grant_repository_error)?;
    Ok(())
}

/// 单张 SUPER_ADMIN 卡的 `__SUPERADMIN__` BASE 贡献撤销（disable 路径）：
///
/// 1. 身份证明：卡模板必须是 ACTIVE `__SUPERADMIN__` 模板，且恰好拥有一个启用的
///    TEMPLATE 源规则集（与 grant 路径同一身份推导）；租户漂移 fail-closed。
/// 2. 锁定 BASE 绑定行（贡献身份 ref_id 的来源）；绑定缺失即 fail-closed ——
///    不谎报撤销完成。
/// 3. 逐条 ALLOW 条目锁定账本 head：缺失 fail-closed；已 tombstone 跳过；
///    Active 贡献收集 REMOVE。
/// 4. 追加携带 actor/operation metadata 的 CARD REVOKE 投影作为 generation/fence
///    锚（与 legacy REVOKE 事件同一写入路径，仅增加 provenance 元数据），
///    然后为每条 Active 贡献物化 REMOVE tombstone（revision 绑定 operation id）。
/// 5. 同事务落 `rule_set_projection_audit` 关联审计行（change_type
///    `SUPERADMIN_DISABLE`）：以 CARD REVOKE 投影事件（event_id/source_generation）
///    为锚，operation_id 用 disable 基础 id（revision 绑定的 REMOVE operation id
///    全部共享该前缀），new_value 关联每条 REMOVE 的 entry/grant/contribution
///    事件号。审计写入失败与账本写入失败同样整体回滚 —— 绝不产生无审计证据的
///    权限回收（与 grant 路径的 INITIAL_REBUILD 审计同一不对称性补齐）。
///
/// 本函数不修改 source 行、不 commit；任一失败向上传播触发整体回滚。
#[allow(clippy::too_many_arguments)]
async fn revoke_superadmin_rule_set_contributions_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    admin_row_id: i64,
    card_id: i64,
    user_id: i64,
    card_tenant_id: Option<i64>,
    card_domain_id: Option<i64>,
    template_id: i64,
    actor_id: i64,
) -> Result<(), AstralError> {
    let tenant_id = card_tenant_id.ok_or_else(|| {
        AstralError::Validation(format!(
            "superadmin card {card_id} has a NULL tenant_id; refusing to revoke its grants without a tenant scope"
        ))
    })?;
    let template_code: Option<String> = sqlx::query_scalar(
        "SELECT template_code FROM user_card_template \
         WHERE template_id = ? AND status = 'ACTIVE'",
    )
    .bind(template_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    if template_code.as_deref() != Some("__SUPERADMIN__") {
        return Err(AstralError::Validation(format!(
            "superadmin card {card_id} template {template_id} is not an ACTIVE __SUPERADMIN__ template; refusing to claim its revocation complete"
        )));
    }
    let rule_set_rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT rule_set_id, tenant_id FROM rule_set \
         WHERE source_type = 'TEMPLATE' AND source_id = ? AND enabled = 1 ORDER BY rule_set_id",
    )
    .bind(template_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    let (rule_set_id, rule_set_tenant_id) = match rule_set_rows.as_slice() {
        [(rule_set_id, rule_set_tenant_id)] => (*rule_set_id, *rule_set_tenant_id),
        other => {
            return Err(AstralError::Validation(format!(
                "template {template_id} must own exactly one enabled TEMPLATE rule set to revoke superadmin contributions, found {}",
                other.len()
            )));
        }
    };
    if rule_set_tenant_id != Some(tenant_id) {
        return Err(AstralError::Permission(format!(
            "__SUPERADMIN__ rule set {rule_set_id} tenant {rule_set_tenant_id:?} does not match superadmin card {card_id} tenant {tenant_id}"
        )));
    }
    let binding_ref_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM card_rule_set_ref \
         WHERE card_id = ? AND rule_set_id = ? AND ref_type = 'BASE' FOR UPDATE",
    )
    .bind(card_id)
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    let Some(ref_id) = binding_ref_id else {
        return Err(AstralError::Validation(format!(
            "superadmin card {card_id} has no BASE binding for rule set {rule_set_id}; refusing to claim revocation complete without ledger contributions"
        )));
    };

    // 启用条目用一致性快照读（身份只依赖不可变 entry/ref 主键）。
    let entries = load_superadmin_rule_set_entries_in_tx(tx, rule_set_id, false).await?;
    struct PendingRemoval<'a> {
        facts: RuleSetEntryLedgerFacts<'a>,
        head: astral_db::GrantHeadSnapshot,
    }
    let mut removals: Vec<PendingRemoval<'_>> = Vec::new();
    for entry in &entries {
        if !superadmin_entry_is_materializable_allow(&entry.effect)? {
            continue;
        }
        let facts = superadmin_entry_facts(
            rule_set_id,
            tenant_id,
            card_domain_id,
            card_id,
            user_id,
            ref_id,
            entry,
        )?;
        let grant_id = derive_ruleset_identity(&facts)?;
        let head = astral_db::read_grant_head_for_update_in_tx(
            tx,
            tenant_id,
            RULE_SET_AGGREGATE_TYPE,
            rule_set_id,
            grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let Some(head) = head else {
            return Err(AstralError::Validation(format!(
                "__SUPERADMIN__ contribution for rule set entry {0} (rule set {1}) has no versioned grant under card {2}; refusing to claim superadmin revocation complete without ledger evidence",
                entry.entry_id, rule_set_id, card_id
            )));
        };
        if disable_entry_needs_remove(head.entry.state) {
            removals.push(PendingRemoval { facts, head });
        }
    }

    // CARD REVOKE parent：generation/fence 锚 + legacy REVOKE 语义（同一路径）。
    let base_operation_id = format!("global-admin:disable:{admin_row_id}:card:{card_id}");
    let parent = append_card_projection_with_metadata_in_tx(
        tx,
        card_id,
        EVENT_TYPE_REVOKE,
        astral_db::ProjectionEventMetadata {
            actor_id,
            operation_id: &base_operation_id,
        },
    )
    .await?;
    // 关联审计行与 REMOVE 的租户边界必须与父投影事件一致；漂移即持久层
    // 不变量破坏，fail-closed 拒绝（与 RULE_SET 投影审计同一租户复核纪律）。
    if parent.tenant_id != Some(tenant_id) {
        return Err(AstralError::Permission(
            "CARD REVOKE projection tenant does not match the superadmin card scope".into(),
        ));
    }
    // 逐条物化 REMOVE tombstone，同时收集审计关联事实（与账本 delta 同一身份
    // 来源：operation/contribution 事件号、entry/grant/revision 维度全部来自
    // 已证明的锁定 head 与派生身份，不引入任何新的随机或请求上下文输入）。
    let mut removal_audits: Vec<serde_json::Value> = Vec::with_capacity(removals.len());
    for pending in &removals {
        let operation_id = superadmin_disable_operation_id(
            admin_row_id,
            card_id,
            pending.head.entry.revision.value(),
        );
        let contribution_event_id = derive_ruleset_contribution_event_id(
            &operation_id,
            &pending.facts,
            RuleSetMutationKind::Remove,
        )?;
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            tx,
            tenant_id,
            RULE_SET_AGGREGATE_TYPE,
            rule_set_id,
            pending.head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;
        let draft = build_ruleset_remove_draft(
            &pending.facts,
            &pending.head,
            &operation_id,
            &parent,
            &contribution_event_id,
        )?;
        append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
        removal_audits.push(serde_json::json!({
            "entryId": pending.facts.entry_id,
            "bindingRefId": pending.facts.ref_id,
            "grantId": pending.head.grant_id.as_str(),
            "fromRevision": pending.head.entry.revision.value(),
            "operationId": operation_id,
            "contributionEventId": contribution_event_id,
        }));
    }

    // 敏感回收审计（与 grant 路径同一表/机制的同事务关联行）：disable 是权限
    // 回收事件，审计行必须能把本次 CARD REVOKE 投影（event_id/source_generation
    // 锚，即全部 REMOVE 的 generation/fence 来源）与 ledger REMOVE 的
    // operation/contribution 事件号相互关联。唯一键
    // uk_rsp_audit_event_generation(event_id, source_generation, change_type) 以
    // 父事件 UUID 为锚天然按次唯一；全部贡献已 tombstone 的幂等重放如实记录
    // 空 removals（回收事实仍落审计，不谎报新增撤销）。insert 冲突由共享
    // helper 按不可变关联字段 fail-closed 复核；失败与账本写入同样整体回滚。
    let disable_audit_detail = serde_json::json!({
        "cardId": card_id,
        "ownerUserId": user_id,
        "adminRowId": admin_row_id,
        "templateId": template_id,
        "tenantId": tenant_id,
        "domainId": card_domain_id,
        "parentSourceEventId": parent.event_id,
        "removals": removal_audits,
    })
    .to_string();
    insert_rule_set_projection_audit_in_tx(
        tx,
        &RuleSetProjectionAuditEntry {
            rule_set_id,
            entry_id: None,
            aggregate_type: ProjectionAggregate::RuleSet.as_str(),
            aggregate_id: rule_set_id,
            event_id: &parent.event_id,
            source_generation: parent.source_generation,
            operation_id: &base_operation_id,
            actor_id,
            change_type: SUPERADMIN_DISABLE_AUDIT_CHANGE_TYPE,
            old_value_json: None,
            new_value_json: Some(&disable_audit_detail),
            tenant_id: Some(tenant_id),
        },
    )
    .await?;
    Ok(())
}

/// 全局管理员记录（identity_global_admin）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GlobalAdminRecord {
    pub id: i64,
    pub user_id: i64,
    pub status: String,
    pub granted_by: Option<i64>,
    pub granted_reason: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 禁用结果（对齐 Java disable 语义）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableOutcome {
    /// 已成功禁用
    Disabled,
    /// 最后一位活跃管理员，受保护
    LastAdminProtected,
    /// 更新未生效（并发竞态等），需回查确认
    UpdateFailed,
}

/// 超管发放结果。管理员行、特权卡、BASE 绑定、授权账本贡献（grant revision +
/// delta event）和 projection outbox 已在同一事务提交；projection 尚未 READY 时
/// 由 API 返回显式 pending，不能伪装成普通成功。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalAdminGrantOutcome {
    pub admin_id: i64,
    pub card_id: i64,
    pub projection_ready: bool,
}

const STATUS_ACTIVE: &str = "ACTIVE";
const STATUS_DISABLED: &str = "DISABLED";

// ─────────────────────────────────────────────────────────────────────────────
// is_active_admin 进程级缓存（读链规模化：每请求 1 次 identity_global_admin 读收敛）
// ─────────────────────────────────────────────────────────────────────────────

/// ACTIVE 全局管理员判定的进程级缓存 TTL（5s 短窗口）。
///
/// 显式取舍（记录在案）：全局管理员撤销/禁用需快速生效，但缓存条目在 TTL
/// 窗口内仍可能携带旧的 ACTIVE 结论——**5s 窗口内已撤销的管理员仍可通过
/// `require_platform_admin` 类管理范围例外判定（放行方向），属显式接受的
/// 安全成本**；反向（新授予/启用延迟 ≤5s 生效）只会延迟放行，是安全方向。
/// 失效方式见模块文档"is_active_admin 进程级缓存"节。
const ACTIVE_ADMIN_CACHE_TTL: Duration = Duration::from_secs(5);

/// 进程缓存容量上限（键数）：超限先淘汰过期条目，仍超限整体清空——缓存是
/// 纯性能优化，清空零正确性损失（下次读回源权威查询）。
const ACTIVE_ADMIN_CACHE_MAX_ENTRIES: usize = 100_000;

/// 进程级缓存：键 `user_id`，值 `(是否 ACTIVE, 填充时刻)`。条目新鲜度随
/// TTL 判定（读取侧检查 + 写入侧机会性清理），无后台清理线程。
static ACTIVE_ADMIN_CACHE: OnceLock<RwLock<HashMap<i64, (bool, Instant)>>> = OnceLock::new();

fn active_admin_cache() -> &'static RwLock<HashMap<i64, (bool, Instant)>> {
    ACTIVE_ADMIN_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 缓存条目新鲜度（纯逻辑；`duration_since` 对未来时刻饱和为 0，恰好到达
/// TTL 即不新鲜，对齐 `cache_epoch` 的边界语义）。
fn active_admin_entry_is_fresh(cached_at: Instant, now: Instant) -> bool {
    now.duration_since(cached_at) < ACTIVE_ADMIN_CACHE_TTL
}

/// TTL 内的缓存结论（未命中/过期/锁中毒 → `None`，调用方回源权威查询）。
fn fresh_active_admin_entry(user_id: i64) -> Option<bool> {
    let cache = active_admin_cache().read().ok()?;
    let (active, cached_at) = cache.get(&user_id)?;
    if active_admin_entry_is_fresh(*cached_at, Instant::now()) {
        return Some(*active);
    }
    None
}

/// 写入缓存（权威查询成功后调用；错误结果绝不缓存）。锁中毒时静默跳过
/// （缓存侧任何异常只意味着下一次读回源权威查询，绝不影响 fail-closed）。
/// 容量清理随 TTL：超限先淘汰过期条目，仍超限整体清空。
fn store_active_admin_entry(user_id: i64, active: bool) {
    let Ok(mut cache) = active_admin_cache().write() else {
        return;
    };
    if cache.len() >= ACTIVE_ADMIN_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, (_, cached_at)| active_admin_entry_is_fresh(*cached_at, now));
        if cache.len() >= ACTIVE_ADMIN_CACHE_MAX_ENTRIES {
            cache.clear();
        }
    }
    cache.insert(user_id, (active, Instant::now()));
}

/// 按 user 主动失效（grant/disable 提交成功后的 evict 钩子：本进程立即生效；
/// 跨实例无广播，由 TTL 兜底，见 [`ACTIVE_ADMIN_CACHE_TTL`] 取舍记录）。
fn evict_active_admin_entry(user_id: i64) {
    if let Ok(mut cache) = active_admin_cache().write() {
        cache.remove(&user_id);
    }
}

fn validate_superadmin_rule_set_scope(
    source_type: &str,
    enabled: i32,
    source_id: Option<i64>,
    template_id: i64,
    rule_set_tenant_id: Option<i64>,
    template_tenant_id: i64,
) -> Result<(), AstralError> {
    if source_type != "TEMPLATE" || enabled != 1 || source_id != Some(template_id) {
        return Err(AstralError::NotFound(
            "__SUPERADMIN__ BASE rule set is not an enabled TEMPLATE source for the template"
                .into(),
        ));
    }
    if rule_set_tenant_id != Some(template_tenant_id) {
        return Err(AstralError::Permission(format!(
            "__SUPERADMIN__ RuleSet tenant_id does not match template tenant_id: rule_set_tenant={rule_set_tenant_id:?}, template_tenant={template_tenant_id}"
        )));
    }
    Ok(())
}

const RULE_SET_INITIAL_REBUILD_CHANGE_TYPE: &str = "INITIAL_REBUILD";

fn nullable_json_i64(value: &serde_json::Value) -> Option<Option<i64>> {
    if value.is_null() {
        Some(None)
    } else {
        value.as_i64().map(Some)
    }
}

fn rule_set_projection_payload_is_valid(
    payload_json: Option<&str>,
    rule_set_id: i64,
    source_generation: i64,
    tenant_id: Option<i64>,
) -> bool {
    let Some(payload_json) = payload_json else {
        return false;
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(payload_json) else {
        return false;
    };
    let actor_valid = payload
        .get("actorId")
        .and_then(serde_json::Value::as_i64)
        .is_some_and(|actor_id| actor_id == SYSTEM_ACTOR_ID || actor_id > 0);
    let operation_valid = payload
        .get("operationId")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|operation_id| !operation_id.trim().is_empty());
    actor_valid
        && operation_valid
        && payload.get("ruleSetId").and_then(serde_json::Value::as_i64) == Some(rule_set_id)
        && payload
            .get("generation")
            .and_then(serde_json::Value::as_i64)
            == Some(source_generation)
        && payload.get("tenantId").and_then(nullable_json_i64) == Some(tenant_id)
}

async fn insert_initial_rule_set_projection_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: i64,
    projection: &astral_db::ProjectionEventIdentity,
    actor_id: i64,
    operation_id: &str,
) -> Result<(), AstralError> {
    if projection.tenant_id != Some(expected_tenant_id) {
        return Err(AstralError::Permission(
            "RuleSet projection tenant does not match __SUPERADMIN__ binding scope".into(),
        ));
    }
    let new_value = serde_json::json!({
        "reason": "INITIAL_REBUILD_FOR_CARD_RULE_SET_BINDING",
        "ruleSetId": rule_set_id,
        "tenantId": expected_tenant_id,
        "actorId": actor_id,
        "operationId": operation_id,
    })
    .to_string();
    sqlx::query(
        "INSERT INTO rule_set_projection_audit \\
         (rule_set_id, entry_id, changed_by, change_type, old_value_json, new_value_json, \\
          changed_at, tenant_id, aggregate_type, aggregate_id, event_id, source_generation, operation_id) \\
         VALUES (?, NULL, ?, ?, NULL, ?, UTC_TIMESTAMP(), ?, 'RULE_SET', ?, ?, ?, ?) \\
         ON DUPLICATE KEY UPDATE audit_id = audit_id",
    )
    .bind(rule_set_id)
    .bind(actor_id)
    .bind(RULE_SET_INITIAL_REBUILD_CHANGE_TYPE)
    .bind(new_value)
    .bind(expected_tenant_id)
    .bind(rule_set_id)
    .bind(&projection.event_id)
    .bind(projection.source_generation)
    .bind(operation_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!(
            "Insert initial RuleSet projection audit failed: {error}"
        ))
    })?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct RuleSetProjectionHeadRow {
    source_generation: i64,
    last_event_id: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct RuleSetProjectionEventRow {
    source_generation: i64,
    tenant_id: Option<i64>,
    event_type: String,
    payload_json: Option<String>,
    status: String,
}

fn rule_set_projection_event_type_is_supported(event_type: &str) -> bool {
    matches!(event_type, EVENT_TYPE_RULE_SET_UPDATE | EVENT_TYPE_REVOKE)
}

fn rule_set_projection_event_status_is_acceptable(status: &str) -> bool {
    matches!(status, "PENDING" | "PROCESSED")
}

/// Append the initial RuleSet proof event and its source audit marker.
async fn append_initial_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: i64,
    actor_id: i64,
    operation_id: &str,
) -> Result<(), AstralError> {
    let projection = append_rule_set_projection_in_tx(
        tx,
        rule_set_id,
        EVENT_TYPE_RULE_SET_UPDATE,
        astral_db::ProjectionEventMetadata {
            actor_id,
            operation_id,
        },
    )
    .await?;
    insert_initial_rule_set_projection_audit_in_tx(
        tx,
        rule_set_id,
        expected_tenant_id,
        &projection,
        actor_id,
        operation_id,
    )
    .await
}

fn rule_set_projection_event_is_valid(
    event: &RuleSetProjectionEventRow,
    rule_set_id: i64,
    source_generation: i64,
    expected_tenant_id: i64,
) -> bool {
    event.source_generation == source_generation
        && event.tenant_id == Some(expected_tenant_id)
        && rule_set_projection_event_type_is_supported(&event.event_type)
        && rule_set_projection_event_status_is_acceptable(&event.status)
        && rule_set_projection_payload_is_valid(
            event.payload_json.as_deref(),
            rule_set_id,
            source_generation,
            Some(expected_tenant_id),
        )
}

fn rule_set_projection_evidence_is_valid(event_is_valid: bool, source_audit_count: i64) -> bool {
    event_is_valid && source_audit_count > 0
}

/// Ensure a RuleSet binding has an independently provable RuleSet projection.
/// A valid current event with source evidence is sufficient (旧链 head READY
/// 与 REBUILD_SNAPSHOT 复核随迁移 20260831000001 退役)。返回值语义为
/// "证据已完备、无需补写"。
async fn ensure_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: i64,
    actor_id: i64,
    operation_id: &str,
) -> Result<bool, AstralError> {
    let head: Option<RuleSetProjectionHeadRow> = sqlx::query_as(
        "SELECT source_generation, last_event_id \\
         FROM authorization_projection_head \\
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Resolve RuleSet projection head failed: {error}"))
    })?;

    let Some(RuleSetProjectionHeadRow {
        source_generation,
        last_event_id,
    }) = head
    else {
        append_initial_rule_set_projection_in_tx(
            tx,
            rule_set_id,
            expected_tenant_id,
            actor_id,
            operation_id,
        )
        .await?;
        return Ok(false);
    };

    let Some(event_id) = last_event_id
        .as_deref()
        .map(str::trim)
        .filter(|event_id| !event_id.is_empty())
    else {
        append_initial_rule_set_projection_in_tx(
            tx,
            rule_set_id,
            expected_tenant_id,
            actor_id,
            operation_id,
        )
        .await?;
        return Ok(false);
    };

    let event: Option<RuleSetProjectionEventRow> = sqlx::query_as(
        "SELECT source_generation, tenant_id, event_type, payload_json, status \\
         FROM authorization_projection_outbox \\
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? AND event_id = ? \\
         FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Resolve RuleSet projection event failed: {error}"))
    })?;
    let event_is_valid = event.as_ref().is_some_and(|event| {
        rule_set_projection_event_is_valid(
            event,
            rule_set_id,
            source_generation,
            expected_tenant_id,
        )
    });
    if !event_is_valid {
        append_initial_rule_set_projection_in_tx(
            tx,
            rule_set_id,
            expected_tenant_id,
            actor_id,
            operation_id,
        )
        .await?;
        return Ok(false);
    }

    let source_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rule_set_projection_audit \\
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? \\
           AND event_id = ? AND source_generation = ? \\
           AND change_type <> 'REBUILD_SNAPSHOT' AND tenant_id <=> ?",
    )
    .bind(rule_set_id)
    .bind(event_id)
    .bind(source_generation)
    .bind(expected_tenant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Verify RuleSet source audit failed: {error}"))
    })?;
    // 旧链 REBUILD_SNAPSHOT 复核随 head READY 语义退役（迁移 20260831000001）：
    // 快照重建通道已下线，有效当前事件 + source 审计关联即为完备证明。
    if rule_set_projection_evidence_is_valid(event_is_valid, source_audit_count) {
        return Ok(true);
    }

    append_initial_rule_set_projection_in_tx(
        tx,
        rule_set_id,
        expected_tenant_id,
        actor_id,
        operation_id,
    )
    .await?;
    Ok(false)
}

/// 行查询列表达式（created_at/updated_at 使用 DATE_FORMAT 对齐既有 wire 格式）
const ADMIN_SELECT_COLUMNS: &str = "id, user_id, status, granted_by, granted_reason, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%s') AS created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%s') AS updated_at";

#[async_trait]
pub trait GlobalAdminRepository: Send + Sync {
    /// 列表（status 过滤可选，ORDER BY status, user_id, id）
    async fn list_admins(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<GlobalAdminRecord>, AstralError>;
    async fn count_active(&self) -> Result<i64, AstralError>;
    async fn count_all(&self) -> Result<i64, AstralError>;
    async fn get_by_user_id(&self, user_id: i64) -> Result<Option<GlobalAdminRecord>, AstralError>;
    async fn get_by_id(&self, id: i64) -> Result<Option<GlobalAdminRecord>, AstralError>;
    /// 用户是否为 ACTIVE 全局管理员（管理范围例外判定，对齐 Java GlobalAdminAccessPort.hasFullAccess）
    async fn is_active_admin(&self, user_id: i64) -> Result<bool, AstralError>;
    /// 授予并完成 SUPER_ADMIN 聚合发放：管理员行、特权卡、BASE 规则集绑定、
    /// `__SUPERADMIN__` RuleSet BASE 贡献的授权账本物化（grant revision + delta
    /// event）和 authorization projection head/outbox 必须在同一事务内提交。
    /// 幂等 enable：账本已 Active 的贡献跳过，不产生重复 Active 授权；disable
    /// 后的重新 enable 以严格 successor 复活既有 grant 身份。
    async fn grant_with_superadmin_privilege(
        &self,
        user_id: i64,
        granted_by: i64,
        reason: Option<&str>,
        template_id: i64,
        rule_set_id: i64,
    ) -> Result<GlobalAdminGrantOutcome, AstralError>;
    /// 原子禁用：仅当该用户为 ACTIVE 且库中存在其他 ACTIVE 管理员时成功。
    /// 受影响的 SUPER_ADMIN 卡 `__SUPERADMIN__` BASE 账本贡献必须在提交前获得
    /// 匹配的 REMOVE tombstone；账本贡献缺失时 fail-closed（不谎报撤销完成）。
    async fn disable_protected(
        &self,
        id: i64,
        user_id: i64,
        granted_by: i64,
        reason: Option<&str>,
    ) -> Result<DisableOutcome, AstralError>;
}

pub struct SqlxGlobalAdminRepository {
    db: MySqlPool,
}

impl SqlxGlobalAdminRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl GlobalAdminRepository for SqlxGlobalAdminRepository {
    async fn list_admins(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<GlobalAdminRecord>, AstralError> {
        match status {
            Some(s) => sqlx::query_as::<_, GlobalAdminRecord>(&format!(
                "SELECT {ADMIN_SELECT_COLUMNS} FROM identity_global_admin \
                 WHERE status = ? ORDER BY status ASC, user_id ASC, id ASC"
            ))
            .bind(s)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, GlobalAdminRecord>(&format!(
                "SELECT {ADMIN_SELECT_COLUMNS} FROM identity_global_admin \
                 ORDER BY status ASC, user_id ASC, id ASC"
            ))
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn count_active(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM identity_global_admin WHERE status = ?")
            .bind(STATUS_ACTIVE)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM identity_global_admin")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_by_user_id(&self, user_id: i64) -> Result<Option<GlobalAdminRecord>, AstralError> {
        sqlx::query_as::<_, GlobalAdminRecord>(&format!(
            "SELECT {ADMIN_SELECT_COLUMNS} FROM identity_global_admin WHERE user_id = ? LIMIT 1"
        ))
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<GlobalAdminRecord>, AstralError> {
        sqlx::query_as::<_, GlobalAdminRecord>(&format!(
            "SELECT {ADMIN_SELECT_COLUMNS} FROM identity_global_admin WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn is_active_admin(&self, user_id: i64) -> Result<bool, AstralError> {
        // 进程级短窗缓存（TTL 5s，取舍见 ACTIVE_ADMIN_CACHE_TTL/模块文档）：
        // 命中直接返回；miss/DB 错误回源权威查询，fail-closed 不变，错误绝不
        // 入缓存。
        if let Some(active) = fresh_active_admin_entry(user_id) {
            return Ok(active);
        }
        let active = astral_db::is_active_global_admin(&self.db, user_id)
            .await
            .map_err(db_error)?;
        store_active_admin_entry(user_id, active);
        Ok(active)
    }

    async fn grant_with_superadmin_privilege(
        &self,
        user_id: i64,
        granted_by: i64,
        reason: Option<&str>,
        template_id: i64,
        rule_set_id: i64,
    ) -> Result<GlobalAdminGrantOutcome, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;

        let template_scope: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT domain_id, tenant_id FROM user_card_template \
             WHERE template_id = ? AND template_code = '__SUPERADMIN__' AND status = 'ACTIVE' \
             FOR UPDATE",
        )
        .bind(template_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let (template_domain_id, template_tenant_id) = template_scope.ok_or_else(|| {
            AstralError::NotFound("__SUPERADMIN__ template scope is unavailable".into())
        })?;
        let domain_id = template_domain_id.ok_or_else(|| {
            AstralError::Database("__SUPERADMIN__ template domain_id is NULL".into())
        })?;
        let tenant_id = template_tenant_id.ok_or_else(|| {
            AstralError::Database("__SUPERADMIN__ template tenant_id is NULL".into())
        })?;

        let rule_set: Option<(String, i32, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT source_type, enabled, source_id, tenant_id FROM rule_set \
             WHERE rule_set_id = ? FOR UPDATE",
        )
        .bind(rule_set_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((source_type, enabled, source_id, rule_set_tenant_id)) = rule_set else {
            return Err(AstralError::NotFound(
                "__SUPERADMIN__ BASE rule set is not an enabled TEMPLATE source for the template"
                    .into(),
            ));
        };
        validate_superadmin_rule_set_scope(
            &source_type,
            enabled,
            source_id,
            template_id,
            rule_set_tenant_id,
            tenant_id,
        )?;

        let admin_id = if let Some((id,)) = sqlx::query_as::<_, (i64,)>(
            "SELECT id FROM identity_global_admin WHERE user_id = ? FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        {
            sqlx::query(
                "UPDATE identity_global_admin SET status = ?, granted_by = ?, \
                 granted_reason = ?, updated_at = NOW() WHERE id = ?",
            )
            .bind(STATUS_ACTIVE)
            .bind(granted_by)
            .bind(reason)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            id
        } else {
            let result = sqlx::query(
                "INSERT INTO identity_global_admin (user_id, status, granted_by, granted_reason) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(user_id)
            .bind(STATUS_ACTIVE)
            .bind(granted_by)
            .bind(reason)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            result.last_insert_id() as i64
        };

        let existing_card: Option<(i64, String, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT card_id, card_status, domain_id, tenant_id FROM user_card \
             WHERE user_id = ? AND template_id = ? AND card_type = 'SUPER_ADMIN' \
               AND card_status != 'DISABLED' ORDER BY card_id LIMIT 1 FOR UPDATE",
        )
        .bind(user_id)
        .bind(template_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;

        let (card_id, card_changed) = match existing_card {
            Some((card_id, status, current_domain_id, current_tenant_id)) => {
                let changed = status != STATUS_ACTIVE
                    || current_domain_id != Some(domain_id)
                    || current_tenant_id != Some(tenant_id);
                if changed {
                    sqlx::query(
                        "UPDATE user_card SET card_status = 'ACTIVE', domain_id = ?, tenant_id = ?, updated_at = NOW() \
                         WHERE card_id = ?",
                    )
                    .bind(domain_id)
                    .bind(tenant_id)
                    .bind(card_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_error)?;
                }
                (card_id, changed)
            }
            None => {
                let result = sqlx::query(
                    "INSERT INTO user_card \
                     (user_id, domain_id, card_type, card_status, template_id, level_id, priority, is_primary, tenant_id) \
                     VALUES (?, ?, 'SUPER_ADMIN', 'ACTIVE', ?, NULL, 0, 0, ?)",
                )
                .bind(user_id)
                .bind(domain_id)
                .bind(template_id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                (result.last_insert_id() as i64, true)
            }
        };

        // 绑定主键 id 是账本贡献 binding 身份（ref_id）的一等来源，必须捕获。
        let binding: Option<(i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT id, ref_type, tenant_id FROM card_rule_set_ref \
             WHERE card_id = ? AND rule_set_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .bind(rule_set_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let (ref_id, binding_changed) = match binding {
            Some((ref_id, ref_type, binding_tenant_id))
                if ref_type == "BASE" && binding_tenant_id == Some(tenant_id) =>
            {
                (ref_id, false)
            }
            Some((ref_id, _, _)) => {
                sqlx::query(
                    "UPDATE card_rule_set_ref SET ref_type = 'BASE', tenant_id = ? \
                     WHERE card_id = ? AND rule_set_id = ?",
                )
                .bind(tenant_id)
                .bind(card_id)
                .bind(rule_set_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                (ref_id, true)
            }
            None => {
                let result = sqlx::query(
                    "INSERT INTO card_rule_set_ref \
                     (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, 'BASE', ?)",
                )
                .bind(card_id)
                .bind(rule_set_id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                (result.last_insert_id() as i64, true)
            }
        };

        let operation_id = superadmin_grant_operation_id(user_id, card_id, rule_set_id);
        let rule_set_projection_ready = ensure_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            tenant_id,
            granted_by,
            &operation_id,
        )
        .await?;
        let actor_user_id = superadmin_ledger_actor(granted_by)?;

        // 锁定读取启用条目并预分类账本动作（head FOR UPDATE）：head 已 Active 的
        // 贡献跳过（幂等 enable 不重复物化），缺失/tombstone 的收集为待写贡献。
        let entries = load_superadmin_rule_set_entries_in_tx(&mut tx, rule_set_id, true).await?;
        let mut pending_contributions: Vec<(
            RuleSetEntryLedgerFacts<'_>,
            Option<astral_db::GrantHeadSnapshot>,
        )> = Vec::new();
        for entry in &entries {
            if !superadmin_entry_is_materializable_allow(&entry.effect)? {
                continue;
            }
            let facts = superadmin_entry_facts(
                rule_set_id,
                tenant_id,
                Some(domain_id),
                card_id,
                user_id,
                ref_id,
                entry,
            )?;
            let grant_id = derive_ruleset_identity(&facts)?;
            let ledger_head = astral_db::read_grant_head_for_update_in_tx(
                &mut tx,
                tenant_id,
                RULE_SET_AGGREGATE_TYPE,
                rule_set_id,
                grant_id,
            )
            .await
            .map_err(map_grant_repository_error)?;
            if grant_ledger_action(ledger_head.as_ref().map(|head| head.entry.state))
                == GrantLedgerAction::Skip
            {
                continue;
            }
            pending_contributions.push((facts, ledger_head));
        }
        let needs_ledger_writes = !pending_contributions.is_empty();

        // 旧链 CARD head READY 门禁已随迁移 20260831000001 退役（CARD/RULE_SET
        // 投影消费权威在新链 delta 队列，head 只保留 writer correlation）。
        // 语义收敛：本次调用有任何变更或账本贡献待写 → 追加 CARD parent +
        // ELIGIBILITY 事件并返回显式 pending；完全无变更且证据已完备 → READY。
        let projection_ready =
            rule_set_projection_ready && !card_changed && !binding_changed && !needs_ledger_writes;
        if !projection_ready {
            // 卡状态/tenant/domain 变更同步影响资格，与 CARD 事件同事务落
            // ELIGIBILITY 事件（superadmin 卡资格缓存失效，防 stale-ALLOW）。
            // CARD parent 携带 actor/operation metadata，作为账本贡献的
            // generation/fence 锚（与 legacy 同一写入路径）。
            let parent = append_card_projection_with_metadata_in_tx(
                &mut tx,
                card_id,
                "SUPER_ADMIN_GRANTED",
                astral_db::ProjectionEventMetadata {
                    actor_id: granted_by,
                    operation_id: &operation_id,
                },
            )
            .await?;
            append_eligibility_projection_in_tx(&mut tx, card_id).await?;
            for (facts, ledger_head) in &pending_contributions {
                match grant_ledger_action(ledger_head.as_ref().map(|head| head.entry.state)) {
                    GrantLedgerAction::Skip => continue,
                    GrantLedgerAction::FreshAdd => {
                        let contribution_event_id = derive_ruleset_contribution_event_id(
                            &operation_id,
                            facts,
                            RuleSetMutationKind::Add,
                        )?;
                        let draft = build_ruleset_add_draft(
                            facts,
                            &operation_id,
                            actor_user_id,
                            &parent,
                            &contribution_event_id,
                        )?;
                        let (base_version, target_version) = astral_db::next_delta_version(None)
                            .map_err(map_grant_repository_error)?;
                        append_ruleset_grant_delta_in_tx(
                            &mut tx,
                            &draft,
                            base_version,
                            target_version,
                        )
                        .await?;
                    }
                    GrantLedgerAction::Resurrect => {
                        let ledger_head = ledger_head.as_ref().ok_or_else(|| {
                            AstralError::Internal(
                                "__SUPERADMIN__ resurrection requires a locked ledger head".into(),
                            )
                        })?;
                        let operation_id = revision_bound_operation_id(
                            &operation_id,
                            ledger_head.entry.revision.value(),
                        );
                        let contribution_event_id = derive_ruleset_contribution_event_id(
                            &operation_id,
                            facts,
                            RuleSetMutationKind::Add,
                        )?;
                        let last_target =
                            astral_db::read_latest_delta_target_version_for_update_in_tx(
                                &mut tx,
                                tenant_id,
                                RULE_SET_AGGREGATE_TYPE,
                                rule_set_id,
                                ledger_head.grant_id,
                            )
                            .await
                            .map_err(map_grant_repository_error)?;
                        let (base_version, target_version) =
                            astral_db::next_delta_version(last_target)
                                .map_err(map_grant_repository_error)?;
                        append_ruleset_resurrection_add_in_tx(
                            &mut tx,
                            ledger_head,
                            facts,
                            &operation_id,
                            actor_user_id,
                            &parent,
                            &contribution_event_id,
                            base_version,
                            target_version,
                        )
                        .await?;
                    }
                }
            }
        }

        tx.commit().await.map_err(db_error)?;
        // is_active_admin 进程缓存 evict 钩子：授权 mutation 提交成功后本进程
        // 立即失效（跨实例由 TTL 兜底，取舍见 ACTIVE_ADMIN_CACHE_TTL）。
        evict_active_admin_entry(user_id);
        Ok(GlobalAdminGrantOutcome {
            admin_id,
            card_id,
            projection_ready,
        })
    }

    async fn disable_protected(
        &self,
        id: i64,
        user_id: i64,
        granted_by: i64,
        reason: Option<&str>,
    ) -> Result<DisableOutcome, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // 锁定全部活跃管理员行（对齐 Java `IdentityGlobalAdminMapper.selectActiveForUpdate()`）。
        // FOR UPDATE 是当前读：并发 disable A/B 时，后到事务阻塞在先到事务提交后重读最新
        // 状态，消除原 EXISTS 派生表快照读的 TOCTOU（双方各见对方活跃 → 双双通过 → 零活跃）。
        let active_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT user_id FROM identity_global_admin WHERE status = ? ORDER BY id FOR UPDATE",
        )
        .bind(STATUS_ACTIVE)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        // 仅剩本行一个活跃管理员 → 受保护（对齐 Java LAST_GLOBAL_ADMIN_PROTECTED）
        if active_ids.len() <= 1 && active_ids.first() == Some(&user_id) {
            tx.rollback().await.map_err(db_error)?;
            return Ok(DisableOutcome::LastAdminProtected);
        }
        // 目标已不在活跃集合（并发下被他人禁用）→ 按 0 行命中分类
        if !active_ids.contains(&user_id) {
            tx.rollback().await.map_err(db_error)?;
            return Ok(classify_disable_outcome(0, active_ids.len() as i64));
        }
        // 在同一 source transaction 内锁定并失活 SUPER_ADMIN 卡，随后追加 REVOKE
        // projection。管理员状态若已提交而特权卡仍 ACTIVE，会形成权限旁路。
        // tenant/domain/template 用于 __SUPERADMIN__ BASE 贡献的账本撤销身份。
        let superadmin_cards: Vec<(i64, Option<i64>, Option<i64>, i64)> = sqlx::query_as(
            "SELECT card_id, tenant_id, domain_id, template_id FROM user_card \
             WHERE user_id = ? AND card_type = 'SUPER_ADMIN' AND card_status = 'ACTIVE' FOR UPDATE",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        let result = sqlx::query(
            "UPDATE identity_global_admin \
             SET status = ?, granted_by = ?, granted_reason = ?, updated_at = NOW() \
             WHERE id = ? AND user_id = ? AND status = ?",
        )
        .bind(STATUS_DISABLED)
        .bind(granted_by)
        .bind(reason)
        .bind(id)
        .bind(user_id)
        .bind(STATUS_ACTIVE)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        if result.rows_affected() == 0 {
            tx.rollback().await.map_err(db_error)?;
            let active_count = self.count_active().await?;
            return Ok(classify_disable_outcome(0, active_count));
        }
        for (card_id, card_tenant_id, card_domain_id, template_id) in superadmin_cards {
            // D1 次序：先在账本为 Active 的 __SUPERADMIN__ BASE 贡献物化 REMOVE
            // tombstone（含 CARD REVOKE 投影锚，head 缺失 fail-closed），再失活
            // source 卡行，最后补 ELIGIBILITY 与 SUPERADMIN_DISABLE 关联审计行
            // —— 全部同事务，任一失败整体回滚（权限回收必须有审计证据）。
            revoke_superadmin_rule_set_contributions_in_tx(
                &mut tx,
                id,
                card_id,
                user_id,
                card_tenant_id,
                card_domain_id,
                template_id,
                granted_by,
            )
            .await?;
            sqlx::query(
                "UPDATE user_card SET card_status = 'DISABLED' \
                 WHERE card_id = ? AND card_status = 'ACTIVE'",
            )
            .bind(card_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            // 卡状态离开 ACTIVE 同步影响资格，同事务落 ELIGIBILITY 事件。
            append_eligibility_projection_in_tx(&mut tx, card_id).await?;
        }
        tx.commit().await.map_err(db_error)?;
        // is_active_admin 进程缓存 evict 钩子：禁用提交成功后本进程立即失效
        // （跨实例由 TTL 兜底，取舍见 ACTIVE_ADMIN_CACHE_TTL）。
        evict_active_admin_entry(user_id);
        Ok(DisableOutcome::Disabled)
    }
}

/// 根据 UPDATE 影响行数与活跃管理员数量判定禁用结果（纯逻辑，可单测）。
///
/// - UPDATE 命中 → 已禁用
/// - 未命中且活跃管理员 ≤1 → 最后一位活跃管理员受保护
/// - 未命中且活跃管理员 >1 → 并发竞态等异常
fn classify_disable_outcome(rows_affected: u64, active_count: i64) -> DisableOutcome {
    if rows_affected > 0 {
        return DisableOutcome::Disabled;
    }
    if active_count <= 1 {
        DisableOutcome::LastAdminProtected
    } else {
        DisableOutcome::UpdateFailed
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Global admin repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_outcome_classifies_success() {
        assert_eq!(classify_disable_outcome(1, 3), DisableOutcome::Disabled);
        assert_eq!(classify_disable_outcome(1, 0), DisableOutcome::Disabled);
    }

    #[test]
    fn disable_outcome_classifies_last_admin_protected() {
        // UPDATE 未命中且活跃管理员 ≤1 → 最后一位活跃管理员受保护
        assert_eq!(
            classify_disable_outcome(0, 0),
            DisableOutcome::LastAdminProtected
        );
        assert_eq!(
            classify_disable_outcome(0, 1),
            DisableOutcome::LastAdminProtected
        );
    }

    #[test]
    fn disable_outcome_classifies_update_failed_on_race() {
        // UPDATE 未命中但存在其他活跃管理员 → 并发竞态
        assert_eq!(classify_disable_outcome(0, 2), DisableOutcome::UpdateFailed);
    }

    #[test]
    fn superadmin_rule_set_requires_matching_enabled_template_source() {
        let error =
            validate_superadmin_rule_set_scope("MANUAL", 1, Some(7), 7, Some(11), 11).unwrap_err();
        assert!(
            matches!(error, AstralError::NotFound(message) if message.contains("TEMPLATE source"))
        );

        let error = validate_superadmin_rule_set_scope("TEMPLATE", 0, Some(7), 7, Some(11), 11)
            .unwrap_err();
        assert!(
            matches!(error, AstralError::NotFound(message) if message.contains("TEMPLATE source"))
        );
    }

    #[test]
    fn superadmin_rule_set_requires_template_tenant_match() {
        let error = validate_superadmin_rule_set_scope("TEMPLATE", 1, Some(7), 7, Some(12), 11)
            .unwrap_err();
        assert!(matches!(error, AstralError::Permission(message) if message.contains("tenant_id")));
    }

    #[test]
    fn ruleset_projection_event_identity_accepts_update_and_revoke() {
        let payload = serde_json::json!({
            "actorId": SYSTEM_ACTOR_ID,
            "operationId": "global-admin:test",
            "ruleSetId": 9,
            "generation": 3,
            "tenantId": 7,
        })
        .to_string();
        let event = RuleSetProjectionEventRow {
            source_generation: 3,
            tenant_id: Some(7),
            event_type: EVENT_TYPE_RULE_SET_UPDATE.into(),
            payload_json: Some(payload),
            status: "PENDING".into(),
        };
        assert!(rule_set_projection_event_is_valid(&event, 9, 3, 7));

        let mut processed = event.clone();
        processed.status = "PROCESSED".into();
        assert!(rule_set_projection_event_is_valid(&processed, 9, 3, 7));

        let mut revoke = event.clone();
        revoke.event_type = EVENT_TYPE_REVOKE.into();
        assert!(rule_set_projection_event_is_valid(&revoke, 9, 3, 7));

        let mut invalid = event.clone();
        invalid.status = "FAILED".into();
        assert!(!rule_set_projection_event_is_valid(&invalid, 9, 3, 7));
        invalid = event;
        invalid.tenant_id = Some(8);
        assert!(!rule_set_projection_event_is_valid(&invalid, 9, 3, 7));
    }

    #[test]
    fn ruleset_projection_proof_does_not_requeue_valid_pending_event() {
        // A valid current event with source audit is enough during the worker
        // window; callers remain not-ready without another generation.
        assert!(rule_set_projection_evidence_is_valid(true, 1));
        assert!(!rule_set_projection_evidence_is_valid(true, 0));
        assert!(!rule_set_projection_evidence_is_valid(false, 1));
    }

    fn superadmin_entry(
        effect: &str,
        resource: Option<&str>,
        action: Option<&str>,
    ) -> SuperadminRuleSetEntryRow {
        SuperadminRuleSetEntryRow {
            entry_id: 31,
            effect: effect.to_owned(),
            resource_type: resource.map(str::to_owned),
            resource_id: Some(77),
            action_code: action.map(str::to_owned),
            condition_json: None,
            valid_from: None,
            valid_to: None,
        }
    }

    #[test]
    fn superadmin_entry_effect_classification_matches_ruleset_semantics() {
        assert!(superadmin_entry_is_materializable_allow("ALLOW").unwrap());
        assert!(superadmin_entry_is_materializable_allow(" allow ").unwrap());
        assert!(!superadmin_entry_is_materializable_allow("DENY").unwrap());
        // 小写 drift 与 rule_set 侧分类一致：DENY 不是 canonical ALLOW。
        assert!(!superadmin_entry_is_materializable_allow("deny").unwrap());
        let error = superadmin_entry_is_materializable_allow("MAYBE").unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(ref message) if message.contains("unknown effect")),
            "unknown effect must fail closed: {error:?}"
        );
    }

    #[test]
    fn superadmin_canonical_fields_require_nonempty_resource_and_action() {
        let entry = superadmin_entry("ALLOW", Some(" learn_course "), Some("read"));
        let (resource, action) = superadmin_entry_canonical_fields(&entry).unwrap();
        assert_eq!(resource, "learn_course");
        assert_eq!(action, "read");

        for invalid in [
            superadmin_entry("ALLOW", Some("  "), Some("read")),
            superadmin_entry("ALLOW", None, Some("read")),
            superadmin_entry("ALLOW", Some("learn_course"), Some(" ")),
            superadmin_entry("ALLOW", Some("learn_course"), None),
        ] {
            let error = superadmin_entry_canonical_fields(&invalid).unwrap_err();
            assert!(
                matches!(error, AstralError::Validation(ref message) if message.contains("31")),
                "entry 31 must fail closed with its identity: {error:?}"
            );
        }
    }

    #[test]
    fn superadmin_entry_facts_bind_identity_and_base_layer() {
        let entry = superadmin_entry("ALLOW", Some("learn_course"), Some("read"));
        let facts = superadmin_entry_facts(9, 7, Some(11), 21, 42, 5, &entry).unwrap();
        assert_eq!(facts.tenant_id, 7);
        assert_eq!(facts.domain_id, Some(11));
        assert_eq!(facts.card_id, 21);
        assert_eq!(facts.user_id, 42);
        assert_eq!(facts.rule_set_id, 9);
        assert_eq!(facts.entry_id, 31);
        assert_eq!(facts.ref_id, 5);
        assert_eq!(facts.ref_type, "BASE");
        assert_eq!(facts.resource, "learn_course");
        assert_eq!(facts.resource_id, Some(77));
        assert_eq!(facts.action, "read");
        assert!(facts.condition_json.is_none());
        // 同一稳定维度必须派生同一 grant 身份（可重放，无随机成分）。
        let again = superadmin_entry_facts(9, 7, Some(11), 21, 42, 5, &entry).unwrap();
        assert_eq!(
            derive_ruleset_identity(&facts).unwrap().to_string(),
            derive_ruleset_identity(&again).unwrap().to_string()
        );
    }

    #[test]
    fn superadmin_ledger_actor_maps_system_actor_and_rejects_others() {
        assert_eq!(superadmin_ledger_actor(SYSTEM_ACTOR_ID).unwrap(), None);
        assert_eq!(superadmin_ledger_actor(5).unwrap(), Some(5));
        let error = superadmin_ledger_actor(0).unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
        let error = superadmin_ledger_actor(-2).unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    #[test]
    fn grant_ledger_action_is_idempotent_for_active_heads() {
        assert_eq!(grant_ledger_action(None), GrantLedgerAction::FreshAdd);
        assert_eq!(
            grant_ledger_action(Some(GrantState::Active)),
            GrantLedgerAction::Skip
        );
        // tombstone 与其他非 Active 状态都需要新的贡献写入（复活/合同裁决）。
        assert_eq!(
            grant_ledger_action(Some(GrantState::Removed)),
            GrantLedgerAction::Resurrect
        );
        assert_eq!(
            grant_ledger_action(Some(GrantState::Revoked)),
            GrantLedgerAction::Resurrect
        );
    }

    #[test]
    fn disable_ledger_action_skips_only_existing_tombstones() {
        assert!(disable_entry_needs_remove(GrantState::Active));
        // 撤销证据已在账本（Removed/Revoked）→ 跳过，不重复 tombstone。
        assert!(!disable_entry_needs_remove(GrantState::Removed));
        assert!(!disable_entry_needs_remove(GrantState::Revoked));
        // 其余状态交由账本 transition 规则 fail-closed，不静默放行。
        assert!(disable_entry_needs_remove(GrantState::Pending));
        assert!(disable_entry_needs_remove(GrantState::Expired));
        assert!(disable_entry_needs_remove(GrantState::Archived));
    }

    #[test]
    fn superadmin_operation_ids_are_stable_and_revision_bound() {
        let base = superadmin_grant_operation_id(42, 21, 9);
        assert_eq!(base, "global-admin:grant:42:21:9");
        assert_eq!(superadmin_grant_operation_id(42, 21, 9), base);

        // 同业务重试（同 revision）重放同一 id；revision 推进后必然分叉。
        let bound = revision_bound_operation_id(&base, 3);
        assert_eq!(bound, "global-admin:grant:42:21:9:r3");
        assert_eq!(revision_bound_operation_id(&base, 3), bound);
        assert_ne!(revision_bound_operation_id(&base, 4), bound);

        let disable = superadmin_disable_operation_id(5, 21, 2);
        assert_eq!(disable, "global-admin:disable:5:card:21:r2");
        assert_eq!(superadmin_disable_operation_id(5, 21, 2), disable);
        assert_ne!(superadmin_disable_operation_id(5, 21, 3), disable);
        assert_ne!(superadmin_disable_operation_id(6, 21, 2), disable);
        // 派生 id 必须保持在审计/事件列宽内（canonical 上限 64/128 字节）。
        assert!(
            disable.len() < crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH
        );
    }

    // ===== is_active_admin 进程缓存 =====

    /// TTL 边界（纯逻辑，对齐 cache_epoch 的新鲜度边界语义）：恰好到达 TTL
    /// 即不新鲜。
    #[test]
    fn active_admin_entry_freshness_honors_ttl_boundary() {
        let cached_at = Instant::now();
        assert!(active_admin_entry_is_fresh(cached_at, cached_at));
        assert!(active_admin_entry_is_fresh(
            cached_at,
            cached_at + ACTIVE_ADMIN_CACHE_TTL - Duration::from_secs(1)
        ));
        assert!(!active_admin_entry_is_fresh(
            cached_at,
            cached_at + ACTIVE_ADMIN_CACHE_TTL
        ));
        assert!(!active_admin_entry_is_fresh(
            cached_at,
            cached_at + ACTIVE_ADMIN_CACHE_TTL + Duration::from_secs(1)
        ));
    }

    /// TTL 常量钉死（5s 短窗口，撤销生效延迟上界 = TTL，取舍见常量文档）。
    #[test]
    fn active_admin_cache_ttl_stays_bounded() {
        assert_eq!(ACTIVE_ADMIN_CACHE_TTL, Duration::from_secs(5));
        assert!(ACTIVE_ADMIN_CACHE_TTL <= Duration::from_secs(60));
    }

    /// 进程缓存往返 + evict：TTL 内命中同值（true/false 均可缓存）；evict 后
    /// 立即 miss（grant/disable 提交成功后的失效语义）；过期条目视为 miss。
    #[test]
    fn active_admin_cache_roundtrip_then_evict() {
        // 独占本测试使用的键，避免与并行测试共享全局 map 互扰。
        let user_id = i64::from_be_bytes(*b"gacache1");

        // 先清掉本键可能的历史状态。
        evict_active_admin_entry(user_id);
        assert!(fresh_active_admin_entry(user_id).is_none());

        // true / false 均可缓存并在 TTL 内命中。
        store_active_admin_entry(user_id, true);
        assert_eq!(fresh_active_admin_entry(user_id), Some(true));
        store_active_admin_entry(user_id, false);
        assert_eq!(fresh_active_admin_entry(user_id), Some(false));

        // evict 后立即 miss（下次读回源权威查询）。
        evict_active_admin_entry(user_id);
        assert!(fresh_active_admin_entry(user_id).is_none());

        // 回拨填充时刻构造过期条目 → 视为 miss。
        active_admin_cache()
            .write()
            .unwrap()
            .insert(user_id, (true, Instant::now() - Duration::from_secs(6)));
        assert!(
            fresh_active_admin_entry(user_id).is_none(),
            "expired entries must never be served"
        );
        evict_active_admin_entry(user_id);
    }
}
