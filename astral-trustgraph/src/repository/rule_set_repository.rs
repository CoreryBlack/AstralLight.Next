//! 规则集数据访问 — RuleSetRepository
//!
//! 对齐 Java `RuleSetService` 的 Mapper 边界（rule_set / rule_set_entry /
//! card_rule_set_ref 表）。列表的 entry_count / bound_card_count 采用批量
//! 预加载（GROUP BY ... IN (...)），消除逐行 N+1 查询，输出语义不变。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_types::{
    AstralError, ProjectionAggregate, EVENT_TYPE_REVOKE, EVENT_TYPE_RULE_SET_UPDATE,
    SYSTEM_ACTOR_ID,
};

use crate::repository::audit_log_repository::{
    insert_rule_set_projection_audit_in_tx, RuleSetMutationContext, RuleSetProjectionAuditEntry,
};
use crate::repository::grant_ledger_adapter::{
    append_ruleset_grant_delta_in_tx, build_ruleset_add_draft, build_ruleset_remove_draft,
    build_ruleset_update_draft, derive_ruleset_contribution_event_id, derive_ruleset_identity,
    map_grant_repository_error, ruleset_update_authorization_content_changed,
    RuleSetEntryLedgerFacts, RuleSetMutationKind, RULE_SET_AGGREGATE_TYPE,
};
use crate::repository::projection_repository::{
    append_card_projection_in_tx, append_card_projection_with_metadata_in_tx,
    append_rule_set_projection_in_tx, append_rule_set_projection_with_tenant_in_tx,
};
use crate::service::rule_set_write_service::validate_entry_fields;

/// 规则集摘要（列表/详情用，含条目数与绑定卡数）
#[derive(Debug, Clone)]
pub struct RuleSetSummary {
    pub id: i64,
    pub name: String,
    pub ref_type: String,
    pub description: Option<String>,
    pub entry_count: i64,
    pub bound_card_count: i64,
}

/// 规则集基础行（rule_set，通过 SQL 别名映射）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleSetRow {
    pub id: i64,
    pub name: String,
    pub ref_type: String,
    pub description: Option<String>,
}

/// 规则集条目（rule_set_entry）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleSetEntryRow {
    pub entry_id: i64,
    pub effect: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,
    pub action_code: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
}

/// 卡片规则集绑定（card_rule_set_ref + rule_set 展示字段）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CardRuleSetBindingRow {
    pub rule_set_id: i64,
    pub rule_set_name: String,
    pub rule_set_code: String,
    pub ref_type: String,
}

/// 新建规则集参数
///
/// `ref_type` 是写入 `rule_set.source_type` 的所有权判别器：generic create 只能
/// 创建自定义所有权；空值与 `TEMPLATE`（模板投影路径专属）在 INSERT 前 fail-closed。
#[derive(Debug)]
pub struct NewRuleSet {
    pub name: String,
    pub ref_type: String,
    pub description: Option<String>,
}

/// 规则集更新补丁（generic update 只允许变更 name/description）
///
/// source_type 是所有权判别器，generic update 不可变：本结构体刻意不携带
/// ref_type/source_type 字段，使所有权改写在类型层面不可表达。wire DTO 仍接受
/// `refType`，但 HTTP adapter 不再把它转发为变更字段。
#[derive(Debug)]
pub struct RuleSetPatch {
    pub name: String,
    pub description: Option<String>,
}

/// 新建条目参数
#[derive(Debug)]
pub struct NewRuleSetEntry {
    pub effect: String,
    pub resource: Option<String>,
    pub resource_id: Option<i64>,
    pub action: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
}

/// 条目更新补丁
#[derive(Debug)]
pub struct RuleSetEntryPatch {
    pub effect: String,
    pub resource: Option<String>,
    pub resource_id: Option<i64>,
    pub action: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
}

const RULE_SET_SELECT: &str = "rule_set_id as id, name, source_type as ref_type, description";
const ENTRY_SELECT: &str =
    "entry_id, effect, resource_type, resource_id, action_code, condition_json, priority";

#[async_trait]
pub trait RuleSetRepository: Send + Sync {
    /// 全量总数
    async fn count_rule_sets(&self) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY rule_set_id）
    async fn list_rule_sets(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuleSetSummary>, AstralError>;
    async fn get_rule_set(&self, rule_set_id: i64) -> Result<Option<RuleSetSummary>, AstralError>;
    /// 新建，返回新 rule_set_id（code 取 name 作为默认值，对齐现有 handler）
    async fn create_rule_set(
        &self,
        new: &NewRuleSet,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError>;
    /// 更新规则集。source_type 是所有权判别器，generic update 不可变：patch 只
    /// 携带 name/description；无实际变更时不写投影/审计。返回前 context 已被
    /// 升级为可证明稳定 operation identity（缺失 request id 时按锁定代次派生）。
    async fn update_rule_set(
        &self,
        rule_set_id: i64,
        patch: &RuleSetPatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// 删除规则集（card_rule_set_ref / rule_set_entry 由 FK 级联或显式清理）。
    /// `Ok(false)` 仅表示事务开始时 source 行不存在（未写任何 durable 状态）；
    /// 锁定捕获后 DELETE 命中 0 行属于不变式破坏，整体回滚并以错误失败。
    async fn delete_rule_set(
        &self,
        rule_set_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError>;
    /// 规则集条目列表（ORDER BY priority）
    async fn list_entries(&self, rule_set_id: i64) -> Result<Vec<RuleSetEntryRow>, AstralError>;
    /// 新建条目，返回新 entry_id
    async fn add_entry(
        &self,
        rule_set_id: i64,
        new: &NewRuleSetEntry,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError>;
    async fn update_entry(
        &self,
        rule_set_id: i64,
        entry_id: i64,
        patch: &RuleSetEntryPatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// 删除条目，返回是否命中
    async fn delete_entry(
        &self,
        rule_set_id: i64,
        entry_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError>;
    /// 全量替换规则集条目：同一事务内先按 D1 语义为全部旧 enabled+ALLOW 贡献写
    /// 版本化 REMOVE（capture-before-delete），完成 source 删除/插入后为新条目
    /// 物化 ADD，最后以 parent RULE_SET 投影 + 新旧双向关联审计收口。
    async fn replace_entries(
        &self,
        rule_set_id: i64,
        entries: &[NewRuleSetEntry],
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// 查询卡片绑定的规则集。
    async fn list_card_bindings(
        &self,
        card_id: i64,
    ) -> Result<Vec<CardRuleSetBindingRow>, AstralError>;
    /// 绑定卡（card_rule_set_ref）
    async fn bind_card(
        &self,
        card_id: i64,
        rule_set_id: i64,
        ref_type: &str,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// 解绑卡，返回是否命中
    async fn unbind_card(
        &self,
        card_id: i64,
        rule_set_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError>;
    /// 模板类规则集总数（name 含 admin/Template）
    async fn count_templates(&self) -> Result<i64, AstralError>;
    /// 模板类规则集分页列表（name 含 admin/Template）
    async fn list_templates(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuleSetSummary>, AstralError>;
    /// 从模板投影规则集（对齐 Java `RuleSetService.createRuleSetFromTemplate`）。
    ///
    /// 单事务：`rule_set`（code 幂等，source_type='TEMPLATE'，source_id=template_id）→
    /// 从 `permission_rule_template` 全量同步 `rule_set_entry` → 追加 RULE_SET
    /// projection，并为绑定卡追加 CARD projection。共享快照由 durable worker
    /// 在提交后重建；此写路径不直接写 `rule_set_snapshot`。
    /// code 已存在（如 `__SUPERADMIN__`）→ 幂等返回现有 rule_set_id，并重新投影。
    async fn create_rule_set_from_template(
        &self,
        template_id: i64,
        code: &str,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError>;
}

pub struct SqlxRuleSetRepository {
    db: MySqlPool,
}

impl SqlxRuleSetRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 汇总（entry_count + bound_card_count）：
/// 对 id 列表批量取 COUNT（GROUP BY ... IN (...)），消除 N+1。
async fn summarize(
    db: &MySqlPool,
    rows: Vec<RuleSetRow>,
) -> Result<Vec<RuleSetSummary>, AstralError> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();

    let mut entry_builder = QueryBuilder::<sqlx::MySql>::new(
        "SELECT rule_set_id, COUNT(*) FROM rule_set_entry WHERE rule_set_id IN (",
    );
    let mut sep = "";
    for id in &ids {
        entry_builder.push(sep).push_bind(*id);
        sep = ", ";
    }
    entry_builder.push(") GROUP BY rule_set_id");
    let entry_counts: Vec<(i64, i64)> = entry_builder
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(db_error)?;

    let mut ref_builder = QueryBuilder::<sqlx::MySql>::new(
        "SELECT rule_set_id, COUNT(DISTINCT card_id) FROM card_rule_set_ref WHERE rule_set_id IN (",
    );
    let mut sep = "";
    for id in &ids {
        ref_builder.push(sep).push_bind(*id);
        sep = ", ";
    }
    ref_builder.push(") GROUP BY rule_set_id");
    let ref_counts: Vec<(i64, i64)> = ref_builder
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(db_error)?;

    let entry_map: std::collections::HashMap<i64, i64> = entry_counts.into_iter().collect();
    let ref_map: std::collections::HashMap<i64, i64> = ref_counts.into_iter().collect();

    Ok(rows
        .into_iter()
        .map(|r| RuleSetSummary {
            id: r.id,
            name: r.name,
            ref_type: r.ref_type,
            description: r.description,
            entry_count: entry_map.get(&r.id).copied().unwrap_or(0),
            bound_card_count: ref_map.get(&r.id).copied().unwrap_or(0),
        })
        .collect())
}

const RULE_SET_INITIAL_REBUILD_CHANGE_TYPE: &str = "INITIAL_REBUILD";

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

/// A current RuleSet projection event may be an update or a revoke. `REVOKE`
/// is not limited to deleting a RuleSet: deny-entry and binding-removal source
/// mutations deliberately use it while the RuleSet snapshot remains valid.
/// This validator preserves those current source-event semantics.
fn rule_set_projection_event_is_valid(
    event: &RuleSetProjectionEventRow,
    rule_set_id: i64,
    source_generation: i64,
    expected_tenant_id: Option<i64>,
) -> bool {
    event.source_generation == source_generation
        && event.tenant_id == expected_tenant_id
        && rule_set_projection_event_type_is_supported(&event.event_type)
        && rule_set_projection_event_status_is_acceptable(&event.status)
        && rule_set_projection_payload_is_valid(
            event.payload_json.as_deref(),
            rule_set_id,
            source_generation,
            expected_tenant_id,
        )
}

fn rule_set_projection_evidence_is_valid(event_is_valid: bool, source_audit_count: i64) -> bool {
    event_is_valid && source_audit_count > 0
}

async fn append_initial_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: Option<i64>,
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
    if projection.tenant_id != expected_tenant_id {
        return Err(AstralError::Permission(
            "RuleSet projection tenant does not match card binding scope".into(),
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
    insert_rule_set_projection_audit_in_tx(
        tx,
        &RuleSetProjectionAuditEntry {
            rule_set_id,
            entry_id: None,
            aggregate_type: ProjectionAggregate::RuleSet.as_str(),
            aggregate_id: rule_set_id,
            event_id: &projection.event_id,
            source_generation: projection.source_generation,
            operation_id,
            actor_id,
            change_type: RULE_SET_INITIAL_REBUILD_CHANGE_TYPE,
            old_value_json: None,
            new_value_json: Some(&new_value),
            tenant_id: expected_tenant_id,
        },
    )
    .await
}

/// Ensure a referenced RuleSet has the same durable initial proof used by
/// starter/global-admin card creation. Only a missing or inconsistent proof
/// appends a RULE_SET event; a normal card bind never mutates rule_set source.
/// 旧链 head READY 语义已随迁移 20260831000001 退役：有效当前事件 + source
/// 审计关联即足以证明初始投影，返回值语义为"证据已完备、无需补写"。
pub(crate) async fn ensure_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: Option<i64>,
    actor_id: i64,
    operation_id: &str,
) -> Result<bool, AstralError> {
    let head: Option<RuleSetProjectionHeadRow> = sqlx::query_as(
        "SELECT source_generation, last_event_id \
         FROM authorization_projection_head \
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
        "SELECT source_generation, tenant_id, event_type, payload_json, status \
         FROM authorization_projection_outbox \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? AND event_id = ? \
         FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Resolve RuleSet projection event failed: {error}"))
    })?;
    let event_valid = event.as_ref().is_some_and(|event| {
        rule_set_projection_event_is_valid(
            event,
            rule_set_id,
            source_generation,
            expected_tenant_id,
        )
    });
    if !event_valid {
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
        "SELECT COUNT(*) FROM rule_set_projection_audit \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? \
           AND event_id = ? AND source_generation = ? \
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
    if rule_set_projection_evidence_is_valid(event_valid, source_audit_count) {
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

async fn append_bound_card_projections_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    event_type: &str,
) -> Result<(), AstralError> {
    let card_ids: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT card_id FROM card_rule_set_ref WHERE rule_set_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    for card_id in card_ids {
        append_card_projection_in_tx(tx, card_id, event_type).await?;
    }
    Ok(())
}

/// 锁定规则集 source row，确保条目 mutation 与规则集删除互斥。
async fn lock_rule_set_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
) -> Result<(), AstralError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT rule_set_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or_else(|| AstralError::NotFound(format!("rule set {rule_set_id} not found")))?;
    Ok(())
}

/// 规则集条目 effect 到投影事件的统一映射。
///
/// DENY 以及删除条目都使用 REVOKE，确保 revoke fence 在所有写路径上
/// 具有一致语义；其余规则集变更使用共享的 RULE_SET_UPDATE 常量。
fn event_type_for_effect(effect: &str) -> &'static str {
    if effect.trim().eq_ignore_ascii_case("DENY") {
        EVENT_TYPE_REVOKE
    } else {
        EVENT_TYPE_RULE_SET_UPDATE
    }
}

fn event_type_for_entries(entries: &[NewRuleSetEntry]) -> &'static str {
    if entries
        .iter()
        .any(|entry| event_type_for_effect(&entry.effect) == EVENT_TYPE_REVOKE)
    {
        EVENT_TYPE_REVOKE
    } else {
        EVENT_TYPE_RULE_SET_UPDATE
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleSet 授权账本物化（ALLOW-only + 版本化全增量）
//
// 每个独立贡献 = 规则集条目 × 绑定卡 × 绑定行（ref）。写路径在既有 source 事务内，
// 保持原有锁序（rule_set → card_rule_set_ref → user_card → grant head → delta
// version），并为每个受影响绑定卡追加一张带 actor/operation 元数据的 CARD 投影
// 事件，其 ProjectionEventIdentity 作为该卡全部账本 delta 的 generation/fence 依据。
//
// Operation identity 单一契约：所有会写 authorization_grant_revision /
// authorization_delta_event 的 mutation 入口，以及 create/update 这类写
// RULE_SET durable projection + audit correlation 的 parent mutation，都在任何
// durable 写入之前调用 `stabilize_rule_set_operation_context` —— 显式 request-id
// 缺失时以锁定的 RULE_SET 投影代次确定性派生，随机 fallback correlation id 绝不
// 允许进入账本或投影/审计身份链；随机 id 先写一部分再替换的分叉同样被禁止。
// 禁用随机/时间戳/线程/索引等非稳定来源；SYSTEM bootstrap 走固定稳定串
// （RuleSetMutationContext::system）。
// ─────────────────────────────────────────────────────────────────────────────

/// 会写授权账本的 RuleSet mutation 类型 token。进入 operation id 派生 key，
/// 保证不同动作（同聚合、同代次重放窗口外）永不共享同一 operation 身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSetLedgerOperationKind {
    CreateRuleSet,
    UpdateRuleSet,
    AddEntry,
    UpdateEntry,
    DeleteEntry,
    BindCard,
    UnbindCard,
    DeleteRuleSet,
}

impl RuleSetLedgerOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CreateRuleSet => "create-rule-set",
            Self::UpdateRuleSet => "update-rule-set",
            Self::AddEntry => "add-entry",
            Self::UpdateEntry => "update-entry",
            Self::DeleteEntry => "delete-entry",
            Self::BindCard => "bind-card",
            Self::UnbindCard => "unbind-card",
            Self::DeleteRuleSet => "delete-rule-set",
        }
    }
}

/// 稳定 operation id 派生（纯函数）：`rule-set:{kind}:{rule_set_id}:gen:{gen}`。
///
/// - 操作类型与 RULE_SET 聚合主键进入 key：不同动作/不同聚合必然分叉；
///   rule_set_id 是全局主键，天然承担租户边界（跨租户不可能同 id）；
/// - 锁定读回的 durable source_generation 进入 key：同一逻辑操作在事务回滚后
///   重放得到同一代次 ⇒ 同一 operation id 与相同贡献事件号；提交成功后的新
///   请求读到推进后的代次，是合法的新操作身份；
/// - 条目/卡/绑定行/租户维度不进入批次级 operation id（批量共享同一 op id 是
///   契约），它们进入每条贡献的事件号派生（derive_ruleset_contribution_event_id）。
fn derive_rule_set_operation_id(
    kind: RuleSetLedgerOperationKind,
    rule_set_id: i64,
    source_generation: i64,
) -> String {
    format!(
        "rule-set:{}:{}:gen:{}",
        kind.as_str(),
        rule_set_id,
        source_generation
    )
}

/// 授权账本写路径的统一 operation identity 门禁。
///
/// 可证明上下文原样复用（显式 request id / SYSTEM 固定串 / 已派生值）；随机
/// fallback 上下文在事务内以锁定的 RULE_SET 投影代次确定性重建。规则集聚合行
/// 已被各调用方先行锁定，此处对 head 的 FOR UPDATE 读与既有 parent-event 追加
/// 同锁序，不引入新的锁序倒置；head 行缺失视为 generation 0（新建聚合首写），
/// 负代次属于持久层不变式破坏，fail-closed。返回的上下文必须贯穿该 mutation
/// 后续全部 source/head/outbox/audit/ledger/delta 写入。
async fn stabilize_rule_set_operation_context(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    kind: RuleSetLedgerOperationKind,
    rule_set_id: i64,
    context: &RuleSetMutationContext,
) -> Result<RuleSetMutationContext, AstralError> {
    if context.has_proven_operation_identity() {
        return Ok(context.clone());
    }
    let source_generation = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT source_generation FROM authorization_projection_head \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .flatten()
    .unwrap_or(0);
    if source_generation < 0 {
        return Err(AstralError::Validation(
            "RULE_SET projection head carries a negative generation; refusing to derive a rule set operation identity from it"
                .into(),
        ));
    }
    let derived = derive_rule_set_operation_id(kind, rule_set_id, source_generation);
    context.clone().with_derived_operation_id(derived)
}

/// 共享账本驱动器的 fail-closed 门禁：任何忘记显式稳定化上下文的调用方在此被
/// 整体拒绝，而不是把随机 correlation id 泄漏进 revision/delta/审计事件链。
fn require_proven_ruleset_operation_identity(
    context: &RuleSetMutationContext,
) -> Result<(), AstralError> {
    if !context.has_proven_operation_identity() {
        return Err(AstralError::Validation(
            "grant ledger materialization requires a provably stable operation id; \
             a random fallback correlation id must never reach durable grant events"
                .into(),
        ));
    }
    Ok(())
}

/// 写前锁定并读回的完整条目行。有效期按 UTC 文本读回，由 adapter 的严格解析器
/// 处理；resource/action 允许旧行为空 —— 物化阶段按 canonical 合同显式拒绝，
/// 而不是 SQL 解码失败。全列锁定读取是 versioned 证据面的一部分：
/// resource_id 以 scoped key（`type:id`/`type:*`）进入 canonical 资源；
/// condition_json/priority 不属于 canonical grant，condition 非空时 ADD/UPDATE
/// fail-closed，priority 保留在 source 行与 legacy 审计 JSON 中。
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct LockedRuleSetEntryRow {
    entry_id: i64,
    effect: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    action_code: Option<String>,
    condition_json: Option<String>,
    priority: i32,
    enabled: i32,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

const LOCKED_RULE_SET_ENTRY_SELECT: &str =
    "entry_id AS entry_id, effect AS effect, resource_type AS resource_type, \
     resource_id AS resource_id, action_code AS action_code, condition_json AS condition_json, \
     priority AS priority, enabled AS enabled, \
     DATE_FORMAT(valid_from, '%Y-%m-%dT%H:%i:%s') AS valid_from, \
     DATE_FORMAT(valid_to, '%Y-%m-%dT%H:%i:%s') AS valid_to";

async fn lock_rule_set_entry_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    entry_id: i64,
) -> Result<Option<LockedRuleSetEntryRow>, AstralError> {
    sqlx::query_as::<_, LockedRuleSetEntryRow>(&format!(
        "SELECT {LOCKED_RULE_SET_ENTRY_SELECT} FROM rule_set_entry \
         WHERE entry_id = ? AND rule_set_id = ? FOR UPDATE"
    ))
    .bind(entry_id)
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)
}

/// 全量替换语义下（update_entry）更新后的完整行状态。
async fn read_rule_set_entries_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    only_enabled: bool,
) -> Result<Vec<LockedRuleSetEntryRow>, AstralError> {
    let predicate = if only_enabled { " AND enabled = 1" } else { "" };
    sqlx::query_as::<_, LockedRuleSetEntryRow>(&format!(
        "SELECT {LOCKED_RULE_SET_ENTRY_SELECT} FROM rule_set_entry \
         WHERE rule_set_id = ?{predicate} ORDER BY entry_id FOR UPDATE"
    ))
    .bind(rule_set_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)
}

/// 绑定卡账本物化所需的锁定事实。`ref_id` 是 card_rule_set_ref 的稳定主键，
/// 作为 binding 身份的一等来源；user/tenant/domain 来自锁定的 user_card 行。
/// `pub(crate)`：卡级联删除（user_card delete_with_cascade）路径经
/// [`append_card_cascade_ruleset_removals_in_tx`] 复用同一身份实现。
#[derive(Debug, Clone)]
pub(crate) struct ProvableBoundCard {
    pub(crate) ref_id: i64,
    #[allow(dead_code)]
    pub(crate) card_id: i64,
    #[allow(dead_code)]
    pub(crate) user_id: i64,
    pub(crate) tenant_id: i64,
    pub(crate) domain_id: Option<i64>,
    pub(crate) ref_type: String,
}

/// 锁定规则集绑定引用（FOR UPDATE，与既有 append_bound_card_projections_in_tx 同一
/// 锁序位置）并逐行严格锁定归属事实：卡缺失/非 ACTIVE/过期/NULL 租户或用户一律
/// fail-closed 整体拒绝 —— 部分物化会留下 source 与 ledger 的不可恢复分叉。
/// `only_ref_id` 限定单条绑定（bind_card 只物化新建引用）。
async fn provable_bound_cards_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    only_ref_id: Option<i64>,
) -> Result<Vec<ProvableBoundCard>, AstralError> {
    let refs: Vec<(i64, i64, String)> = match only_ref_id {
        Some(ref_id) => sqlx::query_as(
            "SELECT id, card_id, ref_type FROM card_rule_set_ref \
             WHERE rule_set_id = ? AND id = ? FOR UPDATE",
        )
        .bind(rule_set_id)
        .bind(ref_id),
        None => sqlx::query_as(
            "SELECT id, card_id, ref_type FROM card_rule_set_ref \
             WHERE rule_set_id = ? ORDER BY id FOR UPDATE",
        )
        .bind(rule_set_id),
    }
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;

    let mut proven = Vec::with_capacity(refs.len());
    for (ref_id, card_id, ref_type) in refs {
        let card: Option<(Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT user_id, tenant_id, domain_id FROM user_card \
             WHERE card_id = ? AND card_status = 'ACTIVE' \
               AND (valid_from IS NULL OR valid_from <= NOW()) \
               AND (valid_until IS NULL OR valid_until >= NOW()) FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
        let Some((user_id, tenant_id, domain_id)) = card else {
            return Err(AstralError::Permission(format!(
                "rule set {rule_set_id} grants cannot be materialized: bound card {card_id} does not exist or is not ACTIVE/currently valid"
            )));
        };
        let user_id = user_id.filter(|value| *value > 0).ok_or_else(|| {
            AstralError::Permission(format!(
                "rule set {rule_set_id} grants cannot be materialized: bound card {card_id} has no usable owner user id"
            ))
        })?;
        let tenant_id = tenant_id.ok_or_else(|| {
            AstralError::Validation(format!(
                "bound card {card_id} has a NULL tenant_id; refusing to materialize rule set grants without a tenant scope"
            ))
        })?;
        proven.push(ProvableBoundCard {
            ref_id,
            card_id,
            user_id,
            tenant_id,
            domain_id,
            ref_type,
        });
    }
    Ok(proven)
}

/// system mutation（SYSTEM_ACTOR_ID=-1）以 None 表达 canonical actor；
/// 用户上下文要求正数（构造时已校验）。
fn ruleset_mutation_actor(actor_id: i64) -> Option<i64> {
    if actor_id == SYSTEM_ACTOR_ID {
        None
    } else {
        Some(actor_id)
    }
}

/// 条目行的 canonical 字段提取：ALLOW 效果 + 非空 resource/action 才能进入
/// canonical 合同；无法证明的 legacy 行显式拒绝而非静默跳过。
fn canonical_entry_grant_fields(
    entry: &LockedRuleSetEntryRow,
) -> Result<(&str, &str), AstralError> {
    let resource = entry
        .resource_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "rule set entry {} lacks a usable resource; refusing to materialize a canonical grant",
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
                "rule set entry {} lacks a usable action; refusing to materialize a canonical grant",
                entry.entry_id
            ))
        })?;
    Ok((resource, action))
}

/// 物化候选分类（纯逻辑）：enabled=1 且 effect 为 ALLOW 的条目是有效授权来源；
/// DENY（任何大小写）不是 canonical ALLOW、禁用行不生效 —— 两者安全跳过；
/// 其余未知 effect 值 fail-closed，不猜测语义。
fn materializable_allow_entries(
    entries: &[LockedRuleSetEntryRow],
) -> Result<Vec<&LockedRuleSetEntryRow>, AstralError> {
    entries
        .iter()
        .filter(|entry| entry.enabled == 1)
        .map(|entry| {
            let effect = entry.effect.trim();
            if effect.eq_ignore_ascii_case("ALLOW") {
                Ok(Some(entry))
            } else if effect.eq_ignore_ascii_case("DENY") {
                // Legacy deny rows never represent an ALLOW grant; they stay out
                // of the ledger and keep their REVOKE projection semantics.
                Ok(None)
            } else {
                Err(AstralError::Validation(format!(
                    "rule set entry {} carries unknown effect {:?}; refusing to classify it as an authorization contribution",
                    entry.entry_id, effect
                )))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|rows| rows.into_iter().flatten().collect())
}

fn ruleset_entry_facts<'a>(
    rule_set_id: i64,
    bound: &'a ProvableBoundCard,
    entry: &'a LockedRuleSetEntryRow,
) -> Result<RuleSetEntryLedgerFacts<'a>, AstralError> {
    let (resource, action) = canonical_entry_grant_fields(entry)?;
    Ok(RuleSetEntryLedgerFacts {
        tenant_id: bound.tenant_id,
        domain_id: bound.domain_id,
        card_id: bound.card_id,
        user_id: bound.user_id,
        rule_set_id,
        entry_id: entry.entry_id,
        ref_id: bound.ref_id,
        ref_type: &bound.ref_type,
        resource,
        resource_id: entry.resource_id,
        action,
        // 条件文本原样传给 adapter：非空值由 canonical ADD/UPDATE 组装门禁
        // fail-closed（canonical 合同无 condition 槽位）；REMOVE 不消费本字段。
        condition_json: entry.condition_json.as_deref(),
        valid_from: entry.valid_from.as_deref(),
        valid_to: entry.valid_to.as_deref(),
    })
}

/// 为每个受影响绑定卡追加 CARD 投影事件并物化 ADD（rev1，base0→target1）。
/// 卡维度一次投影，其身份被该卡下全部条目贡献共享（generation/fence 一致）。
/// 返回全部已物化贡献的关联证据（entry × 绑定行 × 卡 × 独立事件号），供批量
/// 替换等调用方做审计双向关联；其余路径可忽略返回值。
///
/// 首发竞争语义：grant 身份含新鲜自增 ref/entry，跨请求同 grant 并发首发
/// 结构性不可能；`uk_ade_target_version` 唯一键即理论残余竞争的串行化器
/// （败者 source 事务整体回滚，重试幂等收敛），无需额外版本锁读。
#[allow(clippy::too_many_arguments)]
async fn append_ruleset_entry_add_fanout_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    entries: &[&LockedRuleSetEntryRow],
    only_ref_id: Option<i64>,
    card_event_type: &str,
    context: &RuleSetMutationContext,
) -> Result<Vec<RulesetAdditionContribution>, AstralError> {
    require_proven_ruleset_operation_identity(context)?;
    let operation_id = context.operation_id();
    let actor_user_id = ruleset_mutation_actor(context.actor_id());
    let mut added = Vec::with_capacity(entries.len());
    for bound in provable_bound_cards_in_tx(tx, rule_set_id, only_ref_id).await? {
        let card_projection = append_card_projection_with_metadata_in_tx(
            tx,
            bound.card_id,
            card_event_type,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id,
            },
        )
        .await?;
        added.extend(
            materialize_ruleset_adds_for_bound_card_in_tx(
                tx,
                rule_set_id,
                &bound,
                &card_projection,
                operation_id,
                actor_user_id,
                entries,
            )
            .await?,
        );
    }
    Ok(added)
}

/// 单卡规则集条目 ADD 物化共享核心（与 [`materialize_ruleset_removals_for_card_in_tx`]
/// 同一约定）：全部事实输入必须来自调用方已锁定（FOR UPDATE）的行；父事件身份由
/// 调用方传入 —— fanout 为每卡自建 RULE_SET_BOUND 投影，create_card 模板绑定复用
/// 其单张 CARD_CREATED 父事件。每个贡献以稳定维度派生独立且可重放的事件号，
/// ADD rev1（base0→target1）；operation id 必须已过 proven gate。同 grant 首发竞争由
/// `uk_ade_target_version` 唯一键串行化（败者整体回滚，重试幂等收敛）——本站点
/// grant 身份含新鲜 ref/entry，跨请求同 grant 并发首发结构性不可能。
async fn materialize_ruleset_adds_for_bound_card_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    bound: &ProvableBoundCard,
    card_projection: &astral_db::ProjectionEventIdentity,
    operation_id: &str,
    actor_user_id: Option<i64>,
    allow_entries: &[&LockedRuleSetEntryRow],
) -> Result<Vec<RulesetAdditionContribution>, AstralError> {
    let mut added = Vec::with_capacity(allow_entries.len());
    for entry in allow_entries {
        let facts = ruleset_entry_facts(rule_set_id, bound, entry)?;
        let contribution_event_id =
            derive_ruleset_contribution_event_id(operation_id, &facts, RuleSetMutationKind::Add)?;
        let draft = build_ruleset_add_draft(
            &facts,
            operation_id,
            actor_user_id,
            card_projection,
            &contribution_event_id,
        )?;
        let (base_version, target_version) =
            astral_db::next_delta_version(None).map_err(map_grant_repository_error)?;
        append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
        added.push(RulesetAdditionContribution {
            tenant_id: bound.tenant_id,
            card_id: bound.card_id,
            ref_id: bound.ref_id,
            entry_id: entry.entry_id,
            event_id: contribution_event_id,
        });
    }
    Ok(added)
}

/// 为每个受影响绑定卡追加 CARD 投影事件并物化 UPDATE（rev=head+1，成对
/// before-image/digest）。任一卡缺账本头即整体失败：旧数据未 backfill 前禁止
/// 用 legacy 写法替代版本化链路。返回同步发布事件面（读链规模化 Batch E）。
///
/// 收窄 UPDATE 的 stale-ALLOW 闭合（2026-09-04）：每卡先锁定全部条目的
/// grant head 并以与 `build_ruleset_update_draft` 同源的比较判定
/// authorization-content 是否变化；任一条目可能移除旧授权（内容变化/移动）
/// ⟹ 该卡 CARD 父投影事件改用 REVOKE 语义抬 fence，delta 未发布期间严格
/// reader 的 source-freshness 门命中（PENDING）；全部条目均
/// provenance-only/no-op ⟹ 保持调用方 event type（fence 不变，写突发不得
/// 自饥饿——P3 风暴实测教训）。
#[allow(clippy::too_many_arguments)]
async fn append_ruleset_entry_update_fanout_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    entries: &[&LockedRuleSetEntryRow],
    card_event_type: &str,
    context: &RuleSetMutationContext,
) -> Result<Vec<RuleSetSyncSurface>, AstralError> {
    require_proven_ruleset_operation_identity(context)?;
    let operation_id = context.operation_id();
    let actor_user_id = ruleset_mutation_actor(context.actor_id());
    let mut surfaces = Vec::new();
    for bound in provable_bound_cards_in_tx(tx, rule_set_id, None).await? {
        // 第一遍：锁定本卡全部条目的 grant head（FOR UPDATE）并做 before-image
        // 与新 grant 的 authorization-content 比较（head 先于 CARD 父投影事件
        // 落库，父事件语义才能按内容变化结果选择）。
        let mut prepared = Vec::with_capacity(entries.len());
        let mut any_authorization_content_changed = false;
        for entry in entries {
            let facts = ruleset_entry_facts(rule_set_id, &bound, entry)?;
            let grant_id = derive_ruleset_identity(&facts)?;
            let head = astral_db::read_grant_head_for_update_in_tx(
                tx,
                facts.tenant_id,
                RULE_SET_AGGREGATE_TYPE,
                rule_set_id,
                grant_id,
            )
            .await
            .map_err(map_grant_repository_error)?
            .ok_or_else(|| {
                AstralError::Validation(format!(
                    "rule set entry {} has no versioned grant under card {}; refusing to mutate an un-versioned authorization",
                    entry.entry_id, bound.card_id
                ))
            })?;
            any_authorization_content_changed |=
                ruleset_update_authorization_content_changed(&facts, &head)?;
            prepared.push((facts, head));
        }
        let effective_card_event_type = if any_authorization_content_changed {
            EVENT_TYPE_REVOKE
        } else {
            card_event_type
        };
        let card_projection = append_card_projection_with_metadata_in_tx(
            tx,
            bound.card_id,
            effective_card_event_type,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id,
            },
        )
        .await?;
        // 第二遍：锁定该 grant 最后 delta version 并 +1 → Append Update
        // rev=head+1（复用第一遍已锁定的 head，锁序与既有链路一致）。
        for (facts, head) in &prepared {
            let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
                tx,
                facts.tenant_id,
                RULE_SET_AGGREGATE_TYPE,
                rule_set_id,
                head.grant_id,
            )
            .await
            .map_err(map_grant_repository_error)?;
            let (base_version, target_version) =
                astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;
            let contribution_event_id = derive_ruleset_contribution_event_id(
                operation_id,
                facts,
                RuleSetMutationKind::Update,
            )?;
            let draft = build_ruleset_update_draft(
                facts,
                head,
                operation_id,
                actor_user_id,
                &card_projection,
                &contribution_event_id,
            )?;
            append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
            surfaces.push(RuleSetSyncSurface {
                tenant_id: bound.tenant_id,
                card_id: bound.card_id,
                event_id: contribution_event_id,
            });
        }
    }
    Ok(surfaces)
}

/// 为每个受影响绑定卡追加 CARD REVOKE 投影事件并物化 REMOVE tombstone
/// （expected=head revision，before-image/digest 成对）。不再产生普通 DENY：
/// 删除表达为 REMOVE delta + REVOKE 语义的 legacy CARD/RULE_SET 投影事件。
/// 返回同步发布事件面（读链规模化 Batch E）。
#[allow(clippy::too_many_arguments)]
async fn append_ruleset_entry_remove_fanout_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    entries: &[&LockedRuleSetEntryRow],
    context: &RuleSetMutationContext,
) -> Result<Vec<RuleSetSyncSurface>, AstralError> {
    require_proven_ruleset_operation_identity(context)?;
    let operation_id = context.operation_id();
    let mut surfaces = Vec::new();
    for bound in provable_bound_cards_in_tx(tx, rule_set_id, None).await? {
        let card_projection = append_card_projection_with_metadata_in_tx(
            tx,
            bound.card_id,
            EVENT_TYPE_REVOKE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id,
            },
        )
        .await?;
        for entry in entries {
            let facts = ruleset_entry_facts(rule_set_id, &bound, entry)?;
            let grant_id = derive_ruleset_identity(&facts)?;
            let head = astral_db::read_grant_head_for_update_in_tx(
                tx,
                facts.tenant_id,
                RULE_SET_AGGREGATE_TYPE,
                rule_set_id,
                grant_id,
            )
            .await
            .map_err(map_grant_repository_error)?
            .ok_or_else(|| {
                AstralError::Validation(format!(
                    "rule set entry {} has no versioned grant under card {}; refusing to revoke an un-versioned authorization",
                    entry.entry_id, bound.card_id
                ))
            })?;
            let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
                tx,
                facts.tenant_id,
                RULE_SET_AGGREGATE_TYPE,
                rule_set_id,
                head.grant_id,
            )
            .await
            .map_err(map_grant_repository_error)?;
            let (base_version, target_version) =
                astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;
            let contribution_event_id = derive_ruleset_contribution_event_id(
                operation_id,
                &facts,
                RuleSetMutationKind::Remove,
            )?;
            let draft = build_ruleset_remove_draft(
                &facts,
                &head,
                operation_id,
                &card_projection,
                &contribution_event_id,
            )?;
            append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
            surfaces.push(RuleSetSyncSurface {
                tenant_id: bound.tenant_id,
                card_id: bound.card_id,
                event_id: contribution_event_id,
            });
        }
    }
    Ok(surfaces)
}

// ─────────────────────────────────────────────────────────────────────────────
// 解绑 / 删除规则集的 REMOVE 物化（D1：写新账本，杜绝活动幽灵授权）
//
// 两条路径都必须在删除 source 行（binding ref / rule_set）之前锁定并捕获全部
// 授权事实（entry × ref × 卡归属），先完成版本化 REMOVE 贡献写入，再执行既有
// source 删除与 legacy REVOKE 投影/审计。锁序沿用本模块约定：
// rule_set row → rule_set_entry(ORDER BY entry_id) → card_rule_set_ref
// (ORDER BY id) → user_card → grant revision head → delta version。
// 绑定侧（bind/unbind card-first）与 entry 变更路径（rule-set-first）存在既有的
// 跨路径取锁顺序差异；两条路径都在各自事务内保持上述确定性顺序，同一聚合内的
// 竞争最终被 rule_set 行锁串行化。
// ─────────────────────────────────────────────────────────────────────────────

/// 已物化的一条授权账本 REMOVE 贡献关联证据：entry × 绑定行 × 卡及其独立事件号。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RulesetRemovalContribution {
    card_id: i64,
    ref_id: i64,
    entry_id: i64,
    event_id: String,
}

/// 提交后同步发布的事件面（读链规模化 Batch E）：租户 + 卡 + 该卡本次物化的
/// contribution 独立事件号。仅用于 source 提交后定位同步发布目标
/// （`service::sync_publish` 按 `(tenant_id, card_id)` 作用域 claim 并以
/// `event_id` 识别本次写入的事件），不承载账本/审计语义 —— 审计 correlation
/// 仍以各自的 contribution 证据结构为准。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleSetSyncSurface {
    pub(crate) tenant_id: i64,
    pub(crate) card_id: i64,
    pub(crate) event_id: String,
}

/// 组装 removal 审计 detail 的关联字段（键名是消费方契约）：
/// parent source 事件号 + 全部贡献的事件号/条目/卡/绑定行维度。
fn ruleset_removal_audit_detail(
    parent_event_id: &str,
    contributions: &[RulesetRemovalContribution],
) -> serde_json::Value {
    let mut detail = serde_json::Map::new();
    detail.insert(
        "parentSourceEventId".to_owned(),
        serde_json::Value::from(parent_event_id),
    );
    detail.insert(
        "contributionEventIds".to_owned(),
        serde_json::Value::from(
            contributions
                .iter()
                .map(|contribution| contribution.event_id.as_str())
                .collect::<Vec<_>>(),
        ),
    );
    detail.insert(
        "ruleSetEntryIds".to_owned(),
        serde_json::Value::from(
            contributions
                .iter()
                .map(|contribution| contribution.entry_id)
                .collect::<Vec<_>>(),
        ),
    );
    detail.insert(
        "boundCardIds".to_owned(),
        serde_json::Value::from(
            contributions
                .iter()
                .map(|contribution| contribution.card_id)
                .collect::<Vec<_>>(),
        ),
    );
    detail.insert(
        "bindingRefIds".to_owned(),
        serde_json::Value::from(
            contributions
                .iter()
                .map(|contribution| contribution.ref_id)
                .collect::<Vec<_>>(),
        ),
    );
    serde_json::Value::Object(detail)
}

/// 把 removal 关联字段合并进既有审计 old_value JSON；输出确定性字符串，
/// 相同输入必然得到相同 detail（审计不可变列重放校验依赖这一点）。
fn ruleset_removal_audit_old_value(
    base: serde_json::Value,
    parent_event_id: &str,
    contributions: &[RulesetRemovalContribution],
) -> String {
    let detail = ruleset_removal_audit_detail(parent_event_id, contributions);
    let mut merged = base;
    if let (Some(base_object), Some(detail_object)) = (merged.as_object_mut(), detail.as_object()) {
        for (key, value) in detail_object {
            base_object.insert(key.clone(), value.clone());
        }
    }
    merged.to_string()
}

/// 从已锁定（FOR UPDATE）的 unbind 事实构造绑定贡献身份；所有者/租户缺失一律
/// fail-closed（消息对齐 provable_bound_cards_in_tx），部分物化不可能发生。
/// ref_type 合法性由 adapter 在 identity 派生时强制（BASE/OVERLAY）。
fn unbind_bound_card_facts(
    ref_id: i64,
    card_id: i64,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    ref_type: String,
) -> Result<ProvableBoundCard, AstralError> {
    if ref_id <= 0 {
        return Err(AstralError::Internal(
            "card_rule_set_ref insert returned an unusable id".into(),
        ));
    }
    let user_id = user_id.filter(|value| *value > 0).ok_or_else(|| {
        AstralError::Permission(format!(
            "rule set binding {ref_id} removal cannot be materialized: bound card {card_id} has no usable owner user id"
        ))
    })?;
    let tenant_id = tenant_id.ok_or_else(|| {
        AstralError::Validation(format!(
            "bound card {card_id} has a NULL tenant_id; refusing to materialize rule set grants without a tenant scope"
        ))
    })?;
    Ok(ProvableBoundCard {
        ref_id,
        card_id,
        user_id,
        tenant_id,
        domain_id,
        ref_type,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 全量替换（replace_entries）的账本接线支持类型与纯逻辑
//
// 批量替换采用明确 REMOVE(旧 entry_id) + ADD(新 entry_id) 策略：不允许用
// resource/action/priority/数组位置猜测两条目是否“同一稳定来源”，churn 在审计
// detail 中以新旧 entry/contribution ids 呈现。两相共享同一
// RuleSetMutationContext.operation_id，每个贡献以其稳定维度派生互异事件号；
// 禁止出现只有 ADD 没有 old REMOVE（或反之）的部分接线。
// ─────────────────────────────────────────────────────────────────────────────

/// 已物化的一条授权账本 ADD 贡献关联证据（维度与 REMOVE 版对应：entry × 绑定行 × 卡）。
/// `pub(crate)`：create_card 模板 BASE 绑定路径经
/// [`append_card_create_ruleset_entry_adds_in_tx`] 复用同一物化核心并消费证据面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RulesetAdditionContribution {
    /// 贡献所属租户（bound card 的稳定租户边界；同步发布事件面消费）。
    pub(crate) tenant_id: i64,
    pub(crate) card_id: i64,
    pub(crate) ref_id: i64,
    pub(crate) entry_id: i64,
    pub(crate) event_id: String,
}

/// 批量替换审计关联证据：parent source 投影事件号 + 旧/新两组贡献维度。
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleSetBatchReplacementAudit {
    parent_source_event_id: String,
    removals: Vec<RulesetRemovalContribution>,
    additions: Vec<RulesetAdditionContribution>,
}

/// 组装批量替换审计 detail 的关联字段（键名是消费方契约）：parent source 事件号 +
/// 旧/新贡献各自的事件号、条目、卡与绑定行维度。任一相可为空（空替换语义），
/// 输出确定性 JSON —— 审计 immutable 列重放校验依赖逐字节一致。
fn ruleset_batch_replacement_audit_detail(
    audit: &RuleSetBatchReplacementAudit,
) -> serde_json::Value {
    let removal_dims: Vec<(i64, i64, i64, &str)> = audit
        .removals
        .iter()
        .map(|c| (c.entry_id, c.card_id, c.ref_id, c.event_id.as_str()))
        .collect();
    let addition_dims: Vec<(i64, i64, i64, &str)> = audit
        .additions
        .iter()
        .map(|c| (c.entry_id, c.card_id, c.ref_id, c.event_id.as_str()))
        .collect();
    let mut detail = serde_json::Map::new();
    detail.insert(
        "parentSourceEventId".to_owned(),
        serde_json::Value::from(audit.parent_source_event_id.as_str()),
    );
    for (prefix, dims) in [("removed", removal_dims), ("added", addition_dims)] {
        detail.insert(
            format!("{prefix}ContributionEventIds"),
            serde_json::Value::from(dims.iter().map(|dim| dim.3.to_owned()).collect::<Vec<_>>()),
        );
        detail.insert(
            format!("{prefix}RuleSetEntryIds"),
            serde_json::Value::from(dims.iter().map(|dim| dim.0).collect::<Vec<_>>()),
        );
        detail.insert(
            format!("{prefix}BoundCardIds"),
            serde_json::Value::from(dims.iter().map(|dim| dim.1).collect::<Vec<_>>()),
        );
        detail.insert(
            format!("{prefix}BindingRefIds"),
            serde_json::Value::from(dims.iter().map(|dim| dim.2).collect::<Vec<_>>()),
        );
    }
    serde_json::Value::Object(detail)
}

/// 把批量替换关联字段合并进既有审计 JSON；输出确定性字符串。
fn ruleset_batch_replacement_audit_old_value(
    base: serde_json::Value,
    audit: &RuleSetBatchReplacementAudit,
) -> String {
    let detail = ruleset_batch_replacement_audit_detail(audit);
    let mut merged = base;
    if let (Some(base_object), Some(detail_object)) = (merged.as_object_mut(), detail.as_object()) {
        for (key, value) in detail_object {
            base_object.insert(key.clone(), value.clone());
        }
    }
    merged.to_string()
}

/// 无变化判定（纯逻辑，不触库）：仅当锁定读回的全部旧条目与请求行多重集完全一致
/// 时才允许 no-op 短路 —— 行数相等、每行 enabled=1 且有效期两列为 NULL（本路径
/// INSERT 恒不写有效期）、effect 大小写/空白归一后均为 ALLOW、其余各列逐字节一致。
/// 判定保守：任何无法逐字节证明的差异都走完整 REMOVE+ADD 路径，绝不冒充等价。
fn batch_replacement_is_fully_equal(
    old_entries: &[LockedRuleSetEntryRow],
    requested: &[NewRuleSetEntry],
) -> bool {
    if old_entries.len() != requested.len() {
        return false;
    }
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct CanonicalRowKey {
        effect: String,
        resource_type: Option<String>,
        resource_id: Option<i64>,
        action_code: Option<String>,
        condition_json: Option<String>,
        priority: i32,
    }
    let mut old_keys: Vec<CanonicalRowKey> = Vec::with_capacity(old_entries.len());
    for entry in old_entries {
        // 禁用/DENY/带有效期/未知 effect 的旧行不可能等价于已归一化的请求集，
        // 保守拒绝短路；后续 classifier/materializer 会按各自规则处理或拒绝。
        if entry.enabled != 1 || entry.valid_from.is_some() || entry.valid_to.is_some() {
            return false;
        }
        old_keys.push(CanonicalRowKey {
            effect: entry.effect.trim().to_ascii_uppercase(),
            resource_type: entry.resource_type.clone(),
            resource_id: entry.resource_id,
            action_code: entry.action_code.clone(),
            condition_json: entry.condition_json.clone(),
            priority: entry.priority,
        });
    }
    let mut new_keys: Vec<CanonicalRowKey> = requested
        .iter()
        .map(|entry| CanonicalRowKey {
            effect: entry.effect.trim().to_ascii_uppercase(),
            resource_type: entry.resource.clone(),
            resource_id: entry.resource_id,
            action_code: entry.action.clone(),
            condition_json: entry.condition_json.clone(),
            priority: entry.priority,
        })
        .collect();
    old_keys.sort();
    new_keys.sort();
    old_keys == new_keys
}

/// 单卡 REMOVE 贡献物化核心：在给定 CARD 投影身份（generation/fence 锚点）下，
/// 为每个可证明条目链式追加 REMOVE tombstone。head 缺失/stale/gap 或唯一冲突
/// 一律错误上抛、整个事务回滚；不吞错、不降级为只写旧链。
async fn materialize_ruleset_removals_for_card_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    bound: &ProvableBoundCard,
    card_projection_identity: &astral_db::ProjectionEventIdentity,
    operation_id: &str,
    allow_entries: &[&LockedRuleSetEntryRow],
) -> Result<Vec<RulesetRemovalContribution>, AstralError> {
    let mut removed = Vec::with_capacity(allow_entries.len());
    for entry in allow_entries {
        let facts = ruleset_entry_facts(rule_set_id, bound, entry)?;
        let grant_id = derive_ruleset_identity(&facts)?;
        // head 缺失即 fail-closed：未 backfill 的 ALLOW 老数据禁止静默跳过，
        // 否则解绑/删除会把账本里的活跃授权留成幽灵。
        let head = astral_db::read_grant_head_for_update_in_tx(
            tx,
            facts.tenant_id,
            RULE_SET_AGGREGATE_TYPE,
            rule_set_id,
            grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "rule set entry {} has no versioned grant under card {}; refusing to revoke an un-versioned authorization",
                entry.entry_id, bound.card_id
            ))
        })?;
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            tx,
            facts.tenant_id,
            RULE_SET_AGGREGATE_TYPE,
            rule_set_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;
        // 共享 operation_id + entry×card×ref 维度 ⇒ 每个贡献独立且可重放的事件号。
        let contribution_event_id = derive_ruleset_contribution_event_id(
            operation_id,
            &facts,
            RuleSetMutationKind::Remove,
        )?;
        let draft = build_ruleset_remove_draft(
            &facts,
            &head,
            operation_id,
            card_projection_identity,
            &contribution_event_id,
        )?;
        append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
        removed.push(RulesetRemovalContribution {
            card_id: bound.card_id,
            ref_id: bound.ref_id,
            entry_id: entry.entry_id,
            event_id: contribution_event_id,
        });
    }
    Ok(removed)
}

/// 解绑路径的 REMOVE 物化：绑定事实在删除 source ref 之前从锁定行捕获传入，
/// 因此贡献写入绝不重新扫描（此时可能已被删除的）ref 表。单卡恰一张带元数据的
/// CARD REVOKE 投影事件作为该卡全部贡献的 generation/fence。
async fn append_unbind_ruleset_removal_deltas_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    bound: &ProvableBoundCard,
    allow_entries: &[&LockedRuleSetEntryRow],
    context: &RuleSetMutationContext,
) -> Result<Vec<RulesetRemovalContribution>, AstralError> {
    require_proven_ruleset_operation_identity(context)?;
    let operation_id = context.operation_id();
    let card_projection = append_card_projection_with_metadata_in_tx(
        tx,
        bound.card_id,
        EVENT_TYPE_REVOKE,
        astral_db::ProjectionEventMetadata {
            actor_id: context.actor_id(),
            operation_id,
        },
    )
    .await?;
    materialize_ruleset_removals_for_card_in_tx(
        tx,
        rule_set_id,
        bound,
        &card_projection,
        operation_id,
        allow_entries,
    )
    .await
}

/// 卡级联删除返回的单个规则集撤销证据面（供审计关联；不承载账本语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CardCascadeRulesetRemoval {
    pub(crate) rule_set_id: i64,
    /// 该卡在该规则集下的绑定引用主键（card_rule_set_ref.id）。
    pub(crate) binding_ref_ids: Vec<i64>,
    /// 每个 entry × 绑定行贡献的 (entry_id, binding_ref_id, 独立事件号)。
    pub(crate) removed_entries: Vec<CardCascadeRulesetEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CardCascadeRulesetEntry {
    pub(crate) entry_id: i64,
    pub(crate) binding_ref_id: i64,
    pub(crate) event_id: String,
}

/// 卡级联删除（user_card delete_with_cascade）专用的规则集 REMOVE 物化。
///
/// 与 unbind 路径共享同一 remove core，但存在两点来源差异：
/// - user_card 已由调用方先行 FOR UPDATE 锁定（binding-side 锁序：user_card →
///   rule_set → 绑定引用 → entries），本函数不再重复锁卡、也不重新校验 ACTIVE；
/// - generation/fence 锚点由调用方传入的**同一张** parent CARD 投影事件提供
///   （整张卡一次 REVOKE 锚点贯穿 direct/approval/rule set 全部贡献），本函数
///   不再追加自己的 CARD 投影事件 —— 每个 contribution 仍以稳定维度派生独立
///   且可重放的事件号。
///
/// 返回契约：绑定集合对协议参与者随卡行锁冻结，调用方以 DISTINCT rule_set_id
/// 分组，因此正常返回 `Some`。规则集 source 行缺失 = orphan-cleanup（unbind 先例：
/// 删除规则集不会清理 card_rule_set_ref），此时无可锁定条目 ⇒ 无可撤销账本贡献，
/// 仍捕获并返回绑定引用主键供审计与清理计数，不伪造任何 delta。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn append_card_cascade_ruleset_removals_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    card_user_id: i64,
    card_tenant_id: i64,
    card_domain_id: Option<i64>,
    rule_set_id: i64,
    parent_projection: &astral_db::ProjectionEventIdentity,
    operation_id: &str,
) -> Result<Option<CardCascadeRulesetRemoval>, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "card cascade ruleset removal requires the shared durable operation id".into(),
        ));
    }
    // 1) 规则集 source 行（FOR UPDATE；缺失行不持锁，随后取 ref 锁无锁序风险）。
    let rule_set: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT tenant_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE")
            .bind(rule_set_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
    let rule_set_tenant_id = rule_set.map(|(tenant_id,)| tenant_id);

    // 2) 该卡在该规则集下的绑定引用（FOR UPDATE，确定性 id 升序）。
    let refs: Vec<(i64, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, ref_type, tenant_id FROM card_rule_set_ref \
         WHERE card_id = ? AND rule_set_id = ? ORDER BY id FOR UPDATE",
    )
    .bind(card_id)
    .bind(rule_set_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    if refs.is_empty() {
        // 分组来源即该表，按冻结不变式不应发生；作为防御性短路保留。
        return Ok(None);
    }
    let mut removal = CardCascadeRulesetRemoval {
        rule_set_id,
        binding_ref_ids: refs.iter().map(|(ref_id, _, _)| *ref_id).collect(),
        removed_entries: Vec::new(),
    };

    // 3a) Orphan-cleanup：source 已删除 ⇒ 条目无从锁定、无账本贡献可撤销。
    let Some(source_tenant_id) = rule_set_tenant_id else {
        return Ok(Some(removal));
    };

    // 3b) source 在场：先做租户校验（unbind 同一门禁），再锁 enabled 条目并
    // 做 ALLOW-only 分类；未知 effect fail-closed。
    validate_unbind_tenants(
        Some(card_tenant_id),
        refs[0].2,
        RuleSetUnbindSource::Present {
            tenant_id: source_tenant_id,
        },
    )?;
    let entries = read_rule_set_entries_in_tx(tx, rule_set_id, true).await?;
    let allow_entries = materializable_allow_entries(&entries)?;

    for (ref_id, ref_type, binding_tenant_id) in refs {
        // 每个引用行的租户一致性独立验证（首行已在上方统一校验）。
        validate_unbind_tenants(
            Some(card_tenant_id),
            binding_tenant_id,
            RuleSetUnbindSource::Present {
                tenant_id: source_tenant_id,
            },
        )?;
        let bound = unbind_bound_card_facts(
            ref_id,
            card_id,
            Some(card_user_id),
            Some(card_tenant_id),
            card_domain_id,
            ref_type,
        )?;
        let contributions = materialize_ruleset_removals_for_card_in_tx(
            tx,
            rule_set_id,
            &bound,
            parent_projection,
            operation_id,
            &allow_entries,
        )
        .await?;
        for contribution in contributions {
            removal.removed_entries.push(CardCascadeRulesetEntry {
                entry_id: contribution.entry_id,
                binding_ref_id: bound.ref_id,
                event_id: contribution.event_id,
            });
        }
    }
    Ok(Some(removal))
}

/// create_card 模板绑定返回的单个规则集 ADD 证据面（供审计关联；不承载账本语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CardCreateRulesetAddition {
    pub(crate) rule_set_id: i64,
    /// 本卡在该规则集下的新建绑定引用主键（card_rule_set_ref.id）。
    pub(crate) binding_ref_id: i64,
    /// 每个 enabled+ALLOW 条目贡献的独立稳定事件号。
    pub(crate) added_entries: Vec<CardCreateRulesetEntryAddition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CardCreateRulesetEntryAddition {
    pub(crate) entry_id: i64,
    pub(crate) event_id: String,
}

/// create_card 模板 BASE 绑定专用的单卡 RuleSet ADD 物化。
///
/// 与 bind_card 共享 [`materialize_ruleset_adds_for_bound_card_in_tx`] 同一账本链
/// （锁定读回 enabled 条目 → ALLOW-only 分类 → 每贡献独立可重放事件号 → ADD rev1
/// base0→target1），与卡级联删除共用同一父事件约定：
/// - 归属事实由调用方从**本事务新插入**的 user_card 行与严格捕获的 ref 主键传入，
///   本函数按 [`unbind_bound_card_facts`] 同一门禁逐项复核（正数 id / 租户非空）；
/// - generation/fence 锚点复用调用方的**单张 CARD_CREATED 父投影事件**，不再为每个
///   绑定追加 CARD RULE_SET_BOUND 事件 —— 避免旧 worker 对同一张新建卡重复重建；
/// - 空 RuleSet 合法：无任何账本贡献，返回空 `added_entries`，调用方仍写完整
///   父/RULE_SET 投影与审计语义。
///
/// 锁序位置：调用方已持有 user_card 新行（INSERT X 锁）与升序锁定的 rule_set 行 /
/// RULE_SET head；本函数锁定读取该规则集条目并追加 grant revision/delta，与
/// binding-side 家族（user_card → rule_set → refs/entries → grant head/delta）
/// 方向一致，不引入反向锁序。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn append_card_create_ruleset_entry_adds_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    parent_projection: &astral_db::ProjectionEventIdentity,
    context: &RuleSetMutationContext,
    ref_id: i64,
    card_id: i64,
    card_user_id: i64,
    card_tenant_id: i64,
    card_domain_id: Option<i64>,
    ref_type: &str,
) -> Result<CardCreateRulesetAddition, AstralError> {
    require_proven_ruleset_operation_identity(context)?;
    let operation_id = context.operation_id();
    let actor_user_id = ruleset_mutation_actor(context.actor_id());
    // 归属事实合同校验（创建路径不得物化不可证明的贡献；租户缺失整卡失败由
    // 调用方 scope 校验先行覆盖，此处保留最后一道防线）。
    if ref_id <= 0 || card_id <= 0 || rule_set_id <= 0 {
        return Err(AstralError::Internal(
            "create-card rule set binding requires positive card/rule-set/ref identifiers".into(),
        ));
    }
    let user_id = (card_user_id > 0).then_some(card_user_id).ok_or_else(|| {
        AstralError::Validation(format!(
            "newly created card {card_id} has no usable owner user id; refusing to materialize template rule set grants without a provable owner"
        ))
    })?;
    let bound = ProvableBoundCard {
        ref_id,
        card_id,
        user_id,
        tenant_id: card_tenant_id,
        domain_id: card_domain_id,
        ref_type: ref_type.to_owned(),
    };

    let entries = read_rule_set_entries_in_tx(tx, rule_set_id, true).await?;
    let allow_entries = materializable_allow_entries(&entries)?;
    let contributions = materialize_ruleset_adds_for_bound_card_in_tx(
        tx,
        rule_set_id,
        &bound,
        parent_projection,
        operation_id,
        actor_user_id,
        &allow_entries,
    )
    .await?;
    Ok(CardCreateRulesetAddition {
        rule_set_id,
        binding_ref_id: ref_id,
        added_entries: contributions
            .into_iter()
            .map(|contribution| CardCreateRulesetEntryAddition {
                entry_id: contribution.entry_id,
                event_id: contribution.event_id,
            })
            .collect(),
    })
}

/// 删除规则集路径的 REMOVE 物化：refs 已按主键序锁定捕获（provable_bound_cards
/// 返回顺序即 card/ref 确定性顺序），entry×ref 全组合各得独立 REMOVE；
/// 每个 DISTINCT 卡首见时追加一张带元数据的 CARD REVOKE 投影事件，其余引用
/// 复用同一张卡的身份锚点（原 DISTINCT-card 语义不变，证据面更完整）。
async fn append_ruleset_deletion_removal_deltas_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    proven_refs: &[ProvableBoundCard],
    allow_entries: &[&LockedRuleSetEntryRow],
    context: &RuleSetMutationContext,
) -> Result<Vec<RulesetRemovalContribution>, AstralError> {
    require_proven_ruleset_operation_identity(context)?;
    let operation_id = context.operation_id();
    let mut removed = Vec::new();
    let mut projection_by_card: std::collections::HashMap<i64, astral_db::ProjectionEventIdentity> =
        std::collections::HashMap::new();
    for bound in proven_refs {
        // 首见去重：每个 DISTINCT 卡只在第一次出现时追加带元数据的 CARD REVOKE
        // 投影事件，其余引用复用同一身份锚点。
        let projection = match projection_by_card.entry(bound.card_id) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                let identity = append_card_projection_with_metadata_in_tx(
                    tx,
                    bound.card_id,
                    EVENT_TYPE_REVOKE,
                    astral_db::ProjectionEventMetadata {
                        actor_id: context.actor_id(),
                        operation_id,
                    },
                )
                .await?;
                slot.insert(identity)
            }
            std::collections::hash_map::Entry::Occupied(occupied) => occupied.into_mut(),
        };
        removed.extend(
            materialize_ruleset_removals_for_card_in_tx(
                tx,
                rule_set_id,
                bound,
                projection,
                operation_id,
                allow_entries,
            )
            .await?,
        );
    }
    Ok(removed)
}

async fn validate_card_binding_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    rule_set_id: i64,
) -> Result<Option<i64>, AstralError> {
    let card: Option<(String, Option<i64>)> =
        sqlx::query_as("SELECT card_status, tenant_id FROM user_card WHERE card_id = ? FOR UPDATE")
            .bind(card_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
    let Some((card_status, card_tenant_id)) = card else {
        return Err(AstralError::Permission(
            "rule set binding requires an active user card".into(),
        ));
    };
    if card_status != "ACTIVE" {
        return Err(AstralError::Permission(
            "rule set binding requires an active user card".into(),
        ));
    }

    let rule_set: Option<(i32, Option<i64>)> =
        sqlx::query_as("SELECT enabled, tenant_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE")
            .bind(rule_set_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
    let Some((enabled, rule_set_tenant_id)) = rule_set else {
        return Err(AstralError::NotFound(format!(
            "active rule set {rule_set_id} not found"
        )));
    };
    if enabled != 1 {
        return Err(AstralError::NotFound(format!(
            "active rule set {rule_set_id} not found"
        )));
    }

    // 跨租户绑定防护（对齐 Java `RuleSetService.bindCardToRuleSet`）：
    // 1) 规则集与卡租户都非空且不一致 → 拒绝跨租户绑定；
    // 2) 规则集无租户归属、卡有租户上下文 → 拒绝（无法证明归属的规则集不得在租户上下文绑定）。
    // 卡租户来自已验证的身份上下文（require_card_context 已保证操作者卡 == 目标卡），
    // 不从客户端请求体信任租户。
    validate_binding_tenants(rule_set_tenant_id, card_tenant_id)?;
    Ok(card_tenant_id)
}

/// 跨租户绑定判定纯逻辑（对齐 Java `RuleSetService.bindCardToRuleSet`）：
/// - 规则集与卡租户都非空且不一致 → 拒绝；
/// - 仅一侧有租户归属 → 拒绝，避免无法证明的跨范围绑定；
/// - 其余（同租户 / 都无租户）→ 允许。
///
/// This function is called before RuleSet projection proof and reference
/// insertion, so a rejected tenant scope cannot leave a partial binding.
pub(crate) fn validate_binding_tenants(
    rule_set_tenant: Option<i64>,
    card_tenant: Option<i64>,
) -> Result<(), AstralError> {
    match (rule_set_tenant, card_tenant) {
        (Some(rule_set_tenant), Some(card_tenant)) if rule_set_tenant != card_tenant => {
            return Err(AstralError::Permission(format!(
                "cross-tenant rule set binding not allowed: rule_set_tenant={rule_set_tenant}, card_tenant={card_tenant}"
            )));
        }
        (Some(_), None) => {
            return Err(AstralError::Permission(
                "tenant-scoped rule set cannot be bound to a tenantless card".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(AstralError::Permission(
                "rule set without tenant_id cannot be bound in tenant context".into(),
            ));
        }
        (None, None) | (Some(_), Some(_)) => {}
    }
    Ok(())
}

/// Source-row state captured while unbinding. `Missing` is a valid orphan-cleanup
/// case, but it must not be conflated with a present tenantless RuleSet row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSetUnbindSource {
    Missing,
    Present { tenant_id: Option<i64> },
}

#[derive(Debug, sqlx::FromRow)]
struct RuleSetUnbindSourceRow {
    tenant_id: Option<i64>,
}

/// Unbind always requires card/ref tenant equality. If the RuleSet source still
/// exists, its tenant must match too; a missing source is permitted only for a
/// tenant-matching orphan reference and is handled with the captured ref tenant.
fn validate_unbind_tenants(
    card_tenant: Option<i64>,
    binding_tenant: Option<i64>,
    rule_set_source: RuleSetUnbindSource,
) -> Result<(), AstralError> {
    if card_tenant != binding_tenant {
        return Err(AstralError::Permission(
            "rule set unbinding requires matching card and binding tenant identities".into(),
        ));
    }
    if let RuleSetUnbindSource::Present { tenant_id } = rule_set_source {
        if binding_tenant != tenant_id {
            return Err(AstralError::Permission(
                "rule set unbinding requires matching binding and rule set tenant identities"
                    .into(),
            ));
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 共享授权账本 churn 核心（批量替换 / 模板同步 / 启动模板物化 同一实现）
//
// 语义：一次“全量替换”把 rule_set_entry 全部重写（DELETE+INSERT churn 新
// entry_id）。安全默认是 capture-before-delete：先锁定读回全部旧条目并做
// ALLOW-only 分类，对每个 entry×绑定行×卡物化 REMOVE tombstone；随后删除旧
// source 行、严格插入新行并锁读回真实新 entry facts、逐组合物化 ADD
// rev1/base0→target1；全程同一事务，REMOVE/ADD 贡献共享同一稳定 operation id，
// 各自以稳定维度派生互异事件号。禁止只 ADD 不 REMOVE（或反之）的部分接线，
// 禁止把模板 source 当 DIRECT。
// ─────────────────────────────────────────────────────────────────────────────

/// churn 驱动器的调用方专属审计标签：change_type 与 old/new 值的基础 JSON
/// （关联字段由核心统一并入，见 ruleset_batch_replacement_audit_old_value）。
#[derive(Debug, Clone)]
pub(crate) struct LedgerChurnAuditContext<'a> {
    pub change_type: &'a str,
    pub old_value_base: serde_json::Value,
    pub new_value: serde_json::Value,
}

/// 全量替换/模板同步共享的事务内编排核心。要求规则集聚合行已被调用方以
/// FOR UPDATE 锁定；返回受影响 DISTINCT 绑定卡数（no-op 短路返回 0）。
///
/// 身份门禁：随机 fallback 的 operation id 一律拒绝进入账本 —— 相同操作重试
/// 必须得到相同 contribution event IDs，重复 durable rows 显式冲突 fail-closed，
/// 绝不改派新身份绕过。缺 header 的确定性派生属于各自入口的前置步骤（例如
/// 模板同步用 template/rule_set/projection generation 派生后再进入本核心）。
pub(crate) async fn replace_rule_set_entries_churn_with_ledger_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    rows: &[NewRuleSetEntry],
    forced_event_type: Option<&str>,
    audit: LedgerChurnAuditContext<'_>,
    context: &RuleSetMutationContext,
) -> Result<usize, AstralError> {
    if !context.has_proven_operation_identity() {
        return Err(AstralError::Validation(
            "grant ledger materialization requires a provably stable operation id; \
             a random fallback correlation id must never reach durable grant events"
                .into(),
        ));
    }

    // ── Capture-before-replace（锁序沿用本模块约定：rule_set → entries →
    // refs → user_card → grant head → delta version）──
    // 全列锁定读回全部旧条目并做 ALLOW-only 分类；这一步在删除之前完成，
    // REMOVE 的 before-image 输入绝不来自删除后的残缺快照。未知 effect 在此
    // fail-closed，legacy DENY/禁用行按既有语义留在旧链之外（从不转换）。
    let old_entries = read_rule_set_entries_in_tx(tx, rule_set_id, false).await?;
    let old_allow_entries = materializable_allow_entries(&old_entries)?;

    // 无变化短路：仅在锁定读回 + 逐字节归一比对完全证明等值时跳过全部写入，
    // 既不 bump source generation 也不写重复 delta；重放因此不产生新身份。
    if batch_replacement_is_fully_equal(&old_entries, rows) {
        return Ok(0);
    }

    // 绑定卡事实必须在写任何 REMOVE/ADD 之前证明完整：存在不可激活/过期/
    // 租户缺失/死 ref 即整体拒绝 —— 部分物化会留下 source 与 ledger 的分叉，
    // 也绝不允许静默跳过死引用继续制造幽灵。
    let proven_refs = provable_bound_cards_in_tx(tx, rule_set_id, None).await?;

    // ── Old REMOVE 贡献先于任何 source 删除 ──
    // 复用 D1 删除驱动器：每个 DISTINCT 卡一张带 actor/operation 元数据的
    // CARD REVOKE 投影事件作为 generation/fence 锚点，entry×ref 全组合各得
    // 独立稳定的 REMOVE tombstone 事件号；缺账本 head（未 backfill 的旧数据）
    // 即整体失败，绝不以 full snapshot/raw source 冒充 before-image。
    let removals = if old_allow_entries.is_empty() {
        Vec::new()
    } else {
        append_ruleset_deletion_removal_deltas_in_tx(
            tx,
            rule_set_id,
            &proven_refs,
            &old_allow_entries,
            context,
        )
        .await?
    };

    sqlx::query("DELETE FROM rule_set_entry WHERE rule_set_id = ?")
        .bind(rule_set_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    // ── Source 插入：在同一未提交事务内逐条捕获真实新 entry_id ──
    // identity 派生不允许“插入后才发现 id 不够用”的降级路径：
    // 受影响行数与 last_insert_id 都严格校验，失败即保留原状整体回滚。
    let mut new_entry_ids: Vec<i64> = Vec::with_capacity(rows.len());
    for entry in rows {
        let result = sqlx::query(
            "INSERT INTO rule_set_entry (rule_set_id, effect, resource_type, resource_id, action_code, condition_json, priority, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        )
        .bind(rule_set_id)
        .bind(&entry.effect)
        .bind(&entry.resource)
        .bind(entry.resource_id)
        .bind(&entry.action)
        .bind(&entry.condition_json)
        .bind(entry.priority)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "rule set entry batch replace insert did not affect exactly one row".into(),
            ));
        }
        let entry_id = result.last_insert_id() as i64;
        if entry_id <= 0 {
            return Err(AstralError::Internal(
                "rule set entry batch replace insert returned an unusable id".into(),
            ));
        }
        new_entry_ids.push(entry_id);
    }
    // 身份碰撞防御：grant identity 含 source_entry=entry_id，新旧 id 相同会把
    // ADD 打到刚被 REMOVE 的同一稳定授权上；此处明确拒绝而非隐式续链。
    if let Some(entry_id) = new_entry_ids
        .iter()
        .find(|id| old_entries.iter().any(|old| old.entry_id == **id))
    {
        return Err(AstralError::Internal(format!(
            "batch replace produced entry id {entry_id} that collides with a replaced entry id; refusing to alias a stable grant identity across removal and addition"
        )));
    }

    // legacy DB 值仅用于判断既有 REVOKE 语义；新写入值恒为 ALLOW。
    let has_deny = old_entries
        .iter()
        .any(|entry| event_type_for_effect(&entry.effect) == EVENT_TYPE_REVOKE)
        || event_type_for_entries(rows) == EVENT_TYPE_REVOKE;
    let event_type = forced_event_type.unwrap_or(if has_deny {
        EVENT_TYPE_REVOKE
    } else {
        EVENT_TYPE_RULE_SET_UPDATE
    });

    // ── New ADD 贡献：锁定读回已落盘但尚未提交的新行 ──
    // 物化输入来自真实锁定行（含有效期列）而非请求内存副本；每个
    // entry×card×ref 组合派生独立稳定的 ADD rev1/base0→target1 链路，
    // 卡维度复用 append fanout 内带元数据的 CARD 投影锚点（不再重复逐卡
    // 裸广播），且覆盖全部绑定卡 —— 空替换也不丢既有 per-card 信号。
    let stored_entries = read_rule_set_entries_in_tx(tx, rule_set_id, true).await?;
    if stored_entries.len() != new_entry_ids.len() {
        return Err(AstralError::Internal(format!(
            "batch replace stored {} enabled rows but inserted {}; refusing to materialize from a drifted snapshot",
            stored_entries.len(),
            new_entry_ids.len()
        )));
    }
    let allow_refs: Vec<&LockedRuleSetEntryRow> = stored_entries.iter().collect();
    let additions = append_ruleset_entry_add_fanout_in_tx(
        tx,
        rule_set_id,
        &allow_refs,
        None,
        event_type,
        context,
    )
    .await?;

    // ── Parent RULE_SET 投影 + 新旧双向关联审计（位于双相之后才能同时引用
    // 两组贡献事件号；旧/新贡献共享同一 operation id，parent event_id 不复用给
    // 任何 delta）──
    let projection = append_rule_set_projection_in_tx(
        tx,
        rule_set_id,
        event_type,
        astral_db::ProjectionEventMetadata {
            actor_id: context.actor_id(),
            operation_id: context.operation_id(),
        },
    )
    .await?;
    let replacement_audit = RuleSetBatchReplacementAudit {
        parent_source_event_id: projection.event_id.clone(),
        removals,
        additions,
    };
    let audit_old_value =
        ruleset_batch_replacement_audit_old_value(audit.old_value_base, &replacement_audit);
    insert_rule_set_projection_audit_in_tx(
        tx,
        &RuleSetProjectionAuditEntry {
            rule_set_id,
            entry_id: None,
            aggregate_type: ProjectionAggregate::RuleSet.as_str(),
            aggregate_id: rule_set_id,
            event_id: &projection.event_id,
            source_generation: projection.source_generation,
            operation_id: context.operation_id(),
            actor_id: context.actor_id(),
            change_type: audit.change_type,
            old_value_json: Some(&audit_old_value),
            new_value_json: Some(&audit.new_value.to_string()),
            tenant_id: projection.tenant_id,
        },
    )
    .await?;

    // 任一上游错误均已上抛触发整体回滚：不会出现只有 ADD 没有 old REMOVE
    // （或反之）、或旧链已提交而新链失败的中间状态。
    Ok(proven_refs
        .iter()
        .map(|bound| bound.card_id)
        .collect::<std::collections::HashSet<_>>()
        .len())
}

/// generic create 的 source_type 所有权预留门禁（纯函数，INSERT 前调用）。
///
/// `rule_set.source_type` 是所有权判别器：`TEMPLATE` 只属于模板投影路径
/// （`create_rule_set_from_template` 写入 `source_type='TEMPLATE'` 并指向模板），
/// generic create 占用它会把模板所有权重写为无 source_id 的悬空所有权，破坏
/// 模板同步与所有权归因。空 source_type 同样 fail-closed —— 判别器必须可判别。
/// 校验对大小写与首尾空白不敏感；非保留值原样写入，不做静默归一化。
pub(crate) fn validate_generic_rule_set_source_type(source_type: &str) -> Result<(), AstralError> {
    let trimmed = source_type.trim();
    if trimmed.is_empty() {
        return Err(AstralError::Validation(
            "rule set source_type (refType) must not be empty".into(),
        ));
    }
    if trimmed.eq_ignore_ascii_case("TEMPLATE") {
        return Err(AstralError::Validation(
            "source_type 'TEMPLATE' is reserved for the template projection path; \
             generic rule set creation must use a non-reserved ownership discriminator"
                .into(),
        ));
    }
    Ok(())
}

/// generic update 的实际变更集（纯检测，锁定行读回后调用）。
///
/// source_type 是所有权判别器，不在可变字段集合里 —— 该结构体没有它的位置是
/// 刻意的 source 形状约束；审计只记录本结构标记为 true 的字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GenericRuleSetUpdateChanges {
    name: bool,
    description: bool,
}

impl GenericRuleSetUpdateChanges {
    const fn any(self) -> bool {
        self.name || self.description
    }
}

/// 按实际写入值逐字段比较（不做静默归一化；None 与 Some("") 是不同值）。
fn generic_rule_set_update_changes(
    current_name: &str,
    current_description: Option<&str>,
    patch_name: &str,
    patch_description: Option<&str>,
) -> GenericRuleSetUpdateChanges {
    GenericRuleSetUpdateChanges {
        name: current_name != patch_name,
        description: current_description != patch_description,
    }
}

#[async_trait]
impl RuleSetRepository for SqlxRuleSetRepository {
    async fn count_rule_sets(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rule_set")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_rule_sets(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuleSetSummary>, AstralError> {
        let rows = sqlx::query_as::<_, RuleSetRow>(&format!(
            "SELECT {RULE_SET_SELECT} FROM rule_set ORDER BY rule_set_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        summarize(&self.db, rows).await
    }

    async fn get_rule_set(&self, rule_set_id: i64) -> Result<Option<RuleSetSummary>, AstralError> {
        let row = sqlx::query_as::<_, RuleSetRow>(&format!(
            "SELECT {RULE_SET_SELECT} FROM rule_set WHERE rule_set_id=?"
        ))
        .bind(rule_set_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(summarize(&self.db, vec![row]).await?.into_iter().next())
    }

    async fn create_rule_set(
        &self,
        new: &NewRuleSet,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        // source_type 是所有权判别器：generic create 不得创建空所有权，也不得
        // 占用模板投影路径专属的 TEMPLATE 判别器；INSERT 前 fail-closed。
        validate_generic_rule_set_source_type(&new.ref_type)?;
        // 对齐 platform_v4：code (UNIQUE NOT NULL) 用 name 作为默认值，source_type 存储 ref_type。
        // source mutation 与 RULE_SET durable projection 在同一事务内提交。
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let result = sqlx::query(
            "INSERT INTO rule_set (name, code, source_type, description, enabled) VALUES (?, ?, ?, ?, 1)",
        )
        .bind(&new.name)
        .bind(&new.name)
        .bind(&new.ref_type)
        .bind(&new.description)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let rule_set_id = result.last_insert_id() as i64;
        // Operation identity 前置：projection/audit durable 写入之前把上下文升级
        // 为可证明稳定身份；缺失 header 时以锁定 head 代次确定性派生。新聚合 head
        // 缺失 ⇒ 代次 0，create 身份由新聚合主键 + kind token 保证唯一。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::CreateRuleSet,
            rule_set_id,
            context,
        )
        .await?;
        let projection = append_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            EVENT_TYPE_RULE_SET_UPDATE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
        )
        .await?;
        let new_value = serde_json::json!({
            "name": new.name,
            "refType": new.ref_type,
            "description": new.description,
        })
        .to_string();
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: None,
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "CREATE",
                old_value_json: None,
                new_value_json: Some(&new_value),
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(rule_set_id)
    }

    async fn update_rule_set(
        &self,
        rule_set_id: i64,
        patch: &RuleSetPatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        lock_rule_set_in_tx(&mut tx, rule_set_id).await?;
        // 锁定读回当前行，按实际写入值检测可变字段变更。source_type 是所有权
        // 判别器，generic update 不可变：UPDATE 不写 source_type，patch 也不携带。
        let current: (String, Option<String>) =
            sqlx::query_as("SELECT name, description FROM rule_set WHERE rule_set_id = ?")
                .bind(rule_set_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_error)?;
        let changes = generic_rule_set_update_changes(
            &current.0,
            current.1.as_deref(),
            &patch.name,
            patch.description.as_deref(),
        );
        if !changes.any() {
            // 幂等更新：没有任何可变字段实际变化 ⇒ 无 source mutation、无投影、
            // 无审计（审计只记录实际变更的字段；空变更集没有可审计内容）。
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }
        // Operation identity 前置：source UPDATE 与任何 projection/audit durable
        // 写入之前把上下文升级为可证明稳定身份（缺失 header 时锁定 head 代次
        // 确定性派生），与既有条目/绑定 mutation 同一契约。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::UpdateRuleSet,
            rule_set_id,
            context,
        )
        .await?;
        sqlx::query("UPDATE rule_set SET name=?, description=? WHERE rule_set_id=?")
            .bind(&patch.name)
            .bind(&patch.description)
            .bind(rule_set_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        let projection = append_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            EVENT_TYPE_RULE_SET_UPDATE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
        )
        .await?;
        // 审计只包含实际变更的字段：old_value 是变更前值，new_value 是变更后值；
        // refType/source_type 永不出现在 generic update 审计里（不可变字段）。
        let mut new_value = serde_json::Map::new();
        let mut old_value = serde_json::Map::new();
        if changes.name {
            new_value.insert("name".into(), serde_json::json!(&patch.name));
            old_value.insert("name".into(), serde_json::json!(&current.0));
        }
        if changes.description {
            new_value.insert("description".into(), serde_json::json!(&patch.description));
            old_value.insert("description".into(), serde_json::json!(&current.1));
        }
        let new_value = serde_json::Value::Object(new_value).to_string();
        let old_value = serde_json::Value::Object(old_value).to_string();
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: None,
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "UPDATE",
                old_value_json: Some(&old_value),
                new_value_json: Some(&new_value),
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        append_bound_card_projections_in_tx(&mut tx, rule_set_id, EVENT_TYPE_RULE_SET_UPDATE)
            .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn delete_rule_set(
        &self,
        rule_set_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let source: Option<(i64, Option<i64>)> = sqlx::query_as(
            "SELECT rule_set_id, tenant_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE",
        )
        .bind(rule_set_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((_, source_tenant_id)) = source else {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        };
        // Operation identity 前置：capture-before-delete 与任何 durable 写入之前
        // 把上下文升级为可证明稳定身份；缺失 header 时锁定 head 代次确定性派生。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::DeleteRuleSet,
            rule_set_id,
            context,
        )
        .await?;
        // D1 修复：capture-before-delete。先锁定并读出全部条目与绑定事实，
        // 为 entry × ref × 卡 全组合物化版本化 REMOVE；任一贡献失败即整体回滚，
        // 不允许留下与新读链冲突的活动幽灵授权。
        let entries = read_rule_set_entries_in_tx(&mut tx, rule_set_id, false).await?;
        let allow_entries = materializable_allow_entries(&entries)?;
        let proven_refs = provable_bound_cards_in_tx(&mut tx, rule_set_id, None).await?;
        let contributions = append_ruleset_deletion_removal_deltas_in_tx(
            &mut tx,
            rule_set_id,
            &proven_refs,
            &allow_entries,
            context,
        )
        .await?;

        // Capture tenant_id before DELETE: RuleSet projection identity must keep
        // the source tenant even though the worker later observes no source row.
        // 父 RULE_SET REVOKE 投影事件只承担 source correlation，不再充当任何 delta
        // 的 event id（各贡献独立派生事件号）。
        let projection = append_rule_set_projection_with_tenant_in_tx(
            &mut tx,
            rule_set_id,
            EVENT_TYPE_REVOKE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
            source_tenant_id,
        )
        .await?;
        // 审计 detail 关联 parent source 事件与全部贡献维度；legacy DELETE 语义
        // （change_type / REVOKE / tenant）保持不变。
        let old_value = ruleset_removal_audit_old_value(
            serde_json::json!({ "ruleSetId": rule_set_id }),
            &projection.event_id,
            &contributions,
        );
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: None,
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "DELETE",
                old_value_json: Some(&old_value),
                new_value_json: None,
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        // Source deletion runs last inside the same transaction: every versioned
        // ledger REMOVE, the legacy RULE_SET projection, its audit correlation, and
        // one metadata-bearing CARD REVOKE per distinct bound card were written
        // above from locked captures.
        let result = sqlx::query("DELETE FROM rule_set WHERE rule_set_id=?")
            .bind(rule_set_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 0 {
            // 不可能分支（行已在同事务内 FOR UPDATE 锁定读出）：命中 0 行意味着
            // 持久层不变式破坏。此时版本化 REMOVE delta、RULE_SET REVOKE 投影与
            // 审计 correlation 已写入但 source 行未删除 —— 提交会留下与授权读链
            // 冲突的部分删除状态；必须整体回滚并失败，而不是提交半删除快照。
            tx.rollback().await.map_err(db_error)?;
            return Err(AstralError::Internal(format!(
                "rule set {rule_set_id} delete matched zero rows inside its own locked \
                 transaction; rolled back to avoid committing partial projection/ledger state"
            )));
        }
        tx.commit().await.map_err(db_error)?;
        // 读链规模化 Batch E：规则集删除的全部 REMOVE 贡献事件面（卡 → 租户映射
        // 来自提交前锁定的 proven cards）；影响面超阈值或任何失败由 sync_publish
        // 降级为 worker 消化，绝不阻塞本次写请求。
        let tenant_by_card: std::collections::HashMap<i64, i64> = proven_refs
            .iter()
            .map(|bound| (bound.card_id, bound.tenant_id))
            .collect();
        let sync_surfaces: Vec<RuleSetSyncSurface> = contributions
            .iter()
            .filter_map(|contribution| {
                tenant_by_card
                    .get(&contribution.card_id)
                    .map(|tenant_id| RuleSetSyncSurface {
                        tenant_id: *tenant_id,
                        card_id: contribution.card_id,
                        event_id: contribution.event_id.clone(),
                    })
            })
            .collect();
        commit_sync_publish(&self.db, sync_surfaces).await;
        Ok(true)
    }

    async fn list_entries(&self, rule_set_id: i64) -> Result<Vec<RuleSetEntryRow>, AstralError> {
        sqlx::query_as::<_, RuleSetEntryRow>(&format!(
            "SELECT {ENTRY_SELECT} FROM rule_set_entry WHERE rule_set_id=? ORDER BY priority"
        ))
        .bind(rule_set_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn add_entry(
        &self,
        rule_set_id: i64,
        new: &NewRuleSetEntry,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        // 防御加固：repository 不是校验旁路；写入归一化后的 canonical ALLOW。
        let effect = validate_entry_fields(
            &new.effect,
            new.resource.as_deref(),
            new.action.as_deref(),
            new.condition_json.as_deref(),
        )?;
        // source entry、RULE_SET projection 与受影响卡 projection 在同一事务内提交。
        let mut tx = self.db.begin().await.map_err(db_error)?;
        lock_rule_set_in_tx(&mut tx, rule_set_id).await?;
        // Operation identity 前置：任何 durable 写入之前把上下文升级为可证明
        // 稳定身份；缺失 x-request-id 时以锁定的 RULE_SET 投影代次确定性派生，
        // 派生值贯穿后续 source/投影/审计/账本/delta 全链。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::AddEntry,
            rule_set_id,
            context,
        )
        .await?;
        let result = sqlx::query(
            "INSERT INTO rule_set_entry (rule_set_id, effect, resource_type, resource_id, action_code, condition_json, priority, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        )
        .bind(rule_set_id)
        .bind(&effect)
        .bind(&new.resource)
        .bind(new.resource_id)
        .bind(&new.action)
        .bind(&new.condition_json)
        .bind(new.priority)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let entry_id = result.last_insert_id() as i64;
        let event_type = event_type_for_effect(&effect);
        let projection = append_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            event_type,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
        )
        .await?;
        let new_value = serde_json::json!({
            "entryId": entry_id,
            "effect": effect,
            "resource": new.resource,
            "resourceId": new.resource_id,
            "action": new.action,
            "priority": new.priority,
        })
        .to_string();
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: Some(entry_id),
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "CREATE",
                old_value_json: None,
                new_value_json: Some(&new_value),
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        // 锁定读回刚插入的 source 行：物化输入必须来自真实锁定行（含有效期列），
        // 而不是请求参数的内存复制品；随后为每个可证明绑定卡物化 ALLOW ADD 贡献。
        let stored_entry = lock_rule_set_entry_in_tx(&mut tx, rule_set_id, entry_id)
            .await?
            .ok_or_else(|| {
                AstralError::Internal(format!(
                    "rule set entry {entry_id} vanished inside its own creation transaction"
                ))
            })?;
        let allow_entries = materializable_allow_entries(std::slice::from_ref(&stored_entry))?;
        // 影响面透出（读链规模化 Batch E）：捕获全部 ADD 贡献的租户/卡/事件号，
        // 供 source 提交后的同步发布目标定位；失败不阻塞（函数内部保证）。
        let sync_surfaces: Vec<RuleSetSyncSurface> = append_ruleset_entry_add_fanout_in_tx(
            &mut tx,
            rule_set_id,
            &allow_entries,
            None,
            event_type,
            context,
        )
        .await?
        .into_iter()
        .map(|contribution| RuleSetSyncSurface {
            tenant_id: contribution.tenant_id,
            card_id: contribution.card_id,
            event_id: contribution.event_id,
        })
        .collect();
        tx.commit().await.map_err(db_error)?;
        commit_sync_publish(&self.db, sync_surfaces).await;
        Ok(entry_id)
    }
    async fn update_entry(
        &self,
        rule_set_id: i64,
        entry_id: i64,
        patch: &RuleSetEntryPatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        // 防御加固：repository 不是校验旁路；最终写入 effect 必须为 ALLOW。
        let effect = validate_entry_fields(
            &patch.effect,
            patch.resource.as_deref(),
            patch.action.as_deref(),
            patch.condition_json.as_deref(),
        )?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        lock_rule_set_in_tx(&mut tx, rule_set_id).await?;
        // Operation identity 前置：before-image 锁定与任何 durable 写入之前把
        // 上下文升级为可证明稳定身份（缺失 header 时锁定 head 代次确定性派生）。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::UpdateEntry,
            rule_set_id,
            context,
        )
        .await?;
        // 写前锁定并读取完整旧条目行（全量列 + UTC 有效期文本），
        // versioned before-image 与 identity 维度都来自这一份锁定快照。
        let old_entry = lock_rule_set_entry_in_tx(&mut tx, rule_set_id, entry_id)
            .await?
            .ok_or_else(|| AstralError::NotFound(format!("rule set entry {entry_id} not found")))?;
        sqlx::query(
            "UPDATE rule_set_entry SET effect=?, resource_type=?, resource_id=?, action_code=?, condition_json=?, priority=? \
             WHERE entry_id=? AND rule_set_id=?",
        )
        .bind(&effect)
        .bind(&patch.resource)
        .bind(patch.resource_id)
        .bind(&patch.action)
        .bind(&patch.condition_json)
        .bind(patch.priority)
        .bind(entry_id)
        .bind(rule_set_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        // legacy DB 值仅用于判断既有 REVOKE 语义；新写入值恒为 ALLOW
        let event_type = if event_type_for_effect(&old_entry.effect) == EVENT_TYPE_REVOKE
            || event_type_for_effect(&effect) == EVENT_TYPE_REVOKE
        {
            EVENT_TYPE_REVOKE
        } else {
            EVENT_TYPE_RULE_SET_UPDATE
        };
        let projection = append_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            event_type,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
        )
        .await?;
        let new_value = serde_json::json!({
            "entryId": entry_id,
            "effect": effect,
            "resource": patch.resource,
            "resourceId": patch.resource_id,
            "action": patch.action,
            "priority": patch.priority,
        })
        .to_string();
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: Some(entry_id),
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "UPDATE",
                old_value_json: Some(old_entry.effect.as_str()),
                new_value_json: Some(&new_value),
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        // 锁定读回更新后的行状态作为 UPDATE 物化输入；identity（source_entry）
        // 恒为 entry_id，可变属性 resource/action/validity 从真实锁定行读取。
        let updated_entry = lock_rule_set_entry_in_tx(&mut tx, rule_set_id, entry_id)
            .await?
            .ok_or_else(|| {
                AstralError::Internal(format!(
                    "rule set entry {entry_id} vanished inside its own update transaction"
                ))
            })?;
        let allow_entries = materializable_allow_entries(std::slice::from_ref(&updated_entry))?;
        let sync_surfaces = append_ruleset_entry_update_fanout_in_tx(
            &mut tx,
            rule_set_id,
            &allow_entries,
            event_type,
            context,
        )
        .await?;
        #[cfg(feature = "e1-observability")]
        {
            let stamp = policy_engine::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "source_commit_start",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                operation_id = context.operation_id(),
                mutation = "rule_set_entry_update",
                rule_set_id,
                entry_id,
                "e1 authorization observation"
            );
        }
        let commit_result = tx.commit().await;
        #[cfg(feature = "e1-observability")]
        {
            let stamp = policy_engine::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "source_commit_end",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                operation_id = context.operation_id(),
                mutation = "rule_set_entry_update",
                rule_set_id,
                entry_id,
                outcome = if commit_result.is_ok() { "committed" } else { "unknown" },
                "e1 authorization observation"
            );
        }
        commit_result.map_err(db_error)?;
        commit_sync_publish(&self.db, sync_surfaces).await;
        Ok(())
    }

    async fn delete_entry(
        &self,
        rule_set_id: i64,
        entry_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        lock_rule_set_in_tx(&mut tx, rule_set_id).await?;
        // Operation identity 前置：任何 durable 写入之前把上下文升级为可证明
        // 稳定身份；缺失 header 时锁定 head 代次确定性派生。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::DeleteEntry,
            rule_set_id,
            context,
        )
        .await?;
        // DELETE 前锁并取完整旧条目行（含 UTC 有效期与 canonical 字段）；
        // 绑定卡事实在 REMOVE fanout 内以同一锁序（refs → user_card → head）捕获。
        let old_entry = lock_rule_set_entry_in_tx(&mut tx, rule_set_id, entry_id).await?;
        let Some(old_entry) = old_entry else {
            return Ok(false);
        };
        let legacy_old_value = serde_json::json!({
            "entryId": old_entry.entry_id,
            "effect": old_entry.effect,
            "resource": old_entry.resource_type,
            "resourceId": old_entry.resource_id,
            "action": old_entry.action_code,
            "priority": old_entry.priority,
        })
        .to_string();
        sqlx::query("DELETE FROM rule_set_entry WHERE entry_id=? AND rule_set_id=?")
            .bind(entry_id)
            .bind(rule_set_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        let projection = append_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            EVENT_TYPE_REVOKE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
        )
        .await?;
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: Some(entry_id),
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "DELETE",
                old_value_json: Some(&legacy_old_value),
                new_value_json: None,
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        // 仅对 ENABLED+ALLOW 的旧条目物化 REMOVE tombstone：DENY/禁用行从未进入
        // 账本，没有可移除的授权贡献。未 backfill 的 ALLOW 旧数据在此显式拒绝。
        let allow_entries = materializable_allow_entries(std::slice::from_ref(&old_entry))?;
        let sync_surfaces =
            append_ruleset_entry_remove_fanout_in_tx(&mut tx, rule_set_id, &allow_entries, context)
                .await?;
        #[cfg(feature = "e1-observability")]
        {
            let stamp = policy_engine::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "source_commit_start",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                operation_id = context.operation_id(),
                mutation = "rule_set_entry_delete",
                rule_set_id,
                entry_id,
                "e1 authorization observation"
            );
        }
        let commit_result = tx.commit().await;
        #[cfg(feature = "e1-observability")]
        {
            let stamp = policy_engine::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "source_commit_end",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                operation_id = context.operation_id(),
                mutation = "rule_set_entry_delete",
                rule_set_id,
                entry_id,
                outcome = if commit_result.is_ok() { "committed" } else { "unknown" },
                "e1 authorization observation"
            );
        }
        commit_result.map_err(db_error)?;
        commit_sync_publish(&self.db, sync_surfaces).await;
        Ok(true)
    }

    async fn replace_entries(
        &self,
        rule_set_id: i64,
        entries: &[NewRuleSetEntry],
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        // 防御加固：repository 不是校验旁路；逐条校验并归一化 effect（恒为 ALLOW），
        // 任一条目非法时整批拒绝，无部分写入。
        let rows = entries
            .iter()
            .map(|entry| {
                Ok(NewRuleSetEntry {
                    effect: validate_entry_fields(
                        &entry.effect,
                        entry.resource.as_deref(),
                        entry.action.as_deref(),
                        entry.condition_json.as_deref(),
                    )?,
                    resource: entry.resource.clone(),
                    resource_id: entry.resource_id,
                    action: entry.action.clone(),
                    condition_json: entry.condition_json.clone(),
                    priority: entry.priority,
                })
            })
            .collect::<Result<Vec<_>, AstralError>>()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        lock_rule_set_in_tx(&mut tx, rule_set_id).await?;
        // capture → REMOVE → source churn → ADD → parent projection/audit 的完整
        // 编排由共享授权账本 churn 核心承担；模板同步与启动物化复用同一实现。
        replace_rule_set_entries_churn_with_ledger_in_tx(
            &mut tx,
            rule_set_id,
            &rows,
            None,
            LedgerChurnAuditContext {
                change_type: "BATCH_REPLACE_ENTRIES",
                old_value_base: serde_json::json!({ "ruleSetId": rule_set_id }),
                new_value: serde_json::json!({ "entryCount": rows.len() }),
            },
            context,
        )
        .await?;
        tx.commit().await.map_err(db_error)
    }

    async fn list_card_bindings(
        &self,
        card_id: i64,
    ) -> Result<Vec<CardRuleSetBindingRow>, AstralError> {
        sqlx::query_as::<_, CardRuleSetBindingRow>(
            "SELECT ref.rule_set_id, rs.name AS rule_set_name, rs.code AS rule_set_code, ref.ref_type \
             FROM card_rule_set_ref ref \
             INNER JOIN rule_set rs ON rs.rule_set_id = ref.rule_set_id \
             WHERE ref.card_id = ? ORDER BY ref.ref_type, ref.rule_set_id",
        )
        .bind(card_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn bind_card(
        &self,
        card_id: i64,
        rule_set_id: i64,
        ref_type: &str,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        if !matches!(ref_type, "BASE" | "OVERLAY") {
            return Err(AstralError::Validation(
                "ref_type must be BASE or OVERLAY".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let card_tenant_id = validate_card_binding_in_tx(&mut tx, card_id, rule_set_id).await?;
        // Operation identity 前置：绑定引用写入与任何投影/账本事件之前把上下文
        // 升级为可证明稳定身份（缺失 header 时锁定 RULE_SET head 代次派生）。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::BindCard,
            rule_set_id,
            context,
        )
        .await?;
        let ref_result = sqlx::query(
            "INSERT INTO card_rule_set_ref \
             (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, ?, ?)",
        )
        .bind(card_id)
        .bind(rule_set_id)
        .bind(ref_type)
        .bind(card_tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        // 新建绑定的稳定主键即本卡 RuleSet binding 身份的一等来源。
        let ref_id = i64::try_from(ref_result.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Internal("card_rule_set_ref insert returned an unusable id".into())
            })?;
        let projection = append_rule_set_projection_in_tx(
            &mut tx,
            rule_set_id,
            EVENT_TYPE_RULE_SET_UPDATE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
        )
        .await?;
        let new_value = serde_json::json!({ "cardId": card_id, "refType": ref_type }).to_string();
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: None,
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "BIND_CARD",
                old_value_json: None,
                new_value_json: Some(&new_value),
                tenant_id: projection.tenant_id,
            },
        )
        .await?;
        // 绑定时已有 ALLOW entries 的单卡 ADD 物化：条目在 RULE_SET 行锁保护下
        // 锁定读取（add/update/delete 均先锁 rule_set，天然串行），identity 用该卡
        // CARD RULE_SET_BOUND 投影事件（含 actor/operation metadata）作 generation
        // 依据。租户/用户/层无法完整证明时整体回滚；layer=ref_type BASE/OVERLAY。
        let existing_entries = read_rule_set_entries_in_tx(&mut tx, rule_set_id, true).await?;
        let allow_entries = materializable_allow_entries(&existing_entries)?;
        // 影响面透出（读链规模化 Batch E）：单卡绑定物化的全部 ADD 贡献事件号，
        // 供 source 提交后的同步发布目标定位。
        let sync_surfaces: Vec<RuleSetSyncSurface> = append_ruleset_entry_add_fanout_in_tx(
            &mut tx,
            rule_set_id,
            &allow_entries,
            Some(ref_id),
            "RULE_SET_BOUND",
            context,
        )
        .await?
        .into_iter()
        .map(|contribution| RuleSetSyncSurface {
            tenant_id: contribution.tenant_id,
            card_id: contribution.card_id,
            event_id: contribution.event_id,
        })
        .collect();
        tx.commit().await.map_err(db_error)?;
        commit_sync_publish(&self.db, sync_surfaces).await;
        Ok(())
    }

    async fn unbind_card(
        &self,
        card_id: i64,
        rule_set_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;

        // Lock order is deterministic across the binding and RuleSet delete
        // paths: card -> RuleSet source (when present) -> binding reference ->
        // enabled entries. Binding-side mutations take user_card first while
        // entry mutations take the rule_set row first; every side keeps its own
        // fixed internal order under the aggregate row lock, introducing no new
        // opposite ordering inside this transaction.
        let card: Option<(String, Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT card_status, tenant_id, user_id, domain_id FROM user_card WHERE card_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((card_status, card_tenant_id, card_user_id, card_domain_id)) = card else {
            return Err(AstralError::NotFound(format!(
                "user card {card_id} not found"
            )));
        };
        if card_status != "ACTIVE" {
            return Err(AstralError::Permission(
                "rule set unbinding requires an active user card".into(),
            ));
        }

        // A deleted RuleSet source is an orphan-cleanup case, not a missing
        // binding. Keep the captured source/ref tenant for the revoke event.
        let rule_set: Option<RuleSetUnbindSourceRow> =
            sqlx::query_as("SELECT tenant_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE")
                .bind(rule_set_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        let rule_set_source = rule_set.map_or(RuleSetUnbindSource::Missing, |row| {
            RuleSetUnbindSource::Present {
                tenant_id: row.tenant_id,
            }
        });

        let binding: Option<(i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT id, ref_type, tenant_id FROM card_rule_set_ref \
             WHERE card_id = ? AND rule_set_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .bind(rule_set_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((ref_id, ref_type, binding_tenant_id)) = binding else {
            // No source mutation and no projection/audit events for a missing
            // binding, including when the RuleSet source is already gone.
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        };

        validate_unbind_tenants(card_tenant_id, binding_tenant_id, rule_set_source)?;
        let captured_tenant_id = match rule_set_source {
            RuleSetUnbindSource::Missing => binding_tenant_id,
            RuleSetUnbindSource::Present { tenant_id } => tenant_id,
        };
        // Operation identity 前置：仅对确认存在的绑定执行；CARD REVOKE 投影、
        // REMOVE 贡献与审计在任何 durable 写入之前共享同一可证明稳定身份。
        let context = &stabilize_rule_set_operation_context(
            &mut tx,
            RuleSetLedgerOperationKind::UnbindCard,
            rule_set_id,
            context,
        )
        .await?;

        // D1 fix — capture-before-delete. Ownership facts were locked above
        // (user_card + binding reference); entries are locked next so versioned
        // REMOVE tombstones derive from one snapshot, and every contribution is
        // written BEFORE the source reference deletion. A missing RuleSet head
        // (old data never backfilled into the ledger) or any stale/gap/duplicate
        // conflict fails closed and rolls back the whole mutation; DENY and
        // disabled rows never entered the ledger and are skipped by classifier.
        let bound = unbind_bound_card_facts(
            ref_id,
            card_id,
            card_user_id,
            card_tenant_id,
            card_domain_id,
            ref_type,
        )?;
        let entries = read_rule_set_entries_in_tx(&mut tx, rule_set_id, true).await?;
        let allow_entries = materializable_allow_entries(&entries)?;
        let contributions = append_unbind_ruleset_removal_deltas_in_tx(
            &mut tx,
            rule_set_id,
            &bound,
            &allow_entries,
            context,
        )
        .await?;

        // The binding itself is a RuleSet authorization mutation. Use the
        // captured tenant even for a deleted source row so generation evidence
        // remains tenant-scoped after the source disappeared.
        let projection = append_rule_set_projection_with_tenant_in_tx(
            &mut tx,
            rule_set_id,
            EVENT_TYPE_REVOKE,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_id(),
                operation_id: context.operation_id(),
            },
            captured_tenant_id,
        )
        .await?;
        if projection.tenant_id != captured_tenant_id {
            return Err(AstralError::Permission(
                "RuleSet revoke projection tenant does not match binding scope".into(),
            ));
        }
        // Audit detail correlates the parent source event id plus every
        // contribution event / rule-set entry / bound card / binding ref id.
        let old_value = ruleset_removal_audit_old_value(
            serde_json::json!({
                "cardId": card_id,
                "tenantId": captured_tenant_id,
                "refId": bound.ref_id,
                "refType": bound.ref_type,
            }),
            &projection.event_id,
            &contributions,
        );
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id,
                entry_id: None,
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: rule_set_id,
                event_id: &projection.event_id,
                source_generation: projection.source_generation,
                operation_id: context.operation_id(),
                actor_id: context.actor_id(),
                change_type: "UNBIND_CARD",
                old_value_json: Some(&old_value),
                new_value_json: None,
                tenant_id: captured_tenant_id,
            },
        )
        .await?;

        // Source deletion runs last inside this transaction; every ledger REMOVE,
        // the legacy RULE_SET REVOKE projection/audit, and the metadata-bearing
        // CARD REVOKE identity anchor were written above from locked captures.
        let result = sqlx::query(
            "DELETE FROM card_rule_set_ref \
             WHERE card_id = ? AND rule_set_id = ? AND tenant_id <=> ?",
        )
        .bind(card_id)
        .bind(rule_set_id)
        .bind(binding_tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        tx.commit().await.map_err(db_error)?;
        // 读链规模化 Batch E：解绑属单卡影响面；贡献事件面由 REMOVE 物化捕获。
        let sync_surfaces = contributions
            .iter()
            .map(|contribution| RuleSetSyncSurface {
                tenant_id: bound.tenant_id,
                card_id: contribution.card_id,
                event_id: contribution.event_id.clone(),
            })
            .collect();
        commit_sync_publish(&self.db, sync_surfaces).await;
        Ok(true)
    }

    async fn count_templates(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM rule_set WHERE name LIKE '%admin%' OR name LIKE '%Template%'",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_templates(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuleSetSummary>, AstralError> {
        let rows = sqlx::query_as::<_, RuleSetRow>(&format!(
            "SELECT {RULE_SET_SELECT} FROM rule_set WHERE name LIKE '%admin%' OR name LIKE '%Template%' \
             ORDER BY rule_set_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        summarize(&self.db, rows).await
    }

    async fn create_rule_set_from_template(
        &self,
        template_id: i64,
        code: &str,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        // 幂等同步必须把 source entry、RULE_SET projection、绑定卡 CARD projection
        // 和授权账本 REMOVE+ADD 贡献放进同一事务；快照由 durable worker 在提交后
        // 重建。churn 编排（capture-before-delete / 严格插入 / 双相物化）与批量替换
        // 共享同一实现，模板 source 绝不当作 DIRECT，也不会留下旧 active ghost。
        let mut tx = self.db.begin().await.map_err(db_error)?;
        if code.trim().is_empty() {
            return Err(AstralError::Validation(
                "template RuleSet code must not be empty".into(),
            ));
        }
        let template: Option<(String, String, Option<i64>)> = sqlx::query_as(
            "SELECT template_code, template_name, tenant_id FROM user_card_template \
             WHERE template_id = ? AND status = 'ACTIVE' FOR UPDATE",
        )
        .bind(template_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((template_code, template_name, template_tenant_id)) = template else {
            return Err(AstralError::NotFound(format!(
                "active user card template {template_id}"
            )));
        };
        if template_code.trim().is_empty() {
            return Err(AstralError::Validation(format!(
                "template {template_id} has an empty template_code"
            )));
        }

        let existing_by_source: Option<(i64, String)> = sqlx::query_as(
            "SELECT rule_set_id, code FROM rule_set \
             WHERE source_type = 'TEMPLATE' AND source_id = ? FOR UPDATE",
        )
        .bind(template_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let rule_set_id = match existing_by_source {
            Some((id, existing_code)) => {
                if existing_code != code {
                    return Err(AstralError::Validation(format!(
                        "template {template_id} is already owned by RuleSet code {existing_code}"
                    )));
                }
                let existing_tenant_id: Option<i64> =
                    sqlx::query_scalar("SELECT tenant_id FROM rule_set WHERE rule_set_id = ?")
                        .bind(id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_error)?;
                if existing_tenant_id != template_tenant_id {
                    return Err(AstralError::Validation(format!(
                        "template {template_id} RuleSet tenant_id does not match its template"
                    )));
                }
                id
            }
            None => {
                let conflicting_code: Option<(i64, String)> = sqlx::query_as(
                    "SELECT rule_set_id, source_type FROM rule_set WHERE code = ? FOR UPDATE",
                )
                .bind(code)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
                if let Some((conflicting_id, source_type)) = conflicting_code {
                    return Err(AstralError::Validation(format!(
                        "template RuleSet code {code} is already owned by rule set {conflicting_id} ({source_type})"
                    )));
                }
                let result = sqlx::query(
                    "INSERT INTO rule_set (name, code, source_type, source_id, description, enabled, tenant_id) \
                     VALUES (?, ?, 'TEMPLATE', ?, '从权限模板投影生成', 1, ?)",
                )
                .bind(&template_name)
                .bind(code)
                .bind(template_id)
                .bind(template_tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                result.last_insert_id() as i64
            }
        };

        // ── 模板规则读取与 ALLOW-only 校验（fail-closed）：遗留 DENY 模板行整批
        // 拒绝，不自动转换旧数据 ──
        let fetched_template_rules =
            sqlx::query_as::<_, (String, String, Option<i64>, String, Option<String>, i32)>(
                "SELECT effect, resource_type, resource_id, action_code, condition_json, priority \
             FROM permission_rule_template WHERE template_id = ? AND enabled = 1 \
             ORDER BY priority DESC, template_rule_id FOR UPDATE",
            )
            .bind(template_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(db_error)?;
        let rows = fetched_template_rules
            .into_iter()
            .map(
                |(effect, resource_type, resource_id, action_code, condition_json, priority)| {
                    // 归一化 effect（恒为 ALLOW）后组装为规则集条目请求行。
                    let effect = validate_entry_fields(
                        &effect,
                        Some(&resource_type),
                        Some(&action_code),
                        condition_json.as_deref(),
                    )?;
                    Ok(NewRuleSetEntry {
                        effect,
                        resource: Some(resource_type),
                        resource_id,
                        action: Some(action_code),
                        condition_json,
                        priority,
                    })
                },
            )
            .collect::<Result<Vec<_>, AstralError>>()?;

        replace_rule_set_entries_churn_with_ledger_in_tx(
            &mut tx,
            rule_set_id,
            &rows,
            None,
            LedgerChurnAuditContext {
                change_type: "TEMPLATE_SYNC",
                old_value_base: serde_json::json!({ "templateId": template_id }),
                new_value: serde_json::json!({
                    "templateId": template_id,
                    "entryCount": rows.len(),
                }),
            },
            context,
        )
        .await?;

        tx.commit().await.map_err(db_error)?;
        tracing::info!(
            rule_set_id,
            template_id,
            entries = rows.len(),
            "rule set synced from template"
        );
        Ok(rule_set_id)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Rule set repository query failed: {error}"))
}

/// 读链规模化 Batch E：source 事务 commit 成功后的同步发布接线点。
///
/// 把本事务物化的全部 contribution 事件面按卡聚合后交给
/// `service::sync_publish::after_commit_sync_publish`：影响面（受影响卡数）≤
/// 阈值 → 以 worker 同一原语在请求内尝试发布；> 阈值或任何失败（claim 竞争/
/// 发布错误/超时）→ 仅记日志，保持 worker 异步消化，绝不阻塞写请求。
async fn commit_sync_publish(pool: &sqlx::MySqlPool, surfaces: Vec<RuleSetSyncSurface>) {
    let targets = crate::service::sync_publish::group_targets(
        surfaces
            .into_iter()
            .map(|surface| (surface.tenant_id, surface.card_id, surface.event_id))
            .collect(),
    );
    crate::service::sync_publish::after_commit_sync_publish(pool, targets).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_create_source_type_reservation_is_fail_closed() {
        // TEMPLATE 是模板投影路径专属的所有权判别器，大小写与首尾空白不敏感保留。
        for rejected in [
            "TEMPLATE",
            "template",
            "Template",
            " TEMPLATE ",
            "\ttemplate\n",
        ] {
            let error = validate_generic_rule_set_source_type(rejected).unwrap_err();
            assert!(
                matches!(&error, AstralError::Validation(message) if message.contains("reserved")),
                "rejected={rejected:?} unexpected={error:?}"
            );
        }
        // 空 source_type 让所有权判别器失去判别能力，同样 INSERT 前 fail-closed。
        for empty in ["", "   "] {
            let error = validate_generic_rule_set_source_type(empty).unwrap_err();
            assert!(
                matches!(&error, AstralError::Validation(message) if message.contains("must not be empty")),
                "empty={empty:?} unexpected={error:?}"
            );
        }
        for accepted in ["BASE", "OVERLAY", "CUSTOM", " platform "] {
            validate_generic_rule_set_source_type(accepted)
                .unwrap_or_else(|error| panic!("accepted={accepted:?} unexpected={error:?}"));
        }
    }

    #[test]
    fn parent_rule_set_writes_have_dedicated_operation_kinds() {
        // create/update 也写 durable projection + audit correlation，必须与既有
        // 条目/绑定操作共享同一 operation identity 契约：专属 kind token。
        assert_eq!(
            RuleSetLedgerOperationKind::CreateRuleSet.as_str(),
            "create-rule-set"
        );
        assert_eq!(
            RuleSetLedgerOperationKind::UpdateRuleSet.as_str(),
            "update-rule-set"
        );
        // 穷举锁定 kind token 集合：新增 variant 必须带来唯一 token。
        let kinds = [
            RuleSetLedgerOperationKind::CreateRuleSet,
            RuleSetLedgerOperationKind::UpdateRuleSet,
            RuleSetLedgerOperationKind::AddEntry,
            RuleSetLedgerOperationKind::UpdateEntry,
            RuleSetLedgerOperationKind::DeleteEntry,
            RuleSetLedgerOperationKind::BindCard,
            RuleSetLedgerOperationKind::UnbindCard,
            RuleSetLedgerOperationKind::DeleteRuleSet,
        ];
        let mut tokens: Vec<&'static str> = kinds.iter().map(|kind| kind.as_str()).collect();
        let distinct = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(
            tokens.len(),
            distinct,
            "operation kind tokens must be unique"
        );
    }

    #[test]
    fn create_and_update_operation_identity_is_kind_scoped_and_generation_derived() {
        // 派生是确定性的：同 kind + 同聚合 + 同代次重放得到同一 operation id。
        let create = derive_rule_set_operation_id(RuleSetLedgerOperationKind::CreateRuleSet, 42, 7);
        assert_eq!(
            create,
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::CreateRuleSet, 42, 7)
        );
        assert!(
            create.starts_with("rule-set:create-rule-set:42:gen:7"),
            "unexpected derivation shape: {create}"
        );
        // 同聚合同代次：不同操作种类必然分叉（与既有条目/绑定操作不共享身份）。
        assert_ne!(
            create,
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::UpdateRuleSet, 42, 7)
        );
        // 代次推进派生新身份；不同聚合天然分叉。
        assert_ne!(
            create,
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::CreateRuleSet, 42, 8)
        );
        assert_ne!(
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::UpdateRuleSet, 42, 7),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::UpdateRuleSet, 43, 7)
        );
    }

    #[test]
    fn generic_update_change_detection_audits_only_actually_changed_fields() {
        // source_type 不在可变字段集合：检测函数没有它的入参（source 形状约束），
        // 审计因此只会包含 name/description 中实际变化的字段。
        let none = generic_rule_set_update_changes("n", Some("d"), "n", Some("d"));
        assert_eq!(
            none,
            GenericRuleSetUpdateChanges {
                name: false,
                description: false
            }
        );
        assert!(!none.any());
        let name_only = generic_rule_set_update_changes("n", Some("d"), "n2", Some("d"));
        assert!(name_only.name && !name_only.description && name_only.any());
        let desc_only = generic_rule_set_update_changes("n", Some("d"), "n", Some("d2"));
        assert!(!desc_only.name && desc_only.description && desc_only.any());
        // None 与 Some("") 是不同值：按实际写入值比较，不做静默归一化。
        let none_to_empty = generic_rule_set_update_changes("n", None, "n", Some(""));
        assert!(!none_to_empty.name && none_to_empty.description);
        let both = generic_rule_set_update_changes("a", None, "b", Some("d"));
        assert!(both.name && both.description && both.any());
    }

    #[test]
    fn generic_update_patch_shape_has_no_source_type_mutation_field() {
        // 编译期 source 形状测试：RuleSetPatch 不携带 ref_type/source_type 字段，
        // generic update 在类型层面不可能改写所有权判别器。
        let patch = RuleSetPatch {
            name: "n".into(),
            description: Some("d".into()),
        };
        // 仅 name 变化：description 与当前值相同 ⇒ 变更集只含 name。
        let changes = generic_rule_set_update_changes(
            &patch.name,
            patch.description.as_deref(),
            "n2",
            patch.description.as_deref(),
        );
        assert!(changes.name);
        assert!(!changes.description);
    }

    #[test]
    fn binding_same_tenant_is_allowed() {
        assert!(validate_binding_tenants(Some(1), Some(1)).is_ok());
    }

    #[test]
    fn binding_cross_tenant_is_rejected() {
        let error = validate_binding_tenants(Some(1), Some(2)).unwrap_err();
        assert!(
            matches!(error, AstralError::Permission(message) if message.contains("cross-tenant"))
        );
    }

    #[test]
    fn binding_tenantless_rule_set_in_tenant_context_is_rejected() {
        let error = validate_binding_tenants(None, Some(1)).unwrap_err();
        assert!(
            matches!(error, AstralError::Permission(message) if message.contains("without tenant_id"))
        );
    }

    #[test]
    fn binding_tenantless_card_is_rejected_for_tenant_scoped_rule_set() {
        let error = validate_binding_tenants(Some(1), None).unwrap_err();
        assert!(
            matches!(error, AstralError::Permission(message) if message.contains("tenantless card"))
        );
    }

    #[test]
    fn binding_tenantless_card_is_allowed_only_for_tenantless_rule_set() {
        assert!(validate_binding_tenants(None, None).is_ok());
    }

    #[test]
    fn ruleset_projection_event_types_and_statuses_are_explicit() {
        assert!(rule_set_projection_event_type_is_supported(
            EVENT_TYPE_RULE_SET_UPDATE
        ));
        assert!(rule_set_projection_event_type_is_supported(
            EVENT_TYPE_REVOKE
        ));
        assert!(!rule_set_projection_event_type_is_supported("CARD_UPDATE"));
        // Both event types are valid RuleSet source history; the helper proves
        // identity, generation, status, payload, and audits rather than using
        // event type as an authorization decision.
        assert!(rule_set_projection_event_status_is_acceptable("PENDING"));
        assert!(rule_set_projection_event_status_is_acceptable("PROCESSED"));
        assert!(!rule_set_projection_event_status_is_acceptable("FAILED"));
    }

    #[test]
    fn ruleset_projection_event_identity_validates_type_status_and_payload() {
        let payload = serde_json::json!({
            "actorId": SYSTEM_ACTOR_ID,
            "operationId": "ruleset:test",
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
        assert!(rule_set_projection_event_is_valid(&event, 9, 3, Some(7)));

        let mut invalid = event.clone();
        invalid.event_type = "CARD_UPDATE".into();
        assert!(!rule_set_projection_event_is_valid(&invalid, 9, 3, Some(7)));
        invalid = event.clone();
        invalid.status = "FAILED".into();
        assert!(!rule_set_projection_event_is_valid(&invalid, 9, 3, Some(7)));
        invalid = event;
        invalid.event_type = EVENT_TYPE_REVOKE.into();
        // REVOKE is valid current RuleSet source history (for example, a deny
        // entry or binding removal), so it remains eligible for proof when its
        // identity, payload, generation, status, and audits are valid.
        assert!(rule_set_projection_event_is_valid(&invalid, 9, 3, Some(7)));
    }

    #[test]
    fn ruleset_projection_proof_accepts_worker_window_but_requires_ready_rebuild_audit() {
        // A valid PENDING event is a worker window, so it must not trigger a
        // duplicate RULE_SET_UPDATE merely because the worker has not marked it
        // processed yet.
        assert!(rule_set_projection_evidence_is_valid(true, 1));
        assert!(!rule_set_projection_evidence_is_valid(true, 0));
        assert!(!rule_set_projection_evidence_is_valid(false, 1));
    }

    #[test]
    fn unbind_requires_card_ref_identity_and_source_identity_when_present() {
        assert!(validate_unbind_tenants(
            Some(7),
            Some(7),
            RuleSetUnbindSource::Present { tenant_id: Some(7) }
        )
        .is_ok());
        assert!(validate_unbind_tenants(
            None,
            None,
            RuleSetUnbindSource::Present { tenant_id: None }
        )
        .is_ok());
        assert!(validate_unbind_tenants(Some(7), Some(7), RuleSetUnbindSource::Missing).is_ok());
        assert!(validate_unbind_tenants(Some(7), Some(8), RuleSetUnbindSource::Missing).is_err());
        assert!(validate_unbind_tenants(
            Some(7),
            Some(7),
            RuleSetUnbindSource::Present { tenant_id: None }
        )
        .is_err());
        assert!(validate_unbind_tenants(
            None,
            None,
            RuleSetUnbindSource::Present { tenant_id: Some(7) }
        )
        .is_err());
        assert!(validate_unbind_tenants(
            Some(7),
            Some(8),
            RuleSetUnbindSource::Present { tenant_id: Some(8) }
        )
        .is_err());
    }

    #[test]
    fn unbind_source_contains_deterministic_locks_null_safe_delete_and_revoke_evidence() {
        let source = include_str!("rule_set_repository.rs");
        let unbind = source
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .and_then(|body| body.split("async fn unbind_card").nth(1))
            .and_then(|body| body.split("async fn count_templates").next())
            .expect("unbind_card implementation must remain available");
        let card_lock = unbind
            .find("SELECT card_status, tenant_id, user_id, domain_id FROM user_card")
            .expect("unbind must lock the card and capture ownership facts");
        let source_lock = unbind
            .find("SELECT tenant_id FROM rule_set")
            .expect("unbind must lock an existing RuleSet source");
        let ref_lock = unbind
            .find("SELECT id, ref_type, tenant_id FROM card_rule_set_ref")
            .expect("unbind must lock the binding reference");
        assert!(card_lock < source_lock && source_lock < ref_lock);
        assert!(unbind.contains("tenant_id <=> ?"));
        assert!(unbind.contains("append_rule_set_projection_with_tenant_in_tx"));
        assert!(unbind.contains("EVENT_TYPE_REVOKE"));
        // CARD 投影必须携带 actor/operation 元数据（账本 delta 的 generation/fence
        // 锚点）：该投影由共享的解绑移除驱动器统一追加；解绑体内不得再出现丢弃
        // 身份的兼容入口调用。
        assert!(
            unbind.contains("append_unbind_ruleset_removal_deltas_in_tx"),
            "the metadata-bearing CARD REVOKE is appended by the shared removal driver"
        );
        assert!(source.contains("append_card_projection_with_metadata_in_tx"));
        assert!(!unbind.contains("append_card_projection_in_tx("));
        assert!(!unbind.contains("enabled = 1"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RuleSet 授权账本物化接线（ALLOW-only + 版本化全增量）
    // ─────────────────────────────────────────────────────────────────────────

    fn entry_row(effect: &str, enabled: i32) -> LockedRuleSetEntryRow {
        LockedRuleSetEntryRow {
            entry_id: 5077,
            effect: effect.to_owned(),
            resource_type: Some("learn_course".to_owned()),
            resource_id: Some(3),
            action_code: Some("read".to_owned()),
            condition_json: None,
            priority: 5,
            enabled,
            valid_from: None,
            valid_to: None,
        }
    }

    #[test]
    fn materializable_allow_entries_classification_is_fail_closed() {
        let rows = [
            entry_row("ALLOW", 1),
            entry_row("deny", 1),
            entry_row("ALLOW", 0),
        ];
        let allowed = materializable_allow_entries(&rows).unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].entry_id, 5077);

        let unknown = [entry_row("AUDIT", 1)];
        assert!(matches!(
            materializable_allow_entries(&unknown),
            Err(AstralError::Validation(message)) if message.contains("unknown effect")
        ));
    }

    #[test]
    fn materialization_requires_provable_canonical_fields() {
        let mut row = entry_row("ALLOW", 1);
        row.resource_type = None;
        assert!(matches!(
            canonical_entry_grant_fields(&row),
            Err(AstralError::Validation(_))
        ));
        row.resource_type = Some("learn_course".to_owned());
        row.action_code = Some("   ".to_owned());
        assert!(matches!(
            canonical_entry_grant_fields(&row),
            Err(AstralError::Validation(_))
        ));
    }

    /// 结构守卫：add_entry 在既有事务内保持原锁序，并在 source 写入、RULE_SET
    /// 投影与 legacy 审计之后执行带 CARD 投影身份的 ADD fanout。
    #[test]
    fn add_entry_orders_source_projection_audit_then_ledger_fanout() {
        let impl_body = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .expect("repository implementation must remain available")
            .to_owned();
        let add = impl_body
            .split("async fn add_entry")
            .nth(1)
            .and_then(|body| body.split("async fn update_entry").next())
            .expect("add_entry implementation must remain available");
        let insert = add
            .find("INSERT INTO rule_set_entry")
            .expect("source insert");
        let projection = add
            .find("append_rule_set_projection_in_tx")
            .expect("RULE_SET projection");
        let audit = add
            .find("insert_rule_set_projection_audit_in_tx")
            .expect("legacy audit");
        let relock = add
            .find("lock_rule_set_entry_in_tx")
            .expect("locked re-read");
        let fanout = add
            .find("append_ruleset_entry_add_fanout_in_tx")
            .expect("ledger ADD fanout");
        assert!(insert < projection && projection < audit && audit < relock && relock < fanout);
        assert!(!add.contains("append_bound_card_projections_in_tx"));

        // Fanout 内部锁序：绑定引用（FOR UPDATE）→ 归属卡事实 → CARD 投影身份 →
        // 贡献事件派生 → ADD rev1 append。（fanout 位于 impl 块之前的模块层。）
        let fanout_body = include_str!("rule_set_repository.rs")
            .split("async fn append_ruleset_entry_add_fanout_in_tx")
            .nth(1)
            .and_then(|body| {
                body.split("async fn append_ruleset_entry_update_fanout_in_tx")
                    .next()
            })
            .expect("ADD fanout implementation must remain available");
        let provable = fanout_body.find("provable_bound_cards_in_tx").unwrap();
        let card_projection = fanout_body
            .find("append_card_projection_with_metadata_in_tx")
            .unwrap();
        let contribution = fanout_body
            .find("derive_ruleset_contribution_event_id")
            .unwrap();
        let draft = fanout_body.find("build_ruleset_add_draft").unwrap();
        let delta_version = fanout_body.find("next_delta_version(None)").unwrap();
        let append = fanout_body
            .find("append_ruleset_grant_delta_in_tx")
            .unwrap();
        assert!(provable < card_projection);
        assert!(card_projection < contribution && contribution < draft);
        assert!(draft < delta_version && delta_version < append);
        assert!(fanout_body.contains("ProjectionEventMetadata"));
    }

    #[test]
    fn update_and_delete_materialize_via_locked_rows_without_legacy_fanout() {
        let impl_body = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .expect("repository implementation must remain available")
            .to_owned();
        let update = impl_body
            .split("async fn update_entry")
            .nth(1)
            .and_then(|body| body.split("async fn delete_entry").next())
            .expect("update_entry implementation must remain available");
        let old_lock = update
            .find("lock_rule_set_entry_in_tx")
            .expect("old row lock");
        let source_update = update.find("UPDATE rule_set_entry").expect("source update");
        assert!(
            old_lock < source_update,
            "before-image lock precedes the write"
        );
        assert!(update.contains("change_type: \"UPDATE\""));
        assert!(update.contains("append_ruleset_entry_update_fanout_in_tx"));
        assert!(!update.contains("append_bound_card_projections_in_tx"));

        let delete = impl_body
            .split("async fn delete_entry")
            .nth(1)
            .and_then(|body| body.split("async fn replace_entries").next())
            .expect("delete_entry implementation must remain available");
        let delete_lock = delete
            .find("lock_rule_set_entry_in_tx")
            .expect("old row lock");
        let source_delete = delete
            .find("DELETE FROM rule_set_entry")
            .expect("source delete");
        assert!(
            delete_lock < source_delete,
            "DELETE happens after the locked read"
        );
        assert!(
            delete.contains("EVENT_TYPE_REVOKE"),
            "source REVOKE event type must be retained"
        );
        assert!(delete.contains("change_type: \"DELETE\""));
        assert!(delete.contains("materializable_allow_entries"));
        assert!(delete.contains("append_ruleset_entry_remove_fanout_in_tx"));
        assert!(!delete.contains("append_bound_card_projections_in_tx"));
    }

    /// 2026-09-04 收窄 UPDATE 闭合守卫：update fanout 内每卡先锁定全部条目
    /// grant head 并做 authorization-content 比较（head 先于 CARD 父投影事件），
    /// 任一条目内容变化 ⟹ 该卡父事件改用 REVOKE 语义抬 fence（delta 未发布
    /// 期间严格 reader 的 source-freshness 门命中）；全部条目 provenance-only/
    /// no-op ⟹ 保持调用方 event type。
    #[test]
    fn update_fanout_gates_the_card_parent_event_on_authorization_content() {
        let fanout_body = include_str!("rule_set_repository.rs")
            .split("async fn append_ruleset_entry_update_fanout_in_tx")
            .nth(1)
            .and_then(|body| {
                body.split("async fn append_ruleset_entry_remove_fanout_in_tx")
                    .next()
            })
            .expect("UPDATE fanout implementation must remain available");
        let head_lock = fanout_body
            .find("read_grant_head_for_update_in_tx")
            .expect("entry grant heads must be locked before the CARD parent event");
        let content_gate = fanout_body
            .find("ruleset_update_authorization_content_changed")
            .expect("UPDATE fanout must compare before-image vs new grant content");
        let card_projection = fanout_body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("CARD parent event must exist");
        assert!(
            head_lock < content_gate && content_gate < card_projection,
            "heads -> authorization-content gate -> CARD parent event must stay ordered"
        );
        assert!(
            fanout_body.contains("EVENT_TYPE_REVOKE"),
            "content-changing entry updates must raise the fence via a REVOKE-class CARD parent event"
        );
        // no-op 分支保持调用方 event type：调用方实参名必须在 REVOKE 分支之外被消费。
        assert!(
            fanout_body.contains("card_event_type"),
            "provenance-only/no-op updates must keep the caller's original event type"
        );
    }

    #[test]
    fn bind_card_scopes_adds_to_the_new_ref_under_rule_set_bound_event() {
        let bind = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .and_then(|body| body.split("async fn bind_card").nth(1))
            .and_then(|body| body.split("async fn unbind_card").next())
            .expect("bind_card implementation must remain available");
        assert!(bind.contains("\"BASE\" | \"OVERLAY\""));
        assert!(bind.contains("card_rule_set_ref insert returned an unusable id"));
        assert!(bind.contains("read_rule_set_entries_in_tx(&mut tx, rule_set_id, true)"));
        assert!(bind.contains("materializable_allow_entries"));
        assert!(bind.contains("Some(ref_id)"));
        assert!(bind.contains("\"RULE_SET_BOUND\""));
        // 绑定不再使用丢身份的兼容入口；CARD 投影必须携带 metadata 并返回身份。
        assert!(!bind.contains("append_card_projection_in_tx"));
        assert!(bind.contains("append_ruleset_entry_add_fanout_in_tx"));
    }

    /// 结构守卫：create_card 模板绑定的 ADD 物化复用与 bind_card 同一共享核心，
    /// 并复用调用方的单张父投影事件（不追加自己的 CARD 事件、不出现
    /// RULE_SET_BOUND）；条目锁定读取 → ALLOW-only 分类 → 共享链的顺序固定。
    #[test]
    fn create_path_binding_reuses_single_parent_and_the_standard_chain_core() {
        let wrapper = include_str!("rule_set_repository.rs")
            .split("pub(crate) async fn append_card_create_ruleset_entry_adds_in_tx")
            .nth(1)
            .and_then(|body| body.split("/// 删除规则集路径的 REMOVE 物化").next())
            .expect("create-card binding materialization must remain available");

        let entries_read = wrapper
            .find("read_rule_set_entries_in_tx(tx, rule_set_id, true)")
            .expect("enabled entries must be locked under the binding-side order");
        let classify = wrapper
            .find("materializable_allow_entries(&entries)")
            .expect("ALLOW-only classifier gates the materialization set");
        let chain_core = wrapper
            .find("materialize_ruleset_adds_for_bound_card_in_tx(")
            .expect("the shared per-card ADD core must be reused, never rewritten");
        assert!(
            entries_read < classify && classify < chain_core,
            "entries -> classification -> shared ledger chain must stay ordered"
        );
        // 复用父事件：wrapper 内不得再追加任何 CARD 投影事件。
        assert!(
            !wrapper.contains("append_card_projection_with_metadata_in_tx"),
            "the caller's single CARD parent projection is reused; no extra CARD events"
        );
        assert!(!wrapper.contains("\"RULE_SET_BOUND\""));
        // 归属事实防线：正数 ref/card/rule-set 与属主/租户校验保留在 wrapper 内。
        assert!(wrapper.contains("positive card/rule-set/ref identifiers"));
        assert!(wrapper.contains("no usable owner user id"));
    }

    #[test]
    fn proven_bound_cards_fail_closed_on_unprovable_binding_rows() {
        // 该行为由 provable_bound_cards_in_tx 的 SQL 查询编排（JOIN 锁定 + 显式
        // NULL/非 ACTIVE 拒绝）体现；此处锁定其调用面防止回归。
        let source = include_str!("rule_set_repository.rs");
        let helper = source
            .split("async fn provable_bound_cards_in_tx")
            .nth(1)
            .and_then(|body| body.split("fn ruleset_mutation_actor").next())
            .expect("provable bound cards helper must exist");
        assert!(helper.contains("ORDER BY id FOR UPDATE"));
        assert!(helper.contains("card_status = 'ACTIVE'"));
        assert!(helper.contains("valid_until >= NOW()"));
        assert!(helper.contains("NULL tenant_id"));
        assert!(helper.contains("no usable owner user id"));
        // 排序确定性：先 ref 主键再逐行锁卡。
        let select = helper
            .find("SELECT id, card_id, ref_type FROM card_rule_set_ref")
            .unwrap();
        let card_lock = helper
            .find("SELECT user_id, tenant_id, domain_id FROM user_card")
            .unwrap();
        assert!(select < card_lock);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // D1：解绑 / 删除规则集的授权账本 REMOVE 物化（capture-before-delete）
    // ─────────────────────────────────────────────────────────────────────────

    /// 结构守卫：解绑在同一事务内按"捕获 entry/owner/引用事实 → 写全部 REMOVE
    /// 贡献 → legacy RULE_SET REVOKE 投影 → 关联审计 → 删除 source ref"执行；
    /// 任一贡献失败整体回滚，杜绝只写旧链的活动幽灵授权。
    #[test]
    fn unbind_materializes_ledger_removals_before_deleting_the_binding() {
        let unbind = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .and_then(|body| body.split("async fn unbind_card").nth(1))
            .and_then(|body| body.split("async fn count_templates").next())
            .expect("unbind_card implementation must remain available");
        let ref_capture = unbind
            .find("SELECT id, ref_type, tenant_id FROM card_rule_set_ref")
            .expect("binding reference capture");
        let owner_capture = unbind
            .find("unbind_bound_card_facts")
            .expect("owner facts are captured from locked rows before any write");
        let entries_capture = unbind
            .find("read_rule_set_entries_in_tx(&mut tx, rule_set_id, true)")
            .expect("enabled entries must be captured under lock");
        let allow = unbind
            .find("materializable_allow_entries")
            .expect("ALLOW-only classifier gates the removal set");
        let fanout = unbind
            .find("append_unbind_ruleset_removal_deltas_in_tx")
            .expect("versioned REMOVE contributions must be materialized");
        let projection = unbind
            .find("append_rule_set_projection_with_tenant_in_tx")
            .expect("legacy RULE_SET REVOKE projection stays");
        let audit = unbind
            .find("\"UNBIND_CARD\"")
            .expect("legacy UNBIND_CARD audit stays");
        let delete_ref = unbind
            .find("DELETE FROM card_rule_set_ref")
            .expect("source reference deletion stays");
        assert!(
            owner_capture > ref_capture,
            "owner facts follow the ref lock"
        );
        assert!(
            ref_capture < entries_capture && entries_capture < allow,
            "entries are captured after the binding locks"
        );
        assert!(
            allow < fanout && fanout < projection && projection < audit,
            "ledger REMOVE deltas precede the legacy projection and audit"
        );
        assert!(
            audit < delete_ref,
            "the source reference is deleted last in the transaction"
        );
        // 审计 detail 关联 parent source 事件与全部贡献维度；键名契约由
        // removal_audit_old_value_correlates_parent_event_and_all_contributions 锁定。
        assert!(unbind.contains("ruleset_removal_audit_old_value"));
        let all_source = include_str!("rule_set_repository.rs");
        for key in [
            "parentSourceEventId",
            "contributionEventIds",
            "ruleSetEntryIds",
            "boundCardIds",
            "bindingRefIds",
        ] {
            assert!(
                all_source.contains(key),
                "audit detail key {key} must exist"
            );
        }

        // 解绑驱动器：单卡一张带元数据的 CARD REVOKE 投影事件 + 单卡贡献物化。
        let driver = include_str!("rule_set_repository.rs")
            .split("async fn append_unbind_ruleset_removal_deltas_in_tx")
            .nth(1)
            .and_then(|body| {
                body.split("async fn append_ruleset_deletion_removal_deltas_in_tx")
                    .next()
            })
            .expect("unbind removal driver must exist");
        assert!(driver.contains("EVENT_TYPE_REVOKE"));
        assert!(driver.contains("ProjectionEventMetadata"));
        assert!(driver.contains("materialize_ruleset_removals_for_card_in_tx"));
        assert!(
            !driver.contains("append_card_projection_in_tx"),
            "丢身份兼容入口不得回流"
        );

        // 物化核心：head 锁定缺失即 fail-closed；版本链推进在 draft 组装之前，
        // delta append 收尾，任何错误上抛回滚整个事务。
        let core = include_str!("rule_set_repository.rs")
            .split("async fn materialize_ruleset_removals_for_card_in_tx")
            .nth(1)
            .and_then(|body| {
                body.split("async fn append_unbind_ruleset_removal_deltas_in_tx")
                    .next()
            })
            .expect("shared removal core must exist");
        let head_lock = core.find("read_grant_head_for_update_in_tx").unwrap();
        let last_target = core
            .find("read_latest_delta_target_version_for_update_in_tx")
            .unwrap();
        let version = core.find("next_delta_version").unwrap();
        let event_id = core.find("derive_ruleset_contribution_event_id").unwrap();
        let draft = core.find("build_ruleset_remove_draft").unwrap();
        let append = core.find("append_ruleset_grant_delta_in_tx").unwrap();
        assert!(head_lock < last_target && last_target < version);
        assert!(version < event_id && event_id < draft && draft < append);
        assert!(core.contains("RuleSetMutationKind::Remove"));
        assert!(
            core.contains("no versioned grant"),
            "missing ledger head must fail closed instead of skipping"
        );
    }

    /// 测试助手：以固定事实派生一条 REMOVE 贡献事件号（纯逻辑，不触库）。
    fn ruleset_contribution_event_id(
        operation_id: &str,
        tenant_id: i64,
        domain_id: Option<i64>,
        card_id: i64,
        ref_id: i64,
        ref_type: &str,
        entry_id: i64,
    ) -> String {
        let facts = RuleSetEntryLedgerFacts {
            tenant_id,
            domain_id,
            card_id,
            user_id: 42,
            rule_set_id: 9,
            entry_id,
            ref_id,
            ref_type,
            resource: "learn_course",
            resource_id: None,
            action: "read",
            condition_json: None,
            valid_from: None,
            valid_to: None,
        };
        derive_ruleset_contribution_event_id(operation_id, &facts, RuleSetMutationKind::Remove)
            .unwrap()
    }

    /// 结构守卫：删除规则集先锁定全部条目与绑定卡（capture），为 entry×ref×卡
    /// 全组合写 REMOVE（同一 operation、独立贡献事件号），随后才执行既有 source
    /// 删除与 legacy 投影/审计语义；原逐卡裸投影被带元数据版本替代。
    #[test]
    fn delete_rule_set_writes_ledger_removals_before_source_deletion() {
        let delete = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .and_then(|body| body.split("async fn delete_rule_set").nth(1))
            .and_then(|body| body.split("async fn list_entries").next())
            .expect("delete_rule_set implementation must remain available");
        let rule_set_lock = delete
            .find("SELECT rule_set_id, tenant_id FROM rule_set")
            .expect("source row must be locked first");
        let entries_capture = delete
            .find("read_rule_set_entries_in_tx(&mut tx, rule_set_id, false)")
            .expect("all entries are captured (locked) before anything is deleted");
        let refs_capture = delete
            .find("provable_bound_cards_in_tx")
            .expect("every bound card/ref ownership fact is captured under lock");
        let deltas = delete
            .find("append_ruleset_deletion_removal_deltas_in_tx")
            .expect("versioned REMOVE contributions per contribution");
        let projection = delete
            .find("append_rule_set_projection_with_tenant_in_tx")
            .expect("legacy RULE_SET REVOKE projection with captured tenant stays");
        let audit = delete
            .find("change_type: \"DELETE\"")
            .expect("legacy DELETE audit stays");
        let source_delete = delete
            .find("DELETE FROM rule_set WHERE rule_set_id=?")
            .expect("source deletion stays");
        assert!(rule_set_lock < entries_capture && entries_capture < refs_capture);
        assert!(refs_capture < deltas && deltas < projection && projection < audit);
        assert!(audit < source_delete, "source deletion runs last");
        assert!(delete.contains("materializable_allow_entries"));
        assert!(delete.contains("EVENT_TYPE_REVOKE"));
        // 旧的直接扫 DISTINCT card 裸投影循环已被带元数据的驱动的首见去重替代。
        assert!(!delete.contains("SELECT DISTINCT card_id"));
        assert!(!delete.contains("append_bound_card_projections_in_tx"));
        assert!(delete.contains("ruleset_removal_audit_old_value"));

        // 删除驱动器：每个 DISTINCT 卡首见时追加带元数据 CARD REVOKE，其余
        // 引用复用同一锚点；entry×ref 组合全部交给共享核心物化。
        let driver = include_str!("rule_set_repository.rs")
            .split("async fn append_ruleset_deletion_removal_deltas_in_tx")
            .nth(1)
            .and_then(|body| body.split("async fn validate_card_binding_in_tx").next())
            .expect("deletion removal driver must exist");
        assert!(driver.contains("projection_by_card.entry(bound.card_id)"));
        assert!(driver.contains("EVENT_TYPE_REVOKE"));
        assert!(driver.contains("materialize_ruleset_removals_for_card_in_tx"));
    }

    /// 纯逻辑：多卡 × 多条目的解绑/删除操作下，每个贡献得到稳定且互异的独立
    /// 事件号（共享 operation id，不复用父投影事件号）；同维度不同 kind 互异。
    #[test]
    fn removal_contributions_derive_distinct_stable_event_ids() {
        let operation_id = "ruleset:d1-op";
        let mut ids = Vec::new();
        for (card_id, ref_id, ref_type) in [
            (21i64, 100i64, "BASE"),
            (21, 101, "OVERLAY"),
            (22, 102, "BASE"),
        ] {
            for entry_id in [301i64, 302] {
                ids.push(ruleset_contribution_event_id(
                    operation_id,
                    7,
                    Some(11),
                    card_id,
                    ref_id,
                    ref_type,
                    entry_id,
                ));
            }
        }
        let unique = std::collections::HashSet::<&String>::from_iter(ids.iter());
        assert_eq!(
            unique.len(),
            ids.len(),
            "entry × card × ref must collide never"
        );

        // 重放确定性：相同输入必然相同事件号（唯一冲突只能来自真实重复提交）。
        let replayed =
            ruleset_contribution_event_id(operation_id, 7, Some(11), 21, 100, "BASE", 301);
        assert_eq!(ids[0], replayed);

        // kind 域分离：同一贡献的 UPDATE 与 REMOVE 事件号必然不同。
        let update_same_dims = |kind| {
            let facts = RuleSetEntryLedgerFacts {
                tenant_id: 7,
                domain_id: Some(11),
                card_id: 21,
                user_id: 42,
                rule_set_id: 9,
                entry_id: 301,
                ref_id: 100,
                ref_type: "BASE",
                resource: "learn_course",
                resource_id: None,
                action: "read",
                condition_json: None,
                valid_from: None,
                valid_to: None,
            };
            derive_ruleset_contribution_event_id(operation_id, &facts, kind).unwrap()
        };
        assert_ne!(
            update_same_dims(RuleSetMutationKind::Update),
            update_same_dims(RuleSetMutationKind::Remove)
        );
    }

    /// 纯逻辑：解绑归属事实构造 fail-closed —— owner user/tenant 缺失或非法、
    /// 绑定主键不可用都拒绝，消息对齐 ADD 路径的 provable 捕获。
    #[test]
    fn unbind_bound_card_facts_fail_closed_without_ownership_facts() {
        let ok = unbind_bound_card_facts(100, 21, Some(42), Some(7), Some(11), "BASE".into())
            .expect("provable facts pass");
        assert_eq!(ok.ref_id, 100);
        assert_eq!(ok.tenant_id, 7);
        assert_eq!(ok.domain_id, Some(11));

        assert!(unbind_bound_card_facts(0, 21, Some(42), Some(7), None, "BASE".into()).is_err());
        assert!(
            matches!(
                unbind_bound_card_facts(100, 21, None, Some(7), None, "BASE".into()),
                Err(AstralError::Permission(message)) if message.contains("no usable owner user id")
            ),
            "missing owner fails closed"
        );
        assert!(matches!(
            unbind_bound_card_facts(100, 21, Some(-3), Some(7), None, "OVERLAY".into()),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            unbind_bound_card_facts(100, 21, Some(42), None, None, "BASE".into()),
            Err(AstralError::Validation(message)) if message.contains("NULL tenant_id")
        ));
    }

    /// 纯逻辑：removal 审计 detail 关联 parent source 事件与全部贡献维度且输出
    /// 确定（审计 immutable 列重放校验依赖逐字节一致）。
    #[test]
    fn removal_audit_old_value_correlates_parent_event_and_all_contributions() {
        let base = serde_json::json!({ "cardId": 21, "tenantId": 7 });
        let contributions = vec![
            RulesetRemovalContribution {
                card_id: 21,
                ref_id: 100,
                entry_id: 301,
                event_id: "evt-a".to_owned(),
            },
            RulesetRemovalContribution {
                card_id: 22,
                ref_id: 102,
                entry_id: 302,
                event_id: "evt-b".to_owned(),
            },
        ];
        let first = ruleset_removal_audit_old_value(base.clone(), "parent-ev", &contributions);
        let value: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(value["cardId"], 21);
        assert_eq!(value["tenantId"], 7);
        assert_eq!(value["parentSourceEventId"], "parent-ev");
        assert_eq!(
            value["contributionEventIds"],
            serde_json::json!(["evt-a", "evt-b"])
        );
        assert_eq!(value["ruleSetEntryIds"], serde_json::json!([301, 302]));
        assert_eq!(value["boundCardIds"], serde_json::json!([21, 22]));
        assert_eq!(value["bindingRefIds"], serde_json::json!([100, 102]));

        // 相同输入重复组装结果逐字节一致（确定性重放），空贡献列表同样合法。
        let second = ruleset_removal_audit_old_value(base.clone(), "parent-ev", &contributions);
        assert_eq!(first, second);
        let empty = ruleset_removal_audit_old_value(base, "p", &[]);
        let empty_value: serde_json::Value = serde_json::from_str(&empty).unwrap();
        assert_eq!(
            empty_value["contributionEventIds"],
            serde_json::json!(Vec::<String>::new())
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Batch Replace：replace_entries 的版本化账本接线（REMOVE+ADD 双相）
    // ─────────────────────────────────────────────────────────────────────────

    /// 测试助手：以固定事实派生任意 kind 的规则集贡献事件号（纯逻辑，不触库）。
    #[allow(clippy::too_many_arguments)]
    fn contribution_event_id_of_kind(
        operation_id: &str,
        tenant_id: i64,
        domain_id: Option<i64>,
        card_id: i64,
        ref_id: i64,
        ref_type: &str,
        entry_id: i64,
        kind: RuleSetMutationKind,
    ) -> String {
        let facts = RuleSetEntryLedgerFacts {
            tenant_id,
            domain_id,
            card_id,
            user_id: 42,
            rule_set_id: 9,
            entry_id,
            ref_id,
            ref_type,
            resource: "learn_course",
            resource_id: None,
            action: "read",
            condition_json: None,
            valid_from: None,
            valid_to: None,
        };
        derive_ruleset_contribution_event_id(operation_id, &facts, kind).unwrap()
    }

    /// 结构守卫：全量替换在同一事务内按「锁定捕获旧条目 → ALLOW-only 分类 →
    /// 等值短路 → 绑定卡证明 → 旧 ALLOW 条目 REMOVE（capture-before-delete，
    /// D1 驱动器）→ source 删除/插入（严格 rows_affected + last_insert_id 捕获
    /// 新 entry_id，拒绝与旧 id 碰撞）→ 锁定读回新行 → 新 ADD fanout → parent
    /// RULE_SET 投影 → 新旧双向关联审计 → 提交」执行；不再使用丢身份的逐卡裸广播。
    #[test]
    fn replace_entries_orders_capture_remove_then_source_then_add_and_bidirectional_audit() {
        let all_source = include_str!("rule_set_repository.rs");
        let impl_body = all_source
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .expect("repository implementation must remain available")
            .to_owned();
        let replace = impl_body
            .split("async fn replace_entries")
            .nth(1)
            .and_then(|body| body.split("async fn list_card_bindings").next())
            .expect("replace_entries implementation must remain available");
        // 调用方只负责锁定聚合行 + 校验/归一化，随后完整委托共享 churn 核心。
        let lock = replace.find("lock_rule_set_in_tx").expect("aggregate lock");
        let delegation = replace
            .find("replace_rule_set_entries_churn_with_ledger_in_tx")
            .expect("delegates to the shared ledger churn core");
        assert!(lock < delegation);
        assert!(replace.contains("\"BATCH_REPLACE_ENTRIES\""));
        assert!(
            !replace.contains("DELETE FROM rule_set_entry"),
            "churn and ledger materialization must not be separable"
        );

        // 共享核心（批量替换 / 模板同步 / 启动物化同一实现）保持既定次序：
        // capture → classify → no-op 短路 → refs 证明 → old REMOVE → 删除源行
        // → 插入新行并捕获真实 id → 身份碰撞防御 → 锁读回 → new ADD →
        // parent RULE_SET 投影 → 新旧双向关联审计。
        let core = all_source
            .split("pub(crate) async fn replace_rule_set_entries_churn_with_ledger_in_tx")
            .nth(1)
            .and_then(|body| body.split("#[async_trait]").next())
            .expect("shared ledger churn core must remain available");
        let entries_capture = core
            .find("read_rule_set_entries_in_tx(tx, rule_set_id, false)")
            .expect("all old entries captured under lock");
        let classify = core
            .find("materializable_allow_entries")
            .expect("ALLOW-only classifier gates both phases");
        let noop = core
            .find("batch_replacement_is_fully_equal")
            .expect("proved-equal short-circuit stays");
        let refs_capture = core
            .find("provable_bound_cards_in_tx")
            .expect("bound cards proven before any write");
        let remove = core
            .find("append_ruleset_deletion_removal_deltas_in_tx")
            .expect("old contributions are REMOVEd before any deletion");
        let delete = core
            .find("DELETE FROM rule_set_entry WHERE rule_set_id = ?")
            .expect("source deletion");
        let insert = core
            .find("INSERT INTO rule_set_entry")
            .expect("source insertion");
        let id_capture = core
            .find("last_insert_id()")
            .expect("real new entry ids are captured");
        let collision = core
            .find("collides with a replaced entry id")
            .expect("stable grant identity is never aliased across phases");
        let relock = core
            .find("read_rule_set_entries_in_tx(tx, rule_set_id, true)")
            .expect("new rows are locked-read back before materialization");
        let add = core
            .find("append_ruleset_entry_add_fanout_in_tx")
            .expect("new contributions are ADDed from locked rows");
        let projection = core
            .find("append_rule_set_projection_in_tx")
            .expect("parent RULE_SET projection");
        let audit = core
            .find("\"BATCH_REPLACE_ENTRIES\"")
            .or_else(|| core.find("audit.change_type"))
            .expect("caller change type reaches the shared audit row");
        assert!(entries_capture < classify && classify < noop);
        assert!(noop < refs_capture && refs_capture < remove);
        assert!(remove < delete && delete < insert && insert < id_capture);
        assert!(id_capture < collision && collision < relock);
        assert!(relock < add && add < projection && projection < audit);

        // 关联契约：审计同时携带 parent 事件号与旧/新两组贡献维度；
        // 空相显式置空，绝不写“只有 ADD 没有 old REMOVE（或反之）”的半接线。
        assert!(core.contains("ruleset_batch_replacement_audit_old_value"));
        assert!(core.contains("if old_allow_entries.is_empty()"));
        assert!(core.contains("rule set entry batch replace insert did not affect exactly one row"));
        assert!(core.contains("insert returned an unusable id"));
        // 身份门禁：随机 fallback 的 operation id 一律拒绝进入账本。
        assert!(core.contains("has_proven_operation_identity"));
        assert!(
            !core.contains("append_bound_card_projections_in_tx"),
            "the metadata-bearing per-phase CARD anchors replace the identity-free broadcast"
        );
        // before-image pairing 由共享 D1 核心（remove draft）与 adapter 组装器强制：
        // 本路径不得绕过它们自建 codec。
        assert!(all_source.contains("build_ruleset_remove_draft"));
        assert!(all_source.contains("build_ruleset_add_draft"));
    }

    /// 纯逻辑：无变化短路只在可证明完全等价时成立；禁用行/DENY 行/带有效期列/
    /// 字节级差异（含空白）/数量差异一律要求完整 REMOVE+ADD 路径。
    #[test]
    fn batch_replacement_noop_requires_byte_provable_equality() {
        fn requested_entry_with(
            effect: &str,
            resource: Option<&str>,
            priority: i32,
            condition_json: Option<String>,
        ) -> NewRuleSetEntry {
            NewRuleSetEntry {
                effect: effect.to_owned(),
                resource: resource.map(str::to_owned),
                resource_id: Some(3),
                action: Some("read".to_owned()),
                condition_json,
                priority,
            }
        }
        fn requested_entry(effect: &str) -> NewRuleSetEntry {
            requested_entry_with(effect, Some("learn_course"), 5, None)
        }

        let allow = [entry_row("ALLOW", 1)];
        assert!(batch_replacement_is_fully_equal(
            &allow,
            &[requested_entry("ALLOW")]
        ));
        // effect 归一语义等价（classifier 同语义大小写比较）。
        assert!(batch_replacement_is_fully_equal(
            &[entry_row("allow", 1)],
            &[requested_entry("ALLOW")]
        ));

        let mut disabled = entry_row("ALLOW", 0);
        disabled.entry_id = 11;
        assert!(!batch_replacement_is_fully_equal(
            &[disabled],
            &[requested_entry("ALLOW")]
        ));
        assert!(!batch_replacement_is_fully_equal(
            &[entry_row("DENY", 1)],
            &[requested_entry("ALLOW")]
        ));
        let mut bounded = entry_row("ALLOW", 1);
        bounded.valid_to = Some("2026-01-01T00:00:00".to_owned());
        assert!(!batch_replacement_is_fully_equal(
            &[bounded],
            &[requested_entry("ALLOW")]
        ));

        // 非克隆字段级差异：优先级或资源文本的任何字节漂移都不得冒充等价。
        let shifted = requested_entry_with("ALLOW", Some("learn_course"), 6, None);
        assert!(!batch_replacement_is_fully_equal(&allow, &[shifted]));

        let spaced = requested_entry_with("ALLOW", Some("learn_course "), 5, None);
        assert!(!batch_replacement_is_fully_equal(&allow, &[spaced]));

        let with_condition = requested_entry_with(
            "ALLOW",
            Some("learn_course"),
            5,
            Some("{\"timeRange\":{\"from\":\"09:00\",\"to\":\"17:00\"}}".to_owned()),
        );
        assert!(!batch_replacement_is_fully_equal(&allow, &[with_condition]));

        assert!(!batch_replacement_is_fully_equal(
            &[entry_row("ALLOW", 1), entry_row("ALLOW", 1)],
            &[requested_entry("ALLOW")]
        ));
        // 空对空是平凡等价：短路为零写入（既无 REMOVE 也无 ADD，亦不 bump 版本）。
        assert!(batch_replacement_is_fully_equal(&[], &[]));
    }

    /// 纯逻辑：批量替换审计 detail 同时关联 parent source 事件与旧/新两组贡献
    /// 维度，输出确定性 JSON 且两组键空间互不覆盖；任一相为空仍然合法。
    #[test]
    fn batch_replacement_audit_correlates_old_and_new_contributions_deterministically() {
        let audit = RuleSetBatchReplacementAudit {
            parent_source_event_id: "parent-ev".to_owned(),
            removals: vec![
                RulesetRemovalContribution {
                    card_id: 21,
                    ref_id: 100,
                    entry_id: 301,
                    event_id: "evt-r1".to_owned(),
                },
                RulesetRemovalContribution {
                    card_id: 22,
                    ref_id: 102,
                    entry_id: 302,
                    event_id: "evt-r2".to_owned(),
                },
            ],
            additions: vec![
                RulesetAdditionContribution {
                    tenant_id: 7,
                    card_id: 21,
                    ref_id: 103,
                    entry_id: 501,
                    event_id: "evt-a1".to_owned(),
                },
                RulesetAdditionContribution {
                    tenant_id: 7,
                    card_id: 22,
                    ref_id: 104,
                    entry_id: 502,
                    event_id: "evt-a2".to_owned(),
                },
            ],
        };
        let encoded = ruleset_batch_replacement_audit_old_value(
            serde_json::json!({ "ruleSetId": 9 }),
            &audit,
        );
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["ruleSetId"], 9);
        assert_eq!(value["parentSourceEventId"], "parent-ev");
        assert_eq!(
            value["removedContributionEventIds"],
            serde_json::json!(["evt-r1", "evt-r2"])
        );
        assert_eq!(
            value["removedRuleSetEntryIds"],
            serde_json::json!([301, 302])
        );
        assert_eq!(value["removedBoundCardIds"], serde_json::json!([21, 22]));
        assert_eq!(value["removedBindingRefIds"], serde_json::json!([100, 102]));
        assert_eq!(
            value["addedContributionEventIds"],
            serde_json::json!(["evt-a1", "evt-a2"])
        );
        assert_eq!(value["addedRuleSetEntryIds"], serde_json::json!([501, 502]));
        assert_eq!(value["addedBoundCardIds"], serde_json::json!([21, 22]));
        assert_eq!(value["addedBindingRefIds"], serde_json::json!([103, 104]));

        // 相同输入逐字节一致（确定性重放）；空相不被丢键。
        let replayed = ruleset_batch_replacement_audit_old_value(
            serde_json::json!({ "ruleSetId": 9 }),
            &audit,
        );
        assert_eq!(encoded, replayed);
        let empty_sides = RuleSetBatchReplacementAudit {
            parent_source_event_id: "p".to_owned(),
            removals: Vec::new(),
            additions: Vec::new(),
        };
        let empty_encoded =
            ruleset_batch_replacement_audit_old_value(serde_json::json!({}), &empty_sides);
        let empty_value: serde_json::Value = serde_json::from_str(&empty_encoded).unwrap();
        assert_eq!(
            empty_value["removedContributionEventIds"],
            serde_json::json!(Vec::<String>::new())
        );
        assert_eq!(
            empty_value["addedRuleSetEntryIds"],
            serde_json::json!(Vec::<i64>::new())
        );
    }

    /// 纯逻辑：多卡 × 多旧条目的 REMOVE 与多新条目的 ADD 在共享同一 operation id
    /// 下各自独立互异且跨相不碰撞；同输入重放得到相同事件号；同维度不同 kind 互异。
    #[test]
    fn replacement_contribution_event_ids_are_distinct_across_phases_and_stable_on_replay() {
        let operation_id = "ruleset:batch-op";
        let bindings = [
            (21i64, 100i64, "BASE"),
            (21, 101, "OVERLAY"),
            (22, 102, "BASE"),
        ];
        let mut removal_ids = Vec::new();
        for (card_id, ref_id, ref_type) in bindings {
            for entry_id in [301i64, 302] {
                removal_ids.push(contribution_event_id_of_kind(
                    operation_id,
                    7,
                    Some(11),
                    card_id,
                    ref_id,
                    ref_type,
                    entry_id,
                    RuleSetMutationKind::Remove,
                ));
            }
        }
        let mut addition_ids = Vec::new();
        for (card_id, ref_id, ref_type) in bindings {
            for entry_id in [501i64, 502] {
                addition_ids.push(contribution_event_id_of_kind(
                    operation_id,
                    7,
                    Some(11),
                    card_id,
                    ref_id,
                    ref_type,
                    entry_id,
                    RuleSetMutationKind::Add,
                ));
            }
        }
        let mut everything = removal_ids.clone();
        everything.extend(addition_ids.iter().cloned());
        let unique = std::collections::HashSet::<&String>::from_iter(everything.iter());
        assert_eq!(
            unique.len(),
            everything.len(),
            "old REMOVE × new ADD must never collide under one shared operation id"
        );
        // 重放确定性：同一逻辑操作重试复用相同贡献事件号。
        assert_eq!(
            contribution_event_id_of_kind(
                operation_id,
                7,
                Some(11),
                21,
                100,
                "BASE",
                301,
                RuleSetMutationKind::Remove
            ),
            removal_ids[0]
        );
        assert_eq!(
            contribution_event_id_of_kind(
                operation_id,
                7,
                Some(11),
                21,
                100,
                "BASE",
                501,
                RuleSetMutationKind::Add
            ),
            addition_ids[0]
        );
        // 新 entry_id（分离的 source_entry 维度）天然不会命中刚被 REMOVE 的身份：
        // ADD rev1 链路只发生在账本中不存在该稳定授权的情形。
        let facts_drift = |entry_id: i64| {
            contribution_event_id_of_kind(
                operation_id,
                7,
                Some(11),
                21,
                100,
                "BASE",
                entry_id,
                RuleSetMutationKind::Add,
            )
        };
        assert_ne!(facts_drift(301), facts_drift(302));
    }

    /// 结构守卫：模板创建/同步必须通过共享授权账本 churn 核心物化 ——
    /// capture-before-delete、old REMOVE + new ADD、同一事务内完成；
    /// 禁止第二套手写账本接线（不得自建 delta/fanout/等值判定）。
    #[test]
    fn create_rule_set_from_template_materializes_through_the_shared_ledger_churn() {
        let impl_body = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .expect("repository implementation must remain available")
            .to_owned();
        let template = impl_body
            .split("async fn create_rule_set_from_template")
            .nth(1)
            .and_then(|body| body.split("fn db_error").next())
            .expect("create_rule_set_from_template implementation must remain available");
        assert!(template.contains("\"TEMPLATE_SYNC\""));
        assert!(template.contains("permission_rule_template"));
        // 授权账本接线走共享核心（与批量替换同一实现），而不是第二套实现。
        assert!(
            template.contains("replace_rule_set_entries_churn_with_ledger_in_tx"),
            "template materialization must delegate to the shared ledger churn core"
        );
        for forbidden in [
            "append_ruleset_grant_delta_in_tx",
            "derive_ruleset_contribution_event_id",
            "derive_ruleset_identity",
            "build_ruleset_add_draft",
            "build_ruleset_update_draft",
            "build_ruleset_remove_draft",
            "append_ruleset_deletion_removal_deltas_in_tx",
            "append_ruleset_entry_add_fanout_in_tx",
            "append_ruleset_entry_update_fanout_in_tx",
            "append_ruleset_entry_remove_fanout_in_tx",
            "batch_replacement_is_fully_equal",
            // 手写 DELETE+INSERT churn 也必须消失：churn 与账本物化不可分离。
            "DELETE FROM rule_set_entry",
            "INSERT INTO rule_set_entry",
            "materializable_allow_entries",
        ] {
            assert!(
                !template.contains(forbidden),
                "template sync must not hand-roll {forbidden}; use the shared ledger churn core"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Operation identity 单一契约（账本写路径稳定派生 + fail-closed 门禁）
    // ─────────────────────────────────────────────────────────────────────────

    /// 纯逻辑：operation id 派生确定、动作/聚合/代次分叉，且不含任何随机构造。
    #[test]
    fn ruleset_operation_ids_are_deterministic_and_action_scoped() {
        let base = derive_rule_set_operation_id(RuleSetLedgerOperationKind::AddEntry, 9, 4);
        // 同一输入重放必然得到同一 operation id（重试语义的根基）。
        let replayed = derive_rule_set_operation_id(RuleSetLedgerOperationKind::AddEntry, 9, 4);
        assert_eq!(base, replayed);
        assert_eq!(base, "rule-set:add-entry:9:gen:4");

        // 不同操作类型/聚合/代次必须分叉。
        for other in [
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::UpdateEntry, 9, 4),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::DeleteEntry, 9, 4),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::BindCard, 9, 4),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::UnbindCard, 9, 4),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::DeleteRuleSet, 9, 4),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::AddEntry, 10, 4),
            derive_rule_set_operation_id(RuleSetLedgerOperationKind::AddEntry, 9, 5),
        ] {
            assert_ne!(
                base, other,
                "distinct action/aggregate/generation must fork the operation id"
            );
        }
        // 全部六种 kind 两两互异（避免任何动作复用另一动作的身份）。
        let kinds = [
            RuleSetLedgerOperationKind::AddEntry,
            RuleSetLedgerOperationKind::UpdateEntry,
            RuleSetLedgerOperationKind::DeleteEntry,
            RuleSetLedgerOperationKind::BindCard,
            RuleSetLedgerOperationKind::UnbindCard,
            RuleSetLedgerOperationKind::DeleteRuleSet,
        ];
        let unique = std::collections::HashSet::<String>::from_iter(
            kinds
                .iter()
                .map(|kind| derive_rule_set_operation_id(*kind, 9, 4)),
        );
        assert_eq!(unique.len(), kinds.len());

        // 派生体不允许出现随机构造入口（uuid v4 / 时间戳 / 线程来源）。
        let derive_body = include_str!("rule_set_repository.rs")
            .split("fn derive_rule_set_operation_id")
            .nth(1)
            .and_then(|body| {
                body.split("/// 授权账本写路径的统一 operation identity 门禁")
                    .next()
            })
            .expect("pure derivation function must remain available");
        for forbidden in ["new_v4", "SystemTime", "Instant:", "thread::"] {
            assert!(
                !derive_body.contains(forbidden),
                "operation id derivation must stay deterministic; found {forbidden}"
            );
        }
    }

    /// 行为门禁（纯逻辑）：共享驱动器对随机 fallback 上下文整体 fail-closed，
    /// 对显式 request-id 与 SYSTEM 固定串放行 —— 保证任何忘记稳定化的调用方
    /// 不可能把随机 id 泄漏进 revision/delta/审计事件链。
    #[test]
    fn shared_gate_rejects_random_fallback_and_accepts_proven_contexts() {
        let system = RuleSetMutationContext::system("startup:ruleset-materialize").unwrap();
        assert!(require_proven_ruleset_operation_identity(&system).is_ok());
        let explicit = RuleSetMutationContext::user(17, Some("http-req-7")).unwrap();
        assert!(require_proven_ruleset_operation_identity(&explicit).is_ok());
        let derived = RuleSetMutationContext::user(17, None)
            .unwrap()
            .with_derived_operation_id("template-sync:5:9:gen:3".to_owned())
            .unwrap();
        assert!(require_proven_ruleset_operation_identity(&derived).is_ok());
        for fallback in [
            RuleSetMutationContext::user(17, None).unwrap(),
            RuleSetMutationContext::user(17, Some("   ")).unwrap(),
        ] {
            assert!(matches!(
                require_proven_ruleset_operation_identity(&fallback),
                Err(AstralError::Validation(_))
            ));
        }
    }

    /// 结构守卫：派生器锁定 RULE_SET 投影 head 代次（缺失视为 0、负代次拒绝），
    /// 未证明上下文经 with_derived_operation_id 升级为可证明身份。
    #[test]
    fn stabilization_locks_head_generation_and_upgrades_unproven_contexts() {
        let helper = include_str!("rule_set_repository.rs")
            .split("async fn stabilize_rule_set_operation_context")
            .nth(1)
            .and_then(|body| {
                body.split("fn require_proven_ruleset_operation_identity")
                    .next()
            })
            .expect("stabilization helper must remain available");
        assert!(helper.contains("has_proven_operation_identity()"));
        assert!(helper.contains("authorization_projection_head"));
        assert!(helper.contains("aggregate_type = 'RULE_SET'"));
        assert!(helper.contains("FOR UPDATE"));
        assert!(helper.contains("unwrap_or(0)"));
        assert!(
            helper.contains("negative generation"),
            "negative durable generation must fail closed"
        );
        assert!(helper.contains("with_derived_operation_id"));
        assert!(helper.contains("derive_rule_set_operation_id"));
    }

    /// 结构守卫：六个已接授权账本的 mutation 入口都必须在任何 durable 写入之前
    /// 调用统一稳定化，并绑定各自的动作类型 token；其后全部投影/审计/账本写入
    /// 共享同一上下文变量（禁止先用随机 id 写一部分再替换）。
    #[test]
    fn every_ledger_wired_mutation_stabilizes_identity_before_its_first_durable_write() {
        let impl_body = include_str!("rule_set_repository.rs")
            .split("impl RuleSetRepository for SqlxRuleSetRepository")
            .nth(1)
            .expect("repository implementation must remain available");
        // (fn 边界, 下一个 fn 边界, 首 durable 写标记, 动作 token)
        const CASES: &[(&str, &str, &str, &str)] = &[
            (
                "async fn add_entry",
                "async fn update_entry",
                "INSERT INTO rule_set_entry",
                "AddEntry",
            ),
            (
                "async fn update_entry",
                "async fn delete_entry",
                "UPDATE rule_set_entry",
                "UpdateEntry",
            ),
            (
                "async fn delete_entry",
                "async fn replace_entries",
                "DELETE FROM rule_set_entry",
                "DeleteEntry",
            ),
            (
                "async fn delete_rule_set",
                "async fn list_entries",
                "DELETE FROM rule_set WHERE rule_set_id=?",
                "DeleteRuleSet",
            ),
            (
                "async fn bind_card",
                "async fn unbind_card",
                "INSERT INTO card_rule_set_ref",
                "BindCard",
            ),
        ];
        for &(start, _end, first_write, kind_token) in CASES {
            let body = impl_body
                .split(start)
                .nth(1)
                .and_then(|segment| segment.split(_end).next())
                .unwrap_or_else(|| panic!("{start} implementation must remain available"));
            let stabilize_marker = "let context = &stabilize_rule_set_operation_context(";
            assert!(
                body.contains(stabilize_marker),
                "{start} must stabilize the mutation context through the single helper"
            );
            let stabilize_at = body.find(stabilize_marker).unwrap();
            assert!(
                body.contains(kind_token),
                "{start} must bind its own operation kind ({kind_token})"
            );
            let first_write_at = body.find(first_write).unwrap_or_else(|| {
                panic!("{start} must retain its first durable write ({first_write})")
            });
            assert!(
                stabilize_at < first_write_at,
                "{start} must stabilize the operation identity before its first durable write"
            );
            // 稳定化之后不得再引用“外层原始参数”（全部走派生后的绑定）。
            assert!(
                !body[stabilize_at..].contains("RuleSetMutationContext,"),
                "{start} must not re-introduce the raw parameter after stabilization"
            );
        }

        // delete_rule_set 的源行锁必须先于稳定化（缺失源 early-return 保持零写入）。
        let delete_body = impl_body
            .split("async fn delete_rule_set")
            .nth(1)
            .and_then(|segment| segment.split("async fn list_entries").next())
            .expect("delete_rule_set implementation must remain available");
        let lock_at = delete_body
            .find("SELECT rule_set_id, tenant_id FROM rule_set")
            .expect("source row lock");
        let stabilize_at = delete_body
            .find("let context = &stabilize_rule_set_operation_context(")
            .expect("delete_rule_set must stabilize");
        assert!(lock_at < stabilize_at);

        // bind_card 在归属校验之后、绑定引用写入之前稳定化。
        let bind_body = impl_body
            .split("async fn bind_card")
            .nth(1)
            .and_then(|segment| segment.split("async fn unbind_card").next())
            .expect("bind_card implementation must remain available");
        let validate_at = bind_body
            .find("validate_card_binding_in_tx")
            .expect("binding validation");
        let bind_stabilize_at = bind_body
            .find("let context = &stabilize_rule_set_operation_context(")
            .expect("bind_card must stabilize");
        assert!(validate_at < bind_stabilize_at);
        assert!(bind_stabilize_at < bind_body.find("INSERT INTO card_rule_set_ref").unwrap());

        // unbind 仅对确认存在的绑定执行稳定化（missing-binding 早退保持零写入），
        // 且先于 CARD REVOKE 锚点驱动的 REMOVE 物化。
        let unbind_body = impl_body
            .split("async fn unbind_card")
            .nth(1)
            .and_then(|segment| segment.split("async fn count_templates").next())
            .expect("unbind_card implementation must remain available");
        let binding_capture_at = unbind_body
            .find("SELECT id, ref_type, tenant_id FROM card_rule_set_ref")
            .expect("binding reference capture");
        let unbind_stabilize_at = unbind_body
            .find("let context = &stabilize_rule_set_operation_context(")
            .expect("unbind_card must stabilize");
        assert!(binding_capture_at < unbind_stabilize_at);
        assert!(
            unbind_stabilize_at
                < unbind_body
                    .find("append_unbind_ruleset_removal_deltas_in_tx")
                    .expect("removal driver call"),
            "unbind must stabilize before the CARD REVOKE anchor removal fan-out"
        );
        // 六个入口里 UnbindCard 由上面位置断言覆盖，这里补齐 token 绑定校验。
        assert!(unbind_body.contains("UnbindCard"));
    }

    /// 结构守卫：五个共享账本驱动器入口都以内联门禁开头，且位于第一次读取
    /// operation_id 之前 —— 与共享 churn 核心的既有门禁共同构成全链 proven gate。
    #[test]
    fn shared_ledger_drivers_open_with_the_proven_identity_gate() {
        let all_source = include_str!("rule_set_repository.rs");
        for (driver, tail) in [
            (
                "async fn append_ruleset_entry_add_fanout_in_tx",
                "async fn append_ruleset_entry_update_fanout_in_tx",
            ),
            (
                "async fn append_ruleset_entry_update_fanout_in_tx",
                "async fn append_ruleset_entry_remove_fanout_in_tx",
            ),
            (
                "async fn append_ruleset_entry_remove_fanout_in_tx",
                "struct RulesetRemovalContribution",
            ),
            (
                "async fn append_unbind_ruleset_removal_deltas_in_tx",
                "async fn append_ruleset_deletion_removal_deltas_in_tx",
            ),
            (
                "async fn append_ruleset_deletion_removal_deltas_in_tx",
                "async fn validate_card_binding_in_tx",
            ),
            (
                "pub(crate) async fn append_card_create_ruleset_entry_adds_in_tx",
                "async fn validate_card_binding_in_tx",
            ),
        ] {
            let body = all_source
                .split(driver)
                .nth(1)
                .and_then(|segment| segment.split(tail).next())
                .unwrap_or_else(|| panic!("{driver} implementation must remain available"));
            let gate_marker = "require_proven_ruleset_operation_identity(context)?;";
            let gate_at = body
                .find(gate_marker)
                .unwrap_or_else(|| panic!("{driver} must open with the proven identity gate"));
            let operation_read_at = body
                .find("let operation_id = context.operation_id()")
                .unwrap_or_else(|| panic!("{driver} must keep its shared operation id read"));
            assert!(
                gate_at < operation_read_at,
                "{driver} must reject random fallback contexts before any identity consumption"
            );
            // 门禁内不得存在随机身份构造或绕过读数。
            let before_operation = &body[..gate_at];
            for forbidden in ["new_v4", "context.operation_id()"] {
                assert!(
                    !before_operation.contains(forbidden),
                    "{driver} must not consume identities before the gate ({forbidden})"
                );
            }
        }
    }
}
