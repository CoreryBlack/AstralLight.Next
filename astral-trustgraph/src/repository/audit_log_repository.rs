//! 审计日志数据访问 — AuditLogRepository
//!
//! 对齐 Java `AuditLogMapper` 边界（audit_log 表）。

use async_trait::async_trait;
use sqlx::{MySql, MySqlPool, QueryBuilder, Transaction};
use time::{format_description, Date, OffsetDateTime, PrimitiveDateTime, Time};

use astral_db::USER_VISIBLE_AUDIT_PREDICATE;
use astral_types::{AstralError, SYSTEM_ACTOR_ID};

/// Documented actor used only for genuinely system-initiated work such as
/// startup template synchronization and an explicit migration backfill.
pub const SYSTEM_RULE_SET_ACTOR_ID: i64 = SYSTEM_ACTOR_ID;

/// Trusted actor and operation correlation propagated through every RuleSet
/// source mutation. HTTP callers must construct this from Gateway-verified
/// `x-user-id`; the repository never invents an actor on their behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetMutationContext {
    actor_id: i64,
    operation_id: String,
    /// 操作身份可证明性。只有显式传入的 request id、系统固定串、或事务内从
    /// durable 事实确定性派生的 id 才允许作为授权账本 contribution event 的
    /// identity 种子；随机 fallback 只保留给 legacy 投影/审计 correlation，
    /// 一旦进入账本事件就会破坏重放稳定身份与显式冲突语义。
    proven_operation_identity: bool,
}

impl RuleSetMutationContext {
    pub fn user(actor_id: i64, operation_id: Option<&str>) -> Result<Self, AstralError> {
        if actor_id <= 0 {
            return Err(AstralError::Auth(
                "RuleSet mutation requires a verified positive actor id".into(),
            ));
        }
        // 随机 fallback（normalize_operation_id）只服务 legacy correlation；
        // 其产物永远不得被记账驱动器当作账本事件的 identity 种子。
        // 显式携带的 header 必须先通过统一持久化安全性校验：不安全的
        // request id 直接 Validation fail-closed，绝不静默替换或截断。
        let validated = validated_request_operation_id(operation_id)?;
        let proven_operation_identity = validated.is_some();
        Ok(Self {
            actor_id,
            // 校验通过的原样复用；缺失 header 走 legacy 随机 correlation，
            // 该值永远不是可证明身份（proven=false）。
            operation_id: validated.unwrap_or_else(|| format!("ruleset:{}", uuid::Uuid::new_v4())),
            proven_operation_identity,
        })
    }

    pub fn system(operation_id: &str) -> Result<Self, AstralError> {
        if operation_id.trim().is_empty() {
            return Err(AstralError::Validation(
                "system RuleSet operation id must not be empty".into(),
            ));
        }
        Ok(Self {
            actor_id: SYSTEM_RULE_SET_ACTOR_ID,
            operation_id: operation_id.trim().to_owned(),
            proven_operation_identity: true,
        })
    }

    /// 用调用方事务内从已锁定 durable 事实确定性派生的操作身份替换本上下文。
    /// 仅允许模板物化等以“request id 缺失 → 确定性派生”为契约的路径使用：
    /// 派生输入必须是同事务可证明的稳定事实（例如模板/规则集/投影代次），
    /// 而不是进程环境元数据；空派生值一律拒绝。actor 保持不变。
    pub fn with_derived_operation_id(
        &self,
        derived_operation_id: String,
    ) -> Result<Self, AstralError> {
        let trimmed = derived_operation_id.trim();
        if trimmed.is_empty() {
            return Err(AstralError::Validation(
                "derived RuleSet operation identity must not be empty".into(),
            ));
        }
        Ok(Self {
            actor_id: self.actor_id,
            operation_id: trimmed.to_owned(),
            proven_operation_identity: true,
        })
    }

    pub fn has_proven_operation_identity(&self) -> bool {
        self.proven_operation_identity
    }

    pub fn actor_id(&self) -> i64 {
        self.actor_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// 显式 x-request-id 复用为 durable operation_id 时允许的最大长度（canonical 上限）。
/// 与授权账本适配器的 `MAX_HEADER_OPERATION_ID_LENGTH` 及 Java-owned
/// `audit_log.request_id VARCHAR(64)` 共享同一上限：超出即 Validation fail-closed，
/// 绝不截断或静默归一化；两侧常量由单测锁定不得漂移。
pub(crate) const MAX_REQUEST_OPERATION_ID_LENGTH: usize = 64;

fn request_operation_id_byte_is_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
}

/// 请求级 operation identity 的统一入口校验（纯逻辑、单一契约）：
/// - 缺失或纯空白 → `Ok(None)`：调用方按各自语义处理（HTTP 用户上下文保留
///   legacy 随机 correlation，但永不进入账本；系统路径传固定稳定串）；
/// - 携带但超长/含非 ASCII 安全集字符/控制字符 → `Err(Validation)` fail-closed，
///   绝不静默替换或截断 —— 与审批/direct 规则路径的既有头部校验同一条门禁。
pub(crate) fn validated_request_operation_id(
    operation_id: Option<&str>,
) -> Result<Option<String>, AstralError> {
    let Some(header) = operation_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let usable = header.len() <= MAX_REQUEST_OPERATION_ID_LENGTH
        && header.bytes().all(request_operation_id_byte_is_safe);
    if !usable {
        return Err(AstralError::Validation(format!(
            "request id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(Some(header.to_owned()))
}

/// Durable correlation evidence written by source mutations and the projection
/// worker. The table deliberately has no RuleSet foreign key so DELETE history
/// remains queryable after the source row is removed.
#[derive(Debug, Clone)]
pub struct RuleSetProjectionAuditEntry<'a> {
    pub rule_set_id: i64,
    pub entry_id: Option<i64>,
    pub aggregate_type: &'a str,
    pub aggregate_id: i64,
    pub event_id: &'a str,
    pub source_generation: i64,
    pub operation_id: &'a str,
    pub actor_id: i64,
    pub change_type: &'a str,
    pub old_value_json: Option<&'a str>,
    pub new_value_json: Option<&'a str>,
    pub tenant_id: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct RuleSetProjectionAuditRow {
    rule_set_id: i64,
    entry_id: Option<i64>,
    changed_by: i64,
    change_type: String,
    old_value_json: Option<String>,
    new_value_json: Option<String>,
    tenant_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    source_generation: i64,
    operation_id: String,
}

fn immutable_mismatch_fields(
    existing: &RuleSetProjectionAuditRow,
    incoming: &RuleSetProjectionAuditEntry<'_>,
) -> Vec<&'static str> {
    let mut mismatches = Vec::new();
    if existing.event_id != incoming.event_id {
        mismatches.push("event_id");
    }
    if existing.source_generation != incoming.source_generation {
        mismatches.push("source_generation");
    }
    if existing.change_type != incoming.change_type {
        mismatches.push("change_type");
    }
    if existing.rule_set_id != incoming.rule_set_id {
        mismatches.push("rule_set_id");
    }
    if existing.entry_id != incoming.entry_id {
        mismatches.push("entry_id");
    }
    if existing.changed_by != incoming.actor_id {
        mismatches.push("changed_by");
    }
    if existing.old_value_json.as_deref() != incoming.old_value_json {
        mismatches.push("old_value_json");
    }
    if existing.new_value_json.as_deref() != incoming.new_value_json {
        mismatches.push("new_value_json");
    }
    if existing.tenant_id != incoming.tenant_id {
        mismatches.push("tenant_id");
    }
    if existing.aggregate_type != incoming.aggregate_type {
        mismatches.push("aggregate_type");
    }
    if existing.aggregate_id != incoming.aggregate_id {
        mismatches.push("aggregate_id");
    }
    if existing.operation_id != incoming.operation_id {
        mismatches.push("operation_id");
    }
    mismatches
}

/// 审批决策在敏感状态事务内使用的审计关联上下文。
#[derive(Debug, Clone)]
pub struct ApprovalAuditContext {
    /// HTTP 请求 ID；缺失时使用审批请求 ID 生成稳定关联值。
    pub request_id: String,
    /// 数据库中的审批请求 ID，和 HTTP request_id 明确区分。
    pub approval_request_id: i64,
    /// 本次 durable 审批审计的唯一消息 ID。它不改变任何 MQ wire contract。
    pub message_id: String,
}

impl ApprovalAuditContext {
    pub fn new(request_id: Option<&str>, approval_request_id: i64) -> Self {
        Self {
            request_id: request_id
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("approval:{approval_request_id}")),
            approval_request_id,
            message_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// Write source-mutation audit and projection correlation in the same source
/// transaction. No RuleSet source/head/outbox commit can succeed without this
/// evidence.
///
/// `REBUILD_SNAPSHOT` intentionally remains supported here because the worker
/// uses the transaction-owning wrapper while source mutations use this helper
/// directly; the existing unique key includes `change_type`, so both rows can
/// coexist for the same event and generation.
pub async fn insert_rule_set_projection_audit_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    entry: &RuleSetProjectionAuditEntry<'_>,
) -> Result<(), AstralError> {
    if (entry.actor_id != SYSTEM_ACTOR_ID && entry.actor_id <= 0)
        || entry.event_id.trim().is_empty()
        || entry.operation_id.trim().is_empty()
    {
        return Err(AstralError::Validation(
            "RuleSet audit requires actor, event_id, and operation_id".into(),
        ));
    }
    let result = sqlx::query(
        "INSERT INTO rule_set_projection_audit \
         (rule_set_id, entry_id, changed_by, change_type, old_value_json, new_value_json, \
          changed_at, tenant_id, aggregate_type, aggregate_id, event_id, source_generation, operation_id) \
         VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.rule_set_id)
    .bind(entry.entry_id)
    .bind(entry.actor_id)
    .bind(entry.change_type)
    .bind(entry.old_value_json)
    .bind(entry.new_value_json)
    .bind(entry.tenant_id)
    .bind(entry.aggregate_type)
    .bind(entry.aggregate_id)
    .bind(entry.event_id)
    .bind(entry.source_generation)
    .bind(entry.operation_id)
    .execute(&mut **tx)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_database_error()
                .is_some_and(|db| db.is_unique_violation()) =>
        {
            let existing: Option<RuleSetProjectionAuditRow> = sqlx::query_as(
                "SELECT rule_set_id, entry_id, changed_by, change_type, old_value_json, \
                        new_value_json, tenant_id, aggregate_type, aggregate_id, event_id, \
                        source_generation, operation_id \
                 FROM rule_set_projection_audit \
                 WHERE event_id = ? AND source_generation = ? AND change_type = ? \
                 FOR UPDATE",
            )
            .bind(entry.event_id)
            .bind(entry.source_generation)
            .bind(entry.change_type)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|lookup_error| {
                AstralError::Database(format!(
                    "RuleSet audit duplicate lookup failed after insert conflict: {lookup_error}"
                ))
            })?;

            let Some(existing) = existing else {
                return Err(AstralError::Database(format!(
                    "RuleSet audit insert conflicted with an unknown unique key: {error}"
                )));
            };
            let mismatches = immutable_mismatch_fields(&existing, entry);
            if mismatches.is_empty() {
                Ok(())
            } else {
                Err(AstralError::Validation(format!(
                    "RuleSet audit immutable correlation conflict for event_id={}, source_generation={}, change_type={}: {}",
                    entry.event_id,
                    entry.source_generation,
                    entry.change_type,
                    mismatches.join(", ")
                )))
            }
        }
        Err(error) => Err(AstralError::Database(format!(
            "RuleSet audit insert failed: {error}"
        ))),
    }
}

/// Write post-snapshot audit in its own transaction. The worker calls this
/// before marking the head READY; failures leave the outbox retryable.
pub async fn insert_rule_set_projection_audit(
    pool: &MySqlPool,
    entry: &RuleSetProjectionAuditEntry<'_>,
) -> Result<(), AstralError> {
    let mut tx = pool.begin().await.map_err(|error| {
        AstralError::Database(format!("RuleSet audit transaction failed: {error}"))
    })?;
    insert_rule_set_projection_audit_in_tx(&mut tx, entry).await?;
    tx.commit()
        .await
        .map_err(|error| AstralError::Database(format!("RuleSet audit commit failed: {error}")))
}

/// 写入 `audit_log` 所需的审批决策字段。
#[derive(Debug, Clone)]
pub struct ApprovalAuditEntry<'a> {
    pub actor_id: i64,
    pub reviewer_id: Option<i64>,
    pub target_user_id: i64,
    pub target_card_id: Option<i64>,
    pub action: &'a str,
    pub decision: &'a str,
    pub request_reason: Option<&'a str>,
    pub reviewer_comment: Option<&'a str>,
    pub context: &'a ApprovalAuditContext,
}

impl ApprovalAuditEntry<'_> {
    /// 构造可审计的结构化详情；序列化失败必须阻止事务提交。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "actorId": self.actor_id,
            "reviewerId": self.reviewer_id,
            "targetUserId": self.target_user_id,
            "targetCardId": self.target_card_id,
            "approvalRequestId": self.context.approval_request_id,
            "requestId": self.context.request_id,
            "action": self.action,
            "messageId": self.context.message_id,
            "decision": self.decision,
            "requestReason": self.request_reason,
            "reviewerComment": self.reviewer_comment,
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "Approval audit detail serialization failed: {error}"
            ))
        })
    }
}

/// 将敏感审批结果与状态变更写入同一个 InnoDB 事务。
///
/// 不能复用 MQ-first `AuditDualWrite`：它可能在事务提交后异步落库，无法保证
/// 审批状态与 durable audit 原子一致。错误直接返回给调用方，外层事务因此回滚。
pub async fn insert_approval_audit_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    entry: &ApprovalAuditEntry<'_>,
) -> Result<(), AstralError> {
    let reason = entry.reviewer_comment.or(entry.request_reason);
    let detail = entry.detail_json()?;

    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
         VALUES (?, ?, ?, 'permission_request', ?, ?, 'APPROVAL_DECISION', ?, ?)",
    )
    .bind(entry.target_user_id)
    .bind(entry.target_card_id)
    .bind(entry.action)
    .bind(entry.decision)
    .bind(reason)
    .bind(&entry.context.request_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| AstralError::Database(format!("Approval audit insert failed: {error}")))?;
    Ok(())
}

/// 直接 permission_rule mutation 的 durable 审计关联输入。
///
/// 与授权账本（authorization_grant_revision / authorization_delta_event）和 CARD
/// head/outbox 共享同一 operation_id/event_id，使一次 direct 规则变更在审计、
/// 账本与投影三条链上可相互关联。
#[derive(Debug, Clone)]
pub struct DirectRuleAuditEntry<'a> {
    /// 操作者（Gateway 已验证的 x-user-id）。
    pub actor_id: i64,
    /// 目标卡属主用户 id。
    pub target_user_id: i64,
    pub target_card_id: i64,
    /// create | update | remove | remove_by_card | remove_by_source
    pub action: &'a str,
    /// RULE_CREATED | RULE_UPDATED | RULE_REMOVED
    pub decision: &'a str,
    pub operation_id: &'a str,
    /// 父级 CARD head/outbox source 投影事件号。批量路径下它是该批次全部
    /// contribution 共同的 parent；单条路径它与唯一贡献的事件号相同。
    pub event_id: &'a str,
    /// 每条独立账本贡献（revision+delta）自身的事件 id，与 rule_ids 一一对应。
    /// 单条路径即投影事件号本身；批量路径必须携带为每条规则派生的独立贡献
    /// 事件号，保证审计能同时回放 parent 与全部 children 的对应关系。
    pub contribution_event_ids: &'a [&'a str],
    /// 本 mutation 覆盖的 permission_rule 主键（至少一条）。
    pub rule_ids: &'a [i64],
}

impl DirectRuleAuditEntry<'_> {
    /// 结构化详情；序列化失败必须阻止事务提交。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "actorId": self.actor_id,
            "targetUserId": self.target_user_id,
            "targetCardId": self.target_card_id,
            "ruleIds": self.rule_ids,
            "operationId": self.operation_id,
            "eventId": self.event_id,
            "contributionEventIds": self.contribution_event_ids,
            "action": self.action,
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "Direct rule audit detail serialization failed: {error}"
            ))
        })
    }
}

/// 纯校验：direct 规则审计必须携带已验证 actor、目标卡/用户与可关联的
/// operation/event 身份，且至少覆盖一条规则；contribution 事件号与 rule 主键
/// 必须一一对应且各自非空，缺失或错位都拒绝落库。与落库解耦以便单测。
fn validate_direct_rule_audit_entry(entry: &DirectRuleAuditEntry<'_>) -> Result<(), AstralError> {
    if entry.actor_id <= 0
        || entry.target_user_id <= 0
        || entry.target_card_id <= 0
        || entry.operation_id.trim().is_empty()
        || entry.event_id.trim().is_empty()
        || entry.rule_ids.is_empty()
    {
        return Err(AstralError::Validation(
            "direct permission-rule audit requires a verified actor, target ids and operation/event correlation"
                .into(),
        ));
    }
    if entry.contribution_event_ids.len() != entry.rule_ids.len() {
        return Err(AstralError::Validation(format!(
            "direct permission-rule audit requires one contribution event id per rule \
             ({} contributions for {} rules)",
            entry.contribution_event_ids.len(),
            entry.rule_ids.len()
        )));
    }
    if entry
        .contribution_event_ids
        .iter()
        .any(|event_id| event_id.trim().is_empty())
    {
        return Err(AstralError::Validation(
            "direct permission-rule audit requires non-empty contribution event ids".into(),
        ));
    }
    Ok(())
}

/// 把直接规则 mutation 的审计关联写入同一个 InnoDB 事务。
///
/// 沿用 `insert_approval_audit_in_tx` 的既有机制：与 source/head/outbox/账本
/// 同事务落 `audit_log`，任何失败回滚整个 mutation。不能复用 MQ-first
/// AuditDualWrite：它可能在事务提交后异步落库。
pub async fn insert_direct_rule_audit_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    entry: &DirectRuleAuditEntry<'_>,
) -> Result<(), AstralError> {
    validate_direct_rule_audit_entry(entry)?;
    let detail = entry.detail_json()?;
    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
         VALUES (?, ?, ?, 'permission_rule', ?, NULL, 'PERMISSION_RULE_MUTATION', ?, ?)",
    )
    .bind(entry.target_user_id)
    .bind(entry.target_card_id)
    .bind(entry.action)
    .bind(entry.decision)
    .bind(entry.operation_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!(
            "Direct permission-rule audit insert failed: {error}"
        ))
    })?;
    Ok(())
}

/// 卡级联删除中单个规则集贡献组的审计关联证据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCardCascadeRulesetAudit {
    pub rule_set_id: i64,
    /// 该卡在该规则集下的绑定引用主键（card_rule_set_ref.id）。
    pub binding_ref_ids: Vec<i64>,
    /// entry × 绑定行 贡献的三元组（entry_id, binding_ref_id, 独立事件号）。
    pub removed_entries: Vec<(i64, i64, String)>,
}

/// 用户卡级联删除的 durable 审计关联输入。
///
/// 与授权账本（REMOVE tombstone 的 revision/delta）、CARD parent 投影事件、
/// legacy CARD REVOKE/ELIGIBILITY 事件共享同一稳定 operation_id，使一次卡删除
/// 在审计、source、head/outbox 与新账本链上可相互关联。任何一段贡献缺席都
/// 以空数组表达（确定性 JSON），不缺省、不猜测。
#[derive(Debug, Clone)]
pub struct UserCardCascadeAuditEntry<'a> {
    /// 目标卡属主用户 id（锁定 user_card 行读取）。
    pub target_user_id: i64,
    pub target_card_id: i64,
    /// 本 mutation 的稳定 operation id（贯穿全部 contribution 事件）。
    pub operation_id: &'a str,
    /// 父级带 metadata CARD REVOKE 投影事件号（仅 generation/fence/source 关联，
    /// 绝不复用为任一 contribution 的事件号）。
    pub parent_event_id: &'a str,
    /// DIRECT（CARD_ONLY/MANUAL）已撤销规则主键，与事件号一一对应（rule_id 升序）。
    pub direct_rule_ids: &'a [i64],
    pub direct_contribution_event_ids: &'a [&'a str],
    /// APPROVAL（PERMISSION_REQUEST）已撤销规则主键，与事件号一一对应。
    pub approval_rule_ids: &'a [i64],
    pub approval_contribution_event_ids: &'a [&'a str],
    /// DELEGATION 已撤销的委托聚合主键（delegation_id 升序），与下两组一一对应。
    pub delegation_ids: &'a [i64],
    /// 每条 DELEGATION REVOKE tombstone 自身的独立稳定事件号。
    pub delegation_contribution_event_ids: &'a [&'a str],
    /// 每条 DELEGATION 贡献绑定的 CARD 父投影事件号：被删卡自身作为承载时即
    /// `parent_event_id`；远端承载卡则对应该卡事务内追加的专用 REVOKE 事件。
    pub delegation_parent_event_ids: &'a [&'a str],
    /// RULE_SET 撤销贡献组（按 rule_set_id 升序）。
    pub rulesets: &'a [UserCardCascadeRulesetAudit],
}

impl UserCardCascadeAuditEntry<'_> {
    /// 结构化详情；序列化失败必须阻止事务提交。
    fn detail_json(&self) -> Result<String, AstralError> {
        let rulesets: Vec<serde_json::Value> = self
            .rulesets
            .iter()
            .map(|ruleset| {
                serde_json::json!({
                    "ruleSetId": ruleset.rule_set_id,
                    "bindingRefIds": ruleset.binding_ref_ids,
                    "removedEntries": ruleset
                        .removed_entries
                        .iter()
                        .map(|(entry_id, ref_id, event_id)| serde_json::json!({
                            "entryId": entry_id,
                            "bindingRefId": ref_id,
                            "eventId": event_id,
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({
            "targetUserId": self.target_user_id,
            "targetCardId": self.target_card_id,
            "operationId": self.operation_id,
            "parentEventId": self.parent_event_id,
            "directRuleIds": self.direct_rule_ids,
            "directContributionEventIds": self.direct_contribution_event_ids,
            "approvalRuleIds": self.approval_rule_ids,
            "approvalContributionEventIds": self.approval_contribution_event_ids,
            "delegationIds": self.delegation_ids,
            "delegationContributionEventIds": self.delegation_contribution_event_ids,
            "delegationParentEventIds": self.delegation_parent_event_ids,
            "ruleSets": rulesets,
            "action": "cascade_delete",
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "user card cascade audit detail serialization failed: {error}"
            ))
        })
    }
}

/// 纯校验：卡级联审计必须携带正数目标 id、可关联 operation/parent 事件身份；
/// direct/approval 的规则主键与贡献事件号必须一一对应且各自非空；规则集贡献
/// 组的 (entry, ref) 维度必须非零、事件号非空且 ref 归属一致。缺失或错位拒绝落库。
fn validate_user_card_cascade_audit_entry(
    entry: &UserCardCascadeAuditEntry<'_>,
) -> Result<(), AstralError> {
    if entry.target_user_id <= 0 || entry.target_card_id <= 0 {
        return Err(AstralError::Validation(
            "user card cascade audit requires positive target ids".into(),
        ));
    }
    if entry.operation_id.trim().is_empty() || entry.parent_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "user card cascade audit requires operation and parent event correlation".into(),
        ));
    }
    if entry.direct_rule_ids.len() != entry.direct_contribution_event_ids.len()
        || entry.approval_rule_ids.len() != entry.approval_contribution_event_ids.len()
    {
        return Err(AstralError::Validation(
            "user card cascade audit requires one contribution event id per revoked rule \
             (direct and approval arrays must align)"
                .into(),
        ));
    }
    // DELEGATION 家族：delegation 主键 / 独立贡献事件号 / 各自 CARD 父事件号
    // 三个数组必须一一对应，且每条都可追溯（非空 id、非空事件号）。
    if entry.delegation_ids.len() != entry.delegation_contribution_event_ids.len()
        || entry.delegation_ids.len() != entry.delegation_parent_event_ids.len()
    {
        return Err(AstralError::Validation(
            "user card cascade audit requires one contribution event id and one parent \
             projection event per revoked delegation (all delegation arrays must align)"
                .into(),
        ));
    }
    for triple in entry
        .delegation_ids
        .iter()
        .zip(entry.delegation_contribution_event_ids.iter())
        .zip(entry.delegation_parent_event_ids.iter())
    {
        let ((delegation_id, contribution), parent) = triple;
        if *delegation_id <= 0 || contribution.trim().is_empty() || parent.trim().is_empty() {
            return Err(AstralError::Validation(
                "user card cascade audit delegation contributions must carry positive ids, \
                 a non-empty contribution event id and a non-empty parent event id"
                    .into(),
            ));
        }
    }
    for (ids, events) in [
        (entry.direct_rule_ids, entry.direct_contribution_event_ids),
        (
            entry.approval_rule_ids,
            entry.approval_contribution_event_ids,
        ),
    ] {
        if ids.iter().any(|id| *id <= 0) || events.iter().any(|event_id| event_id.trim().is_empty())
        {
            return Err(AstralError::Validation(
                "user card cascade audit requires positive rule ids and non-empty contribution ids"
                    .into(),
            ));
        }
    }
    for ruleset in entry.rulesets {
        if ruleset.rule_set_id <= 0 || ruleset.binding_ref_ids.is_empty() {
            return Err(AstralError::Validation(
                "user card cascade audit requires a positive rule set id with captured bindings"
                    .into(),
            ));
        }
        if ruleset.binding_ref_ids.iter().any(|id| *id <= 0) {
            return Err(AstralError::Validation(
                "user card cascade audit requires positive binding ref ids".into(),
            ));
        }
        if ruleset
            .removed_entries
            .iter()
            .any(|(entry_id, ref_id, event_id)| {
                *entry_id <= 0
                    || *ref_id <= 0
                    || !ruleset.binding_ref_ids.contains(ref_id)
                    || event_id.trim().is_empty()
            })
        {
            return Err(AstralError::Validation(
                "user card cascade audit ruleset entries must reference a captured binding and carry a contribution event id"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// 把用户卡级联删除的审计关联写入同一个 InnoDB 事务。
///
/// 沿用 `insert_direct_rule_audit_in_tx` 的既有机制：与 source 清理、head/outbox、
/// 授权账本 REMOVE 同事务落 `audit_log`，任何失败回滚整个 mutation。不能复用
/// MQ-first AuditDualWrite：它可能在事务提交后异步落库。
pub async fn insert_user_card_cascade_audit_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    entry: &UserCardCascadeAuditEntry<'_>,
) -> Result<(), AstralError> {
    validate_user_card_cascade_audit_entry(entry)?;
    let detail = entry.detail_json()?;
    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
         VALUES (?, ?, 'cascade_delete', 'user_card', ?, NULL, 'USER_CARD_MUTATION', ?, ?)",
    )
    .bind(entry.target_user_id)
    .bind(entry.target_card_id)
    // decision 与父 CARD REVOKE 投影事件的语义对齐（撤销事实贯穿两条链）。
    .bind("CARD_REVOKED")
    .bind(entry.operation_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        AstralError::Database(format!("user card cascade audit insert failed: {error}"))
    })?;
    Ok(())
}

/// 审计日志记录
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditLogRecord {
    pub id: i64,
    pub created_at: Option<String>,
    pub user_id: i64,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: Option<String>,
    pub card_id: Option<i64>,
}

/// 审计日志查询过滤。日期只接受固定 ISO 日期或 RFC3339，全部通过绑定参数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditLogFilter {
    pub user_id: Option<i64>,
    pub action: Option<String>,
    pub from: Option<PrimitiveDateTime>,
    pub to_exclusive: Option<PrimitiveDateTime>,
}

impl AuditLogFilter {
    pub fn new(
        user_id: Option<i64>,
        action: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Self, AstralError> {
        if user_id.is_some_and(|id| id <= 0) {
            return Err(AstralError::Validation(
                "audit userId must be positive".into(),
            ));
        }
        let action = action
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if action
            .as_ref()
            .is_some_and(|value| value.len() > 64 || value.contains('\0'))
        {
            return Err(AstralError::Validation(
                "audit action filter is invalid".into(),
            ));
        }
        let from = from.map(parse_audit_filter_time).transpose()?;
        let to = to.map(parse_audit_filter_time).transpose()?;
        if from.zip(to).is_some_and(|(from, to)| from > to) {
            return Err(AstralError::Validation(
                "audit from must not be after to".into(),
            ));
        }
        let to_exclusive = to.map(|value| value + time::Duration::seconds(1));
        Ok(Self {
            user_id,
            action,
            from,
            to_exclusive,
        })
    }
}

fn parse_audit_filter_time(value: &str) -> Result<PrimitiveDateTime, AstralError> {
    let raw = value.trim();
    if let Ok(date) = Date::parse(raw, &format_description::well_known::Iso8601::DEFAULT) {
        return Ok(PrimitiveDateTime::new(date, Time::MIDNIGHT));
    }
    let timestamp = OffsetDateTime::parse(raw, &format_description::well_known::Rfc3339)
        .map_err(|_| AstralError::Validation("audit dates must be ISO date or RFC3339".into()))?;
    Ok(PrimitiveDateTime::new(timestamp.date(), timestamp.time()))
}

/// 审计统计
#[derive(Debug, Clone, Default)]
pub struct AuditStatsRecord {
    pub total: i64,
    pub allowed: i64,
    pub denied: i64,
    pub unique_users: i64,
    pub top_resources: Vec<(String, i64)>,
}

#[async_trait]
pub trait AuditLogRepository: Send + Sync {
    async fn count_logs(&self, filter: &AuditLogFilter) -> Result<i64, AstralError>;
    async fn list_logs(
        &self,
        filter: &AuditLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogRecord>, AstralError>;
    async fn stats(&self) -> Result<AuditStatsRecord, AstralError>;
}

pub struct SqlxAuditLogRepository {
    db: MySqlPool,
}

fn push_audit_filter<'args>(builder: &mut QueryBuilder<'args, MySql>, filter: &AuditLogFilter) {
    builder.push(" WHERE ").push(USER_VISIBLE_AUDIT_PREDICATE);
    if let Some(user_id) = filter.user_id {
        builder.push(" AND user_id = ").push_bind(user_id);
    }
    if let Some(action) = &filter.action {
        builder.push(" AND action = ").push_bind(action.clone());
    }
    if let Some(from) = filter.from {
        builder.push(" AND created_at >= ").push_bind(from);
    }
    if let Some(to) = filter.to_exclusive {
        builder.push(" AND created_at < ").push_bind(to);
    }
}

fn user_visible_audit_count_sql(filter: &AuditLogFilter) -> QueryBuilder<'static, MySql> {
    let mut builder = QueryBuilder::<MySql>::new("SELECT COUNT(*) FROM audit_log");
    push_audit_filter(&mut builder, filter);
    builder
}

fn user_visible_audit_list_sql(
    filter: &AuditLogFilter,
    limit: i64,
    offset: i64,
) -> QueryBuilder<'static, MySql> {
    let mut builder = QueryBuilder::<MySql>::new(
        "SELECT id, created_at, user_id, action, resource, decision, reason, card_id FROM audit_log",
    );
    push_audit_filter(&mut builder, filter);
    builder
        .push(" ORDER BY created_at DESC, id DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    builder
}

fn audit_authorization_source_predicate_sql() -> &'static str {
    "event_type = 'AUTHZ_CHECK' AND decision IN ('ALLOW', 'DENY')"
}

pub(crate) fn audit_mutation_source_predicate_sql() -> &'static str {
    "decision <> 'INTERNAL' AND \
     (event_type IN ('USER_CARD_MUTATION', 'PERMISSION_RULE_MUTATION', 'RULE_CHANGE', \
                     'APPROVAL_DECISION', 'CARD_TEMPLATE_MUTATION', 'LEVEL_TEMPLATE_MUTATION', \
                     'DELEGATION_CREATED', 'DELEGATION_UPDATED', 'DELEGATION_REVOKED') \
      OR (resource IN ('user_card', 'permission_rule', 'permission_request', \
                       'card_template', 'level_template', 'permission_delegation') \
          AND event_type IS NOT NULL AND event_type <> 'AUTHZ_CHECK'))"
}

fn audit_stats_counts_sql() -> String {
    format!(
        "SELECT COUNT(*), COALESCE(SUM(decision = 'ALLOW'), 0), \
         COALESCE(SUM(decision = 'DENY'), 0) FROM audit_log WHERE {USER_VISIBLE_AUDIT_PREDICATE} AND {}",
        audit_authorization_source_predicate_sql()
    )
}

fn audit_top_resources_sql() -> String {
    format!(
        "SELECT resource, COUNT(*) AS total FROM audit_log WHERE {USER_VISIBLE_AUDIT_PREDICATE} AND {} GROUP BY resource ORDER BY total DESC, resource ASC LIMIT 10",
        audit_authorization_source_predicate_sql()
    )
}

fn audit_unique_users_sql() -> String {
    format!(
        "SELECT COUNT(DISTINCT user_id) FROM audit_log WHERE {USER_VISIBLE_AUDIT_PREDICATE} AND {}",
        audit_authorization_source_predicate_sql()
    )
}

impl SqlxAuditLogRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AuditLogRepository for SqlxAuditLogRepository {
    async fn count_logs(&self, filter: &AuditLogFilter) -> Result<i64, AstralError> {
        user_visible_audit_count_sql(filter)
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_logs(
        &self,
        filter: &AuditLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogRecord>, AstralError> {
        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        user_visible_audit_list_sql(filter, limit, offset)
            .build_query_as::<AuditLogRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn stats(&self) -> Result<AuditStatsRecord, AstralError> {
        let (total, allowed, denied): (i64, i64, i64) = sqlx::query_as(&audit_stats_counts_sql())
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        let unique_users: i64 = sqlx::query_scalar(&audit_unique_users_sql())
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        let top_resources: Vec<(String, i64)> = sqlx::query_as(&audit_top_resources_sql())
            .fetch_all(&self.db)
            .await
            .map_err(db_error)?;
        Ok(AuditStatsRecord {
            total,
            allowed,
            denied,
            unique_users,
            top_resources,
        })
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Audit log repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_filters_are_validated_and_applied_to_count_and_list() {
        assert_eq!(
            USER_VISIBLE_AUDIT_PREDICATE,
            astral_db::USER_VISIBLE_AUDIT_PREDICATE
        );
        let filter = AuditLogFilter::new(
            Some(17),
            Some(" update "),
            Some("2026-01-01"),
            Some("2026-01-02"),
        )
        .expect("canonical filters");
        let count_sql = user_visible_audit_count_sql(&filter).sql().to_owned();
        let list_sql = user_visible_audit_list_sql(&filter, 10, 0).sql().to_owned();
        for predicate in [
            "decision <> 'INTERNAL'",
            "user_id = ?",
            "action = ?",
            "created_at >= ?",
            "created_at < ?",
        ] {
            assert!(
                count_sql.contains(predicate),
                "count is missing {predicate}"
            );
            assert!(list_sql.contains(predicate), "list is missing {predicate}");
        }
        assert!(list_sql.contains("ORDER BY created_at DESC, id DESC"));
        assert!(audit_stats_counts_sql().contains("event_type = 'AUTHZ_CHECK'"));
        assert!(!audit_stats_counts_sql().contains('\\'));
        assert!(audit_unique_users_sql().contains("event_type = 'AUTHZ_CHECK'"));
        assert!(audit_top_resources_sql().contains("event_type = 'AUTHZ_CHECK'"));
        assert!(audit_top_resources_sql().contains("LIMIT 10"));
        assert!(
            audit_authorization_source_predicate_sql().contains("decision IN ('ALLOW', 'DENY')")
        );
        assert!(AuditLogFilter::new(Some(0), None, None, None).is_err());
        assert!(AuditLogFilter::new(None, None, Some("yesterday"), None).is_err());
        assert!(AuditLogFilter::new(None, None, Some("2026-01-03"), Some("2026-01-02")).is_err());
    }

    #[test]
    fn stats_and_compliance_feed_are_explicit_policy_and_mutation_scopes() {
        assert!(audit_authorization_source_predicate_sql().contains("AUTHZ_CHECK"));
        assert!(audit_mutation_source_predicate_sql().contains("USER_CARD_MUTATION"));
        assert!(audit_mutation_source_predicate_sql().contains("PERMISSION_RULE_MUTATION"));
        assert!(audit_mutation_source_predicate_sql().contains("APPROVAL_DECISION"));
        assert!(audit_mutation_source_predicate_sql().contains("DELEGATION_UPDATED"));
        assert!(audit_mutation_source_predicate_sql().contains("event_type <> 'AUTHZ_CHECK'"));
    }
    #[test]
    fn approval_audit_detail_preserves_actor_target_decision_and_request_context() {
        let context = ApprovalAuditContext::new(Some("http-request-7"), 42);
        let entry = ApprovalAuditEntry {
            actor_id: 17,
            reviewer_id: Some(17),
            target_user_id: 23,
            target_card_id: Some(29),
            action: "approve",
            decision: "APPROVED",
            request_reason: Some("need access"),
            reviewer_comment: Some("approved"),
            context: &context,
        };

        let detail: serde_json::Value =
            serde_json::from_str(&entry.detail_json().expect("detail should serialize"))
                .expect("detail should be valid JSON");
        assert_eq!(detail["actorId"], 17);
        assert_eq!(detail["reviewerId"], 17);
        assert_eq!(detail["targetUserId"], 23);
        assert_eq!(detail["targetCardId"], 29);
        assert_eq!(detail["approvalRequestId"], 42);
        assert_eq!(detail["requestId"], "http-request-7");
        assert_eq!(detail["action"], "approve");
        assert_eq!(detail["decision"], "APPROVED");
        assert_eq!(detail["requestReason"], "need access");
        assert_eq!(detail["reviewerComment"], "approved");
        assert!(detail["messageId"].as_str().is_some());
    }

    #[test]
    fn approval_audit_context_falls_back_when_request_id_is_missing_or_blank() {
        assert_eq!(
            ApprovalAuditContext::new(None, 42).request_id,
            "approval:42"
        );
        assert_eq!(
            ApprovalAuditContext::new(Some("  "), 42).request_id,
            "approval:42"
        );
    }

    #[test]
    fn http_context_requires_a_positive_verified_actor() {
        assert!(RuleSetMutationContext::user(17, Some("request-7")).is_ok());
        assert!(RuleSetMutationContext::user(0, Some("request-7")).is_err());
        assert!(RuleSetMutationContext::user(-1, Some("request-7")).is_err());
    }

    #[test]
    fn random_operation_fallback_is_never_marked_proven() {
        // 显式 request id / 系统固定串是可证明身份；
        // 缺失 header 时的随机 fallback 不是。
        let with_header = RuleSetMutationContext::user(17, Some("request-7")).unwrap();
        assert!(with_header.has_proven_operation_identity());
        assert_eq!(with_header.operation_id(), "request-7");
        let system = RuleSetMutationContext::system("startup:ruleset").unwrap();
        assert!(system.has_proven_operation_identity());
        let fallback = RuleSetMutationContext::user(17, None).unwrap();
        assert!(!fallback.has_proven_operation_identity());
        assert!(
            fallback.operation_id().starts_with("ruleset:"),
            "missing header keeps the legacy correlation shape"
        );
        let blank = RuleSetMutationContext::user(17, Some("   ")).unwrap();
        assert!(!blank.has_proven_operation_identity());
        // 派生重建只提升身份可证明性，不改变 actor 与其它事实；
        // 重放相同输入必然得到相同派生串（确定性由调用方保证）。
        let rebased = fallback
            .clone()
            .with_derived_operation_id("template-sync:5:9:gen:3".to_owned())
            .unwrap();
        assert_eq!(rebased.actor_id(), fallback.actor_id());
        assert_eq!(rebased.operation_id(), "template-sync:5:9:gen:3");
        assert_ne!(
            rebased, fallback,
            "derived identity must replace the random fallback"
        );
        assert!(rebased.has_proven_operation_identity());
        assert!(
            fallback
                .clone()
                .with_derived_operation_id("   ".to_owned())
                .is_err(),
            "blank derived identity must fail closed"
        );
    }

    /// 显式 x-request-id 是请求级 identity 的唯一可信入口：只允许安全 ASCII
    /// 且长度受限；不安全值必须 Validation fail-closed，绝不静默替换/截断。
    #[test]
    fn explicit_request_header_that_is_not_durable_safe_fails_closed() {
        for unsafe_header in [
            "a b",
            "x\ny",
            "\u{1}control",
            "控制字符",
            &"z".repeat(MAX_REQUEST_OPERATION_ID_LENGTH + 1),
        ] {
            let describe = unsafe_header;
            assert!(
                matches!(
                    RuleSetMutationContext::user(17, Some(unsafe_header)),
                    Err(AstralError::Validation(_))
                ),
                "unsafe explicit header must fail closed: {describe:?}"
            );
        }
        // 安全 ASCII 头部原样复用为持久 operation id。
        for safe in [
            "req-5",
            "http_9.bin:a/b",
            &"y".repeat(MAX_REQUEST_OPERATION_ID_LENGTH),
        ] {
            let context = RuleSetMutationContext::user(17, Some(safe))
                .unwrap_or_else(|error| panic!("safe header must pass: {error}"));
            assert_eq!(context.operation_id(), safe);
            assert!(context.has_proven_operation_identity());
        }
        // 与授权账本适配器同一上限常量的共享契约（两侧不得漂移）。
        assert_eq!(
            MAX_REQUEST_OPERATION_ID_LENGTH,
            crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH
        );
    }

    #[test]
    fn system_context_is_explicit_and_correlated() {
        let context = RuleSetMutationContext::system("startup:ruleset").unwrap();
        assert_eq!(context.actor_id(), SYSTEM_RULE_SET_ACTOR_ID);
        assert_eq!(context.operation_id(), "startup:ruleset");
        assert!(RuleSetMutationContext::system(" ").is_err());
    }

    fn direct_audit_entry<'a>(
        actor_id: i64,
        target_user_id: i64,
        target_card_id: i64,
        operation_id: &'a str,
        event_id: &'a str,
        contribution_event_ids: &'a [&'a str],
        rule_ids: &'a [i64],
    ) -> DirectRuleAuditEntry<'a> {
        DirectRuleAuditEntry {
            actor_id,
            target_user_id,
            target_card_id,
            action: "update",
            decision: "RULE_UPDATED",
            operation_id,
            event_id,
            contribution_event_ids,
            rule_ids,
        }
    }

    /// direct 规则审计 detail 必须保留 actor/目标/规则集合与 operation/event 关联，
    /// 且同时记录 parent 投影事件与每条规则的 contribution 事件号。
    #[test]
    fn direct_rule_audit_detail_preserves_actor_target_and_correlation() {
        let entry = direct_audit_entry(
            17,
            23,
            29,
            "permission-rule:update:7",
            "evt-parent-7",
            &["evt-c-7", "evt-c-9"],
            &[7, 9],
        );
        let detail: serde_json::Value =
            serde_json::from_str(&entry.detail_json().expect("detail should serialize"))
                .expect("detail should be valid JSON");
        assert_eq!(detail["actorId"], 17);
        assert_eq!(detail["targetUserId"], 23);
        assert_eq!(detail["targetCardId"], 29);
        assert_eq!(detail["ruleIds"][0], 7);
        assert_eq!(detail["ruleIds"][1], 9);
        assert_eq!(detail["operationId"], "permission-rule:update:7");
        // parent CARD 投影事件与全部 children 一并保留，可相互关联。
        assert_eq!(detail["eventId"], "evt-parent-7");
        assert_eq!(detail["contributionEventIds"][0], "evt-c-7");
        assert_eq!(detail["contributionEventIds"][1], "evt-c-9");
        assert_eq!(detail["action"], "update");

        // 批量移除的聚合条目允许覆盖多条规则（同一 operation id）。
        let batch = direct_audit_entry(
            17,
            23,
            29,
            "permission-rule:remove-by-card:29",
            "evt-card-29",
            &["c-3", "c-5", "c-8"],
            &[3, 5, 8],
        );
        assert!(
            batch.detail_json().is_ok(),
            "batch audit entry must serialize"
        );

        // 单条路径：唯一贡献即父投影事件号本身。
        let single = direct_audit_entry(
            17,
            23,
            29,
            "permission-rule:remove:8",
            "evt-proj-8",
            &["evt-proj-8"],
            &[8],
        );
        let detail = serde_json::from_str::<serde_json::Value>(
            &single.detail_json().expect("single should serialize"),
        )
        .unwrap();
        assert_eq!(detail["eventId"], detail["contributionEventIds"][0]);
    }

    /// 审计关联校验 fail-closed：缺 actor、缺目标、缺 rule 关联，以及
    /// contribution 事件号缺失/错位/为空都拒绝落库。
    #[test]
    fn direct_rule_audit_validation_fails_closed_on_missing_correlation() {
        assert!(validate_direct_rule_audit_entry(&direct_audit_entry(
            17,
            23,
            29,
            "op-7",
            "evt-7",
            &["evt-7"],
            &[7],
        ))
        .is_ok());
        for invalid in [
            direct_audit_entry(0, 23, 29, "op-7", "evt-7", &["evt-7"], &[7]),
            direct_audit_entry(-1, 23, 29, "op-7", "evt-7", &["evt-7"], &[7]),
            direct_audit_entry(17, 0, 29, "op-7", "evt-7", &["evt-7"], &[7]),
            direct_audit_entry(17, 23, -4, "op-7", "evt-7", &["evt-7"], &[7]),
            direct_audit_entry(17, 23, 29, " ", "evt-7", &["evt-7"], &[7]),
            direct_audit_entry(17, 23, 29, "op-7", "", &["evt-7"], &[7]),
            direct_audit_entry(17, 23, 29, "op-7", "evt-7", &["evt-7"], &[]),
            // 贡献事件号数量必须与规则一一对应：少一条即错位，拒绝落库。
            direct_audit_entry(17, 23, 29, "op-7", "evt-7", &[], &[7]),
            direct_audit_entry(17, 23, 29, "op-7", "evt-7", &["evt-7"], &[7, 9]),
            // 空贡献事件号不可追溯，拒绝落库。
            direct_audit_entry(17, 23, 29, "op-7", "evt-7", &[" "], &[7]),
            direct_audit_entry(17, 23, 29, "op-7", "evt-7", &[""], &[7]),
        ] {
            assert!(
                matches!(
                    validate_direct_rule_audit_entry(&invalid),
                    Err(AstralError::Validation(_))
                ),
                "invalid audit entry must be rejected"
            );
        }
    }

    fn audit_entry() -> RuleSetProjectionAuditEntry<'static> {
        RuleSetProjectionAuditEntry {
            rule_set_id: 11,
            entry_id: Some(22),
            aggregate_type: "RULE_SET",
            aggregate_id: 11,
            event_id: "event-11",
            source_generation: 7,
            operation_id: "operation-11",
            actor_id: 33,
            change_type: "UPDATE",
            old_value_json: Some(r#"{"enabled":false}"#),
            new_value_json: Some(r#"{"enabled":true}"#),
            tenant_id: Some(44),
        }
    }

    fn audit_row() -> RuleSetProjectionAuditRow {
        RuleSetProjectionAuditRow {
            rule_set_id: 11,
            entry_id: Some(22),
            changed_by: 33,
            change_type: "UPDATE".to_owned(),
            old_value_json: Some(r#"{"enabled":false}"#.to_owned()),
            new_value_json: Some(r#"{"enabled":true}"#.to_owned()),
            tenant_id: Some(44),
            aggregate_type: "RULE_SET".to_owned(),
            aggregate_id: 11,
            event_id: "event-11".to_owned(),
            source_generation: 7,
            operation_id: "operation-11".to_owned(),
        }
    }

    #[test]
    fn exact_rule_set_audit_replay_matches_every_immutable_field() {
        assert!(immutable_mismatch_fields(&audit_row(), &audit_entry()).is_empty());
    }

    #[test]
    fn conflicting_rule_set_audit_replay_reports_every_immutable_field() {
        let mut existing = audit_row();
        existing.event_id = "event-other".to_owned();
        existing.source_generation = 8;
        existing.change_type = "CREATE".to_owned();
        existing.rule_set_id = 12;
        existing.entry_id = None;
        existing.changed_by = 34;
        existing.old_value_json = None;
        existing.new_value_json = Some(r#"{"enabled":false}"#.to_owned());
        existing.tenant_id = None;
        existing.aggregate_type = "CARD".to_owned();
        existing.aggregate_id = 12;
        existing.operation_id = "operation-other".to_owned();

        assert_eq!(
            immutable_mismatch_fields(&existing, &audit_entry()),
            vec![
                "event_id",
                "source_generation",
                "change_type",
                "rule_set_id",
                "entry_id",
                "changed_by",
                "old_value_json",
                "new_value_json",
                "tenant_id",
                "aggregate_type",
                "aggregate_id",
                "operation_id",
            ]
        );
    }

    fn cascade_audit_entry() -> UserCardCascadeAuditEntry<'static> {
        UserCardCascadeAuditEntry {
            target_user_id: 42,
            target_card_id: 21,
            operation_id: "user-card:delete:21:gen:4",
            parent_event_id: "parent-event-1",
            direct_rule_ids: &[5077, 5100],
            direct_contribution_event_ids: &["evt-direct-1", "evt-direct-2"],
            approval_rule_ids: &[6011],
            approval_contribution_event_ids: &["evt-approval-1"],
            delegation_ids: &[],
            delegation_contribution_event_ids: &[],
            delegation_parent_event_ids: &[],
            rulesets: &[],
        }
    }

    #[test]
    fn cascade_audit_detail_correlates_parent_and_every_contribution_family() {
        let rulesets = [UserCardCascadeRulesetAudit {
            rule_set_id: 31,
            binding_ref_ids: vec![101, 102],
            removed_entries: vec![
                (901, 101, "evt-rs-1".to_owned()),
                (902, 102, "evt-rs-2".to_owned()),
            ],
        }];
        let delegation_ids = [8100i64];
        let delegation_events = ["evt-delegation-1"];
        let delegation_parents = ["parent-event-1"];
        let entry = UserCardCascadeAuditEntry {
            rulesets: &rulesets,
            delegation_ids: &delegation_ids,
            delegation_contribution_event_ids: &delegation_events,
            delegation_parent_event_ids: &delegation_parents,
            ..cascade_audit_entry()
        };
        let detail: serde_json::Value = serde_json::from_str(
            &entry
                .detail_json()
                .expect("cascade detail should serialize"),
        )
        .expect("valid JSON");
        assert_eq!(detail["targetUserId"], 42);
        assert_eq!(detail["targetCardId"], 21);
        assert_eq!(detail["operationId"], "user-card:delete:21:gen:4");
        assert_eq!(detail["parentEventId"], "parent-event-1");
        assert_eq!(detail["directRuleIds"][1], 5100);
        assert_eq!(detail["directContributionEventIds"][0], "evt-direct-1");
        assert_eq!(detail["approvalRuleIds"][0], 6011);
        assert_eq!(detail["approvalContributionEventIds"][0], "evt-approval-1");
        // DELEGATION 家族与 direct/approval 并列保留，parent 与独立事件号并存。
        assert_eq!(detail["delegationIds"][0], 8100);
        assert_eq!(
            detail["delegationContributionEventIds"][0],
            "evt-delegation-1"
        );
        assert_eq!(detail["delegationParentEventIds"][0], "parent-event-1");
        assert_eq!(detail["ruleSets"][0]["ruleSetId"], 31);
        assert_eq!(detail["ruleSets"][0]["bindingRefIds"][1], 102);
        assert_eq!(
            detail["ruleSets"][0]["removedEntries"][1]["eventId"],
            "evt-rs-2"
        );
        assert_eq!(
            detail["ruleSets"][0]["removedEntries"][1]["bindingRefId"],
            102
        );
        assert!(validate_user_card_cascade_audit_entry(&entry).is_ok());
    }

    #[test]
    fn cascade_audit_validation_rejects_unprovable_or_misaligned_evidence() {
        // 非法目标 id / 缺失关联。
        for broken in [
            UserCardCascadeAuditEntry {
                target_user_id: 0,
                ..cascade_audit_entry()
            },
            UserCardCascadeAuditEntry {
                target_card_id: -3,
                ..cascade_audit_entry()
            },
            UserCardCascadeAuditEntry {
                parent_event_id: "  ",
                ..cascade_audit_entry()
            },
            UserCardCascadeAuditEntry {
                operation_id: "",
                ..cascade_audit_entry()
            },
        ] {
            assert!(
                validate_user_card_cascade_audit_entry(&broken).is_err(),
                "unprovable correlation must fail closed"
            );
        }
        // rule 数与贡献数错位 / 空事件号。
        let misaligned = UserCardCascadeAuditEntry {
            direct_contribution_event_ids: &["evt-direct-1"],
            ..cascade_audit_entry()
        };
        assert!(validate_user_card_cascade_audit_entry(&misaligned).is_err());
        let empty_event = UserCardCascadeAuditEntry {
            direct_contribution_event_ids: &["evt-direct-1", ""],
            ..cascade_audit_entry()
        };
        assert!(validate_user_card_cascade_audit_entry(&empty_event).is_err());
        // 规则集组：引用被清空 / entry 指向未捕获的 binding / 空 binding。
        let dangling_ref = [UserCardCascadeRulesetAudit {
            rule_set_id: 31,
            binding_ref_ids: vec![101],
            removed_entries: vec![(901, 404, "evt-rs-x".to_owned())],
        }];
        assert!(
            validate_user_card_cascade_audit_entry(&UserCardCascadeAuditEntry {
                rulesets: &dangling_ref,
                ..cascade_audit_entry()
            })
            .is_err()
        );
        let no_bindings = [UserCardCascadeRulesetAudit {
            rule_set_id: 31,
            binding_ref_ids: vec![],
            removed_entries: vec![],
        }];
        assert!(
            validate_user_card_cascade_audit_entry(&UserCardCascadeAuditEntry {
                rulesets: &no_bindings,
                ..cascade_audit_entry()
            })
            .is_err()
        );
        // DELEGATION 家族：三个数组必须对齐，事件号/父事件号缺失或非法 id 拒绝落库。
        let delegation_ids = [8100i64];
        let one_event = ["evt-delegation-1"];
        let one_parent = ["parent-delegation-1"];
        let aligned = UserCardCascadeAuditEntry {
            delegation_ids: &delegation_ids,
            delegation_contribution_event_ids: &one_event,
            delegation_parent_event_ids: &one_parent,
            ..cascade_audit_entry()
        };
        assert!(validate_user_card_cascade_audit_entry(&aligned).is_ok());
        for broken in [
            UserCardCascadeAuditEntry {
                delegation_ids: &delegation_ids,
                delegation_contribution_event_ids: &[],
                delegation_parent_event_ids: &one_parent,
                ..cascade_audit_entry()
            },
            UserCardCascadeAuditEntry {
                delegation_ids: &delegation_ids,
                delegation_contribution_event_ids: &one_event,
                delegation_parent_event_ids: &[],
                ..cascade_audit_entry()
            },
        ] {
            assert!(
                validate_user_card_cascade_audit_entry(&broken).is_err(),
                "misaligned delegation arrays must be rejected"
            );
        }
        for bad in [
            UserCardCascadeAuditEntry {
                delegation_ids: &[0],
                delegation_contribution_event_ids: &one_event,
                delegation_parent_event_ids: &one_parent,
                ..cascade_audit_entry()
            },
            UserCardCascadeAuditEntry {
                delegation_ids: &delegation_ids,
                delegation_contribution_event_ids: &[" "],
                delegation_parent_event_ids: &one_parent,
                ..cascade_audit_entry()
            },
            UserCardCascadeAuditEntry {
                delegation_ids: &delegation_ids,
                delegation_contribution_event_ids: &one_event,
                delegation_parent_event_ids: &[""],
                ..cascade_audit_entry()
            },
        ] {
            assert!(
                validate_user_card_cascade_audit_entry(&bad).is_err(),
                "untraceable delegation contribution must fail closed"
            );
        }
    }
}
