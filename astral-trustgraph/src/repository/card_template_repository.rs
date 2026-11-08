//! 卡片模板数据访问 — CardTemplateRepository
//!
//! 对齐 Java `UserCardTemplateMapper` 边界（user_card_template 表）。
//! 写路径约束：
//! 1. status 白名单：仅 ACTIVE/INACTIVE，未知值 fail-closed。
//! 2. `__SUPERADMIN__` 模板与任意模板在仍有 ACTIVE 卡绑定时禁止脱离 ACTIVE
//!    （两个守卫持模板/卡行锁执行，拒绝性校验优先于变更检测）。
//! 3. 同 card_type 仅允许一个 SYSTEM 默认模板；SYSTEM 标记清理与本次写入
//!    同事务同连接。
//! 4. create/update/delete 以 `AuthorizationSourceTransaction` 为宿主（模板行
//!    是 owning-binding 存在性 source；源活动栅栏先于 begin、commit 证明后才
//!    返回），守卫、变更检测与审计同生共死。
//! 5. update 不追加 legacy 投影事件、不产生授权账本 delta（模板字段为
//!    issuance-only，无授权读侧消费者；TEMPLATE RuleSet 授权内容归
//!    `permission_rule_template` 同步路径）；审计关联为同事务 `audit_log`
//!    （actor/operation/实际变更字段 old/new）。
//! 6. `update_template_with_context` requires a verified positive actor and the
//!    exact operation identity from its admission proof; missing identity remains PENDING.

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder, Transaction};

use astral_types::AstralError;

use crate::repository::audit_log_repository::RuleSetMutationContext;
use crate::repository::authorization_source_transaction::{
    begin_source_transaction_with_capability, AuthorizationSourceTransaction,
    SourceMutationCapability,
};
use astral_db::{
    TypedRowOperation, TypedSourceRowImageReceipt, TypedSourceRowLookup, TypedSourceTable,
};

/// 卡片模板记录（user_card_template）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CardTemplateRecord {
    pub template_id: i64,
    pub domain_id: Option<i64>,
    pub template_code: Option<String>,
    pub template_name: String,
    pub card_type: Option<String>,
    pub template_scope: Option<String>,
    pub version_no: Option<i32>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct ActorCardRow {
    card_id: i64,
    user_id: i64,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    card_status: String,
}

/// 新建模板参数（handler 完成默认值解析后传入）
#[derive(Debug)]
pub struct NewCardTemplate {
    pub template_name: String,
    pub template_code: Option<String>,
    pub card_type: String,
    pub domain_id: Option<i64>,
    pub template_scope: String,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
}

/// 部分更新补丁（仅更新非 None 字段，对齐 Java Mapper.updateById 语义）
#[derive(Debug, Default)]
pub struct CardTemplatePatch {
    pub template_name: Option<String>,
    pub template_code: Option<String>,
    pub card_type: Option<String>,
    pub template_scope: Option<String>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
    pub status: Option<String>,
}

impl CardTemplatePatch {
    /// 是否为空补丁（所有字段 None）：空补丁不产生任何 SQL 与事务。
    fn is_empty(&self) -> bool {
        self.template_name.is_none()
            && self.template_code.is_none()
            && self.card_type.is_none()
            && self.template_scope.is_none()
            && self.default_priority.is_none()
            && self.default_roles_json.is_none()
            && self.resource_scope_json.is_none()
            && self.status.is_none()
    }
}

/// SELECT 列表达式（对齐 user_card_template 真实列名）
/// CAST(domain_id AS SIGNED) — 真实 DB 中 domain_id 可能为 DECIMAL 类型
/// CAST(json columns AS CHAR) — 确保 JSON 列以字符串返回
const TEMPLATE_SELECT_COLUMNS: &str = "template_id, CAST(domain_id AS SIGNED) as domain_id, \
     template_code, template_name, card_type, template_scope, version_no, default_priority, \
     CAST(default_roles_json AS CHAR) as default_roles_json, \
     CAST(resource_scope_json AS CHAR) as resource_scope_json, \
     status, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

/// 卡片模板 status 写路径白名单（大小写敏感；未知值 fail-closed 拒绝）
pub const CARD_TEMPLATE_STATUS_ACTIVE: &str = "ACTIVE";
pub const CARD_TEMPLATE_STATUS_INACTIVE: &str = "INACTIVE";
/// SYSTEM scope 常量（同 card_type 仅允许一个 SYSTEM 默认模板）
const TEMPLATE_SCOPE_SYSTEM: &str = "SYSTEM";
const TEMPLATE_SCOPE_TENANT: &str = "TENANT";
/// 规范超级管理员模板 code（与 GlobalAdmin grant/disable 的身份推导一致）
const SUPERADMIN_TEMPLATE_CODE: &str = "__SUPERADMIN__";
/// SUPER_ADMIN 卡的 card_type / card_status 取值（与 GlobalAdmin 发放路径一致）
const SUPER_ADMIN_CARD_TYPE: &str = "SUPER_ADMIN";
const CARD_STATUS_ACTIVE: &str = "ACTIVE";

/// 审计 action：卡片模板创建。
const CARD_TEMPLATE_AUDIT_ACTION_CREATE: &str = "card_template_create";
/// 审计 action：卡片模板删除。
const CARD_TEMPLATE_AUDIT_ACTION_DELETE: &str = "card_template_delete";
/// 审计 action：卡片模板部分更新（实际变更触发同事务审计 correlation）。
const CARD_TEMPLATE_AUDIT_ACTION_UPDATE: &str = "card_template_update";
/// event_type（audit_log.event_type VARCHAR(32)）：卡片模板 mutation 家族。
/// 三种 source mutation 共用同一 durable 审计关联通道。
const CARD_TEMPLATE_AUDIT_EVENT_TYPE: &str = "CARD_TEMPLATE_MUTATION";
/// resource：模板聚合名（单表，明细中携带模板身份）。
const CARD_TEMPLATE_AUDIT_RESOURCE: &str = "card_template";
/// `audit_log.decision` 固定值：模板 mutation 语义。
const CARD_TEMPLATE_AUDIT_DECISION_CREATE: &str = "TEMPLATE_CREATED";
const CARD_TEMPLATE_AUDIT_DECISION_DELETE: &str = "TEMPLATE_DELETED";
const CARD_TEMPLATE_AUDIT_DECISION_UPDATE: &str = "TEMPLATE_UPDATED";

/// `audit_log` 兜底关联 INSERT（仅绑定参数 + 固定 decision 常量；所有可变输入
/// 走 `?` 绑定，绝不拼接请求输入）。仅当模板尚无 TEMPLATE RuleSet 投影 owner
/// 时使用——此时没有 RULE_SET head/outbox 通道可写，审计是唯一 durable 证据。
const CARD_TEMPLATE_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
     VALUES (?, NULL, ?, ?, ?, NULL, ?, ?, ?)";

/// 锁定读回的模板当前行（守卫与变更检测的事务内事实来源）。JSON 列以
/// `CAST(... AS CHAR)` 读回（对齐 `TEMPLATE_SELECT_COLUMNS` 的列类型注释）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct CardTemplateCurrentRow {
    domain_id: Option<i64>,
    card_type: Option<String>,
    template_code: Option<String>,
    template_scope: Option<String>,
    template_name: String,
    default_priority: Option<i32>,
    default_roles_json: Option<String>,
    resource_scope_json: Option<String>,
    status: Option<String>,
}

/// update 的逐字段变更标记（`generic_rule_set_update_changes` 风格）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CardTemplateUpdateChanges {
    template_name: bool,
    template_code: bool,
    card_type: bool,
    template_scope: bool,
    default_priority: bool,
    default_roles_json: bool,
    resource_scope_json: bool,
    status: bool,
}

impl CardTemplateUpdateChanges {
    /// 是否存在任何实际变更；全部 false 时 update 走空提交（无投影/审计）。
    fn any(&self) -> bool {
        self.template_name
            || self.template_code
            || self.card_type
            || self.template_scope
            || self.default_priority
            || self.default_roles_json
            || self.resource_scope_json
            || self.status
    }
}

/// 按实际写入值逐字段比较（不做静默归一化；None 与 Some("") 是不同值，
/// None 补丁字段表示"不修改"而非"清空"）。纯逻辑，便于单测。
fn generic_card_template_update_changes(
    current: &CardTemplateCurrentRow,
    patch: &CardTemplatePatch,
) -> CardTemplateUpdateChanges {
    // None 补丁字段 = 不修改（与 QueryBuilder 只写 Some 字段的 UPDATE 语义、
    // 上方函数契约注释一致）；只有携带值且与锁定现值不同才算实际变更。
    CardTemplateUpdateChanges {
        template_name: patch
            .template_name
            .as_ref()
            .is_some_and(|value| *value != current.template_name),
        template_code: patch
            .template_code
            .as_deref()
            .is_some_and(|value| Some(value) != current.template_code.as_deref()),
        card_type: patch
            .card_type
            .as_deref()
            .is_some_and(|value| Some(value) != current.card_type.as_deref()),
        template_scope: patch
            .template_scope
            .as_deref()
            .is_some_and(|value| Some(value) != current.template_scope.as_deref()),
        default_priority: patch
            .default_priority
            .is_some_and(|value| Some(value) != current.default_priority),
        default_roles_json: patch
            .default_roles_json
            .as_deref()
            .is_some_and(|value| Some(value) != current.default_roles_json.as_deref()),
        resource_scope_json: patch
            .resource_scope_json
            .as_deref()
            .is_some_and(|value| Some(value) != current.resource_scope_json.as_deref()),
        status: patch
            .status
            .as_deref()
            .is_some_and(|value| Some(value) != current.status.as_deref()),
    }
}

/// 带上下文 update 的调用方 actor 守卫（纯函数）：审计必须落已验证正数
/// actor（exact HTTP 身份）；system/零/负值上下文一律 Auth 拒绝。
fn guard_card_template_update_actor(actor_id: i64) -> Result<(), AstralError> {
    if actor_id <= 0 {
        return Err(AstralError::Auth(
            "card template update requires a verified positive actor id".into(),
        ));
    }
    Ok(())
}

/// 把实际变更字段映射为审计 old/new JSON（纯逻辑；只包含实际变更的字段，
/// 对齐 `rule_set_repository::update_rule_set` 的"审计只记录实际变更"契约；
/// 键名对齐 DTO camelCase）。
fn changed_field_values(
    changes: &CardTemplateUpdateChanges,
    current: &CardTemplateCurrentRow,
    patch: &CardTemplatePatch,
) -> (serde_json::Value, serde_json::Value) {
    let mut old_value = serde_json::Map::new();
    let mut new_value = serde_json::Map::new();
    let mut record = |key: &str, old: serde_json::Value, new: serde_json::Value| {
        old_value.insert(key.into(), old);
        new_value.insert(key.into(), new);
    };
    if changes.template_name {
        record(
            "templateName",
            serde_json::json!(&current.template_name),
            serde_json::json!(&patch.template_name),
        );
    }
    if changes.template_code {
        record(
            "templateCode",
            serde_json::json!(&current.template_code),
            serde_json::json!(&patch.template_code),
        );
    }
    if changes.card_type {
        record(
            "cardType",
            serde_json::json!(&current.card_type),
            serde_json::json!(&patch.card_type),
        );
    }
    if changes.template_scope {
        record(
            "templateScope",
            serde_json::json!(&current.template_scope),
            serde_json::json!(&patch.template_scope),
        );
    }
    if changes.default_priority {
        record(
            "defaultPriority",
            serde_json::json!(current.default_priority),
            serde_json::json!(patch.default_priority),
        );
    }
    if changes.default_roles_json {
        record(
            "defaultRolesJson",
            serde_json::json!(&current.default_roles_json),
            serde_json::json!(&patch.default_roles_json),
        );
    }
    if changes.resource_scope_json {
        record(
            "resourceScopeJson",
            serde_json::json!(&current.resource_scope_json),
            serde_json::json!(&patch.resource_scope_json),
        );
    }
    if changes.status {
        record(
            "status",
            serde_json::json!(&current.status),
            serde_json::json!(&patch.status),
        );
    }
    (
        serde_json::Value::Object(old_value),
        serde_json::Value::Object(new_value),
    )
}

/// 卡片模板 mutation 的同事务审计关联输入：一条记录覆盖一次 update 的全部
/// 实际变更字段（对有无 TEMPLATE RuleSet owner 的模板同一语义）。
struct CardTemplateAuditEntry<'a> {
    template_id: i64,
    action: &'a str,
    decision: &'a str,
    old_value: &'a serde_json::Value,
    new_value: &'a serde_json::Value,
    context: &'a RuleSetMutationContext,
}

async fn validate_card_template_admission(
    tx: &mut AuthorizationSourceTransaction,
    context: &RuleSetMutationContext,
    domain_id: Option<i64>,
    _template_id: Option<i64>,
) -> Result<(), AstralError> {
    let SourceMutationCapability::User(admission) = context.source_capability() else {
        return Err(AstralError::Pending(
            "card template mutation requires proof-bound authorization admission".into(),
        ));
    };
    let scope = &admission.proof().scope;
    match context.source_capability() {
        SourceMutationCapability::User(admission)
            if admission.proof().operation_id == context.operation_id() => {}
        SourceMutationCapability::User(_) => {
            return Err(AstralError::Pending(
                "card template config completion operation id differs from its admission proof"
                    .into(),
            ));
        }
        _ => {
            return Err(AstralError::Pending(
                "card template config completion requires proof-bound user admission".into(),
            ));
        }
    }
    if scope.user_id != Some(context.actor_id()) {
        return Err(AstralError::Permission(
            "card template admission user does not match the verified actor".into(),
        ));
    }
    let actor_card: Option<ActorCardRow> = sqlx::query_as(
        "SELECT card_id, user_id, tenant_id, domain_id, card_status FROM user_card \
         WHERE card_id = ? FOR UPDATE",
    )
    .bind(scope.card_id)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(db_error)?;
    let Some(actor_card) = actor_card else {
        return Err(AstralError::Permission(
            "card template admission actor card is unavailable".into(),
        ));
    };
    if actor_card.card_id != scope.card_id
        || actor_card.user_id != context.actor_id()
        || actor_card.tenant_id != Some(scope.tenant_id)
        || actor_card.card_status != CARD_STATUS_ACTIVE
    {
        return Err(AstralError::Permission(
            "card template admission does not match the locked actor card".into(),
        ));
    }
    let domain_matches = match (scope.domain.clone(), domain_id) {
        (astral_types::AuthorizationDomainScope::Any, _) => true,
        (astral_types::AuthorizationDomainScope::NoDomain, None) => true,
        (astral_types::AuthorizationDomainScope::Exact(value), Some(expected)) => value == expected,
        _ => false,
    };
    let card_scope_matches = match scope.domain {
        astral_types::AuthorizationDomainScope::Any => true,
        astral_types::AuthorizationDomainScope::NoDomain => actor_card.domain_id.is_none(),
        astral_types::AuthorizationDomainScope::Exact(expected) => {
            actor_card.domain_id == Some(expected)
        }
    };
    if !domain_matches || !card_scope_matches {
        return Err(AstralError::Permission(
            "card template admission does not match the locked template domain scope".into(),
        ));
    }
    Ok(())
}

impl CardTemplateAuditEntry<'_> {
    /// 结构化审计详情；序列化失败必须阻止事务提交。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "templateId": self.template_id,
            "operationId": self.context.operation_id(),
            "actorId": self.context.actor_id(),
            "action": self.action,
            "decision": self.decision,
            "changedFields": {
                "old": self.old_value,
                "new": self.new_value,
            },
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "card template audit detail serialization failed: {error}"
            ))
        })
    }

    /// 纯校验：正数模板 id、正数 actor、非空 action/decision/operation id
    /// （fail-closed）。
    fn validate(&self) -> Result<(), AstralError> {
        if self.template_id <= 0 {
            return Err(AstralError::Validation(
                "card template audit requires a positive template id".into(),
            ));
        }
        if self.context.actor_id() <= 0 {
            return Err(AstralError::Validation(
                "card template audit requires a positive actor id".into(),
            ));
        }
        if self.action.trim().is_empty() || self.decision.trim().is_empty() {
            return Err(AstralError::Validation(
                "card template audit requires non-empty action and decision".into(),
            ));
        }
        if self.context.operation_id().trim().is_empty() {
            return Err(AstralError::Validation(
                "card template audit requires a non-empty operation id".into(),
            ));
        }
        Ok(())
    }
}

/// 把卡片模板 mutation 的审计关联写入调用方 source 事务（`audit_log`）。
/// 沿用 `insert_level_template_audit_in_tx` 的既有机制：与 source mutation 同
/// 事务落库，任何失败回滚整个 mutation。不能复用 MQ-first AuditDualWrite：
/// 它可能在事务提交后异步落库，无法保证与 source 原子一致。
async fn insert_card_template_audit_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    entry: &CardTemplateAuditEntry<'_>,
) -> Result<astral_db::TypedSourceAuditReceipt, AstralError> {
    entry.validate()?;
    let detail = entry.detail_json()?;
    let result = sqlx::query(CARD_TEMPLATE_AUDIT_INSERT_SQL)
        .bind(entry.context.actor_id())
        .bind(entry.action)
        .bind(CARD_TEMPLATE_AUDIT_RESOURCE)
        .bind(entry.decision)
        .bind(CARD_TEMPLATE_AUDIT_EVENT_TYPE)
        .bind(entry.context.operation_id())
        .bind(&detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("card template audit insert failed: {error}"))
        })?;
    astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(result.last_insert_id() as i64)
}

#[async_trait]
pub trait CardTemplateRepository: Send + Sync {
    /// 活跃模板总数（status='ACTIVE'）
    async fn count_templates(&self) -> Result<i64, AstralError>;
    /// 活跃模板分页列表（ORDER BY template_id）
    async fn list_templates(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CardTemplateRecord>, AstralError>;
    async fn get_template(&self, id: i64) -> Result<Option<CardTemplateRecord>, AstralError>;
    /// 新建模板；若 scope=SYSTEM 先在同一事务内清除同类型其他 SYSTEM 标记。
    /// source mutation 与 CREATE 审计关联同事务提交。
    async fn create_template(
        &self,
        new: &NewCardTemplate,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError>;
    /// Update using the verified actor and a stable operation identity.
    /// Missing request identity is derived once from locked durable facts.
    async fn update_template_with_context(
        &self,
        id: i64,
        patch: &CardTemplatePatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// Transactionally delete only when no observable schema reference exists.
    /// source mutation 与 DELETE 审计关联同事务提交。
    async fn delete_template_if_unreferenced(
        &self,
        id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxCardTemplateRepository {
    db: MySqlPool,
}

impl SqlxCardTemplateRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

impl SqlxCardTemplateRepository {
    fn stage_config_evidence(
        tx: &mut AuthorizationSourceTransaction,
        mut images: Vec<TypedSourceRowImageReceipt>,
        mut audits: Vec<astral_db::TypedSourceAuditReceipt>,
    ) -> Result<(), AstralError> {
        images.sort_by(|left, right| {
            (left.table().as_str(), left.key()).cmp(&(right.table().as_str(), right.key()))
        });
        audits.sort_by_key(astral_db::TypedSourceAuditReceipt::audit_log_id);
        for image in images {
            tx.stage_typed_source_image(image)?;
        }
        for audit in audits {
            tx.stage_typed_source_audit(audit)?;
        }
        Ok(())
    }

    /// 将同 card_type 下其他 SYSTEM 模板降为 TENANT（SYSTEM 仅允许一个）。
    /// 必须在持有调用方事务的情况下执行，与本次写入同一连接、同生共死。
    async fn clear_system_scope_in_tx(
        tx: &mut AuthorizationSourceTransaction,
        card_type: &str,
        excluded_template_id: Option<i64>,
        context: &RuleSetMutationContext,
    ) -> Result<
        (
            Vec<TypedSourceRowImageReceipt>,
            Vec<astral_db::TypedSourceAuditReceipt>,
        ),
        AstralError,
    > {
        // All candidates are locked in stable primary-key order before any mutation.
        // ConfigCompletion permits at most 64 audit rows; the caller also records
        // its primary mutation, so cleanup is bounded to 63 source rows.
        let targets: Vec<(i64,)> = if let Some(excluded_template_id) = excluded_template_id {
            sqlx::query_as(
                "SELECT template_id FROM user_card_template \
                 WHERE card_type = ? AND template_scope = 'SYSTEM' AND template_id <> ? \
                 ORDER BY template_id LIMIT 64 FOR UPDATE",
            )
            .bind(card_type)
            .bind(excluded_template_id)
            .fetch_all(&mut ***tx)
            .await
            .map_err(db_error)?
        } else {
            sqlx::query_as(
                "SELECT template_id FROM user_card_template \
                 WHERE card_type = ? AND template_scope = 'SYSTEM' \
                 ORDER BY template_id LIMIT 64 FOR UPDATE",
            )
            .bind(card_type)
            .fetch_all(&mut ***tx)
            .await
            .map_err(db_error)?
        };
        if targets.len() > 63 {
            return Err(AstralError::Pending(
                "system card-template cleanup exceeds ConfigCompletion's bounded audit capacity"
                    .into(),
            ));
        }

        let mut images = Vec::with_capacity(targets.len());
        let mut audits = Vec::with_capacity(targets.len());
        for (template_id,) in targets {
            // Capture/mutate/capture/seal each locked row before proceeding to the
            // next. This avoids retaining multiple exclusive transaction borrows.
            let lookup = TypedSourceRowLookup::PrimaryId { id: template_id };
            let mut capture = tx.typed_row_capture(
                TypedSourceTable::UserCardTemplate,
                TypedRowOperation::Update,
            );
            capture.capture_before_in_tx(&lookup).await?;
            let card_type_owned = card_type.to_owned();
            let result = capture
                .with_tx_mut(|tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE user_card_template SET template_scope = 'TENANT' \
                             WHERE template_id = ? AND card_type = ? AND template_scope = 'SYSTEM'",
                        )
                        .bind(template_id)
                        .bind(card_type_owned)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                    })
                })
                .await?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Pending(format!(
                    "locked SYSTEM card template {template_id} changed outside the bounded cleanup set"
                )));
            }
            capture.capture_after_in_tx(&lookup).await?;
            let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
            let before: serde_json::Value =
                serde_json::from_str(image.before_image()).map_err(|error| {
                    AstralError::Pending(format!(
                        "SYSTEM card-template before image is invalid: {error}"
                    ))
                })?;
            if before["template_id"].as_i64() != Some(template_id)
                || before["card_type"].as_str() != Some(card_type)
                || before["template_scope"].as_str() != Some(TEMPLATE_SCOPE_SYSTEM)
            {
                return Err(AstralError::Pending(format!(
                    "typed SYSTEM card-template image does not match locked cleanup row {template_id}"
                )));
            }
            let audit = insert_card_template_audit_in_tx(
                tx,
                &CardTemplateAuditEntry {
                    template_id,
                    action: CARD_TEMPLATE_AUDIT_ACTION_UPDATE,
                    decision: CARD_TEMPLATE_AUDIT_DECISION_UPDATE,
                    old_value: &serde_json::json!({ "templateScope": before["template_scope"] }),
                    new_value: &serde_json::json!({ "templateScope": TEMPLATE_SCOPE_TENANT }),
                    context,
                },
            )
            .await?;
            images.push(image);
            audits.push(audit);
        }
        Ok((images, audits))
    }

    /// 事务内锁定引用指定模板的全部卡行，并统计
    /// `(ACTIVE 卡总数, ACTIVE SUPER_ADMIN 卡数)`。
    /// 锁定（而非只读）以串行化并发卡状态翻转：任何并发 mutation 必须等本事务
    /// 提交/回滚后才能改变这些卡，守卫计数与模板状态变更因此原子成立。
    async fn lock_and_count_active_cards(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        template_id: i64,
    ) -> Result<(i64, i64), AstralError> {
        let rows: Vec<(Option<String>, String)> = sqlx::query_as(
            "SELECT card_type, card_status FROM user_card \
             WHERE template_id = ? FOR UPDATE",
        )
        .bind(template_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
        let total_active = rows
            .iter()
            .filter(|(_, status)| status == CARD_STATUS_ACTIVE)
            .count() as i64;
        let super_admin_active = rows
            .iter()
            .filter(|(card_type, status)| {
                card_type.as_deref() == Some(SUPER_ADMIN_CARD_TYPE) && status == CARD_STATUS_ACTIVE
            })
            .count() as i64;
        Ok((total_active, super_admin_active))
    }

    async fn detach_child_templates_in_tx(
        tx: &mut AuthorizationSourceTransaction,
        parent_template_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<
        (
            Vec<TypedSourceRowImageReceipt>,
            Vec<astral_db::TypedSourceAuditReceipt>,
        ),
        AstralError,
    > {
        let targets: Vec<(i64,)> = sqlx::query_as(
            "SELECT template_id FROM user_card_template \
             WHERE parent_template_id = ? AND template_id <> ? \
             ORDER BY template_id LIMIT 64 FOR UPDATE",
        )
        .bind(parent_template_id)
        .bind(parent_template_id)
        .fetch_all(&mut ***tx)
        .await
        .map_err(db_error)?;
        if targets.len() > 63 {
            return Err(AstralError::Pending(
                "card-template child detach exceeds ConfigCompletion's bounded audit capacity"
                    .into(),
            ));
        }

        let mut images = Vec::with_capacity(targets.len());
        let mut audits = Vec::with_capacity(targets.len());
        for (template_id,) in targets {
            let lookup = TypedSourceRowLookup::PrimaryId { id: template_id };
            let mut capture = tx.typed_row_capture(
                TypedSourceTable::UserCardTemplate,
                TypedRowOperation::Update,
            );
            capture.capture_before_in_tx(&lookup).await?;
            let result = capture
                .with_tx_mut(|tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE user_card_template SET parent_template_id = NULL \
                             WHERE template_id = ? AND parent_template_id = ?",
                        )
                        .bind(template_id)
                        .bind(parent_template_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                    })
                })
                .await?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Pending(format!(
                    "locked child card template {template_id} changed outside the bounded detach set"
                )));
            }
            capture.capture_after_in_tx(&lookup).await?;
            let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
            let before: serde_json::Value =
                serde_json::from_str(image.before_image()).map_err(|error| {
                    AstralError::Pending(format!(
                        "card-template child before image is invalid: {error}"
                    ))
                })?;
            if before["parent_template_id"].as_i64() != Some(parent_template_id) {
                return Err(AstralError::Pending(format!(
                    "typed child image does not match locked parent relation for template {template_id}"
                )));
            }
            let audit = insert_card_template_audit_in_tx(
                tx,
                &CardTemplateAuditEntry {
                    template_id,
                    action: CARD_TEMPLATE_AUDIT_ACTION_UPDATE,
                    decision: CARD_TEMPLATE_AUDIT_DECISION_UPDATE,
                    old_value: &serde_json::json!({ "parentTemplateId": parent_template_id }),
                    new_value: &serde_json::json!({ "parentTemplateId": null }),
                    context,
                },
            )
            .await?;
            images.push(image);
            audits.push(audit);
        }
        Ok((images, audits))
    }

    async fn apply_template_update(
        &self,
        id: i64,
        patch: &CardTemplatePatch,
        caller: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        guard_card_template_update_actor(caller.actor_id())?;
        // 空补丁：无字段更新（对齐原语义，不产生 SQL 与事务）
        if patch.is_empty() {
            return Ok(());
        }
        // status 白名单（repository 层防线的兜底）：任何来源的补丁都不得携带
        // 白名单之外的状态；API 层已在进入本方法前做过同一校验。
        if let Some(status) = &patch.status {
            guard_card_template_status(status)?;
        }

        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed）。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, caller.source_capability()).await?;

        // TEMPLATE RuleSet 投影 owner（若存在）先于模板行锁定：与规则模板同步
        // 路径锁序一致，避免 AB-BA 死锁；该锁同时串行化本 update 与模板规则
        // 同步。本 update 自身不写任何 RULE_SET 投影/账本状态。
        let _rule_set_id: Option<i64> = sqlx::query_as::<_, (i64,)>(
            "SELECT rule_set_id FROM rule_set \
             WHERE source_type = 'TEMPLATE' AND source_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .map(|(rule_set_id,)| rule_set_id);

        // 行锁：与 GlobalAdmin grant（同样以 FOR UPDATE 锁定本模板行）串行化，
        // 并为下方守卫与变更检测提供事务内已证明的当前状态（JSON 列以 CHAR
        // 读回，列类型语义与 TEMPLATE_SELECT_COLUMNS 一致）。
        let current: Option<CardTemplateCurrentRow> = sqlx::query_as(
            "SELECT domain_id, card_type, template_code, template_scope, template_name, default_priority, \
             CAST(default_roles_json AS CHAR), CAST(resource_scope_json AS CHAR), status \
             FROM user_card_template WHERE template_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;

        // 模板不存在：保持原语义（UPDATE 影响 0 行时返回 Ok，由 handler 的
        // 后续 get 报 NotFound）；事务 drop 即回滚，无任何 source 变更。
        let Some(current) = current else {
            return Ok(());
        };
        validate_card_template_admission(&mut tx, caller, current.domain_id, Some(id)).await?;

        // 守卫是拒绝性校验，不产生写入，且优先于变更检测（下线意图即便与
        // 现值相同也不得绕过守卫）。计数行已在本事务内锁定。
        if let Some(target_status) = &patch.status {
            let (active_cards, active_super_admin_cards) =
                Self::lock_and_count_active_cards(&mut tx, id).await?;
            guard_superadmin_active_deactivation(
                current.template_code.as_deref(),
                active_super_admin_cards,
                target_status,
                id,
            )?;
            guard_no_active_cards(active_cards, target_status, id)?;
        }

        // 变更检测：无可变字段实际变化 ⇒ 无 source mutation、无审计。
        let changes = generic_card_template_update_changes(&current, patch);
        if !changes.any() {
            // CONFIG_COMPLETION requires a real changed before/after source image;
            // do not consume an admission or claim success for an unchanged row.
            return Err(AstralError::Pending(
                "card template update has no changed source image to complete".into(),
            ));
        }

        // 生效值：以补丁覆盖后的 card_type/template_scope 判定守卫与清理目标。
        let effective_card_type: Option<String> =
            patch.card_type.clone().or(current.card_type.clone());
        let effective_scope: Option<String> = patch
            .template_scope
            .clone()
            .or(current.template_scope.clone());

        // CONFIG_COMPLETION audit.request_id must equal the proof operation id;
        // do not replace a missing/random request identity with a derived label.
        if !caller.has_proven_operation_identity() {
            return Err(AstralError::Pending(
                "card template config completion requires the admission proof operation id".into(),
            ));
        }
        let context = caller;
        let mut cleanup_images = Vec::new();
        let mut cleanup_audits = Vec::new();

        // SYSTEM 清理与本次 UPDATE 同事务/同一连接：UPDATE 失败即整体回滚。
        if effective_scope.as_deref() == Some(TEMPLATE_SCOPE_SYSTEM)
            && (patch.template_scope.is_some() || patch.card_type.is_some())
        {
            if let Some(card_type) = &effective_card_type {
                (cleanup_images, cleanup_audits) =
                    Self::clear_system_scope_in_tx(&mut tx, card_type, Some(id), context).await?;
            }
        }

        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::UserCardTemplate,
            TypedRowOperation::Update,
        );
        capture.capture_before_in_tx(&lookup).await?;

        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE user_card_template SET ");
        let mut first = true;
        if let Some(name) = &patch.template_name {
            if !first {
                builder.push(", ");
            }
            builder.push("template_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.template_code {
            if !first {
                builder.push(", ");
            }
            builder.push("template_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(card_type) = &patch.card_type {
            if !first {
                builder.push(", ");
            }
            builder.push("card_type = ").push_bind(card_type.clone());
            first = false;
        }
        if let Some(scope) = &patch.template_scope {
            if !first {
                builder.push(", ");
            }
            builder.push("template_scope = ").push_bind(scope.clone());
            first = false;
        }
        if let Some(priority) = patch.default_priority {
            if !first {
                builder.push(", ");
            }
            builder.push("default_priority = ").push_bind(priority);
            first = false;
        }
        if let Some(json) = &patch.default_roles_json {
            if !first {
                builder.push(", ");
            }
            builder
                .push("default_roles_json = ")
                .push_bind(json.clone());
            first = false;
        }
        if let Some(json) = &patch.resource_scope_json {
            if !first {
                builder.push(", ");
            }
            builder
                .push("resource_scope_json = ")
                .push_bind(json.clone());
            first = false;
        }
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            // status 是补丁的最后一个字段，无需再翻转 first（避免 dead assignment）
            builder.push("status = ").push_bind(status.clone());
        }
        builder.push(" WHERE template_id = ").push_bind(id);
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move { builder.build().execute(&mut **tx).await.map_err(db_error) })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(format!(
                "card template {id} update did not prove exactly one changed source row"
            )));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;

        // 审计 correlation（同一 source 事务）：update 不追加 legacy 投影事件、
        // 不产生授权账本 delta（模块头约束 5），全部实际变更字段以同事务
        // `audit_log` 行关联（actor/operation/old/new）。任何失败回滚整个 update。
        let (old_value, new_value) = changed_field_values(&changes, &current, patch);
        let audit = insert_card_template_audit_in_tx(
            &mut tx,
            &CardTemplateAuditEntry {
                template_id: id,
                action: CARD_TEMPLATE_AUDIT_ACTION_UPDATE,
                decision: CARD_TEMPLATE_AUDIT_DECISION_UPDATE,
                old_value: &old_value,
                new_value: &new_value,
                context,
            },
        )
        .await?;
        cleanup_images.push(image);
        cleanup_audits.push(audit);
        Self::stage_config_evidence(&mut tx, cleanup_images, cleanup_audits)?;
        tx.commit_consuming().await?;
        Ok(())
    }
}

#[async_trait]
impl CardTemplateRepository for SqlxCardTemplateRepository {
    async fn count_templates(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_card_template WHERE status = 'ACTIVE'",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_templates(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CardTemplateRecord>, AstralError> {
        sqlx::query_as::<_, CardTemplateRecord>(&format!(
            "SELECT {TEMPLATE_SELECT_COLUMNS} FROM user_card_template \
             WHERE status = 'ACTIVE' ORDER BY template_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_template(&self, id: i64) -> Result<Option<CardTemplateRecord>, AstralError> {
        sqlx::query_as::<_, CardTemplateRecord>(&format!(
            "SELECT {TEMPLATE_SELECT_COLUMNS} FROM user_card_template WHERE template_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_template(
        &self,
        new: &NewCardTemplate,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        guard_card_template_update_actor(context.actor_id())?;
        // 先锁定调用方证明卡和模板所属 scope，再允许 owning-binding source 写入。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        validate_card_template_admission(&mut tx, context, new.domain_id, None).await?;

        let domain_id = new.domain_id.filter(|value| *value > 0).ok_or_else(|| {
            AstralError::Validation("card template create requires a positive domain id".into())
        })?;
        let template_code = new
            .template_code
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AstralError::Validation(
                    "card template create requires its unique template code".into(),
                )
            })?;
        if !context.has_proven_operation_identity() {
            return Err(AstralError::Pending(
                "card template config completion requires the admission proof operation id".into(),
            ));
        }
        let lookup = TypedSourceRowLookup::CardTemplateNatural {
            domain_id,
            template_code: template_code.to_owned(),
        };
        let mut cleanup_images = Vec::new();
        let mut cleanup_audits = Vec::new();
        // If scope is SYSTEM, each old SYSTEM row is changed under an ordered lock
        // with its own real image and same-transaction audit evidence.
        if new.template_scope == TEMPLATE_SCOPE_SYSTEM {
            (cleanup_images, cleanup_audits) =
                Self::clear_system_scope_in_tx(&mut tx, &new.card_type, None, context).await?;
        }
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::UserCardTemplate,
            TypedRowOperation::Insert,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let template_name_owned = new.template_name.clone();
        let template_code_owned = new.template_code.clone();
        let card_type_owned = new.card_type.clone();
        let domain_id_owned = new.domain_id;
        let template_scope_owned = new.template_scope.clone();
        let default_priority_owned = new.default_priority;
        let default_roles_json_owned = new.default_roles_json.clone();
        let resource_scope_json_owned = new.resource_scope_json.clone();
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO user_card_template (template_name, template_code, card_type, domain_id, \
                         template_scope, default_priority, default_roles_json, resource_scope_json, status) \
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
                    )
                    .bind(template_name_owned)
                    .bind(template_code_owned)
                    .bind(card_type_owned)
                    .bind(domain_id_owned)
                    .bind(template_scope_owned)
                    .bind(default_priority_owned)
                    .bind(default_roles_json_owned)
                    .bind(resource_scope_json_owned)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "card template insert did not prove exactly one source row".into(),
            ));
        }
        let new_id = i64::try_from(result.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Pending("card template insert returned invalid id".into())
            })?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        if image.key() != new_id {
            return Err(AstralError::Pending(
                "card template inserted row differs from its locked natural-key readback".into(),
            ));
        }
        let empty = serde_json::json!({});
        let audit = insert_card_template_audit_in_tx(
            &mut tx,
            &CardTemplateAuditEntry {
                template_id: new_id,
                action: CARD_TEMPLATE_AUDIT_ACTION_CREATE,
                decision: CARD_TEMPLATE_AUDIT_DECISION_CREATE,
                old_value: &empty,
                new_value: &serde_json::json!({
                    "templateName": new.template_name,
                    "templateCode": new.template_code,
                    "cardType": new.card_type,
                    "domainId": new.domain_id,
                    "templateScope": new.template_scope,
                }),
                context,
            },
        )
        .await?;
        cleanup_images.push(image);
        cleanup_audits.push(audit);
        Self::stage_config_evidence(&mut tx, cleanup_images, cleanup_audits)?;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    async fn update_template_with_context(
        &self,
        id: i64,
        patch: &CardTemplatePatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        self.apply_template_update(id, patch, context).await
    }

    async fn delete_template_if_unreferenced(
        &self,
        id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        let current: Option<(Option<i64>, Option<String>, Option<String>, String)> =
            sqlx::query_as(
                "SELECT domain_id, template_code, template_scope, template_name \
             FROM user_card_template WHERE template_id = ? FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        let Some((domain_id, template_code, template_scope, template_name)) = current else {
            tx.commit_consuming().await?;
            return Ok(false);
        };
        validate_card_template_admission(&mut tx, context, domain_id, Some(id)).await?;

        let user_card_refs: Vec<(i64,)> =
            sqlx::query_as("SELECT card_id FROM user_card WHERE template_id = ? FOR UPDATE")
                .bind(id)
                .fetch_all(&mut **tx)
                .await
                .map_err(db_error)?;
        let level_template_refs: Vec<(i64,)> = sqlx::query_as(
            "SELECT template_id FROM identity_level_template \
             WHERE user_card_template_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
        let rule_set_refs: Vec<(i64,)> = sqlx::query_as(
            "SELECT rule_set_id FROM rule_set \
             WHERE source_type = 'TEMPLATE' AND source_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
        let reference_count =
            user_card_refs.len() + level_template_refs.len() + rule_set_refs.len();
        guard_no_template_references(reference_count as i64, id)?;

        if !context.has_proven_operation_identity() {
            return Err(AstralError::Pending(
                "card template config completion requires the admission proof operation id".into(),
            ));
        }
        let (mut child_images, mut child_audits) =
            Self::detach_child_templates_in_tx(&mut tx, id, context).await?;
        // The schema's self-FK is ON DELETE SET NULL. Every child row is explicitly
        // detached above with a real typed image/audit, so the later FK action is a
        // no-op. The ordered locking read and transaction prevent an unaccounted set.
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::UserCardTemplate,
            TypedRowOperation::Delete,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(|tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM user_card_template WHERE template_id = ?")
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(format!(
                "card template {id} disappeared during typed locked delete"
            )));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_card_template_audit_in_tx(
            &mut tx,
            &CardTemplateAuditEntry {
                template_id: id,
                action: CARD_TEMPLATE_AUDIT_ACTION_DELETE,
                decision: CARD_TEMPLATE_AUDIT_DECISION_DELETE,
                old_value: &serde_json::json!({
                    "templateCode": template_code,
                    "templateName": template_name,
                    "templateScope": template_scope,
                    "domainId": domain_id,
                }),
                new_value: &serde_json::json!({}),
                context,
            },
        )
        .await?;
        child_images.push(image);
        child_audits.push(audit);
        Self::stage_config_evidence(&mut tx, child_images, child_audits)?;
        tx.commit_consuming().await?;
        Ok(true)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Card template repository query failed: {error}"))
}

/// 删除前校验：任何当前 schema 可观察引用都拒绝删除。
pub fn guard_no_template_references(ref_count: i64, template_id: i64) -> Result<(), AstralError> {
    if ref_count > 0 {
        return Err(AstralError::Validation(format!(
            "cannot delete card_template {template_id}: {ref_count} references still exist"
        )));
    }
    Ok(())
}

/// status 白名单守卫：写路径仅接受 ACTIVE/INACTIVE；其余值（含大小写变体与
/// 前后空白）fail-closed 拒绝，不静默改写，避免未知状态写入 source。
pub fn guard_card_template_status(status: &str) -> Result<(), AstralError> {
    if status != CARD_TEMPLATE_STATUS_ACTIVE && status != CARD_TEMPLATE_STATUS_INACTIVE {
        return Err(AstralError::Validation(format!(
            "invalid card template status '{status}': only ACTIVE or INACTIVE is allowed"
        )));
    }
    Ok(())
}

/// 规范 `__SUPERADMIN__` 模板 ACTIVE 下线守卫（纯函数，便于单测）：
/// 只要仍有 ACTIVE SUPER_ADMIN 卡引用该模板，任何脱离 ACTIVE 的目标状态都
/// fail-closed 拒绝——否则 GlobalAdmin disable 的撤销身份证明（模板必须
/// status='ACTIVE' 且 code='__SUPERADMIN__'）会失败，撤销路径被堵死。
/// 允许方向：改回 ACTIVE（恢复），或已无 ACTIVE 引用时的下线。
pub fn guard_superadmin_active_deactivation(
    template_code: Option<&str>,
    active_super_admin_cards: i64,
    target_status: &str,
    template_id: i64,
) -> Result<(), AstralError> {
    if template_code == Some(SUPERADMIN_TEMPLATE_CODE)
        && target_status != CARD_TEMPLATE_STATUS_ACTIVE
        && active_super_admin_cards > 0
    {
        return Err(AstralError::Validation(format!(
            "cannot change canonical __SUPERADMIN__ card template {template_id} status \
             to '{target_status}': {active_super_admin_cards} ACTIVE SUPER_ADMIN card(s) \
             still reference it; deactivate or revoke them first"
        )));
    }
    Ok(())
}

/// 模板状态收紧的活跃卡守卫（纯函数，便于单测）：目标状态脱离 ACTIVE（下线/
/// 收紧方向）且仍有 ACTIVE 卡绑定该模板时 fail-closed 拒绝——活跃卡的授权
/// 载体定义不得被静默下线（绝不静默 DISABLED/INACTIVE），否则卡保持"看似
/// 有效"而其模板授权来源已被抽走，且无任何拒绝证据。允许方向：改回 ACTIVE
/// （恢复），或已无 ACTIVE 卡绑定时的下线。已被 `update_template` 在持有模板
/// 行锁与卡行锁的事务内接线；不级联变更任何卡（不自动停卡/撤权）。
pub fn guard_no_active_cards(
    active_cards: i64,
    target_status: &str,
    template_id: i64,
) -> Result<(), AstralError> {
    if target_status != CARD_TEMPLATE_STATUS_ACTIVE && active_cards > 0 {
        return Err(AstralError::Validation(format!(
            "cannot change card template {template_id} status to '{target_status}': \
             {active_cards} ACTIVE card(s) still bound; deactivate or revoke them first"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_rejects_when_active_cards_bound_and_tightening() {
        let err = guard_no_active_cards(2, "INACTIVE", 10).unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains('2'));
        assert!(err.to_string().contains("INACTIVE"));
    }

    #[test]
    fn guard_rejects_any_non_active_target_even_outside_whitelist() {
        // 纵深防御：白名单外目标同样拒绝（与 __SUPERADMIN__ 守卫同风格）
        let err = guard_no_active_cards(1, "DISABLED", 10).unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[test]
    fn guard_rejects_any_reference_not_only_active_cards() {
        let err = guard_no_template_references(1, 10).unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
        assert!(err.to_string().contains("references"));
    }
    #[test]
    fn guard_allows_when_no_active_cards_bound() {
        assert!(guard_no_active_cards(0, "INACTIVE", 10).is_ok());
    }

    #[test]
    fn guard_allows_reactivation_direction() {
        // 改回 ACTIVE（恢复方向）始终允许，即使仍有活跃卡
        assert!(guard_no_active_cards(5, "ACTIVE", 10).is_ok());
    }

    #[test]
    fn status_whitelist_accepts_active_and_inactive() {
        assert!(guard_card_template_status(CARD_TEMPLATE_STATUS_ACTIVE).is_ok());
        assert!(guard_card_template_status(CARD_TEMPLATE_STATUS_INACTIVE).is_ok());
    }

    #[test]
    fn status_whitelist_rejects_unknown_and_case_variants() {
        for bad in [
            "", "active", "inactive", "ACTIVE ", " ACTIVE", "DISABLED", "ARCHIVED",
        ] {
            let err = guard_card_template_status(bad).unwrap_err();
            assert!(matches!(err, AstralError::Validation(_)), "case {bad:?}");
            assert!(err.to_string().contains("ACTIVE or INACTIVE"));
        }
    }

    #[test]
    fn superadmin_guard_rejects_deactivation_with_active_cards() {
        let err = guard_superadmin_active_deactivation(Some("__SUPERADMIN__"), 3, "INACTIVE", 7)
            .unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
        assert!(err.to_string().contains("__SUPERADMIN__"));
        assert!(err.to_string().contains('3'));
        assert!(err.to_string().contains("INACTIVE"));
    }

    #[test]
    fn superadmin_guard_rejects_any_non_active_target() {
        // 白名单外目标同样拒绝（纵深防御：即使白名单被绕过也不会放行）
        let err = guard_superadmin_active_deactivation(Some("__SUPERADMIN__"), 1, "DISABLED", 7)
            .unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[test]
    fn superadmin_guard_allows_when_no_active_cards_reference() {
        assert!(
            guard_superadmin_active_deactivation(Some("__SUPERADMIN__"), 0, "INACTIVE", 7).is_ok()
        );
    }

    #[test]
    fn superadmin_guard_allows_other_templates_none_and_reactivation() {
        // 非规范模板不受守卫约束
        assert!(guard_superadmin_active_deactivation(Some("OTHER_CODE"), 5, "INACTIVE", 7).is_ok());
        assert!(guard_superadmin_active_deactivation(None, 5, "INACTIVE", 7).is_ok());
        // 改回 ACTIVE（恢复方向）始终允许
        assert!(
            guard_superadmin_active_deactivation(Some("__SUPERADMIN__"), 5, "ACTIVE", 7).is_ok()
        );
    }

    #[test]
    fn patch_empty_detection_covers_all_fields() {
        assert!(CardTemplatePatch::default().is_empty());
        let patch = CardTemplatePatch {
            status: Some("ACTIVE".into()),
            ..Default::default()
        };
        assert!(!patch.is_empty());
    }

    /// update 当前行的测试构造（列序无关，字段语义对齐锁定读回）。
    fn current_row() -> CardTemplateCurrentRow {
        CardTemplateCurrentRow {
            domain_id: None,
            card_type: Some("STANDARD".into()),
            template_code: Some("TPL_CODE".into()),
            template_scope: Some("TENANT".into()),
            template_name: "Template".into(),
            default_priority: Some(1),
            default_roles_json: Some("[\"admin\"]".into()),
            resource_scope_json: Some("{\"domains\":[1]}".into()),
            status: Some("ACTIVE".into()),
        }
    }

    /// 变更检测（generic_rule_set_update_changes 风格）：None 补丁字段 = 不
    /// 修改；全等补丁 = 无实际变更（空提交、不写投影/审计）；不做静默归一化
    /// （None 与 Some("") 是不同值）。
    #[test]
    fn update_change_detection_matches_only_actual_field_changes() {
        let current = current_row();
        // 全 None 补丁：无修改
        let changes = generic_card_template_update_changes(&current, &CardTemplatePatch::default());
        assert!(!changes.any());

        // 全字段同值补丁：无实际变更
        let same = CardTemplatePatch {
            template_name: Some(current.template_name.clone()),
            template_code: current.template_code.clone(),
            card_type: current.card_type.clone(),
            template_scope: current.template_scope.clone(),
            default_priority: current.default_priority,
            default_roles_json: current.default_roles_json.clone(),
            resource_scope_json: current.resource_scope_json.clone(),
            status: current.status.clone(),
        };
        let changes = generic_card_template_update_changes(&current, &same);
        assert!(!changes.any(), "identical patch must be a no-op");

        // 逐字段变更一一对应
        let renamed = CardTemplatePatch {
            template_name: Some("Renamed".into()),
            ..Default::default()
        };
        let changes = generic_card_template_update_changes(&current, &renamed);
        assert!(changes.template_name);
        assert!(
            !changes.template_code
                && !changes.card_type
                && !changes.template_scope
                && !changes.default_priority
                && !changes.default_roles_json
                && !changes.resource_scope_json
                && !changes.status
        );

        // 不做归一化：None 与 Some("") 是不同值
        let mut current = current_row();
        current.default_roles_json = None;
        let blank = CardTemplatePatch {
            default_roles_json: Some(String::new()),
            ..Default::default()
        };
        let changes = generic_card_template_update_changes(&current, &blank);
        assert!(changes.default_roles_json, "None vs Some(\"\") must differ");
    }

    /// 审计 old/new JSON 只包含实际变更的字段（对齐 update_rule_set 的
    /// "审计只记录实际变更" 契约），键名对齐 DTO camelCase，序列化确定。
    #[test]
    fn changed_field_values_covers_only_changed_fields_deterministically() {
        let current = current_row();
        let patch = CardTemplatePatch {
            status: Some("INACTIVE".into()),
            template_name: Some("Renamed".into()),
            ..Default::default()
        };
        let changes = generic_card_template_update_changes(&current, &patch);
        let (old, new) = changed_field_values(&changes, &current, &patch);
        let old_obj = old.as_object().expect("old value must be an object");
        let new_obj = new.as_object().expect("new value must be an object");
        assert_eq!(old_obj.len(), 2);
        assert_eq!(new_obj.len(), 2);
        assert_eq!(old["status"], "ACTIVE");
        assert_eq!(new["status"], "INACTIVE");
        assert_eq!(old["templateName"], "Template");
        assert_eq!(new["templateName"], "Renamed");
        assert!(old_obj.get("cardType").is_none());
        assert!(old_obj.get("templateCode").is_none());
        // 确定性：两次序列化结果一致
        let (old2, new2) = changed_field_values(&changes, &current, &patch);
        assert_eq!(
            (old.to_string(), new.to_string()),
            (old2.to_string(), new2.to_string())
        );
    }

    /// ConfigCompletion operation identity is inherited verbatim from the proof.
    #[test]
    fn card_template_operation_id_is_not_replaced_by_a_derived_label() {
        let context = RuleSetMutationContext::user(17, Some("trusted-request-id")).unwrap();
        assert_eq!(context.operation_id(), "trusted-request-id");
        assert!(context.has_proven_operation_identity());
    }

    /// 兜底审计输入：确定性 JSON（携带模板身份/operation/actor/变更字段），
    /// 校验对非正模板 id 与空 operation id fail-closed。
    #[test]
    fn card_template_audit_entry_validates_and_serializes_deterministically() {
        let context = RuleSetMutationContext::user(17, Some("trusted-request-id")).unwrap();
        let old = serde_json::json!({ "status": "ACTIVE" });
        let new = serde_json::json!({ "status": "INACTIVE" });
        let entry = CardTemplateAuditEntry {
            template_id: 3,
            action: CARD_TEMPLATE_AUDIT_ACTION_UPDATE,
            decision: CARD_TEMPLATE_AUDIT_DECISION_UPDATE,
            old_value: &old,
            new_value: &new,
            context: &context,
        };
        assert!(entry.validate().is_ok());
        let detail = entry.detail_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(parsed["templateId"], 3);
        assert_eq!(parsed["operationId"], "trusted-request-id");
        assert_eq!(parsed["actorId"], 17);
        assert_eq!(parsed["changedFields"]["old"]["status"], "ACTIVE");
        assert_eq!(parsed["changedFields"]["new"]["status"], "INACTIVE");
        // 确定性：两次序列化结果一致
        assert_eq!(entry.detail_json().unwrap(), detail);

        // fail-closed：非正模板 id / 空 operation id
        let zero = CardTemplateAuditEntry {
            template_id: 0,
            action: CARD_TEMPLATE_AUDIT_ACTION_UPDATE,
            decision: CARD_TEMPLATE_AUDIT_DECISION_UPDATE,
            old_value: &old,
            new_value: &new,
            context: &context,
        };
        assert!(matches!(zero.validate(), Err(AstralError::Validation(_))));
        let blank_context = RuleSetMutationContext::system(" ").unwrap_err();
        assert!(matches!(blank_context, AstralError::Validation(_)));
    }

    /// 源序守卫：update 共同实现必须按序完成 授权源事务 begin → TEMPLATE
    /// RuleSet owner 锁定 → 模板行锁定 → 状态守卫 → 变更检测（空变更提前提交）
    /// → identity 稳定化 → UPDATE → 同事务 audit_log correlation →
    /// commit_consuming；且不得引入随机 identity。
    #[test]
    fn update_tx_orders_locks_guards_changes_audit_and_commit() {
        let source = include_str!("card_template_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let update_body = production
            .split("async fn apply_template_update")
            // 该字面量在实现中唯一（两个 delegate 调用点不带 "async fn" 前缀）；
            // nth(1) 从实现体起，再以 impl delete 声明截断。
            .nth(1)
            .and_then(|body| {
                body.split("async fn delete_template_if_unreferenced")
                    .next()
            })
            .expect("apply_template_update implementation must be delimited");
        let wrapper_begin = update_body
            .find("begin_source_transaction_with_capability(&self.db, caller.source_capability())")
            .expect("update must host the proof-bound source mutation in the dispatcher");
        let rule_set_lock = update_body
            .find("SELECT rule_set_id FROM rule_set")
            .expect("update must lock the TEMPLATE RuleSet projection owner first");
        let row_lock = update_body
            .find("FROM user_card_template WHERE template_id = ? FOR UPDATE")
            .expect("update must lock the template row");
        let guard = update_body
            .find("guard_no_active_cards(active_cards, target_status, id)")
            .expect("update must wire the active-card deactivation guard");
        let changes = update_body
            .find("generic_card_template_update_changes(&current, patch)")
            .expect("update must run generic change detection");
        let no_change = update_body
            .find("if !changes.any()")
            .expect("update must short-commit on no actual change");
        let stabilize = update_body
            .find("caller.has_proven_operation_identity()")
            .expect("update must stabilize operation identity before durable writes");
        let scope_update = update_body
            .find("Self::clear_system_scope_in_tx(")
            .expect("SYSTEM cleanup must share the stabilized source transaction");
        let capture_before = update_body
            .find("capture.capture_before_in_tx(&lookup)")
            .expect("update must capture the actual before row under lock");
        let source_update = update_body
            .find("builder.build().execute(&mut **tx)")
            .expect("update must mutate the template row on the wrapper connection");
        let capture_after = update_body
            .find("capture.capture_after_in_tx(&lookup)")
            .expect("update must capture the actual after row under lock");
        let audit = update_body
            .find("insert_card_template_audit_in_tx")
            .expect("update must write the same-transaction audit_log correlation");
        let commit = update_body
            .rfind("tx.commit_consuming()")
            .expect("update must commit through the wrapper consuming commit");
        assert!(
            wrapper_begin < rule_set_lock
                && rule_set_lock < row_lock
                && row_lock < guard
                && guard < changes
                && changes < no_change
                && no_change < stabilize
                && stabilize < scope_update
                && scope_update < capture_before
                && capture_before < source_update
                && source_update < capture_after
                && capture_after < audit
                && audit < commit,
            "update must order: wrapper begin -> rule_set owner lock -> template lock -> \
             status guards -> change detection -> no-change short-circuit -> identity -> \
             UPDATE -> audit_log -> commit_consuming"
        );
        assert!(
            !update_body.contains("tx.commit()"),
            "update must not bypass the wrapper's proven-commit gate with a raw commit"
        );
        assert!(
            !update_body.contains("uuid::Uuid"),
            "card template update must not fall back to random operation identity"
        );
    }

    /// issuance-only 约束：update 不追加 legacy 投影事件、不产生授权账本
    /// delta/revision、不做 ELIGIBILITY 失效扇出——模板字段无授权读侧消费者，
    /// 已发卡授权在发卡/绑定时物化，之后不重导出。
    #[test]
    fn update_produces_no_legacy_projection_ledger_or_invalidation_writes() {
        let source = include_str!("card_template_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let update_body = production
            .split("async fn apply_template_update")
            .nth(1)
            .and_then(|body| {
                body.split("async fn delete_template_if_unreferenced")
                    .next()
            })
            .expect("apply_template_update implementation must be delimited");
        for forbidden in [
            // legacy RULE_SET head/outbox 伪刷新（retired 链路，无生产效果）
            concat!("append_rule_set_", "projection_in_tx"),
            concat!("EVENT_TYPE_RULE_SET_", "UPDATE"),
            concat!("insert_rule_set_", "projection_audit_in_tx"),
            // 授权账本 delta/revision（issuance-only 字段不重导出授权）
            concat!("authorization_grant_", "revision"),
            concat!("authorization_delta_", "event"),
            concat!("grant_", "ledger"),
            // ELIGIBILITY 失效扇出（模板字段不触碰资格缓存）
            concat!("append_eligibility_", "projection_with_invalidation_in_tx"),
        ] {
            assert!(
                !update_body.contains(forbidden),
                "issuance-only template update must not emit {forbidden}"
            );
        }
    }

    /// 审计 correlation 统一走同事务 `audit_log`：绑定 actor/operation（进入
    /// detail JSON 与 request_id 列）与实际变更字段 old/new；不再存在
    /// rule_set_projection_audit 分支。
    #[test]
    fn audit_correlation_is_same_transaction_audit_log_for_every_template() {
        let source = include_str!("card_template_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let update_body = production
            .split("async fn apply_template_update")
            .nth(1)
            .and_then(|body| {
                body.split("async fn delete_template_if_unreferenced")
                    .next()
            })
            .expect("apply_template_update implementation must be delimited");
        let audit = update_body
            .find("insert_card_template_audit_in_tx")
            .expect("update must write the same-transaction audit_log correlation");
        assert!(
            update_body[audit..].contains("context,"),
            "audit_log correlation must bind the verified update context"
        );
        // operation identity 进入审计关联（request_id 列 + detail JSON）。
        assert!(
            CARD_TEMPLATE_AUDIT_INSERT_SQL.contains("request_id"),
            "audit correlation must land in the request_id column"
        );
        assert!(
            !update_body.contains("rule_set_projection_audit"),
            "the retired rule_set_projection_audit branch must stay removed"
        );
    }

    #[test]
    fn context_update_requires_verified_actor_and_stable_operation() {
        assert!(matches!(
            guard_card_template_update_actor(0),
            Err(AstralError::Auth(_))
        ));
        assert!(matches!(
            guard_card_template_update_actor(-3),
            Err(AstralError::Auth(_))
        ));
        assert!(guard_card_template_update_actor(42).is_ok());

        let source = include_str!("card_template_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("async fn update_template("));
        let update = production
            .split("async fn apply_template_update(")
            .nth(1)
            .unwrap();
        let actor = update
            .find("guard_card_template_update_actor(caller.actor_id())?")
            .unwrap();
        let transaction = update
            .find("begin_source_transaction_with_capability")
            .unwrap();
        assert!(actor < transaction);
        assert!(update.contains("caller.has_proven_operation_identity()"));
        assert!(!update.contains("with_derived_operation_id("));
        assert!(update.contains("TypedRowOperation::Update"));
        assert!(update.contains("capture_before_in_tx(&lookup)"));
        assert!(update.contains("capture_after_in_tx(&lookup)"));
        let stage = update
            .find("Self::stage_config_evidence(&mut tx, cleanup_images, cleanup_audits)?")
            .expect("update must stage the captured image and audit receipts");
        let commit = update
            .find("tx.commit_consuming()")
            .expect("update must use the consuming proven-commit gate");
        assert!(stage < commit);
        let staging_helper = production
            .split("fn stage_config_evidence(")
            .nth(1)
            .and_then(|body| body.split("async fn clear_system_scope_in_tx").next())
            .expect("config evidence staging helper must be in production");
        assert!(staging_helper.contains("stage_typed_source_image"));
        assert!(staging_helper.contains("stage_typed_source_audit"));
        assert!(!update.contains("RuleSetMutationContext::system"));
        assert!(!update.contains("uuid::Uuid"));
        let delegated = production
            .split("async fn update_template_with_context(")
            .nth(2)
            .unwrap();
        assert!(delegated.contains("self.apply_template_update(id, patch, context).await"));
    }

    /// 审计 SQL 只用绑定参数 + 固定常量，绝不拼接请求输入；event_type/
    /// request_id 落在 correlation 列上（对齐 level_template 的既有契约）。
    #[test]
    fn audit_sql_is_parameterized_and_constants_stable() {
        assert!(CARD_TEMPLATE_AUDIT_INSERT_SQL.contains("VALUES (?, NULL, ?, ?, ?, NULL, ?, ?, ?)"));
        assert!(
            CARD_TEMPLATE_AUDIT_INSERT_SQL.contains("event_type")
                && CARD_TEMPLATE_AUDIT_INSERT_SQL.contains("request_id"),
            "audit correlation must land in event_type/request_id columns"
        );
        assert_eq!(CARD_TEMPLATE_AUDIT_RESOURCE, "card_template");
        assert_eq!(CARD_TEMPLATE_AUDIT_EVENT_TYPE, "CARD_TEMPLATE_MUTATION");
        assert_eq!(CARD_TEMPLATE_AUDIT_ACTION_CREATE, "card_template_create");
        assert_eq!(CARD_TEMPLATE_AUDIT_ACTION_UPDATE, "card_template_update");
        assert_eq!(CARD_TEMPLATE_AUDIT_ACTION_DELETE, "card_template_delete");
        assert_eq!(CARD_TEMPLATE_AUDIT_DECISION_CREATE, "TEMPLATE_CREATED");
        assert_eq!(CARD_TEMPLATE_AUDIT_DECISION_UPDATE, "TEMPLATE_UPDATED");
        assert_eq!(CARD_TEMPLATE_AUDIT_DECISION_DELETE, "TEMPLATE_DELETED");
    }
}
