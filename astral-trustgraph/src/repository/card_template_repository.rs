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
//! 6. `update_template_with_context` 要求已验证正数 actor（审计落 exact HTTP
//!    身份）；未证明 operation id 在事务内以锁定 durable 事实确定性派生一次，
//!    绝不随机 fallback。`update_template` 为显式兼容路径（派生 system 身份，
//!    行为不变）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder, Transaction};

use astral_types::AstralError;

use crate::repository::audit_log_repository::RuleSetMutationContext;
use crate::repository::authorization_source_transaction::AuthorizationSourceTransaction;

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
/// 规范超级管理员模板 code（与 GlobalAdmin grant/disable 的身份推导一致）
const SUPERADMIN_TEMPLATE_CODE: &str = "__SUPERADMIN__";
/// SUPER_ADMIN 卡的 card_type / card_status 取值（与 GlobalAdmin 发放路径一致）
const SUPER_ADMIN_CARD_TYPE: &str = "SUPER_ADMIN";
const CARD_STATUS_ACTIVE: &str = "ACTIVE";

/// 审计 action：卡片模板部分更新（实际变更触发同事务审计 correlation）。
const CARD_TEMPLATE_AUDIT_ACTION_UPDATE: &str = "card_template_update";
/// event_type（audit_log.event_type VARCHAR(32)）：卡片模板 mutation 家族。
/// update 的唯一 durable 审计关联通道（与 source mutation 同生共死）。
const CARD_TEMPLATE_AUDIT_EVENT_TYPE: &str = "CARD_TEMPLATE_MUTATION";
/// resource：模板聚合名（单表，无租户列可证明，明细中携带模板身份）。
const CARD_TEMPLATE_AUDIT_RESOURCE: &str = "card_template";
/// `audit_log.decision` 固定值：模板 mutation 语义（非授权投影事件语义——
/// 本路径不追加任何 legacy 投影事件，见模块头范围结论）。
const CARD_TEMPLATE_AUDIT_DECISION: &str = "TEMPLATE_UPDATED";

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

/// 卡片模板 update 的确定性 operation id（纯逻辑）：以模板主键与锁定的
/// RULE_SET 投影代次派生，同一 durable 状态重放得到同一 id —— 禁止随机
/// fallback 进入审计 correlation。
fn derive_card_template_update_operation_id(template_id: i64, source_generation: i64) -> String {
    format!("card-template-update:{template_id}:gen:{source_generation}")
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
    old_value: &'a serde_json::Value,
    new_value: &'a serde_json::Value,
    context: &'a RuleSetMutationContext,
}

impl CardTemplateAuditEntry<'_> {
    /// 结构化审计详情；序列化失败必须阻止事务提交。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "templateId": self.template_id,
            "operationId": self.context.operation_id(),
            "actorId": self.context.actor_id(),
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

    /// 纯校验：正数模板 id、非空 operation id（fail-closed）。
    fn validate(&self) -> Result<(), AstralError> {
        if self.template_id <= 0 {
            return Err(AstralError::Validation(
                "card template audit requires a positive template id".into(),
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
) -> Result<(), AstralError> {
    entry.validate()?;
    let detail = entry.detail_json()?;
    sqlx::query(CARD_TEMPLATE_AUDIT_INSERT_SQL)
        .bind(entry.context.actor_id())
        .bind(CARD_TEMPLATE_AUDIT_ACTION_UPDATE)
        .bind(CARD_TEMPLATE_AUDIT_RESOURCE)
        .bind(CARD_TEMPLATE_AUDIT_DECISION)
        .bind(CARD_TEMPLATE_AUDIT_EVENT_TYPE)
        .bind(entry.context.operation_id())
        .bind(&detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("card template audit insert failed: {error}"))
        })?;
    Ok(())
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
    /// 新建模板；若 scope=SYSTEM 先在同一事务内清除同类型其他 SYSTEM 标记
    async fn create_template(&self, new: &NewCardTemplate) -> Result<i64, AstralError>;
    /// 部分更新（显式兼容路径）：守卫/变更检测/同事务 audit_log 语义与
    /// `update_template_with_context` 一致；审计落派生 system 身份（行为不变）。
    /// 不追加 legacy 投影事件，不产生账本 delta（模块头约束 5）。
    async fn update_template(&self, id: i64, patch: &CardTemplatePatch) -> Result<(), AstralError>;
    /// 带可信调用方身份的部分更新（additive；source 语义与 `update_template`
    /// 完全一致，审计关联改用 exact 调用方身份）。
    ///
    /// `context.actor_id()` 必须为已验证正数（非正数 Auth fail-closed）；
    /// `context` 为已证明 operation id 时原样复用，未证明（request id 缺失）
    /// 时在事务内以锁定 durable 事实确定性派生一次——同一 durable 状态重放
    /// 得到同一 id，绝不随机 fallback。
    ///
    /// 默认实现 fail-closed：测试替身按需覆写；任何实现都不得静默降级为
    /// 派生 system 身份（生产 exact actor 合同）。
    async fn update_template_with_context(
        &self,
        id: i64,
        patch: &CardTemplatePatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (id, patch, context);
        Err(AstralError::Internal(
            "update_template_with_context requires an implementation carrying the \
             verified caller identity"
                .into(),
        ))
    }
    /// Transactionally delete only when no observable schema reference exists.
    async fn delete_template_if_unreferenced(&self, id: i64) -> Result<bool, AstralError>;
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
    /// 将同 card_type 下其他 SYSTEM 模板降为 TENANT（SYSTEM 仅允许一个）。
    /// 必须在持有调用方事务的情况下执行，与本次写入同一连接、同生共死。
    async fn clear_system_scope_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        card_type: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE user_card_template SET template_scope = 'TENANT' \
             WHERE card_type = ? AND template_scope = 'SYSTEM'",
        )
        .bind(card_type)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        Ok(())
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

    /// 事务内锁定读取 RULE_SET 投影 head 代次（owner 缺失 ⇒ 0；负值 fail-closed）。
    async fn locked_rule_set_head_generation(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        rule_set_id: Option<i64>,
    ) -> Result<i64, AstralError> {
        let source_generation = match rule_set_id {
            Some(rule_set_id) => sqlx::query_scalar::<_, Option<i64>>(
                "SELECT source_generation FROM authorization_projection_head \
                 WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? FOR UPDATE",
            )
            .bind(rule_set_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?
            .flatten()
            .unwrap_or(0),
            None => 0,
        };
        if source_generation < 0 {
            return Err(AstralError::Validation(
                "RULE_SET projection head carries a negative generation; refusing to derive a card template update operation identity from it"
                    .into(),
            ));
        }
        Ok(source_generation)
    }

    /// 兼容路径身份（`update_template` 显式保留）：system 上下文，operation id
    /// 以事务内锁定的 RULE_SET head 代次确定性派生（对 head 的 FOR UPDATE 读
    /// 与既有锁序一致，不引入新的锁序倒置）。
    async fn stabilize_card_template_operation_context(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        template_id: i64,
        rule_set_id: Option<i64>,
    ) -> Result<RuleSetMutationContext, AstralError> {
        let source_generation = Self::locked_rule_set_head_generation(tx, rule_set_id).await?;
        RuleSetMutationContext::system(&derive_card_template_update_operation_id(
            template_id,
            source_generation,
        ))
    }

    /// update 共同实现：`caller` 为 `None` 时走兼容派生 system 路径；
    /// `Some(ctx)` 时审计关联使用 exact 调用方身份。
    async fn apply_template_update(
        &self,
        id: i64,
        patch: &CardTemplatePatch,
        caller: Option<&RuleSetMutationContext>,
    ) -> Result<(), AstralError> {
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
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;

        // TEMPLATE RuleSet 投影 owner（若存在）先于模板行锁定：与规则模板同步
        // 路径锁序一致，避免 AB-BA 死锁；该锁同时串行化本 update 与模板规则
        // 同步。本 update 自身不写任何 RULE_SET 投影/账本状态。
        let rule_set_id: Option<i64> = sqlx::query_as::<_, (i64,)>(
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
            "SELECT card_type, template_code, template_scope, template_name, default_priority, \
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
            // 幂等更新：空提交，保持原"0 行也返回 Ok"的调用方语义。
            tx.commit_consuming().await?;
            return Ok(());
        }

        // 生效值：以补丁覆盖后的 card_type/template_scope 判定守卫与清理目标。
        let effective_card_type: Option<String> =
            patch.card_type.clone().or(current.card_type.clone());
        let effective_scope: Option<String> = patch
            .template_scope
            .clone()
            .or(current.template_scope.clone());

        // SYSTEM 清理与本次 UPDATE 同事务/同一连接：UPDATE 失败即整体回滚。
        if effective_scope.as_deref() == Some(TEMPLATE_SCOPE_SYSTEM) {
            if let Some(card_type) = &effective_card_type {
                Self::clear_system_scope_in_tx(&mut tx, card_type).await?;
            }
        }

        // Operation identity 前置：任何 audit durable 写入之前确定可证明身份。
        // None → 兼容路径：system 身份由锁定的 RULE_SET head 代次确定性派生。
        // Some(ctx) → 已验证 actor；已证明 operation id 原样复用，未证明
        // （request id 缺失）以同一锁定事实确定性派生一次，绝不随机 fallback。
        let context = match caller {
            None => {
                Self::stabilize_card_template_operation_context(&mut tx, id, rule_set_id).await?
            }
            Some(ctx) => {
                guard_card_template_update_actor(ctx.actor_id())?;
                if ctx.has_proven_operation_identity() {
                    ctx.clone()
                } else {
                    let source_generation =
                        Self::locked_rule_set_head_generation(&mut tx, rule_set_id).await?;
                    ctx.clone().with_derived_operation_id(
                        derive_card_template_update_operation_id(id, source_generation),
                    )?
                }
            }
        };

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
        builder.build().execute(&mut **tx).await.map_err(db_error)?;

        // 审计 correlation（同一 source 事务）：update 不追加 legacy 投影事件、
        // 不产生授权账本 delta（模块头约束 5），全部实际变更字段以同事务
        // `audit_log` 行关联（actor/operation/old/new）。任何失败回滚整个 update。
        let (old_value, new_value) = changed_field_values(&changes, &current, patch);
        insert_card_template_audit_in_tx(
            &mut tx,
            &CardTemplateAuditEntry {
                template_id: id,
                old_value: &old_value,
                new_value: &new_value,
                context: &context,
            },
        )
        .await?;
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

    async fn create_template(&self, new: &NewCardTemplate) -> Result<i64, AstralError> {
        // 授权源事务宿主：模板行是 owning-binding 存在性 source（组合内存
        // resolver 缓存严格 server facts，依赖源活动栅栏保证 binding 更新的
        // epoch complete）；栅栏先于 DB begin 取得，拒绝发证即 fail-closed。
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;

        // 如果设为 SYSTEM，先在同一事务/连接上清除同类型其他默认标记：
        // 后续 INSERT 失败即整体回滚，不会留下已降级的旧 SYSTEM 默认模板。
        if new.template_scope == TEMPLATE_SCOPE_SYSTEM {
            Self::clear_system_scope_in_tx(&mut tx, &new.card_type).await?;
        }

        let result = sqlx::query(
            "INSERT INTO user_card_template (template_name, template_code, card_type, domain_id, \
             template_scope, default_priority, default_roles_json, resource_scope_json, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(&new.template_name)
        .bind(&new.template_code)
        .bind(&new.card_type)
        .bind(new.domain_id)
        .bind(&new.template_scope)
        .bind(new.default_priority)
        .bind(&new.default_roles_json)
        .bind(&new.resource_scope_json)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        let new_id = result.last_insert_id() as i64;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    async fn update_template(&self, id: i64, patch: &CardTemplatePatch) -> Result<(), AstralError> {
        // 显式兼容路径：无调用方身份，审计落派生 system 身份（行为不变）。
        self.apply_template_update(id, patch, None).await
    }

    async fn update_template_with_context(
        &self,
        id: i64,
        patch: &CardTemplatePatch,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        guard_card_template_update_actor(context.actor_id())?;
        self.apply_template_update(id, patch, Some(context)).await
    }

    async fn delete_template_if_unreferenced(&self, id: i64) -> Result<bool, AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed），
        // 关闭"零引用守卫语义与在线 repair"之间的竞态；commit 证明后才返回。
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        let exists: Option<(i64,)> = sqlx::query_as(
            "SELECT template_id FROM user_card_template WHERE template_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
        if exists.is_none() {
            tx.commit_consuming().await?;
            return Ok(false);
        }

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

        let result = sqlx::query("DELETE FROM user_card_template WHERE template_id = ?")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        tx.commit_consuming().await?;
        Ok(result.rows_affected() > 0)
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
    use astral_types::SYSTEM_ACTOR_ID;

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

    /// operation id 派生：确定性 + 模板/代次互异，无随机成分（对齐
    /// derive_template_sync_operation_id 的测试契约）。
    #[test]
    fn card_template_operation_id_is_deterministic_and_generation_scoped() {
        assert_eq!(
            derive_card_template_update_operation_id(5, 3),
            derive_card_template_update_operation_id(5, 3)
        );
        assert_ne!(
            derive_card_template_update_operation_id(5, 3),
            derive_card_template_update_operation_id(6, 3)
        );
        assert_ne!(
            derive_card_template_update_operation_id(5, 3),
            derive_card_template_update_operation_id(5, 4)
        );
        assert!(derive_card_template_update_operation_id(5, 0).contains(":gen:0"));
    }

    /// 兜底审计输入：确定性 JSON（携带模板身份/operation/actor/变更字段），
    /// 校验对非正模板 id 与空 operation id fail-closed。
    #[test]
    fn card_template_audit_entry_validates_and_serializes_deterministically() {
        let context = RuleSetMutationContext::system("card-template-update:3:gen:0").unwrap();
        let old = serde_json::json!({ "status": "ACTIVE" });
        let new = serde_json::json!({ "status": "INACTIVE" });
        let entry = CardTemplateAuditEntry {
            template_id: 3,
            old_value: &old,
            new_value: &new,
            context: &context,
        };
        assert!(entry.validate().is_ok());
        let detail = entry.detail_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(parsed["templateId"], 3);
        assert_eq!(parsed["operationId"], "card-template-update:3:gen:0");
        assert_eq!(parsed["actorId"], SYSTEM_ACTOR_ID);
        assert_eq!(parsed["changedFields"]["old"]["status"], "ACTIVE");
        assert_eq!(parsed["changedFields"]["new"]["status"], "INACTIVE");
        // 确定性：两次序列化结果一致
        assert_eq!(entry.detail_json().unwrap(), detail);

        // fail-closed：非正模板 id / 空 operation id
        let zero = CardTemplateAuditEntry {
            template_id: 0,
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
        let update_body = source
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
            .find("AuthorizationSourceTransaction::begin(&self.db)")
            .expect("update must host the source mutation in the authorization source wrapper");
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
            .find("stabilize_card_template_operation_context")
            .expect("update must stabilize operation identity before durable writes");
        let source_update = update_body
            .find("builder.build().execute(&mut **tx)")
            .expect("update must mutate the template row on the wrapper connection");
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
                && stabilize < source_update
                && source_update < audit
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
        let update_body = source
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
        let update_body = source
            .split("async fn apply_template_update")
            .nth(1)
            .and_then(|body| {
                body.split("async fn delete_template_if_unreferenced")
                    .next()
            })
            .expect("apply_template_update implementation must be delimited");
        for binding in [
            "template_id: id",
            "old_value: &old_value",
            "new_value: &new_value",
            "context: &context",
        ] {
            assert!(
                update_body.contains(binding),
                "audit_log correlation must bind {binding}"
            );
        }
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

    /// 身份合同：`update_template_with_context` 要求已验证正数 actor（审计落
    /// exact HTTP 身份，system/负值 Auth 拒绝）；已证明 operation id 原样复用，
    /// 未证明以锁定 durable 事实确定性派生一次（绝不随机 fallback，也绝不
    /// 逐重试漂移）；兼容路径 `update_template` 显式保留并委托 None。
    #[test]
    fn context_update_identity_contract_and_legacy_compat() {
        // actor 守卫（纯函数）：非正一律 Auth 拒绝，正数放行。
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
        // additive trait 入口存在（trait 声明与 impl 均为多行签名，只锚定名）。
        assert!(
            source.contains(concat!("async fn update_template_", "with_context")),
            "the additive with-context entry must exist"
        );
        // 两个入口的委托关系：legacy → None，with_context → Some(context)。
        // token 以 concat 构造，避免本测试字面量混入 matches 计数。
        let legacy_token = concat!("self.apply_template_update(id, patch, ", "None).await");
        let context_token = concat!(
            "self.apply_template_update(id, patch, ",
            "Some(context)).await"
        );
        assert!(
            source.matches(legacy_token).count() == 1,
            "exactly the legacy path must delegate with None"
        );
        assert!(
            source.matches(context_token).count() == 1,
            "exactly the with-context path must delegate with Some(context)"
        );
        let with_context_body = source
            .split("async fn update_template_with_context")
            .nth(2)
            .and_then(|body| body.split("async fn apply_template_update").next())
            .expect("with_context implementation must be delimited");
        assert!(
            with_context_body.contains("guard_card_template_update_actor(context.actor_id())"),
            "with_context must fail closed on unverified actors before any transaction"
        );

        // 共同实现内的身份分派：已证明原样复用；未证明确定性派生一次；
        // 兼容 arm 保持派生 system 身份。随机 fallback 任何位置都不得出现。
        let update_body = source
            .split("async fn apply_template_update")
            .nth(1)
            .and_then(|body| {
                body.split("async fn delete_template_if_unreferenced")
                    .next()
            })
            .expect("apply_template_update implementation must be delimited");
        assert!(
            update_body.contains("ctx.has_proven_operation_identity()"),
            "a proven operation identity must be reused verbatim"
        );
        let derivation = update_body
            .find("ctx.clone().with_derived_operation_id(")
            .expect("an unproven context must derive once from locked durable facts");
        let derived_id = update_body
            .find("derive_card_template_update_operation_id(id, source_generation)")
            .expect("the derivation must reuse the existing deterministic helper");
        assert!(
            derivation < derived_id,
            "the derived id must feed with_derived_operation_id (derive once, before SQL)"
        );
        // 兼容 arm：update_template 无上下文时仍派生 system 身份（stabilize fn）。
        let system_token = concat!(
            "RuleSetMutationContext::",
            "system(&derive_card_template_update_operation_id("
        );
        assert!(
            source.contains(system_token),
            "the legacy arm must keep the derived system identity"
        );
        assert!(
            !update_body.contains("uuid::Uuid") && !update_body.contains("ruleset:"),
            "no random fallback (uuid or ruleset: prefix) may reach the audit correlation"
        );
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
        assert_eq!(CARD_TEMPLATE_AUDIT_ACTION_UPDATE, "card_template_update");
        assert_eq!(CARD_TEMPLATE_AUDIT_DECISION, "TEMPLATE_UPDATED");
    }
}
