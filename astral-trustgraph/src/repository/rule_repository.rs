//! 权限规则数据访问 — RuleRepository
//!
//! 对齐 Java `PermissionRuleMapper` 边界（permission_rule 表）。
//! 只返回领域 record 与 `AstralError`，不返回 Axum/HTTP 类型；
//! 快照重建等副作用由 `service::rule_write_service` 编排，不在此层。
//!
//! direct 生命周期接线（versioned incremental ALLOW-only 计划）：
//! create/update/delete/delete_by_card/delete_by_source 在同一个 source
//! transaction 内完成 source mutation → 带 metadata 的 CARD head/outbox append
//! （保留 durable `ProjectionEventIdentity`）→ 审计关联（audit_log）→ 授权账本
//! （`authorization_grant_revision` + `authorization_delta_event`）。任何一步
//! 失败都会整体回滚，不得只写旧链。网络/MQ/Redis/编译一律在事务外。
//!
//! 事件身份契约：CARD 投影事件是 contribution 的 **parent source event**；
//! 每条独立 grant contribution 的 revision/delta 落库使用自己的 contribution
//! event id（由共享 operation_id + 租户/卡/rule/kind 经 astral-types 固定
//! namespace 确定性派生）。单条路径（1 rule : 1 投影事件）两者相同；批量路径
//! 必须逐规则派生独立事件号，否则第二条 REMOVE 必然撞上
//! `authorization_delta_event.uk_ade_event` 全局唯一键导致整批回滚。
//! 审计同时记录 parent 与全部 children。
//!
//! 稳定身份：direct 来源使用 `GrantIdentityKey::direct`（aggregate=`USER_CARD`、
//! aggregate_id=card_id、source_entry=rule_id、binding scope=user-card:{card}）。
//! 同一 rule_id 更新资源/action/priority/validity 复用同一 grant（Update delta）；
//! source-entry（rule 主键）语义变更只会来自新的 Create，因此本路径不需要
//! Remove+Add 重键。绝不随机生成业务身份、不用数组索引或 payload 反查。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{AstralError, EVENT_TYPE_REVOKE};

use crate::repository::audit_log_repository::{
    insert_direct_rule_audit_in_tx, DirectRuleAuditEntry,
};
use crate::repository::grant_ledger_adapter::{
    append_direct_grant_delta_in_tx, build_direct_add_draft, build_direct_remove_draft,
    build_direct_update_draft, derive_direct_contribution_event_id,
    derive_direct_rule_batch_operation_id, derive_direct_rule_operation_id,
    direct_update_authorization_content_changed, map_grant_repository_error,
    reject_unrepresentable_condition, DirectRuleLedgerFacts, DirectRuleMutationContext,
    DirectRuleOperationKind, DIRECT_AGGREGATE_TYPE,
};
use crate::repository::projection_repository::append_card_projection_with_metadata_in_tx;

/// 权限规则记录（permission_rule，snake_case，无 serde）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleRecord {
    pub rule_id: i64,
    pub card_id: i64,
    pub tenant_id: Option<i64>,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub source_type: String,
    pub source_id: Option<i64>,
    pub enabled: Option<i32>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 新建规则参数（默认值解析在 service 层完成）
#[derive(Debug, Clone)]
pub struct NewRule {
    pub card_id: i64,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub source_type: String,
    pub enabled: i32,
}

/// 部分更新补丁（仅更新非 None 字段；对齐现有 handler 语义）
#[derive(Debug, Default)]
pub struct RulePatch {
    pub effect: Option<String>,
    pub resource_type: Option<String>,
    pub action_code: Option<String>,
    pub priority: Option<i32>,
    pub condition_json: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

const RULE_SELECT_COLUMNS: &str = "rule_id, card_id, tenant_id, resource_type, resource_id, \
     action_code, effect, condition_json, priority, source_type, source_id, \
     DATE_FORMAT(valid_from, '%Y-%m-%dT%H:%i:%sZ') as valid_from, \
     DATE_FORMAT(valid_to, '%Y-%m-%dT%H:%i:%sZ') as valid_to, \
     enabled, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

/// 锁定读取使用的列集：有效期用可证明的 UTC 串（去 Z 后仍由适配器按 UTC 解析，
/// 与写入约定一致）；JOIN user_card 补齐授权账本组装所需的属主/租户/域事实。
/// 锁定读取使用的列集：有效期用可证明的 UTC 串（去 Z 后仍由适配器按 UTC 解析，
/// 与写入约定一致）；JOIN user_card 补齐授权账本组装所需的属主/租户/域事实。
/// 卡级联删除路径（user_card_repository 的远端 DELEGATION 规则锁定）经本常量
/// 引用同一列清单，避免两处 SQL 漂移。
pub(crate) const LOCKED_RULE_SELECT: &str = "pr.rule_id AS rule_id, pr.card_id AS card_id, \
     uc.user_id AS user_id, pr.tenant_id AS tenant_id, uc.domain_id AS domain_id, \
     pr.resource_type AS resource_type, pr.resource_id AS resource_id, \
     pr.action_code AS action_code, pr.effect AS effect, \
     pr.condition_json AS condition_json, pr.priority AS priority, \
     DATE_FORMAT(pr.valid_from, '%Y-%m-%dT%H:%i:%s') AS valid_from, \
     DATE_FORMAT(pr.valid_to, '%Y-%m-%dT%H:%i:%s') AS valid_to, \
     pr.source_type AS source_type, pr.source_id AS source_id, pr.enabled AS enabled";

/// 承载卡必须 ACTIVE 且当前有效（沿用审批路径的归属闸门语义）。
const LOCKED_CARD_GATE: &str =
    "uc.card_status = 'ACTIVE' AND (uc.valid_from IS NULL OR uc.valid_from <= NOW()) \
     AND (uc.valid_until IS NULL OR uc.valid_until >= NOW())";

/// direct 路径只允许卡载来源；TEMPLATE 由 RuleSet API 管理。
const DIRECT_SOURCE_FILTER: &str = "pr.source_type IN ('CARD_ONLY', 'MANUAL')";

/// 事务内锁定的完整规则行 + 卡片归属事实（FOR UPDATE，锁定旧规则行与承载卡行）。
///
/// 全列读取是版本化 before-image 合同的一部分：即使当前账本组装只使用身份/租户/
/// 有效期子集，完整旧行也必须被锁定并读回（resource/condition/source 字段保留
/// 为结构化证据面），避免部分读取掩盖 drift。
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub(crate) struct LockedRuleRow {
    pub(crate) rule_id: i64,
    pub(crate) card_id: i64,
    pub(crate) user_id: i64,
    pub(crate) tenant_id: Option<i64>,
    pub(crate) domain_id: Option<i64>,
    #[allow(dead_code)]
    pub(crate) resource_type: String,
    pub(crate) resource_id: Option<i64>,
    #[allow(dead_code)]
    pub(crate) action_code: String,
    pub(crate) effect: String,
    #[allow(dead_code)]
    pub(crate) condition_json: Option<String>,
    #[allow(dead_code)]
    pub(crate) priority: i32,
    /// source 行真实有效期（可证明的 UTC 串；None 即 perpetual 边界缺失）。
    pub(crate) valid_from: Option<String>,
    pub(crate) valid_to: Option<String>,
    pub(crate) source_type: String,
    pub(crate) source_id: Option<i64>,
    pub(crate) enabled: Option<i32>,
}

/// canonical grant 只接受 enabled=1 的规则：禁用语义通过删除表达，否则会造出
/// 「源已停用、账本仍 Active」的超额授权面。fail-closed 拒绝而不是静默降级。
fn require_canonical_direct_enabled(enabled: Option<i32>) -> Result<(), AstralError> {
    if enabled.unwrap_or(1) == 1 {
        Ok(())
    } else {
        Err(AstralError::Validation(
            "disabled rules cannot carry an active direct grant; delete the rule instead".into(),
        ))
    }
}

/// 更新补丁是否完全为空（既有语义：no-op，不写 delta、不开事务）。
fn patch_is_empty(patch: &RulePatch) -> bool {
    patch.effect.is_none()
        && patch.resource_type.is_none()
        && patch.action_code.is_none()
        && patch.priority.is_none()
        && patch.condition_json.is_none()
        && patch.valid_from.is_none()
        && patch.valid_to.is_none()
}

/// identity 专用 facts（REMOVE/tombstone 与 UPDATE-head 定位共用）：resource/
/// action/resource_id/condition/有效期不参与 GrantIdentityKey 派生，全部留空；
/// 仅租户/卡/rule 维度进入身份。resource_id/condition 的真实值只进 ADD/UPDATE
/// payload 组装（见 create/update 的 facts），REMOVE 无 payload 不消费。
fn direct_identity_facts(row: &LockedRuleRow) -> DirectRuleLedgerFacts<'static> {
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

#[async_trait]
pub trait RuleRepository: Send + Sync {
    /// 全量总数
    async fn count_rules(&self) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY card_id, priority）
    async fn list_rules(&self, limit: i64, offset: i64) -> Result<Vec<RuleRecord>, AstralError>;
    /// 按卡查询（ORDER BY priority）
    async fn list_rules_by_card(&self, card_id: i64) -> Result<Vec<RuleRecord>, AstralError>;
    async fn get_rule(&self, rule_id: i64) -> Result<Option<RuleRecord>, AstralError>;
    /// 新建，返回新 rule_id。事务内先锁定并验证承载卡，再 INSERT + CARD 投影 +
    /// 审计关联 + 授权账本 ADD rev1（任一失败整体回滚）。
    async fn create_rule(
        &self,
        new: &NewRule,
        context: &DirectRuleMutationContext,
    ) -> Result<i64, AstralError>;
    /// 部分更新（仅应用非 None 字段；空补丁为 no-op 不写 delta）。事务内锁定并
    /// 读取完整旧行 + 账本 head（FOR UPDATE），同 grant_id 写 UPDATE rev=head+1
    /// 并保留 before-image/digest 成对证据。
    async fn update_rule(
        &self,
        rule_id: i64,
        patch: &RulePatch,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError>;
    /// 取规则的 card_id（删除前使用），返回是否命中
    async fn get_rule_card_id(&self, rule_id: i64) -> Result<Option<i64>, AstralError>;
    /// 校验规则属于指定用户的某张卡（MANUAL source_type），返回 card_id
    async fn find_manual_rule_card_for_user(
        &self,
        rule_id: i64,
        user_id: i64,
    ) -> Result<Option<i64>, AstralError>;
    /// 删除单条规则，返回是否命中。删除前锁定并读取完整旧行，tombstone 固定
    /// 为 REMOVE delta（source removal 语义），before-image/digest 成对落库。
    async fn delete_rule(
        &self,
        rule_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<bool, AstralError>;
    /// 删除卡的全部规则（确定性 rule_id 升序锁定处理；任一条失败整体回滚）。
    async fn delete_rules_by_card(
        &self,
        card_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError>;
    /// 权限检查：最高优先级匹配的 effect（无命中返回 None → DENY）
    async fn check_effect(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
        resource_id: Option<i64>,
    ) -> Result<Option<String>, AstralError>;
    /// 按 source_type + source_id 删除规则（delegation revoke 使用），返回影响行数。
    /// 逐卡升序分组处理，每条规则都产生 REMOVE tombstone，失败整体回滚。
    async fn delete_rules_by_source(
        &self,
        source_type: &str,
        source_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<u64, AstralError>;
    /// 用户卡规则总数（JOIN user_card，active + enabled）
    async fn count_user_rules(&self, user_id: i64) -> Result<i64, AstralError>;
    /// 用户卡规则分页（JOIN user_card，ORDER BY priority DESC, rule_id）
    async fn list_user_rules(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuleRecord>, AstralError>;
    /// 是否由 repository 在 source mutation 事务内追加 projection head/outbox。
    /// 纯测试替身默认返回 false，service 会保留兼容副作用路径。
    fn writes_projection_in_transaction(&self) -> bool {
        false
    }
}

pub struct SqlxRuleRepository {
    db: MySqlPool,
}

impl SqlxRuleRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }

    /// 锁定单条规则（含承载卡归属事实）；缺失或承载卡失效时 None。
    async fn lock_rule_for_mutation<'e, E>(
        executor: E,
        rule_id: i64,
    ) -> Result<Option<LockedRuleRow>, AstralError>
    where
        E: sqlx::Executor<'e, Database = sqlx::MySql>,
    {
        let sql = format!(
            "SELECT {LOCKED_RULE_SELECT} FROM permission_rule pr \
             INNER JOIN user_card uc ON uc.card_id = pr.card_id \
             WHERE pr.rule_id = ? AND {DIRECT_SOURCE_FILTER} AND {LOCKED_CARD_GATE} \
             FOR UPDATE"
        );
        sqlx::query_as::<_, LockedRuleRow>(&sql)
            .bind(rule_id)
            .fetch_optional(executor)
            .await
            .map_err(db_error)
    }

    /// 锁定一个 card 下全部 direct 规则（确定性 rule_id 升序）。
    async fn lock_rules_by_card<'e, E>(
        executor: E,
        card_id: i64,
    ) -> Result<Vec<LockedRuleRow>, AstralError>
    where
        E: sqlx::Executor<'e, Database = sqlx::MySql>,
    {
        let sql = format!(
            "SELECT {LOCKED_RULE_SELECT} FROM permission_rule pr \
             INNER JOIN user_card uc ON uc.card_id = pr.card_id \
             WHERE pr.card_id = ? AND {DIRECT_SOURCE_FILTER} AND {LOCKED_CARD_GATE} \
             ORDER BY pr.rule_id ASC FOR UPDATE"
        );
        sqlx::query_as::<_, LockedRuleRow>(&sql)
            .bind(card_id)
            .fetch_all(executor)
            .await
            .map_err(db_error)
    }

    /// 按 source 锁定全部规则（确定性 rule_id 升序）。
    async fn lock_rules_by_source<'e, E>(
        executor: E,
        source_type: &str,
        source_id: i64,
    ) -> Result<Vec<LockedRuleRow>, AstralError>
    where
        E: sqlx::Executor<'e, Database = sqlx::MySql>,
    {
        let sql = format!(
            "SELECT {LOCKED_RULE_SELECT} FROM permission_rule pr \
             INNER JOIN user_card uc ON uc.card_id = pr.card_id \
             WHERE pr.source_type = ? AND pr.source_id = ? AND {DIRECT_SOURCE_FILTER} AND {LOCKED_CARD_GATE} \
             ORDER BY pr.rule_id ASC FOR UPDATE"
        );
        sqlx::query_as::<_, LockedRuleRow>(&sql)
            .bind(source_type)
            .bind(source_id)
            .fetch_all(executor)
            .await
            .map_err(db_error)
    }

    /// 卡级联删除专用：锁定一个 card 下**全部来源**的 permission_rule 行
    /// （CARD_ONLY / MANUAL / PERMISSION_REQUEST / DELEGATION，不按 DIRECT 过滤），
    /// 按 rule_id 升序锁定读取。调用方必须已先以 FOR UPDATE 锁定承载卡
    /// （user_card → permission_rule 的 binding-side 锁序，见 unbind_card 注释）；
    /// JOIN 读取 user_card 归属事实但不再额外过滤卡状态 —— 级联路径在锁定后
    /// 自行分类处置（DELEGATION 跳过、DENY/禁用行按分类器语义处理）。
    pub(crate) async fn lock_all_card_rules_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        card_id: i64,
    ) -> Result<Vec<LockedRuleRow>, AstralError> {
        let sql = format!(
            "SELECT {LOCKED_RULE_SELECT} FROM permission_rule pr \
             INNER JOIN user_card uc ON uc.card_id = pr.card_id \
             WHERE pr.card_id = ? \
             ORDER BY pr.rule_id ASC FOR UPDATE"
        );
        sqlx::query_as::<_, LockedRuleRow>(&sql)
            .bind(card_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(db_error)
    }

    /// 读取账本 head（无头即 fail-closed：legacy 规则没有 durable 授权历史，
    /// 无法在不伪造数据的情况下进入版本化链路）。
    async fn expect_head_for_mutation(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        tenant_id: i64,
        card_id: i64,
        rule_id: i64,
        grant_id: astral_types::GrantId,
    ) -> Result<astral_db::GrantHeadSnapshot, AstralError> {
        astral_db::read_grant_head_for_update_in_tx(
            tx,
            tenant_id,
            DIRECT_AGGREGATE_TYPE,
            card_id,
            grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "direct grant ledger entry missing for rule {rule_id} under card {card_id}; refusing to mutate an un-versioned authorization"
            ))
        })
    }
}

#[async_trait]
impl RuleRepository for SqlxRuleRepository {
    fn writes_projection_in_transaction(&self) -> bool {
        true
    }

    async fn count_rules(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM permission_rule \
             WHERE source_type IN ('CARD_ONLY', 'MANUAL')",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_rules(&self, limit: i64, offset: i64) -> Result<Vec<RuleRecord>, AstralError> {
        sqlx::query_as::<_, RuleRecord>(&format!(
            "SELECT {RULE_SELECT_COLUMNS} FROM permission_rule \
             WHERE source_type IN ('CARD_ONLY', 'MANUAL') \
             ORDER BY card_id, priority LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_rules_by_card(&self, card_id: i64) -> Result<Vec<RuleRecord>, AstralError> {
        sqlx::query_as::<_, RuleRecord>(&format!(
            "SELECT {RULE_SELECT_COLUMNS} FROM permission_rule \
             WHERE card_id=? AND source_type IN ('CARD_ONLY', 'MANUAL') ORDER BY priority"
        ))
        .bind(card_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_rule(&self, rule_id: i64) -> Result<Option<RuleRecord>, AstralError> {
        sqlx::query_as::<_, RuleRecord>(&format!(
            "SELECT {RULE_SELECT_COLUMNS} FROM permission_rule \
             WHERE rule_id=? AND source_type IN ('CARD_ONLY', 'MANUAL')"
        ))
        .bind(rule_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_rule(
        &self,
        new: &NewRule,
        context: &DirectRuleMutationContext,
    ) -> Result<i64, AstralError> {
        // 防御加固：repository 不是校验旁路。canonical grant 只接受 ALLOW/eenabled=1，
        // 校验先于任何事务副作用。canonical 合同无 condition 槽位：非空条件授权
        // 无法被无条件 ALLOW 忠实表达，任何副作用开始前 Validation fail-closed。
        let effect = crate::service::validate_canonical_grant_effect(&new.effect)?;
        require_canonical_direct_enabled(Some(new.enabled))?;
        reject_unrepresentable_condition(new.condition_json.as_deref(), "direct rule create")?;
        let mut tx = self.db.begin().await.map_err(db_error)?;

        // 先锁定并验证承载卡：不存在/非 ACTIVE/过期/租户 NULL 一律拒绝，
        // 不再允许静默写旧规则（对齐审批路径的归属闸门）。
        let card: Option<(i64, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT uc.user_id, uc.tenant_id, uc.domain_id FROM user_card uc \
             WHERE uc.card_id = ? AND uc.card_status = 'ACTIVE' \
               AND (uc.valid_from IS NULL OR uc.valid_from <= NOW()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= NOW()) FOR UPDATE",
        )
        .bind(new.card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((user_id, tenant_id, domain_id)) = card else {
            return Err(AstralError::Permission(
                "rule target card does not exist or is not ACTIVE/currently valid".into(),
            ));
        };

        let result = sqlx::query(
            "INSERT INTO permission_rule (card_id, tenant_id, resource_type, resource_id, action_code, effect, \
             condition_json, priority, source_type, source_id, valid_from, valid_to, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
        )
        .bind(new.card_id)
        .bind(tenant_id)
        .bind(&new.resource_type)
        .bind(new.resource_id)
        .bind(&new.action_code)
        .bind(&effect)
        .bind(&new.condition_json)
        .bind(new.priority)
        .bind(&new.source_type)
        .bind(&new.valid_from)
        .bind(&new.valid_to)
        .bind(new.enabled)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "permission_rule insert did not apply exactly one row".into(),
            ));
        }
        // 稳定 rule_id 即本贡献的 source_entry；严格校验 last_insert_id。
        let rule_id = i64::try_from(result.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Internal("permission_rule insert returned an unusable rule id".into())
            })?;

        // 上方守卫保证只写入 ALLOW → 新 grant 使用 CREATED 生命周期事件。
        let operation_id = derive_direct_rule_operation_id(
            DirectRuleOperationKind::Create,
            rule_id,
            context.header(),
        )?;
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            new.card_id,
            "RULE_CREATED",
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_user_id,
                operation_id: &operation_id,
            },
        )
        .await?;

        insert_direct_rule_audit_in_tx(
            &mut tx,
            &DirectRuleAuditEntry {
                actor_id: context.actor_user_id,
                target_user_id: user_id,
                target_card_id: new.card_id,
                action: "create",
                decision: "RULE_CREATED",
                operation_id: &operation_id,
                event_id: &projection.event_id,
                // 单条路径：唯一贡献即父投影事件号本身。
                contribution_event_ids: &[projection.event_id.as_str()],
                rule_ids: &[rule_id],
            },
        )
        .await?;

        let facts = DirectRuleLedgerFacts {
            tenant_id,
            domain_id,
            card_id: new.card_id,
            user_id,
            rule_id,
            resource: &new.resource_type,
            resource_id: new.resource_id,
            action: &new.action_code,
            condition_json: new.condition_json.as_deref(),
            valid_from: new.valid_from.as_deref(),
            valid_to: new.valid_to.as_deref(),
        };
        // 同步发布目标租户（读链规模化 Batch E）：纯派生、与 draft 组装同源，
        // draft 成功即本解析必然成功；任一失败仍在事务内整体回滚。
        let sync_tenant_id = resolve_direct_tenant_id(&facts)?;
        let draft =
            build_direct_add_draft(&facts, &operation_id, context.actor_user_id, &projection)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(None).map_err(map_grant_repository_error)?;
        append_direct_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;

        tx.commit().await.map_err(db_error)?;
        // 读链规模化 Batch E：source 事务已提交（durable delta 入账）。单卡影响面
        // 天然 ≤ 阈值，commit 后以 worker 同一原语在请求内尝试发布本卡 delta；
        // 任何失败只记日志，绝不阻塞本次写请求（收敛由 projector worker 兜底）。
        crate::service::sync_publish::after_commit_sync_publish(
            &self.db,
            vec![crate::service::sync_publish::SyncPublishTarget::single(
                sync_tenant_id,
                new.card_id,
                projection.event_id.clone(),
            )],
        )
        .await;
        Ok(rule_id)
    }

    async fn update_rule(
        &self,
        rule_id: i64,
        patch: &RulePatch,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError> {
        // 校验先于事务：显式提供的 effect 必须为 ALLOW。更新补丁的 condition_json
        // 即事务后的最终行值（未提供 → 覆写为 NULL），故非空条件可在任何副作用前
        // fail-closed：canonical 合同无 condition 槽位，不静默丢弃条件后放宽授权。
        let validated_effect = match &patch.effect {
            Some(raw) => Some(crate::service::validate_canonical_grant_effect(raw)?),
            None => None,
        };
        reject_unrepresentable_condition(patch.condition_json.as_deref(), "direct rule update")?;
        // 空补丁保持既有 no-op 语义：不进事务、不写 delta、不动投影。
        if patch_is_empty(patch) {
            return Ok(());
        }

        let mut tx = self.db.begin().await.map_err(db_error)?;
        // 写前 FOR UPDATE 读取完整旧规则行（card/user/tenant/domain/source/
        // effect/resource/action/validity/condition/priority/enabled 全量）。
        let row = Self::lock_rule_for_mutation(&mut *tx, rule_id)
            .await?
            .ok_or_else(|| AstralError::NotFound(format!("rule {rule_id} not found")))?;
        require_canonical_direct_enabled(row.enabled)?;

        // 合并 patch 得到最终字段值（None 表示沿用 DB 既有值）。
        let final_effect = match &validated_effect {
            Some(effect) => effect.clone(),
            None => row.effect.clone(),
        };
        crate::service::validate_canonical_grant_effect(&final_effect)?;
        let final_resource = patch
            .resource_type
            .clone()
            .unwrap_or_else(|| row.resource_type.clone());
        let final_action = patch
            .action_code
            .clone()
            .unwrap_or_else(|| row.action_code.clone());
        let final_priority = patch.priority.unwrap_or(row.priority);
        let final_condition = patch.condition_json.clone();
        let final_valid_from = patch.valid_from.clone().or_else(|| row.valid_from.clone());
        let final_valid_to = patch.valid_to.clone().or_else(|| row.valid_to.clone());

        let result = sqlx::query(
            "UPDATE permission_rule SET effect = ?, resource_type = ?, action_code = ?, \
             priority = ?, condition_json = ?, valid_from = ?, valid_to = ? WHERE rule_id = ?",
        )
        .bind(&final_effect)
        .bind(&final_resource)
        .bind(&final_action)
        .bind(final_priority)
        .bind(&final_condition)
        .bind(&final_valid_from)
        .bind(&final_valid_to)
        .bind(rule_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() > 1 {
            return Err(AstralError::Internal(
                "permission_rule update touched more than one row".into(),
            ));
        }

        let operation_id = derive_direct_rule_operation_id(
            DirectRuleOperationKind::Update,
            rule_id,
            context.header(),
        )?;
        // 账本三步前置：head（FOR UPDATE，legacy 缺失即 fail-closed）先于 CARD
        // 父投影事件落库 —— 收窄 UPDATE 的 stale-ALLOW 闭合需要先拿到
        // before-image（head.payload）才能决定父事件语义。
        let facts = DirectRuleLedgerFacts {
            tenant_id: row.tenant_id,
            domain_id: row.domain_id,
            card_id: row.card_id,
            user_id: row.user_id,
            rule_id: row.rule_id,
            resource: &final_resource,
            resource_id: row.resource_id,
            action: &final_action,
            condition_json: final_condition.as_deref(),
            valid_from: final_valid_from.as_deref(),
            valid_to: final_valid_to.as_deref(),
        };
        let identity_facts = direct_identity_facts(&row);
        let tenant_scope_for_read = resolve_direct_tenant_id(&identity_facts)?;
        let head = Self::expect_head_for_mutation(
            &mut tx,
            tenant_scope_for_read,
            row.card_id,
            rule_id,
            derive_direct_grant_identity(&identity_facts)?,
        )
        .await?;

        // 收窄 UPDATE 的 stale-ALLOW 闭合（2026-09-04）：比较 before-image
        // （head.payload）与新 grant 的 authorization-content 字段
        // （resource/action/effect/validity，与 UPDATE 账本草稿组装同源）。
        // 任何可能移除旧授权的内容变化/移动 → CARD 父投影事件改用 REVOKE 语义
        // 抬 fence，delta 未发布期间严格 reader 的 source-freshness 门命中
        // （PENDING）；纯 provenance-only/no-op UPDATE 保持 RULE_UPDATED
        // （fence 不变，写突发不得自饥饿——P3 风暴实测教训）。
        let card_event_type = if direct_update_authorization_content_changed(&facts, &head)? {
            EVENT_TYPE_REVOKE
        } else {
            "RULE_UPDATED"
        };
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            row.card_id,
            card_event_type,
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_user_id,
                operation_id: &operation_id,
            },
        )
        .await?;

        insert_direct_rule_audit_in_tx(
            &mut tx,
            &DirectRuleAuditEntry {
                actor_id: context.actor_user_id,
                target_user_id: row.user_id,
                target_card_id: row.card_id,
                action: "update",
                // 审计 decision 保持业务动作词汇表（RULE_UPDATED）；fence 抬升
                // 是投影事件语义，由 CARD 父事件 kind 与账本 delta 记录承载。
                decision: "RULE_UPDATED",
                operation_id: &operation_id,
                event_id: &projection.event_id,
                // 单条路径：唯一贡献即父投影事件号本身。
                contribution_event_ids: &[projection.event_id.as_str()],
                rule_ids: &[rule_id],
            },
        )
        .await?;

        // 锁定该 grant 最后 delta version 并 +1 → Append Update rev=head+1。
        // 补丁不含 resource_id：对象作用域沿用锁定行的真实值。
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            &mut tx,
            tenant_scope_for_read,
            DIRECT_AGGREGATE_TYPE,
            row.card_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;

        let draft = build_direct_update_draft(
            &facts,
            &head,
            &operation_id,
            context.actor_user_id,
            &projection,
        )?;
        append_direct_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;

        tx.commit().await.map_err(db_error)?;
        // 读链规模化 Batch E：单卡影响面，commit 后请求内尝试同步发布（失败仅
        // 记日志，绝不阻塞写请求；收敛由 projector worker 兜底）。
        crate::service::sync_publish::after_commit_sync_publish(
            &self.db,
            vec![crate::service::sync_publish::SyncPublishTarget::single(
                tenant_scope_for_read,
                row.card_id,
                projection.event_id.clone(),
            )],
        )
        .await;
        Ok(())
    }

    async fn get_rule_card_id(&self, rule_id: i64) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT card_id FROM permission_rule \
             WHERE rule_id=? AND source_type IN ('CARD_ONLY', 'MANUAL')",
        )
        .bind(rule_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn find_manual_rule_card_for_user(
        &self,
        rule_id: i64,
        user_id: i64,
    ) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            r#"SELECT pr.card_id FROM permission_rule pr
               INNER JOIN user_card uc ON pr.card_id = uc.card_id
               WHERE pr.rule_id = ? AND uc.user_id = ? AND pr.source_type IN ('CARD_ONLY', 'MANUAL')"#,
        )
        .bind(rule_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_rule(
        &self,
        rule_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // 删除前锁定并读取完整旧规则行；找不到保持原有明确 NotFound 语义。
        let Some(row) = Self::lock_rule_for_mutation(&mut *tx, rule_id).await? else {
            return Ok(false);
        };

        let result = sqlx::query("DELETE FROM permission_rule WHERE rule_id=?")
            .bind(rule_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "permission_rule delete did not apply exactly one row".into(),
            ));
        }

        // 删除仍发 legacy CARD REVOKE 事件（revoke_fence 递增），但携带真实 actor
        // 与稳定 operation_id 以保留 ProjectionEventIdentity。
        let operation_id = derive_direct_rule_operation_id(
            DirectRuleOperationKind::Remove,
            rule_id,
            context.header(),
        )?;
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            row.card_id,
            "REVOKE",
            astral_db::ProjectionEventMetadata {
                actor_id: context.actor_user_id,
                operation_id: &operation_id,
            },
        )
        .await?;

        insert_direct_rule_audit_in_tx(
            &mut tx,
            &DirectRuleAuditEntry {
                actor_id: context.actor_user_id,
                target_user_id: row.user_id,
                target_card_id: row.card_id,
                action: "remove",
                decision: "RULE_REMOVED",
                operation_id: &operation_id,
                event_id: &projection.event_id,
                // 单条删除 1 rule : 1 投影事件：贡献事件号保持与 source 相同。
                contribution_event_ids: &[projection.event_id.as_str()],
                rule_ids: &[rule_id],
            },
        )
        .await?;

        let identity_facts = direct_identity_facts(&row);
        let tenant_id = resolve_direct_tenant_id(&identity_facts)?;
        let head = Self::expect_head_for_mutation(
            &mut tx,
            tenant_id,
            row.card_id,
            rule_id,
            derive_direct_grant_identity(&identity_facts)?,
        )
        .await?;
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            &mut tx,
            tenant_id,
            DIRECT_AGGREGATE_TYPE,
            row.card_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;
        // 单条删除（1 rule : 1 投影事件）：贡献事件号即 source 事件号本身。
        let draft = build_direct_remove_draft(
            &identity_facts,
            &head,
            &operation_id,
            &projection,
            &projection.event_id,
        )?;
        append_direct_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;

        tx.commit().await.map_err(db_error)?;
        // 读链规模化 Batch E：单卡影响面，commit 后请求内尝试同步发布 REMOVE
        // tombstone（撤销零延迟生效；失败仅记日志，绝不阻塞写请求）。
        crate::service::sync_publish::after_commit_sync_publish(
            &self.db,
            vec![crate::service::sync_publish::SyncPublishTarget::single(
                tenant_id,
                row.card_id,
                projection.event_id.clone(),
            )],
        )
        .await;
        Ok(true)
    }

    async fn delete_rules_by_card(
        &self,
        card_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // 批量路径按确定性 rule_id 升序锁定/处理；任何一条失败整体回滚。
        let rows = Self::lock_rules_by_card(&mut *tx, card_id).await?;

        let operation_id = derive_direct_rule_batch_operation_id(
            "remove-by-card",
            &card_id.to_string(),
            context.header(),
        )?;
        if !rows.is_empty() {
            // 一次调用共用一个 REMOVE batch operation id 与一张卡的 REVOKE 投影事件。
            // 该投影事件是本批次全部 REMOVE contribution 的 parent source 事件。
            let projection = append_card_projection_with_metadata_in_tx(
                &mut tx,
                card_id,
                "REVOKE",
                astral_db::ProjectionEventMetadata {
                    actor_id: context.actor_user_id,
                    operation_id: &operation_id,
                },
            )
            .await?;
            let owner_user_id = rows[0].user_id;

            // 先为每条锁定规则解析租户并派生该贡献独立、可重放的 event id
            // （共享同一 operation_id）。纯计算先于任何删除副作用执行：
            // 任一派生失败在进入删除前即整体回滚，杜绝半途状态。
            // 同一批次内不同 rule 必然得到不同贡献事件号，满足
            // authorization_delta_event.uk_ade_event 的全局唯一约束。
            let mut plan: Vec<(i64, i64, String)> = Vec::with_capacity(rows.len());
            for row in &rows {
                let identity_facts = direct_identity_facts(row);
                let tenant_id = resolve_direct_tenant_id(&identity_facts)?;
                let contribution_event_id = derive_direct_contribution_event_id(
                    &operation_id,
                    &identity_facts,
                    DirectRuleOperationKind::Remove,
                )?;
                plan.push((row.rule_id, tenant_id, contribution_event_id));
            }

            let mut removed_rule_ids = Vec::with_capacity(rows.len());
            for row in &rows {
                let result = sqlx::query("DELETE FROM permission_rule WHERE rule_id=?")
                    .bind(row.rule_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_error)?;
                if result.rows_affected() != 1 {
                    return Err(AstralError::Internal(format!(
                        "permission_rule delete missed locked rule {} under card {}",
                        row.rule_id, card_id
                    )));
                }
                removed_rule_ids.push(row.rule_id);
            }
            for (index, row) in rows.iter().enumerate() {
                let identity_facts = direct_identity_facts(row);
                let tenant_id = resolve_direct_tenant_id(&identity_facts)?;
                let head = Self::expect_head_for_mutation(
                    &mut tx,
                    tenant_id,
                    row.card_id,
                    row.rule_id,
                    derive_direct_grant_identity(&identity_facts)?,
                )
                .await?;
                let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
                    &mut tx,
                    tenant_id,
                    DIRECT_AGGREGATE_TYPE,
                    row.card_id,
                    head.grant_id,
                )
                .await
                .map_err(map_grant_repository_error)?;
                let (base_version, target_version) = astral_db::next_delta_version(last_target)
                    .map_err(map_grant_repository_error)?;
                // 每条规则使用自己派生的 contribution 事件号；parent 投影事件
                // 只提供 generation/fence 绑定，绝不重复作为多个 delta 的事件号。
                let contribution_event_id = &plan[index].2;
                let draft = build_direct_remove_draft(
                    &identity_facts,
                    &head,
                    &operation_id,
                    &projection,
                    contribution_event_id,
                )?;
                append_direct_grant_delta_in_tx(&mut tx, &draft, base_version, target_version)
                    .await?;
            }
            let contribution_refs: Vec<&str> = plan
                .iter()
                .map(|(_, _, event_id)| event_id.as_str())
                .collect();
            insert_direct_rule_audit_in_tx(
                &mut tx,
                &DirectRuleAuditEntry {
                    actor_id: context.actor_user_id,
                    target_user_id: owner_user_id,
                    target_card_id: card_id,
                    action: "remove_by_card",
                    decision: "RULE_REMOVED",
                    operation_id: &operation_id,
                    event_id: &projection.event_id,
                    // 审计同时关联 parent 投影事件与全部 contribution/规则。
                    contribution_event_ids: &contribution_refs,
                    rule_ids: &removed_rule_ids,
                },
            )
            .await?;
        } else {
            // 保持既有行为：即使没有规则也推进一次 CARD REVOKE 代次/围栏。
            append_card_projection_with_metadata_in_tx(
                &mut tx,
                card_id,
                "REVOKE",
                astral_db::ProjectionEventMetadata {
                    actor_id: context.actor_user_id,
                    operation_id: &operation_id,
                },
            )
            .await?;
        }

        tx.commit().await.map_err(db_error)
    }

    async fn check_effect(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
        resource_id: Option<i64>,
    ) -> Result<Option<String>, AstralError> {
        sqlx::query_scalar(
            "SELECT effect FROM permission_rule \
             WHERE card_id=? AND resource_type=? AND action_code=? \
             AND (resource_id IS NULL OR resource_id=?) \
             AND source_type IN ('CARD_ONLY', 'MANUAL') \
             AND enabled = 1 \
             ORDER BY priority DESC LIMIT 1",
        )
        .bind(card_id)
        .bind(resource_type)
        .bind(action_code)
        .bind(resource_id.unwrap_or(0))
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_rules_by_source(
        &self,
        source_type: &str,
        source_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<u64, AstralError> {
        if !matches!(source_type, "CARD_ONLY" | "MANUAL") {
            return Err(AstralError::Validation(
                "public permission-rule source deletion accepts only CARD_ONLY or MANUAL".into(),
            ));
        }
        // 删除后无法回查受影响卡，因此必须在同一事务内先取卡再删并补投影，
        // 避免旧快照继续被读侧接受。
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let rows = Self::lock_rules_by_source(&mut *tx, source_type, source_id).await?;

        let operation_id = derive_direct_rule_batch_operation_id(
            "remove-by-source",
            &format!("{source_type}:{source_id}"),
            context.header(),
        )?;

        // 先为每条锁定规则解析租户并派生独立、可重放的贡献事件号（全部规则共享
        // 同一个 batch operation id；租户/卡/rule 维度参与派生，因此跨卡/跨租户
        // 分组也永不碰撞）。纯计算先于任何删除副作用执行，任一失败整体回滚。
        let mut contribution_by_rule: std::collections::HashMap<i64, String> =
            std::collections::HashMap::with_capacity(rows.len());
        for row in &rows {
            let identity_facts = direct_identity_facts(row);
            let contribution_event_id = derive_direct_contribution_event_id(
                &operation_id,
                &identity_facts,
                DirectRuleOperationKind::Remove,
            )?;
            if contribution_by_rule
                .insert(row.rule_id, contribution_event_id)
                .is_some()
            {
                return Err(AstralError::Internal(format!(
                    "locked rules under source {source_type}:{source_id} are not unique"
                )));
            }
        }

        // 升序 distinct card 分组逐卡处理：每卡一个 REVOKE 投影事件（沿用既有行为）。
        // 该投影事件是本卡分组的全部 REMOVE contribution 的 parent source 事件。
        let mut ordered_cards: Vec<i64> = Vec::new();
        for row in &rows {
            if ordered_cards.last() != Some(&row.card_id) {
                ordered_cards.push(row.card_id);
            }
        }
        let mut total_removed: u64 = 0;
        for card_id in ordered_cards {
            let group: Vec<&LockedRuleRow> = rows.iter().filter(|r| r.card_id == card_id).collect();
            let projection = append_card_projection_with_metadata_in_tx(
                &mut tx,
                card_id,
                "REVOKE",
                astral_db::ProjectionEventMetadata {
                    actor_id: context.actor_user_id,
                    operation_id: &operation_id,
                },
            )
            .await?;
            let mut removed_rule_ids = Vec::with_capacity(group.len());
            for row in &group {
                let result = sqlx::query("DELETE FROM permission_rule WHERE rule_id=?")
                    .bind(row.rule_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_error)?;
                if result.rows_affected() != 1 {
                    return Err(AstralError::Internal(format!(
                        "permission_rule delete missed locked rule {} via source deletion",
                        row.rule_id
                    )));
                }
                total_removed += 1;
                removed_rule_ids.push(row.rule_id);
            }
            let mut group_contribution_refs = Vec::with_capacity(group.len());
            for row in &group {
                let identity_facts = direct_identity_facts(row);
                let tenant_id = resolve_direct_tenant_id(&identity_facts)?;
                let head = Self::expect_head_for_mutation(
                    &mut tx,
                    tenant_id,
                    row.card_id,
                    row.rule_id,
                    derive_direct_grant_identity(&identity_facts)?,
                )
                .await?;
                let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
                    &mut tx,
                    tenant_id,
                    DIRECT_AGGREGATE_TYPE,
                    row.card_id,
                    head.grant_id,
                )
                .await
                .map_err(map_grant_repository_error)?;
                let (base_version, target_version) = astral_db::next_delta_version(last_target)
                    .map_err(map_grant_repository_error)?;
                // 每条规则的 delta 使用自己派生的贡献事件号（不重复 source 事件号）；
                // 本卡投影事件只提供 generation/fence 绑定。
                let contribution_event_id =
                    contribution_by_rule.get(&row.rule_id).ok_or_else(|| {
                        AstralError::Internal(format!(
                            "missing derived contribution event id for locked rule {}",
                            row.rule_id
                        ))
                    })?;
                let draft = build_direct_remove_draft(
                    &identity_facts,
                    &head,
                    &operation_id,
                    &projection,
                    contribution_event_id,
                )?;
                append_direct_grant_delta_in_tx(&mut tx, &draft, base_version, target_version)
                    .await?;
                group_contribution_refs.push(contribution_event_id.as_str());
            }
            insert_direct_rule_audit_in_tx(
                &mut tx,
                &DirectRuleAuditEntry {
                    actor_id: context.actor_user_id,
                    target_user_id: group[0].user_id,
                    target_card_id: card_id,
                    action: "remove_by_source",
                    decision: "RULE_REMOVED",
                    operation_id: &operation_id,
                    event_id: &projection.event_id,
                    // 审计同时关联本卡的 parent 投影事件与该分组全部 contribution/规则。
                    contribution_event_ids: &group_contribution_refs,
                    rule_ids: &removed_rule_ids,
                },
            )
            .await?;
        }

        tx.commit().await.map_err(db_error)?;
        Ok(total_removed)
    }

    async fn count_user_rules(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM permission_rule pr
               INNER JOIN user_card uc ON pr.card_id = uc.card_id
               WHERE uc.user_id = ? AND uc.card_status = 'ACTIVE' AND pr.enabled = 1
                 AND pr.source_type IN ('CARD_ONLY', 'MANUAL')"#,
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_user_rules(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuleRecord>, AstralError> {
        sqlx::query_as::<_, RuleRecord>(&format!(
            "SELECT {RULE_SELECT_COLUMNS} FROM permission_rule pr \
             INNER JOIN user_card uc ON pr.card_id = uc.card_id \
               WHERE uc.user_id = ? AND uc.card_status = 'ACTIVE' AND pr.enabled = 1 \
                 AND pr.source_type IN ('CARD_ONLY', 'MANUAL') \
             ORDER BY pr.priority DESC, pr.rule_id LIMIT ? OFFSET ?"
        ))
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

/// 解析直接规则的稳定租户边界（fail-closed：NULL/非正租户拒绝组装）。
fn resolve_direct_tenant_id(facts: &DirectRuleLedgerFacts<'_>) -> Result<i64, AstralError> {
    crate::repository::grant_ledger_adapter::derive_direct_tenant(facts)
}

/// 通过共享适配器派生 direct grant 身份（保持 identity 逻辑单一事实源）。
fn derive_direct_grant_identity(
    facts: &DirectRuleLedgerFacts<'_>,
) -> Result<astral_types::GrantId, AstralError> {
    crate::repository::grant_ledger_adapter::derive_direct_identity(facts)
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Rule repository query failed: {error}"))
}

#[cfg(test)]
mod direct_ledger_shape_tests {
    /// SQL 实现块的锚点：只在其后扫描方法体，避免测试源码自引用污染。
    const IMPL_ANCHOR: &str = "impl RuleRepository for SqlxRuleRepository";

    fn method_body<'a>(source: &'a str, signature: &str, terminator: &str, label: &str) -> &'a str {
        let after_impl = source
            .split(IMPL_ANCHOR)
            .nth(1)
            .expect("sqlx repository implementation must exist");
        let start = after_impl
            .find(signature)
            .unwrap_or_else(|| panic!("{label} signature `{signature}` must exist"));
        let rest = &after_impl[start..];
        let end = rest
            .find(terminator)
            .unwrap_or_else(|| panic!("{label} terminator `{terminator}` must exist"));
        &rest[..end]
    }

    /// 全文件范围搜索（用于 impl 外的私有锁定 helper 结构断言）。
    fn source_window<'a>(
        source: &'a str,
        signature: &str,
        terminator: &str,
        label: &str,
    ) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{label} signature `{signature}` must exist"));
        let rest = &source[start..];
        let end = rest
            .find(terminator)
            .unwrap_or_else(|| panic!("{label} terminator `{terminator}` must exist"));
        &rest[..end]
    }

    /// 在任意文本片段内取 marker 之间的切片（不要求 impl 锚点，用于对方法体
    /// 子窗口做进一步断言）。
    fn segment<'a>(text: &'a str, start_marker: &str, end_marker: &str, label: &str) -> &'a str {
        let start = text
            .find(start_marker)
            .unwrap_or_else(|| panic!("{label} start `{start_marker}` must exist"));
        let rest = &text[start..];
        let end = rest
            .find(end_marker)
            .unwrap_or_else(|| panic!("{label} end `{end_marker}` must exist"));
        &rest[..end]
    }

    /// include_str! 顺序断言：按 marker 出现顺序校验事务链，且 commit 收尾。
    fn assert_ordered(body: &'static str, markers: &[(&str, &str)]) {
        let commit_position = body.rfind("tx.commit()").expect("commit must exist");
        let mut previous = 0;
        for (label, marker) in markers {
            let position = body
                .find(marker)
                .unwrap_or_else(|| panic!("{label} marker `{marker}` must exist"));
            assert!(
                position >= previous,
                "{label} must appear in order at or after offset {previous}"
            );
            if *label != "commit last" {
                assert!(
                    position < commit_position,
                    "{label} must stay before the final commit"
                );
            }
            previous = position;
        }
    }

    const CREATE_SIG: &str = "async fn create_rule(";
    const UPDATE_SIG: &str = "async fn update_rule(";
    const DELETE_SIG: &str = "async fn delete_rule(";

    /// create：锁卡验证 → INSERT（rows/last_insert_id 守卫）→ derive op →
    /// 带 metadata 投影 → audit → ADD 草稿 → version 链 → revision+delta 同 tx。
    #[test]
    fn create_transaction_chain_order_is_pinned() {
        assert_ordered(
            method_body(
                include_str!("rule_repository.rs"),
                CREATE_SIG,
                UPDATE_SIG,
                "create",
            ),
            &[
                ("card lock", "FOR UPDATE"),
                ("card missing guard", "does not exist or is not ACTIVE"),
                ("insert guard", "rows_affected() != 1"),
                ("last_insert_id guard", "last_insert_id()"),
                ("operation id derive", "derive_direct_rule_operation_id"),
                (
                    "metadata projection",
                    "append_card_projection_with_metadata_in_tx",
                ),
                ("audit correlation", "insert_direct_rule_audit_in_tx"),
                ("add draft", "build_direct_add_draft"),
                ("version chain", "next_delta_version"),
                ("ledger append", "append_direct_grant_delta_in_tx"),
                ("commit last", "tx.commit()"),
            ],
        );
    }

    /// update：空补丁 no-op 在一切副作用之前；锁定完整旧行 + head FOR UPDATE，
    /// before-image/digest 成对，Update rev=head+1 同 tx 提交。
    #[test]
    fn update_transaction_chain_order_and_guards_are_pinned() {
        let source = include_str!("rule_repository.rs");
        // 空补丁 no-op 必须出现在 begin 之前（不再打开任何事务）。
        let body = method_body(source, UPDATE_SIG, DELETE_SIG, "update");
        let noop = body.find("patch_is_empty(patch)").expect("no-op guard");
        let begin = body.find("self.db.begin()").expect("transaction begin");
        assert!(
            noop < begin,
            "empty patch no-op must short-circuit before opening any transaction"
        );

        assert_ordered(
            body,
            &[
                ("full row lock", "lock_rule_for_mutation"),
                ("not found guard", "AstralError::NotFound"),
                (
                    "enabled gate",
                    "require_canonical_direct_enabled(row.enabled)",
                ),
                ("source update", "UPDATE permission_rule SET"),
                ("operation id derive", "derive_direct_rule_operation_id"),
                // 2026-09-04 收窄 UPDATE 闭合：head（before-image）先于 CARD 父
                // 投影事件落库，authorization-content 比较结果决定父事件语义。
                ("head lock", "expect_head_for_mutation"),
                (
                    "authorization-content gate",
                    "direct_update_authorization_content_changed",
                ),
                (
                    "metadata projection",
                    "append_card_projection_with_metadata_in_tx",
                ),
                ("audit correlation", "insert_direct_rule_audit_in_tx"),
                (
                    "locked last delta version",
                    "read_latest_delta_target_version_for_update_in_tx",
                ),
                ("version successor", "next_delta_version"),
                ("before-image update draft", "build_direct_update_draft"),
                ("ledger append", "append_direct_grant_delta_in_tx"),
                ("commit last", "tx.commit()"),
            ],
        );

        // 收窄 UPDATE 的 stale-ALLOW 闭合语义钉死：content gate 命中 ⟹ CARD 父
        // 投影事件改用 REVOKE 语义抬 fence（严格 reader 的 freshness 门在 delta
        // 未发布期间命中）；no-op/provenance-only ⟹ 保持 RULE_UPDATED。
        assert!(body.contains("direct_update_authorization_content_changed"));
        assert!(
            body.contains("EVENT_TYPE_REVOKE"),
            "content-changing updates must raise the fence via a REVOKE-class CARD parent event"
        );
        assert!(
            body.contains("\"RULE_UPDATED\""),
            "provenance-only/no-op updates must keep the original event type"
        );
    }

    /// delete：锁定旧行 NotFound 保持 → DELETE rows==1 → REVOKE 投影带真实身份 →
    /// audit → REMOVE tombstone（固定 source removal 语义）→ rev+delta 同 tx。
    #[test]
    fn delete_transaction_chain_order_is_pinned() {
        let body = method_body(
            include_str!("rule_repository.rs"),
            DELETE_SIG,
            "async fn delete_rules_by_card(",
            "delete",
        );

        assert_ordered(
            body,
            &[
                ("row lock", "lock_rule_for_mutation"),
                ("source delete guard", "rows_affected() != 1"),
                (
                    "metadata projection call",
                    "append_card_projection_with_metadata_in_tx",
                ),
                ("audit correlation", "insert_direct_rule_audit_in_tx"),
                ("head lock", "expect_head_for_mutation"),
                ("version chain", "next_delta_version"),
                ("remove draft", "build_direct_remove_draft"),
                ("ledger append", "append_direct_grant_delta_in_tx"),
                ("commit last", "tx.commit()"),
            ],
        );

        // 删除路径不得使用旧的丢身份投影 helper；tombstone 一律 REMOVE 语义。
        assert!(
            !body.contains("append_card_projection_in_tx("),
            "identity-dropping projection helper must not be used on the direct path"
        );
        assert!(!body.contains("build_direct_add_draft"));

        // head 缺失 fail-closed 由共享 helper 保证（legacy 无账本记录即拒绝）。
        let whole = include_str!("rule_repository.rs");
        let helper = source_window(
            whole,
            "async fn expect_head_for_mutation",
            "#[async_trait]",
            "expect head helper",
        );
        assert!(
            helper.contains("refusing to mutate an un-versioned authorization"),
            "expect_head_for_mutation must fail closed when the durable ledger entry is missing"
        );
    }

    /// 批量删除按确定性 rule_id 升序锁定；by-card 恒发一次 REVOKE；
    /// 失败整体回滚由单一事务保证（begin/commit 同一方法体内）。
    #[test]
    fn batch_delete_paths_are_deterministically_ordered() {
        let source = include_str!("rule_repository.rs");

        let card_lock = source_window(
            source,
            "async fn lock_rules_by_card",
            "async fn lock_rules_by_source",
            "card lock sql",
        );
        assert!(
            card_lock.contains("ORDER BY pr.rule_id ASC"),
            "batch by-card deletion must lock rules in deterministic rule_id ascending order"
        );
        let source_lock = source_window(
            source,
            "async fn lock_rules_by_source",
            "async fn expect_head_for_mutation",
            "source lock sql",
        );
        assert!(
            source_lock.contains("ORDER BY pr.rule_id ASC"),
            "batch by-source deletion must lock rules in deterministic rule_id ascending order"
        );

        let batch_body = method_body(
            source,
            "async fn delete_rules_by_card(",
            "async fn check_effect(",
            "delete_rules_by_card",
        );
        assert!(batch_body.contains("derive_direct_rule_batch_operation_id"));
        assert!(batch_body.matches("self.db.begin").count() == 1);
        // 空 result 的既有行为保持：仍然推进 CARD REVOKE 代次/围栏。
        assert!(batch_body.contains("!rows.is_empty()"));
        assert!(batch_body.matches("tx.commit").count() == 1);

        let source_batch = method_body(
            source,
            "async fn delete_rules_by_source(",
            "async fn count_user_rules",
            "delete_rules_by_source",
        );
        assert!(source_batch.contains("only CARD_ONLY or MANUAL"));
        assert!(source_batch.matches("self.db.begin").count() == 1);
        assert!(source_batch.matches("tx.commit").count() == 1);
        assert!(
            !source_batch.contains("append_card_projection_in_tx("),
            "identity-dropping projection helper must not be used on the direct path"
        );
    }

    /// F1 核心合同：批量路径的每条规则必须在删除副作用发生**之前**从共享
    /// operation id 派生自己的 contribution event id，账本落库每条 delta 使用
    /// 独立事件号（不重复 parent 投影事件号），审计同时记录 parent 与全部
    /// children。任何一条失败仍由单一事务整体回滚。
    #[test]
    fn batch_removals_derive_independent_contribution_events_before_deletion() {
        let source = include_str!("rule_repository.rs");

        // —— by-card：派生先于 DELETE；build/append 接受独立贡献号；audit 双层关联。
        let batch_body = method_body(
            source,
            "async fn delete_rules_by_card(",
            "async fn check_effect(",
            "delete_rules_by_card",
        );
        let derive_position = batch_body
            .find("derive_direct_contribution_event_id")
            .expect("by-card batch must derive per-rule contribution events");
        let delete_position = batch_body
            .find("DELETE FROM permission_rule")
            .expect("by-card batch must delete the locked rules");
        assert!(
            derive_position < delete_position,
            "contribution ids must be derived before any deletion side effect inside the tx"
        );
        // build_direct_remove_draft 显式传入派生的贡献事件号（第 5 个实参）。
        let remove_call = segment(
            batch_body,
            "let draft = build_direct_remove_draft(",
            "append_direct_grant_delta_in_tx",
            "by-card remove draft",
        );
        assert!(
            remove_call.contains("contribution_event_id"),
            "by-card ledger append must consume the per-rule derived contribution event id"
        );
        // 审计必须同时携带 parent 投影事件与全部贡献事件号。
        let audit_window = segment(
            batch_body,
            "&DirectRuleAuditEntry {",
            ".await?",
            "by-card audit entry",
        );
        for marker in [
            "event_id: &projection.event_id",
            "contribution_event_ids: &contribution_refs",
            "rule_ids: &removed_rule_ids",
        ] {
            assert!(
                audit_window.contains(marker),
                "by-card audit must correlate parent+children via `{marker}`"
            );
        }

        // —— by-source：全量预派生（跨卡分组共享同一 operation id），分组审计双层关联。
        let source_batch = method_body(
            source,
            "async fn delete_rules_by_source(",
            "async fn count_user_rules",
            "delete_rules_by_source",
        );
        let plan_position = source_batch
            .find("derive_direct_contribution_event_id")
            .expect("by-source batch must derive per-rule contribution events");
        let group_projection_position = source_batch
            .find("ordered_cards")
            .expect("by-source batch must keep per-card grouping");
        assert!(
            plan_position < group_projection_position,
            "all contribution ids must be derived before the per-card projection loop"
        );
        let remove_call = segment(
            source_batch,
            "let draft = build_direct_remove_draft(",
            "append_direct_grant_delta_in_tx",
            "by-source remove draft",
        );
        assert!(
            remove_call.contains("contribution_event_id"),
            "by-source ledger append must consume the per-rule derived contribution event id"
        );
        let audit_window = segment(
            source_batch,
            "&DirectRuleAuditEntry {",
            ".await?",
            "by-source audit entry",
        );
        for marker in [
            "event_id: &projection.event_id",
            "contribution_event_ids: &group_contribution_refs",
            "rule_ids: &removed_rule_ids",
        ] {
            assert!(
                audit_window.contains(marker),
                "by-source audit must correlate parent+children via `{marker}`"
            );
        }
    }

    /// 单条路径语义保持不变：唯一 contribution 即投影/source 事件号本身，
    /// 且审计逐字段对齐该关联。
    #[test]
    fn single_rule_paths_keep_the_source_event_as_their_only_contribution_event() {
        let source = include_str!("rule_repository.rs");
        let body = method_body(
            source,
            DELETE_SIG,
            "async fn delete_rules_by_card(",
            "single delete",
        );
        let projection_position = body
            .find("&projection,")
            .expect("single delete passes the projection identity");
        let contribution_position = body[projection_position..]
            .find("&projection.event_id,")
            .map(|offset| offset + projection_position)
            .expect("single delete must reuse the source event id as its own");
        assert!(
            contribution_position
                < body
                    .find("append_direct_grant_delta_in_tx")
                    .unwrap_or(usize::MAX),
            "the draft builder receives the explicit source/contribution pair in order"
        );
        assert!(
            body.contains("contribution_event_ids: &[projection.event_id.as_str()]"),
            "single-path audit correlates parent and its one contribution"
        );
        for signature in [CREATE_SIG, UPDATE_SIG] {
            let other = method_body(source, signature, "\n    async fn", signature);
            assert!(
                other.contains("contribution_event_ids: &[projection.event_id.as_str()]"),
                "{signature} keeps its single-contribution audit correlation"
            );
        }
    }

    /// trait 合同结构守卫：5 个 mutation 入参都要求已验证操作上下文。
    #[test]
    fn mutating_trait_methods_require_verified_mutation_context() {
        let source = include_str!("rule_repository.rs");
        // find 命中的第一个位置即 trait 定义（trait 在 impl 之前）。
        for method in [
            CREATE_SIG,
            UPDATE_SIG,
            DELETE_SIG,
            "async fn delete_rules_by_card(",
            "async fn delete_rules_by_source(",
        ] {
            let start = source
                .find(method)
                .unwrap_or_else(|| panic!("{method} must exist in the trait"));
            let mut end = start + method.len() + 400;
            while end > start && !source.is_char_boundary(end) {
                end -= 1;
            }
            let window = &source[start..end];
            assert!(
                window.contains("context: &DirectRuleMutationContext"),
                "{method} must thread the verified mutation context"
            );
        }
    }
}
