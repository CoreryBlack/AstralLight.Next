//! 策略模板数据访问 — TemplateRepository
//!
//! 对齐 Java `PermissionRuleTemplateMapper` 边界（permission_rule_template 表）。
//! 事务性更新（delete-then-insert）收口为聚合方法；apply/async apply 的下沉查询在此。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{AstralError, EVENT_TYPE_REVOKE, EVENT_TYPE_RULE_SET_UPDATE};

use crate::repository::audit_log_repository::RuleSetMutationContext;
use crate::repository::rule_set_repository::{
    replace_rule_set_entries_churn_with_ledger_in_tx, LedgerChurnAuditContext, NewRuleSetEntry,
};
use crate::service::rule_set_write_service::validate_entry_fields;

/// 模板摘要（列表/详情聚合）
#[derive(Debug, Clone)]
pub struct TemplateSummary {
    pub id: String,
    pub rule_count: i64,
    pub resources: Vec<String>,
}

/// 模板规则行（permission_rule_template）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TemplateRuleRecord {
    pub id: i64,
    pub template_id: String,
    pub effect: String,
    pub resource: String,
    pub action: String,
}

/// 模板规则请求（resource/action 必填，effect 默认 ALLOW）
#[derive(Debug, Clone)]
pub struct TemplateRuleInput {
    pub effect: String,
    pub resource: String,
    pub action: String,
}

/// 合规报表数据
#[derive(Debug, Clone, Default)]
pub struct ComplianceData {
    pub total_rules: i64,
    pub active_rules: i64,
    pub over_permission_cards: i64,
    pub unused_permission_rules: i64,
    pub recent_changes: Vec<PolicyChangeRow>,
}

/// 最近权限变更行
#[derive(Debug, Clone)]
pub struct PolicyChangeRow {
    pub id: i64,
    pub resource: String,
    pub action: String,
    pub changed_by: i64,
    pub changed_at: String,
}

#[async_trait]
pub trait TemplateRepository: Send + Sync {
    /// 模板总数（DISTINCT template_id）
    async fn count_templates(&self) -> Result<i64, AstralError>;
    /// 分页模板摘要（GROUP BY template_id）
    async fn list_templates(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TemplateSummary>, AstralError>;
    /// 单模板摘要
    async fn get_template(&self, template_id: &str) -> Result<TemplateSummary, AstralError>;
    /// 创建模板（可选批量插入 rules）
    async fn create_template(
        &self,
        template_id: &str,
        rules: &[TemplateRuleInput],
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// 事务性更新：删旧插新，返回插入数
    async fn update_template(
        &self,
        template_id: &str,
        rules: &[TemplateRuleInput],
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError>;
    /// 读取模板规则（RuleSet 管理/审计展示用）
    async fn list_template_rules(
        &self,
        template_id: &str,
    ) -> Result<Vec<TemplateRuleRecord>, AstralError>;
    /// Legacy template apply endpoints are intentionally retired. Template
    /// authorization is materialized/bound through the RuleSet API instead.
    /// 使用模板规则全量同步其共享 RuleSet；source mutation、RULE_SET 事件、
    /// ACTIVE 绑定卡 CARD 事件与授权账本（old REMOVE + new ADD 贡献）在同一
    /// 事务内提交，返回受影响卡数。
    async fn sync_template_projection(
        &self,
        template_id: &str,
        context: &RuleSetMutationContext,
    ) -> Result<usize, AstralError>;
    /// 新建模板规则，返回新 rule_id
    async fn create_template_rule(
        &self,
        template_id: &str,
        rule: &TemplateRuleInput,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError>;
    /// 部分更新模板规则
    async fn update_template_rule(
        &self,
        rule_id: i64,
        effect: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError>;
    /// 查回模板规则
    async fn get_template_rule(
        &self,
        rule_id: i64,
    ) -> Result<Option<TemplateRuleRecord>, AstralError>;
    /// 删除模板规则，返回是否命中；source mutation 与 projection 使用同一 actor context。
    async fn delete_template_rule(
        &self,
        rule_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError>;
    /// 合规概览数据
    async fn compliance_overview(&self) -> Result<ComplianceData, AstralError>;
    /// 合规报表：总卡数 / 启用规则数 / 人均规则数
    async fn compliance_report(&self) -> Result<(i64, i64, Option<f64>), AstralError>;
}

pub struct SqlxTemplateRepository {
    db: MySqlPool,
}

impl SqlxTemplateRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

fn event_type_for_effect(effect: &str) -> &'static str {
    if effect.trim().eq_ignore_ascii_case("DENY") {
        EVENT_TYPE_REVOKE
    } else {
        EVENT_TYPE_RULE_SET_UPDATE
    }
}

fn template_numeric_id(template_id: &str) -> Result<i64, AstralError> {
    let parsed = template_id.parse::<i64>().map_err(|_| {
        AstralError::Validation(
            "template authorization requires a numeric user_card_template.template_id".into(),
        )
    })?;
    if parsed <= 0 {
        return Err(AstralError::Validation(
            "template authorization requires a positive numeric user_card_template.template_id"
                .into(),
        ));
    }
    Ok(parsed)
}

/// 模板 source mutation 的唯一合法持久化 effect。模板条目是授权事实来源，
/// 成功路径只落库 canonical `ALLOW`；` allow ` 等大小写/空白变体在写入前
/// 归一，DENY/未知 effect 在任何 source/audit/outbox/projection 写入前
/// fail-closed 拒绝。
const CANONICAL_TEMPLATE_EFFECT: &str = "ALLOW";

/// Validate every template rule before changing either the template source or
/// its shared RuleSet projection, returning the canonical effect to persist.
/// Invalid rows must fail closed instead of being skipped or materialized as an
/// incomplete RuleSet; success always persists exactly `ALLOW`, never the raw
/// casing/whitespace variant supplied by the caller.
fn validate_template_rule(rule: &TemplateRuleInput) -> Result<&'static str, AstralError> {
    let effect =
        validate_entry_fields(&rule.effect, Some(&rule.resource), Some(&rule.action), None)?;
    // 防御性收口：即便共享校验语义未来放宽，模板 source mutation 也绝不
    // 持久化非 canonical `ALLOW` 的值。
    if effect != CANONICAL_TEMPLATE_EFFECT {
        return Err(AstralError::Validation(format!(
            "template source mutations only persist canonical ALLOW effect, got: {:?}",
            rule.effect
        )));
    }
    Ok(CANONICAL_TEMPLATE_EFFECT)
}

fn validate_template_rule_projection(
    effect: &str,
    resource: &str,
    action: &str,
    condition_json: Option<&str>,
) -> Result<(), AstralError> {
    // 最终写入 effect 也必须为 ALLOW（来源可能是模板行的既有 DB 值）；
    // fail-closed：遗留 DENY 模板行的更新会被整行拒绝，而不是继续持久化 DENY。
    validate_entry_fields(effect, Some(resource), Some(action), condition_json).map(|_| ())
}

/// Validate a partial template-rule update against the complete post-update row
/// and return the effect to persist. The whole row (including values carried
/// over from the current DB row) must pass ALLOW-only validation, so a legacy
/// DENY row is rejected wholesale instead of being re-persisted; an explicitly
/// supplied effect always persists exactly canonical `ALLOW` (never the raw
/// casing/whitespace variant), and `None` leaves the effect column untouched.
fn validate_template_rule_update(
    effect: Option<&str>,
    current_effect: &str,
    current_resource: &str,
    current_action: &str,
    resource: Option<&str>,
    action: Option<&str>,
) -> Result<Option<&'static str>, AstralError> {
    let resulting_effect = effect.unwrap_or(current_effect);
    let resulting_resource = resource.unwrap_or(current_resource);
    let resulting_action = action.unwrap_or(current_action);
    // An explicitly supplied empty resource/action is invalid; it must not be
    // mistaken for an omitted optional field and silently replaced with the
    // current value.
    validate_template_rule_projection(
        resulting_effect,
        resulting_resource,
        resulting_action,
        None,
    )?;
    Ok(effect.map(|_| CANONICAL_TEMPLATE_EFFECT))
}

/// Ensure that a user-card template has exactly one canonical TEMPLATE RuleSet
/// source. The source row is locked/created in the same transaction as the
/// template rule mutation, so a projection can never observe a template rule
/// without its RuleSet owner.
async fn ensure_template_rule_set_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    template_id: &str,
) -> Result<i64, AstralError> {
    let template_id = template_numeric_id(template_id)?;
    let existing: Option<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT rule_set_id, tenant_id FROM rule_set \
         WHERE source_type = 'TEMPLATE' AND source_id = ? FOR UPDATE",
    )
    .bind(template_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    let template: Option<(String, String, Option<i64>)> = sqlx::query_as(
        "SELECT template_code, template_name, tenant_id FROM user_card_template \
         WHERE template_id = ? AND status = 'ACTIVE' FOR UPDATE",
    )
    .bind(template_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    let Some((code, name, tenant_id)) = template else {
        return Err(AstralError::NotFound(format!(
            "active user card template {template_id}"
        )));
    };
    if let Some((rule_set_id, rule_set_tenant_id)) = existing {
        if rule_set_tenant_id != tenant_id {
            return Err(AstralError::Validation(format!(
                "template {template_id} RuleSet tenant_id does not match its template"
            )));
        }
        return Ok(rule_set_id);
    }
    if code.trim().is_empty() {
        return Err(AstralError::Validation(format!(
            "template {template_id} has an empty template_code"
        )));
    }

    let conflicting_code: Option<(i64, String)> =
        sqlx::query_as("SELECT rule_set_id, source_type FROM rule_set WHERE code = ? FOR UPDATE")
            .bind(&code)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
    if let Some((rule_set_id, source_type)) = conflicting_code {
        return Err(AstralError::Validation(format!(
            "template code {code} is already owned by rule set {rule_set_id} ({source_type})"
        )));
    }

    let result = sqlx::query(
        "INSERT INTO rule_set \
         (name, code, source_type, source_id, description, enabled, tenant_id) \
         VALUES (?, ?, 'TEMPLATE', ?, 'Canonical template RuleSet', 1, ?)",
    )
    .bind(&name)
    .bind(&code)
    .bind(template_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(result.last_insert_id() as i64)
}

/// 模板同步专用的确定性 operation id（纯逻辑）：显式 request id 缺失时，
/// 以模板/规则集/锁定读回的 durable 投影代次派生，同一 durable 状态重放得到
/// 同一 id —— 禁止随机 fallback 进入授权账本事件。
fn derive_template_sync_operation_id(
    template_id: &str,
    rule_set_id: i64,
    source_generation: i64,
) -> String {
    format!("template-sync:{template_id}:{rule_set_id}:gen:{source_generation}")
}

/// Operation identity 前置：可证明稳定的上下文原样复用；随机 fallback 上下文
/// 在事务内以锁定的 RULE_SET 投影代次确定性重建。规则集聚合行已被
/// ensure_template_rule_set_in_tx 锁定，此处对 head 的 FOR UPDATE 读与既有
/// parent-event 追加同锁序，不引入新的锁序倒置。
async fn stabilize_template_operation_context(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    template_id: &str,
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
            "RULE_SET projection head carries a negative generation; refusing to derive a template sync operation identity from it"
                .into(),
        ));
    }
    let derived = derive_template_sync_operation_id(template_id, rule_set_id, source_generation);
    context.clone().with_derived_operation_id(derived)
}

/// 将锁定读回的模板行映射并校验为规则集条目请求行（纯逻辑）：归一化 effect
/// （恒为 ALLOW），遗留 DENY/未注册资源/非法条件行整批拒绝（fail-closed）。
#[allow(clippy::type_complexity)]
fn template_rows_to_entry_requests(
    fetched: Vec<(String, String, Option<i64>, String, Option<String>, i32)>,
) -> Result<Vec<NewRuleSetEntry>, AstralError> {
    fetched
        .into_iter()
        .map(
            |(effect, resource_type, resource_id, action_code, condition_json, priority)| {
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
        .collect()
}

async fn sync_template_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    template_id: &str,
    forced_event_type: Option<&str>,
    context: Option<&RuleSetMutationContext>,
) -> Result<usize, AstralError> {
    let rule_set_id = ensure_template_rule_set_in_tx(tx, template_id).await?;
    let context = context.ok_or_else(|| {
        AstralError::Auth("RuleSet template projection requires an actor context".into())
    })?;
    let context =
        stabilize_template_operation_context(tx, template_id, rule_set_id, context).await?;

    // 锁定读回启用的模板行；物化语义与批量替换完全一致：
    // capture-before-delete → old REMOVE（仅 enabled+ALLOW，legacy DENY 不转换）
    // → DELETE+INSERT churn 新 entry_id → 锁读回真实新 entry facts → 逐卡逐
    // entry ADD rev1/base0→target1 → parent RULE_SET 投影 + 新旧双向关联审计。
    // 空/无变化模板走明确的 REMOVE-only / no-op 短路，重复同步不无故重写；
    // 绑定 ref 的 user_card 归属不完整即整体失败，绝不静默跳过死引用。
    let fetched_template_rules =
        sqlx::query_as::<_, (String, String, Option<i64>, String, Option<String>, i32)>(
            "SELECT effect, resource_type, resource_id, action_code, condition_json, priority \
         FROM permission_rule_template WHERE template_id = ? AND enabled = 1 \
         ORDER BY priority DESC, template_rule_id FOR UPDATE",
        )
        .bind(template_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    let rows = template_rows_to_entry_requests(fetched_template_rules)?;

    replace_rule_set_entries_churn_with_ledger_in_tx(
        tx,
        rule_set_id,
        &rows,
        forced_event_type,
        LedgerChurnAuditContext {
            change_type: "TEMPLATE_SYNC",
            old_value_base: serde_json::json!({ "templateId": template_id }),
            new_value: serde_json::json!({
                "templateId": template_id,
                "entryCount": rows.len(),
            }),
        },
        &context,
    )
    .await
}

#[async_trait]
impl TemplateRepository for SqlxTemplateRepository {
    async fn count_templates(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT template_id) FROM permission_rule_template",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_templates(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TemplateSummary>, AstralError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT template_id, COUNT(*) as rule_count, GROUP_CONCAT(DISTINCT resource_type) as resources \
             FROM permission_rule_template GROUP BY template_id ORDER BY template_id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;

        Ok(rows
            .iter()
            .map(|r| {
                let tid: String = r.get("template_id");
                let resources_opt: Option<String> = r.get("resources");
                let resources_str = resources_opt.unwrap_or_default();
                TemplateSummary {
                    id: tid,
                    rule_count: r.get("rule_count"),
                    resources: resources_str
                        .split(',')
                        .map(|s| s.to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                }
            })
            .collect())
    }

    async fn get_template(&self, template_id: &str) -> Result<TemplateSummary, AstralError> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT COUNT(*) as rule_count, GROUP_CONCAT(DISTINCT resource_type) as resources \
             FROM permission_rule_template WHERE template_id = ?",
        )
        .bind(template_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;

        let resources_opt: Option<String> = row.get("resources");
        let resources_str = resources_opt.unwrap_or_default();
        Ok(TemplateSummary {
            id: template_id.to_string(),
            rule_count: row.get("rule_count"),
            resources: resources_str
                .split(',')
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    async fn create_template(
        &self,
        template_id: &str,
        rules: &[TemplateRuleInput],
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let effects = rules
            .iter()
            .map(validate_template_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        ensure_template_rule_set_in_tx(&mut tx, template_id).await?;
        for (rule, effect) in rules.iter().zip(effects) {
            sqlx::query(
                "INSERT INTO permission_rule_template (template_id, effect, resource_type, action_code) VALUES (?, ?, ?, ?)",
            )
            .bind(template_id)
            .bind(effect)
            .bind(&rule.resource)
            .bind(&rule.action)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        }
        let event_type = if rules
            .iter()
            .any(|rule| event_type_for_effect(&rule.effect) == EVENT_TYPE_REVOKE)
        {
            EVENT_TYPE_REVOKE
        } else {
            EVENT_TYPE_RULE_SET_UPDATE
        };
        sync_template_rule_set_projection_in_tx(
            &mut tx,
            template_id,
            Some(event_type),
            Some(context),
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn update_template(
        &self,
        template_id: &str,
        rules: &[TemplateRuleInput],
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        let effects = rules
            .iter()
            .map(validate_template_rule)
            .collect::<Result<Vec<_>, _>>()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        ensure_template_rule_set_in_tx(&mut tx, template_id).await?;
        let had_deny = !sqlx::query_scalar::<_, String>(
            "SELECT effect FROM permission_rule_template \
             WHERE template_id = ? AND effect = 'DENY' FOR UPDATE",
        )
        .bind(template_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?
        .is_empty();

        sqlx::query("DELETE FROM permission_rule_template WHERE template_id = ?")
            .bind(template_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        let mut inserted = 0i64;
        for (rule, effect) in rules.iter().zip(effects) {
            sqlx::query(
                "INSERT INTO permission_rule_template (template_id, effect, resource_type, action_code) VALUES (?, ?, ?, ?)",
            )
            .bind(template_id)
            .bind(effect)
            .bind(&rule.resource)
            .bind(&rule.action)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            inserted += 1;
        }

        // 上游 validate_template_rule/validate_entry_fields（validate_canonical_grant_effect）
        // 在任何写入前 fail-closed 拒绝一切 DENY 变体（归一化后仅接受 ALLOW），因此
        // "本次新插入 DENY → REVOKE" 分支不可达，已移除；事件类型仅由锁定读回的
        // 遗留 DENY 行（had_deny）触发 REVOKE。
        let event_type = if had_deny {
            EVENT_TYPE_REVOKE
        } else {
            EVENT_TYPE_RULE_SET_UPDATE
        };
        sync_template_rule_set_projection_in_tx(
            &mut tx,
            template_id,
            Some(event_type),
            Some(context),
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(inserted)
    }

    async fn list_template_rules(
        &self,
        template_id: &str,
    ) -> Result<Vec<TemplateRuleRecord>, AstralError> {
        sqlx::query_as::<_, TemplateRuleRecord>(
            "SELECT template_rule_id as id, template_id, effect, resource_type as resource, action_code as action \
             FROM permission_rule_template WHERE template_id = ? ORDER BY template_rule_id",
        )
        .bind(template_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn sync_template_projection(
        &self,
        template_id: &str,
        context: &RuleSetMutationContext,
    ) -> Result<usize, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let synced =
            sync_template_rule_set_projection_in_tx(&mut tx, template_id, None, Some(context))
                .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(synced)
    }

    async fn create_template_rule(
        &self,
        template_id: &str,
        rule: &TemplateRuleInput,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        let effect = validate_template_rule(rule)?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        ensure_template_rule_set_in_tx(&mut tx, template_id).await?;
        let result = sqlx::query(
            "INSERT INTO permission_rule_template (template_id, effect, resource_type, action_code) VALUES (?, ?, ?, ?)",
        )
        .bind(template_id)
        .bind(effect)
        .bind(&rule.resource)
        .bind(&rule.action)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let rule_id = result.last_insert_id() as i64;
        sync_template_rule_set_projection_in_tx(
            &mut tx,
            template_id,
            Some(event_type_for_effect(&rule.effect)),
            Some(context),
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(rule_id)
    }

    async fn update_template_rule(
        &self,
        rule_id: i64,
        effect: Option<&str>,
        resource: Option<&str>,
        action: Option<&str>,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let current: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT template_id, effect, resource_type, action_code \
             FROM permission_rule_template WHERE template_rule_id = ? FOR UPDATE",
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((template_id, current_effect, current_resource, current_action)) = current else {
            return Err(AstralError::NotFound(format!("template rule {rule_id}")));
        };

        // Validate the complete post-update row and obtain the canonical effect
        // to persist for an explicitly supplied effect (None = column kept).
        let effect_update = validate_template_rule_update(
            effect,
            &current_effect,
            &current_resource,
            &current_action,
            resource,
            action,
        )?;

        let mut builder =
            sqlx::QueryBuilder::<sqlx::MySql>::new("UPDATE permission_rule_template SET ");
        let mut separated = builder.separated(", ");
        if let Some(canonical_effect) = effect_update {
            separated.push("effect = ").push_bind(canonical_effect);
        }
        if let Some(resource) = resource {
            separated.push("resource_type = ").push_bind(resource);
        }
        if let Some(action) = action {
            separated.push("action_code = ").push_bind(action);
        }
        if effect.is_none() && resource.is_none() && action.is_none() {
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }
        builder
            .push(" WHERE template_rule_id = ")
            .push_bind(rule_id);
        builder.build().execute(&mut *tx).await.map_err(db_error)?;

        let resulting_effect: String = sqlx::query_scalar(
            "SELECT effect FROM permission_rule_template WHERE template_rule_id = ?",
        )
        .bind(rule_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        let event_type = if event_type_for_effect(&resulting_effect) == EVENT_TYPE_REVOKE
            || event_type_for_effect(&current_effect) == EVENT_TYPE_REVOKE
        {
            EVENT_TYPE_REVOKE
        } else {
            EVENT_TYPE_RULE_SET_UPDATE
        };
        sync_template_rule_set_projection_in_tx(
            &mut tx,
            &template_id,
            Some(event_type),
            Some(context),
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn get_template_rule(
        &self,
        rule_id: i64,
    ) -> Result<Option<TemplateRuleRecord>, AstralError> {
        sqlx::query_as::<_, TemplateRuleRecord>(
            "SELECT template_rule_id as id, template_id, effect, resource_type as resource, action_code as action \
             FROM permission_rule_template WHERE template_rule_id = ?",
        )
        .bind(rule_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_template_rule(
        &self,
        rule_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let template_id: Option<String> = sqlx::query_scalar(
            "SELECT template_id FROM permission_rule_template WHERE template_rule_id = ? FOR UPDATE",
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some(template_id) = template_id else {
            return Ok(false);
        };
        sqlx::query("DELETE FROM permission_rule_template WHERE template_rule_id = ?")
            .bind(rule_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sync_template_rule_set_projection_in_tx(
            &mut tx,
            &template_id,
            Some(EVENT_TYPE_REVOKE),
            Some(context),
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn compliance_overview(&self) -> Result<ComplianceData, AstralError> {
        use sqlx::Row;
        let total_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM permission_rule \
             WHERE source_type IN ('CARD_ONLY', 'MANUAL')",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        let active_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM permission_rule pr \
             JOIN user_card uc ON uc.card_id = pr.card_id \
             WHERE uc.card_status = 'ACTIVE' \
               AND pr.source_type IN ('CARD_ONLY', 'MANUAL')",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        let over_permission_cards: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT pr.card_id) FROM permission_rule pr \
             WHERE pr.effect = 'ALLOW' AND pr.action_code = 'delete' \
               AND pr.source_type IN ('CARD_ONLY', 'MANUAL')",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        let unused_permission_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ( \
             SELECT DISTINCT pr.resource_type, pr.action_code FROM permission_rule pr \
             WHERE pr.effect = 'ALLOW' \
               AND pr.source_type IN ('CARD_ONLY', 'MANUAL') \
             AND NOT EXISTS ( \
                 SELECT 1 FROM permission_hit_stat phs \
                 WHERE phs.resource_type = pr.resource_type COLLATE utf8mb4_unicode_ci \
                 AND phs.action_code = pr.action_code COLLATE utf8mb4_unicode_ci \
             ) \
             ) t",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;

        let recent_rows = sqlx::query(
            "SELECT id, resource, action, user_id, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as changed_at \
             FROM audit_log WHERE event_type = 'RULE_CHANGE' \
             ORDER BY created_at DESC LIMIT 10",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;
        let recent_changes = recent_rows
            .iter()
            .map(|r| PolicyChangeRow {
                id: r.get("id"),
                resource: r.get("resource"),
                action: r.get("action"),
                changed_by: r.get("user_id"),
                changed_at: r.get("changed_at"),
            })
            .collect();

        Ok(ComplianceData {
            total_rules,
            active_rules,
            over_permission_cards,
            unused_permission_rules,
            recent_changes,
        })
    }

    async fn compliance_report(&self) -> Result<(i64, i64, Option<f64>), AstralError> {
        let total_cards: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_card")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        let total_rules: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM permission_rule WHERE enabled = 1")
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        let avg_rules: Option<f64> = sqlx::query_scalar(
            "SELECT AVG(cnt) FROM (SELECT COUNT(*) as cnt FROM permission_rule WHERE enabled = 1 GROUP BY card_id) t",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok((total_cards, total_rules, avg_rules))
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Template repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一行与 SQL 读回列序一致的模板规则（effect/resource/resource_id/
    /// action/condition/priority）。
    fn template_row(
        effect: &str,
        resource: &str,
        action: &str,
        priority: i32,
    ) -> (String, String, Option<i64>, String, Option<String>, i32) {
        (
            effect.to_owned(),
            resource.to_owned(),
            None,
            action.to_owned(),
            None,
            priority,
        )
    }

    #[test]
    fn template_rows_map_to_normalized_allow_only_entry_requests() {
        let rows = template_rows_to_entry_requests(vec![
            template_row("allow", "learn_course", "read", 0),
            template_row("ALLOW", "learn_subject", "create", 7),
        ])
        .unwrap();
        assert_eq!(rows.len(), 2);
        // effect 归一恒为 ALLOW：模板条目是 canonical 授权来源。
        assert!(rows.iter().all(|row| row.effect == "ALLOW"));
        assert_eq!(rows[0].resource.as_deref(), Some("learn_course"));
        assert_eq!(rows[1].resource.as_deref(), Some("learn_subject"));
        assert_eq!(rows[1].action.as_deref(), Some("create"));
        assert_eq!(rows[1].priority, 7);
    }

    #[test]
    fn legacy_deny_and_unregistered_template_rows_fail_closed() {
        let error =
            template_rows_to_entry_requests(vec![template_row("DENY", "learn_course", "read", 0)])
                .unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(ref message) if message.contains("ALLOW")),
            "legacy DENY template rows must be rejected, not converted"
        );
        let error = template_rows_to_entry_requests(vec![template_row("ALLOW", "", "read", 0)])
            .unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
        let error = template_rows_to_entry_requests(vec![template_row(
            "ALLOW",
            "totally_unknown_resource",
            "read",
            0,
        )])
        .unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(_)),
            "unregistered resources must fail closed like the RuleSet path"
        );
    }

    /// 批量/单条模板规则的校验入口必须返回 canonical 持久化 effect：等价
    /// ALLOW 变体（大小写/空白）归一为 `ALLOW`，原始变体绝不进入 INSERT 绑定；
    /// DENY/未知 effect 在任何 source/audit/outbox/projection 写入前拒绝。
    #[test]
    fn template_rule_validation_returns_canonical_allow_effect_to_persist() {
        for raw in ["ALLOW", "allow", " Allow ", "\tALLOW\n"] {
            let effect = validate_template_rule(&TemplateRuleInput {
                effect: raw.to_owned(),
                resource: "learn_course".to_owned(),
                action: "read".to_owned(),
            })
            .unwrap_or_else(|error| panic!("effect variant {raw:?} must be accepted: {error:?}"));
            assert_eq!(effect, "ALLOW");
        }
        for raw in ["DENY", "deny", "Deny ", "MASK", ""] {
            assert!(
                validate_template_rule(&TemplateRuleInput {
                    effect: raw.to_owned(),
                    resource: "learn_course".to_owned(),
                    action: "read".to_owned(),
                })
                .is_err(),
                "effect variant {raw:?} must fail closed before any source write"
            );
        }
    }

    /// 部分更新行为：显式提供 effect 时整行校验通过后恒返回 canonical
    /// `ALLOW`（` allow ` 等原始变体不进入 UPDATE 绑定）；省略 effect 返回
    /// None（effect 列不动）但整行（含既有 effect）仍须通过 ALLOW-only 校验；
    /// 遗留 DENY 行整行拒绝，绝不产生可持久化的非 ALLOW 值。
    #[test]
    fn template_rule_update_persists_canonical_allow_and_keeps_deny_fail_closed() {
        let persisted = validate_template_rule_update(
            Some(" allow "),
            "ALLOW",
            "learn_course",
            "read",
            Some("learn_course"),
            Some("create"),
        )
        .unwrap();
        assert_eq!(persisted, Some("ALLOW"));

        let persisted = validate_template_rule_update(
            None,
            "ALLOW",
            "learn_course",
            "read",
            Some("learn_subject"),
            None,
        )
        .unwrap();
        assert_eq!(persisted, None);

        // 遗留 DENY 行即使只改 resource/action 也整行拒绝（fail-closed）。
        assert!(validate_template_rule_update(
            None,
            "DENY",
            "learn_course",
            "read",
            Some("learn_course"),
            None,
        )
        .is_err());
        // 显式 DENY 同样拒绝。
        assert!(validate_template_rule_update(
            Some("DENY"),
            "ALLOW",
            "learn_course",
            "read",
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn template_sync_operation_id_is_deterministic_and_generation_scoped() {
        // 相同 durable 状态重放得到相同派生 id；模板/规则集/代次任一变化互异，
        // 绝无随机成分。gen:0 覆盖首次同步（尚无 RULE_SET 投影 head）。
        assert_eq!(
            derive_template_sync_operation_id("5", 9, 3),
            derive_template_sync_operation_id("5", 9, 3)
        );
        assert_ne!(
            derive_template_sync_operation_id("5", 9, 3),
            derive_template_sync_operation_id("6", 9, 3)
        );
        assert_ne!(
            derive_template_sync_operation_id("5", 9, 3),
            derive_template_sync_operation_id("5", 10, 3)
        );
        assert_ne!(
            derive_template_sync_operation_id("5", 9, 3),
            derive_template_sync_operation_id("5", 9, 4)
        );
        assert!(derive_template_sync_operation_id("5", 9, 0).contains(":gen:0"));
    }

    /// 结构守卫：sync_template_rule_set_projection_in_tx 必须
    /// （按序）先做 operation identity 稳定化，再映射校验模板行，最后完整委托
    /// 共享授权账本 churn 核心；本文件不得出现手写 rule_set_entry churn、逐卡
    /// 裸广播或随机 identity fallback。
    #[test]
    fn template_sync_delegates_to_the_shared_ledger_churn_core() {
        let sync = include_str!("template_repository.rs")
            .split("async fn sync_template_rule_set_projection_in_tx")
            .nth(1)
            .and_then(|body| body.split("#[async_trait]").next())
            .expect("template sync implementation must remain available");
        let stabilize = sync
            .find("stabilize_template_operation_context")
            .expect("operation identity must be stabilized first");
        let rows = sync
            .find("template_rows_to_entry_requests")
            .expect("shared validation mapping must precede the churn");
        let delegate = sync
            .find("replace_rule_set_entries_churn_with_ledger_in_tx")
            .expect("materialization must delegate to the shared ledger churn core");
        assert!(stabilize < rows && rows < delegate);
        assert!(sync.contains("\"TEMPLATE_SYNC\""));
        for forbidden in [
            "DELETE FROM rule_set_entry",
            "INSERT INTO rule_set_entry",
            "append_card_projection_in_tx",
            "normalize_operation_id",
            "uuid::Uuid",
        ] {
            assert!(
                !sync.contains(forbidden),
                "template sync must not hand-roll {forbidden}"
            );
        }
    }

    /// 结构守卫：身份稳定化复用已证明上下文；缺失 header 时在事务内以锁定的
    /// durable 投影代次确定性派生，异常代次 fail-closed，空白派生值被拒绝。
    #[test]
    fn template_context_stabilization_derives_from_locked_durable_generation() {
        let body = include_str!("template_repository.rs")
            .split("async fn stabilize_template_operation_context")
            .nth(1)
            .and_then(|part| {
                part.split("async fn template_rows_to_entry_requests")
                    .next()
            })
            .expect("stabilization implementation must remain available");
        assert!(body.contains("has_proven_operation_identity()"));
        assert!(body.contains("authorization_projection_head"));
        assert!(body.contains("FOR UPDATE"));
        assert!(body.contains("with_derived_operation_id"));
        assert!(body.contains("source_generation < 0"));
    }

    /// 结构守卫：模板 source 写入路径不得把调用方原始 effect 直接落库 ——
    /// 批量 create/update 与单条 create 绑定 validate_template_rule 的归一
    /// 结果，部分更新绑定 canonical 常量；否则 ` allow ` 等变体会原样写入
    /// permission_rule_template 并污染 canonical 授权来源。
    #[test]
    fn template_source_writes_never_bind_raw_effect_input() {
        let source = include_str!("template_repository.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("implementation section must remain available");
        assert!(
            !source.contains(".bind(&rule.effect)"),
            "template INSERTs must bind the validated canonical effect, not the raw input"
        );
        assert!(
            !source.contains(".push_bind(effect)"),
            "partial-effect UPDATE must bind the canonical effect, not the raw input"
        );
        assert!(
            source.contains("const CANONICAL_TEMPLATE_EFFECT: &str = \"ALLOW\";"),
            "canonical ALLOW constant must remain the single persistence value"
        );
    }
}
