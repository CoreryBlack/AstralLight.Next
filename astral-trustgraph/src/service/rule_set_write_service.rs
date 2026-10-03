//! 规则集写路径编排 — RuleSetWriteService
//!
//! 条目与规则集 source mutation 由 repository 在同一事务内完成，并追加
//! RULE_SET durable projection 及受影响卡片的 CARD projection。快照重建、缓存
//! 失效和消息发布统一由 projection worker 在提交后处理。

use std::sync::Arc;

use astral_types::{AstralError, ResourceRegistry, ACTION_ALIASES};

use crate::repository::audit_log_repository::RuleSetMutationContext;
use policy_engine::{evaluator_for, normalize_condition_json, ConditionGroup};

use crate::repository::rule_set_repository::{
    validate_generic_rule_set_source_type, NewRuleSet, NewRuleSetEntry, RuleSetEntryPatch,
    RuleSetPatch, RuleSetRepository,
};

/// 新建规则集参数
///
/// `ref_type` 是写入 `rule_set.source_type` 的所有权判别器：generic create 只能
/// 创建自定义所有权；空值与 `TEMPLATE`（模板投影路径专属）在任何 source mutation
/// 之前 fail-closed（service 与 repository 双重门禁，同一纯函数）。
#[derive(Debug)]
pub struct CreateRuleSetRequest {
    pub name: String,
    pub ref_type: String,
    pub description: Option<String>,
}

/// 更新规则集参数
///
/// source_type 是所有权判别器，generic update 不可变：本请求刻意不携带
/// ref_type/source_type 字段。wire DTO（HTTP 层）仍接受 `refType` 以保持请求
/// 兼容，但不再把它转发为变更字段。
#[derive(Debug)]
pub struct UpdateRuleSetRequest {
    pub name: String,
    pub description: Option<String>,
}

/// 新建条目参数
#[derive(Debug)]
pub struct AddEntryRequest {
    pub effect: String,
    pub resource: Option<String>,
    pub resource_id: Option<i64>,
    pub action: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
}

/// 更新条目参数
#[derive(Debug)]
pub struct UpdateEntryRequest {
    pub effect: String,
    pub resource: Option<String>,
    pub resource_id: Option<i64>,
    pub action: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
}

/// 绑定/解绑卡参数
#[derive(Debug)]
pub struct BindCardRequest {
    pub card_id: i64,
    pub ref_type: String,
}

/// Validate a rule-set entry before any source mutation begins.
/// Shared permission-rule field validation used by RuleSet and template writes.
///
/// Template rules are source definitions for RuleSet entries, so they must be
/// rejected with the same registry/effect/condition semantics before any source
/// mutation begins. Keeping this validator in the write service prevents the
/// template adapter from silently accepting a rule that the canonical RuleSet
/// path would reject.
///
/// 返回归一化后的 canonical effect（恒为 `"ALLOW"`）：RuleSet 条目是 canonical
/// grant/source mutation，只接受 ALLOW；拒绝结果由 PolicyEngine
/// DEFAULT_DENY/PENDING 表达。调用方必须把返回值写入 source。
pub(crate) fn validate_entry_fields(
    effect: &str,
    resource: Option<&str>,
    action: Option<&str>,
    condition_json: Option<&str>,
) -> Result<String, AstralError> {
    let effect = crate::service::validate_canonical_grant_effect(effect)?;
    let resource = resource
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AstralError::Validation("resource is required".into()))?;
    let action = action
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AstralError::Validation("action is required".into()))?;

    let registry = ResourceRegistry::global();
    if let Err(error) = registry.validate(resource, action) {
        // 别名动作（如 write）作为规则载荷是有意支持的语义：引擎读侧在请求
        // 具体动作时按 get_alias_sources 回退匹配存储为别名的规则（engine.rs
        // 别名展开），编译器为别名载荷触发全量重建（ActionAliasImpact）。
        // 接受条件 fail-closed：action 必须是已知别名，且其展开动作集中的
        // 每一项都在该资源下注册——任何一项未注册即整体拒绝，绝不产生部分
        // 授予的规则载荷（战役 CS_8 发现：别名载荷曾被 API 门禁结构性拒绝，
        // 引擎的别名语义因此不可达）。
        let alias_expansion_registered = ACTION_ALIASES
            .iter()
            .filter(|(alias, _)| *alias == action)
            .any(|(_, expanded)| {
                expanded
                    .iter()
                    .all(|item| registry.validate(resource, item).is_ok())
            });
        if !alias_expansion_registered {
            return Err(AstralError::Validation(error.to_string()));
        }
    }

    let Some(condition_json) = condition_json else {
        return Ok(effect);
    };
    let value: serde_json::Value = serde_json::from_str(condition_json)
        .map_err(|error| AstralError::Validation(format!("malformed condition_json: {error}")))?;
    let group = normalize_condition_json(&value).ok_or_else(|| {
        AstralError::Validation("condition_json does not contain a supported condition".into())
    })?;
    let supported = registry
        .list_supported_conditions(resource)
        .ok_or_else(|| AstralError::Validation(format!("unregistered resource: {resource}")))?;

    let conditions = match group {
        ConditionGroup::AllOf(values) | ConditionGroup::AnyOf(values) => values,
        ConditionGroup::Not(value) => vec![*value],
    };
    for condition in conditions {
        let evaluator = evaluator_for(&condition.condition_type)
            .map_err(|error| AstralError::Validation(error.to_string()))?;
        let condition_name = match condition.condition_type.as_str() {
            "TimeRangeCondition" => "timeRange",
            "IpRangeCondition" => "ipRange",
            "RateLimitCondition" => "rateLimit",
            "DeviceTypeCondition" => "deviceType",
            "ResourcePropertyCondition" => "resourceProperty",
            "OwnerOnlyCondition" => "ownerOnly",
            "BelongsToTenantCondition" => "belongsToTenant",
            "ScopeCondition" => "scope",
            other => other,
        };
        if !supported.iter().any(|item| {
            item == condition_name || (condition_name == "scope" && item.starts_with("scope:"))
        }) {
            return Err(AstralError::Validation(format!(
                "condition '{condition_name}' is not supported for resource '{resource}'"
            )));
        }
        let _ = evaluator;
    }
    Ok(effect)
}
/// RuleSetWriteService
pub struct RuleSetWriteService {
    repo: Arc<dyn RuleSetRepository>,
}

impl RuleSetWriteService {
    pub fn new(repo: Arc<dyn RuleSetRepository>) -> Self {
        Self { repo }
    }

    fn validate_entry(&self, entry: &AddEntryRequest) -> Result<String, AstralError> {
        validate_entry_fields(
            &entry.effect,
            entry.resource.as_deref(),
            entry.action.as_deref(),
            entry.condition_json.as_deref(),
        )
    }

    fn validate_update_entry(&self, entry: &UpdateEntryRequest) -> Result<String, AstralError> {
        validate_entry_fields(
            &entry.effect,
            entry.resource.as_deref(),
            entry.action.as_deref(),
            entry.condition_json.as_deref(),
        )
    }

    pub async fn create_rule_set(
        &self,
        req: &CreateRuleSetRequest,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        // 所有权预留门禁：空/TEMPLATE source_type 在任何事务或 source mutation
        // 之前拒绝（repository INSERT 前还有同一纯函数的第二道门禁）。
        validate_generic_rule_set_source_type(&req.ref_type)?;
        let id = self
            .repo
            .create_rule_set(
                &NewRuleSet {
                    name: req.name.clone(),
                    ref_type: req.ref_type.clone(),
                    description: req.description.clone(),
                },
                context,
            )
            .await?;
        Ok(id)
    }

    /// 更新规则集。source_type 不可变：`RuleSetPatch` 只携带 name/description；
    /// repository 在 source transaction 内追加 RULE_SET/CARD projection，并在
    /// durable 写入前把上下文稳定化为可证明 operation identity。
    pub async fn update_rule_set(
        &self,
        rule_set_id: i64,
        req: &UpdateRuleSetRequest,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        self.repo
            .update_rule_set(
                rule_set_id,
                &RuleSetPatch {
                    name: req.name.clone(),
                    description: req.description.clone(),
                },
                context,
            )
            .await
    }

    /// 删除规则集。repository 保留 RULE_SET 删除事件，并为原绑定卡追加 REVOKE。
    pub async fn delete_rule_set(
        &self,
        rule_set_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let deleted = self.repo.delete_rule_set(rule_set_id, context).await?;
        if !deleted {
            return Err(AstralError::NotFound(format!(
                "rule set {rule_set_id} not found"
            )));
        }
        Ok(())
    }

    /// 新增条目 → rebuild 规则集快照（卡片 projection 已在 repository source tx 登记）
    pub async fn add_entry(
        &self,
        rule_set_id: i64,
        req: &AddEntryRequest,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        // 写入归一化后的 canonical effect，而非原始入参
        let effect = self.validate_entry(req)?;
        let entry_id = self
            .repo
            .add_entry(
                rule_set_id,
                &NewRuleSetEntry {
                    effect,
                    resource: req.resource.clone(),
                    resource_id: req.resource_id,
                    action: req.action.clone(),
                    condition_json: req.condition_json.clone(),
                    priority: req.priority,
                },
                context,
            )
            .await?;
        Ok(entry_id)
    }

    /// 更新条目 → rebuild 规则集快照（卡片 projection 已在 repository source tx 登记）
    pub async fn update_entry(
        &self,
        rule_set_id: i64,
        entry_id: i64,
        req: &UpdateEntryRequest,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        // 最终写入 effect 必须为 ALLOW（更新与创建同一 fail-closed 语义）
        let effect = self.validate_update_entry(req)?;
        self.repo
            .update_entry(
                rule_set_id,
                entry_id,
                &RuleSetEntryPatch {
                    effect,
                    resource: req.resource.clone(),
                    resource_id: req.resource_id,
                    action: req.action.clone(),
                    condition_json: req.condition_json.clone(),
                    priority: req.priority,
                },
                context,
            )
            .await
    }

    /// 删除条目。repository 在同一事务内追加 RULE_SET/CARD REVOKE 事件。
    pub async fn delete_entry(
        &self,
        rule_set_id: i64,
        entry_id: i64,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let deleted = self
            .repo
            .delete_entry(rule_set_id, entry_id, context)
            .await?;
        if !deleted {
            return Err(AstralError::NotFound(format!(
                "rule set entry {entry_id} not found"
            )));
        }
        Ok(())
    }

    /// 全量替换规则集条目，由 repository 在同一事务内完成 source mutation 与投影事件。
    pub async fn replace_entries(
        &self,
        rule_set_id: i64,
        entries: &[AddEntryRequest],
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let mut rows = Vec::with_capacity(entries.len());
        for entry in entries {
            // 先全量校验再构建：任一条目非法时整批拒绝，无部分写入
            let effect = self.validate_entry(entry)?;
            rows.push(NewRuleSetEntry {
                effect,
                resource: entry.resource.clone(),
                resource_id: entry.resource_id,
                action: entry.action.clone(),
                condition_json: entry.condition_json.clone(),
                priority: entry.priority,
            });
        }
        self.repo.replace_entries(rule_set_id, &rows, context).await
    }

    /// 查询卡片规则集绑定。
    pub async fn list_card_bindings(
        &self,
        card_id: i64,
    ) -> Result<Vec<crate::repository::rule_set_repository::CardRuleSetBindingRow>, AstralError>
    {
        self.repo.list_card_bindings(card_id).await
    }

    /// 绑定卡 → 卡片落 durable 投影事件
    pub async fn bind_card(
        &self,
        rule_set_id: i64,
        req: &BindCardRequest,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        if !matches!(req.ref_type.as_str(), "BASE" | "OVERLAY") {
            return Err(AstralError::Validation(
                "ref_type must be BASE or OVERLAY".into(),
            ));
        }
        self.repo
            .bind_card(req.card_id, rule_set_id, &req.ref_type, context)
            .await?;
        Ok(())
    }

    /// 解绑卡 → 卡片落 durable 投影事件（REVOKE 语义，围栏递增）
    pub async fn unbind_card(
        &self,
        rule_set_id: i64,
        req: &BindCardRequest,
        context: &RuleSetMutationContext,
    ) -> Result<(), AstralError> {
        let removed = self
            .repo
            .unbind_card(req.card_id, rule_set_id, context)
            .await?;
        if !removed {
            return Err(AstralError::NotFound(format!(
                "rule set binding not found for card {}",
                req.card_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_entry_fields;
    use super::{validate_generic_rule_set_source_type, UpdateRuleSetRequest};
    use astral_types::AstralError;

    #[test]
    fn update_request_shape_carries_no_ownership_mutation_field() {
        // 编译期 source 形状测试：UpdateRuleSetRequest 不再携带 ref_type/source_type
        // 字段 —— HTTP wire DTO 仍接受 refType（请求兼容），但它不会被转发为变更字段。
        let req = UpdateRuleSetRequest {
            name: "n".into(),
            description: Some("d".into()),
        };
        assert_eq!(req.name, "n");
        assert_eq!(req.description.as_deref(), Some("d"));
    }

    #[test]
    fn create_source_type_reservation_gate_is_fail_closed() {
        // service 侧与 repository 侧共用同一纯函数：空/TEMPLATE 所有权在任何
        // source mutation 之前拒绝，非保留值放行。
        for rejected in ["TEMPLATE", "template", " TEMPLATE ", "", "   "] {
            assert!(
                validate_generic_rule_set_source_type(rejected).is_err(),
                "rejected={rejected:?} must fail closed"
            );
        }
        for accepted in ["BASE", "OVERLAY", "CUSTOM"] {
            validate_generic_rule_set_source_type(accepted)
                .unwrap_or_else(|error| panic!("accepted={accepted:?} unexpected={error:?}"));
        }
    }

    #[test]
    fn rejects_invalid_effect_before_mutation() {
        let error =
            validate_entry_fields("GRANT", Some("learn_course"), Some("read"), None).unwrap_err();
        assert!(matches!(error, AstralError::Validation(message) if message.contains("effect")));
    }

    #[test]
    fn entry_effect_is_allow_only() {
        // canonical grant 只接受 ALLOW：DENY/未知值/空值全部拒绝
        for rejected in ["DENY", "deny", "REVOKE", "", "   "] {
            let error = validate_entry_fields(rejected, Some("learn_course"), Some("read"), None)
                .expect_err("non-ALLOW entry effect must be rejected");
            assert!(
                matches!(&error, AstralError::Validation(message) if message.contains("ALLOW")),
                "rejected={rejected:?} unexpected={error:?}"
            );
        }
    }

    #[test]
    fn allow_is_normalized_for_source_write() {
        // 大小写/空白归一后返回 canonical effect，供写入方使用
        let effect = validate_entry_fields(" allow ", Some("learn_course"), Some("read"), None)
            .expect("case-insensitive ALLOW must be accepted");
        assert_eq!(effect, "ALLOW");
    }

    #[test]
    fn accepts_allow_entry_before_mutation() {
        validate_entry_fields("ALLOW", Some("learn_course"), Some("read"), None)
            .expect("valid ALLOW entry should pass validation");
    }

    #[test]
    fn rejects_unregistered_action_before_mutation() {
        let error = validate_entry_fields("ALLOW", Some("learn_course"), Some("approve"), None)
            .unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(message) if message.contains("Invalid action"))
        );
    }

    #[test]
    fn accepts_alias_action_whose_expansion_is_registered() {
        // write → create/update/delete：learn_subject 三者全部注册，别名载荷
        // 合法（引擎读侧别名展开以存储别名规则为前提）。
        validate_entry_fields("ALLOW", Some("learn_subject"), Some("write"), None)
            .expect("registered alias expansion must be accepted");
    }

    #[test]
    fn rejects_alias_action_with_unregistered_expansion() {
        // learn_device only registers read; a write alias cannot partially grant.
        let error =
            validate_entry_fields("ALLOW", Some("learn_device"), Some("write"), None).unwrap_err();
        assert!(matches!(error, AstralError::Validation(_)));
    }

    #[test]
    fn rejects_malformed_condition_before_mutation() {
        let error = validate_entry_fields(
            "ALLOW",
            Some("learn_course"),
            Some("read"),
            Some("{malformed"),
        )
        .unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(message) if message.contains("malformed condition_json"))
        );
    }

    #[test]
    fn rejects_unsupported_condition_for_resource() {
        let error = validate_entry_fields(
            "ALLOW",
            Some("learn_device"),
            Some("read"),
            Some(r#"{"ownerOnly":true}"#),
        )
        .unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(message) if message.contains("not supported"))
        );
    }
}
