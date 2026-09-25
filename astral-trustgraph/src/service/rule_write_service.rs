//! 权限规则写路径编排 — RuleWriteService
//!
//! 对齐 Java `PermissionRuleWriteCoordinator`：写库后统一触发快照重建副作用。
//! 写操作编排为「repository 变更 → 查回 → rebuild_card_snapshot」，
//! rebuild 在查回之后执行，避免快照重建阻塞响应。

use std::sync::Arc;

use astral_types::AstralError;
use sqlx::MySqlPool;

use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
use crate::repository::rule_repository::{NewRule, RulePatch, RuleRecord, RuleRepository};
use crate::service::personal_permission_service::validate_registry_resource_action;
use crate::service::side_effect::PermissionSideEffects;

/// 新建规则请求（默认值解析在 service 完成，对齐现有 handler 语义）
#[derive(Debug, Clone)]
pub struct CreateRuleRequest {
    pub card_id: i64,
    pub effect: String,
    pub resource_type: String,
    pub action_code: String,
    pub priority: Option<i32>,
    pub condition_json: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub source_type: Option<String>,
    pub resource_id: Option<i64>,
    pub enabled: Option<i32>,
}

/// 更新规则请求（对齐现有 handler 语义）
#[derive(Debug, Clone)]
pub struct UpdateRuleRequest {
    pub card_id: i64,
    pub effect: String,
    pub resource_type: String,
    pub action_code: String,
    pub priority: Option<i32>,
    pub condition_json: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
}

/// RuleWriteService（依赖注入 `Arc<dyn RuleRepository>` + 副作用执行器）
pub struct RuleWriteService {
    repo: Arc<dyn RuleRepository>,
    side_effects: Arc<dyn PermissionSideEffects>,
    sod_db: Option<MySqlPool>,
}

const PUBLIC_RULE_SOURCE_TYPES: &[&str] = &["CARD_ONLY", "MANUAL"];

/// Normalize and enforce the ownership contract for public permission-rule
/// CRUD. TEMPLATE rules are materialized only through permission_rule_template →
/// RuleSet → durable projection, never through permission_rule.
pub(crate) fn validate_public_rule_source_type(
    source_type: Option<&str>,
) -> Result<String, AstralError> {
    let normalized = source_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("MANUAL")
        .to_ascii_uppercase();
    if PUBLIC_RULE_SOURCE_TYPES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(AstralError::Validation(format!(
            "source_type must be CARD_ONLY or MANUAL; TEMPLATE is managed by RuleSet APIs (received {normalized})"
        )))
    }
}

impl RuleWriteService {
    pub fn new(
        repo: Arc<dyn RuleRepository>,
        side_effects: Arc<dyn PermissionSideEffects>,
    ) -> Self {
        Self {
            repo,
            side_effects,
            sod_db: None,
        }
    }

    /// 生产路径启用 Java 等价的 MANUAL 授权前 SoD 校验；测试/旧注入器保持
    /// 不连接数据库的兼容构造函数，默认不启用该外部依赖。
    pub fn with_sod_db(mut self, db: MySqlPool) -> Self {
        self.sod_db = Some(db);
        self
    }

    async fn validate_manual_grant(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
        source_type: &str,
    ) -> Result<(), AstralError> {
        if source_type == "CARD_ONLY" {
            return Ok(());
        }
        let Some(db) = &self.sod_db else {
            return Ok(());
        };
        let result =
            astral_db::check_sod_conflict(db, card_id, None, resource_type, action_code, None)
                .await
                .map_err(|error| {
                    AstralError::Database(format!("SoD grant validation failed: {error}"))
                })?;
        if result.has_conflict {
            return Err(AstralError::Permission(format!(
                "SoD grant conflict: permission '{resource_type}:{action_code}' conflicts with '{}' under policy '{}'",
                result.conflict_permission.unwrap_or_default(),
                result.conflict_policy.unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// 创建规则 → 查回 → rebuild（返回完整规则）
    pub async fn create_rule(
        &self,
        req: &CreateRuleRequest,
        context: &DirectRuleMutationContext,
    ) -> Result<RuleRecord, AstralError> {
        // fail-closed：canonical 写路径只接受 ALLOW；先于任何 repository/SoD 校验。
        let effect = crate::service::validate_canonical_grant_effect(&req.effect)?;
        let source_type = validate_public_rule_source_type(req.source_type.as_deref())?;
        // fail-closed：未注册资源/动作、空白值一律 Validation 拒绝，先于 SoD 与
        // 任何 source mutation。返回归一化（trim）后的二元组，调用方必须把
        // 规范化值写入 source，而不是原始入参。
        let (resource_type, action_code) =
            validate_registry_resource_action(&req.resource_type, &req.action_code)?;
        let enabled = req.enabled.unwrap_or(1);
        let priority = req.priority.unwrap_or(100);
        if enabled != 0 {
            self.validate_manual_grant(req.card_id, &resource_type, &action_code, &source_type)
                .await?;
        }

        let rule_id = self
            .repo
            .create_rule(
                &NewRule {
                    card_id: req.card_id,
                    resource_type: resource_type.clone(),
                    resource_id: req.resource_id,
                    action_code: action_code.clone(),
                    effect,
                    condition_json: req.condition_json.clone(),
                    priority,
                    valid_from: req.valid_from.clone(),
                    valid_to: req.valid_to.clone(),
                    source_type,
                    enabled,
                },
                context,
            )
            .await?;

        let row = self.repo.get_rule(rule_id).await?.ok_or_else(|| {
            AstralError::Database(format!("rule {rule_id} not found after insert"))
        })?;

        tracing::info!(
            card_id = req.card_id,
            resource_type = %resource_type,
            action_code = %action_code,
            "rule created"
        );

        // SQLx repository 已在 source transaction 内追加 projection；兼容测试/旧实现
        // 仍通过 side-effect port 记录 durable 请求。新 grant 恒为 ALLOW，
        // 使用 CREATED 生命周期事件（删除/撤销才使用 REVOKE）。
        if !self.repo.writes_projection_in_transaction() {
            self.side_effects
                .request_card_projection(req.card_id, "RULE_CREATED")
                .await?;
        }
        Ok(row)
    }

    /// 更新规则 → 查回 → rebuild（返回完整规则）
    pub async fn update_rule(
        &self,
        rule_id: i64,
        req: &UpdateRuleRequest,
        context: &DirectRuleMutationContext,
    ) -> Result<RuleRecord, AstralError> {
        // fail-closed：最终写入 effect 必须为 ALLOW，且校验先于任何事务/读取副作用。
        let effect = crate::service::validate_canonical_grant_effect(&req.effect)?;
        // fail-closed：update 补丁总是覆写 resource/action，合并后的最终值即请求值
        // （RulePatch 恒为 Some）。未注册资源/动作、空白值在任何读取/事务副作用之前
        // Validation 拒绝；规范化（trim）值写入 source，消除 raw/trim 漂移。
        let (resource_type, action_code) =
            validate_registry_resource_action(&req.resource_type, &req.action_code)?;
        // Lock the durable ownership boundary before changing the rule. The request
        // card_id is only a compatibility assertion and never the projection target.
        let existing = self
            .repo
            .get_rule(rule_id)
            .await?
            .ok_or_else(|| AstralError::Internal(format!("Rule {rule_id} not found")))?;
        if existing.card_id != req.card_id {
            return Err(AstralError::Permission(
                "rule card context does not match requested card".into(),
            ));
        }

        self.repo
            .update_rule(
                rule_id,
                &RulePatch {
                    effect: Some(effect),
                    resource_type: Some(resource_type),
                    action_code: Some(action_code),
                    priority: Some(req.priority.unwrap_or(100)),
                    condition_json: req.condition_json.clone(),
                    valid_from: req.valid_from.clone(),
                    valid_to: req.valid_to.clone(),
                },
                context,
            )
            .await?;

        let row = self.repo.get_rule(rule_id).await?.ok_or_else(|| {
            AstralError::Database(format!("rule {rule_id} not found after update"))
        })?;

        tracing::info!(id = rule_id, card_id = existing.card_id, "rule updated");

        // SQLx repository 已在同一 source transaction 内追加 projection。
        // 更新后的 canonical grant 恒为 ALLOW，使用 UPDATED 生命周期事件。
        if !self.repo.writes_projection_in_transaction() {
            self.side_effects
                .request_card_projection(existing.card_id, "RULE_UPDATED")
                .await?;
        }
        Ok(row)
    }

    /// 删除规则 → rebuild 该卡的快照
    pub async fn delete_rule(
        &self,
        rule_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError> {
        // 先查询 card_id（删除后无法获取）
        let card_id = self
            .repo
            .get_rule_card_id(rule_id)
            .await?
            .ok_or_else(|| AstralError::Internal(format!("Rule {rule_id} not found")))?;

        let deleted = self.repo.delete_rule(rule_id, context).await?;
        if !deleted {
            return Err(AstralError::NotFound(format!("rule {rule_id} not found")));
        }

        tracing::warn!(id = rule_id, card_id, "rule deleted");

        if !self.repo.writes_projection_in_transaction() {
            self.side_effects
                .request_card_projection(card_id, "REVOKE")
                .await?;
        }
        Ok(())
    }

    /// 删除卡的全部规则 → durable 投影事件
    pub async fn delete_rules_by_card(
        &self,
        card_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError> {
        self.repo.delete_rules_by_card(card_id, context).await?;
        tracing::warn!(card_id, "all rules for card deleted");

        if !self.repo.writes_projection_in_transaction() {
            self.side_effects
                .request_card_projection(card_id, "REVOKE")
                .await?;
        }
        Ok(())
    }

    /// 手动重建卡片快照（对齐 Java `PermissionRuleController.rebuildSnapshot`）：
    /// 只落 durable `CARD_REBUILD` 投影事件，由投影 worker 统一重建快照、失效缓存并
    /// MQ 刷新。不再直接同步 rebuild/evict/publish —— 绕过 head/outbox 会让刷新消息
    /// 缺少 generation/fence，且与不变式 2「禁止绕过 durable 链」冲突。
    pub async fn rebuild_snapshot(&self, card_id: i64) -> Result<(), AstralError> {
        self.side_effects
            .request_card_projection(card_id, "CARD_REBUILD")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
    use crate::repository::rule_repository::NewRule;
    use crate::service::side_effect::PermissionSideEffects;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// 测试用操作上下文（Gateway 已验证 actor；不使用 request-id 头）。
    fn mutation_context() -> DirectRuleMutationContext {
        DirectRuleMutationContext::user(17, None).expect("positive actor must be accepted")
    }

    /// 记录触发的 durable 投影事件（no-op，不连 DB）
    struct RecordingSideEffects {
        events: Mutex<Vec<(i64, String)>>,
    }

    impl RecordingSideEffects {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<(i64, String)> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PermissionSideEffects for RecordingSideEffects {
        async fn request_card_projection(
            &self,
            card_id: i64,
            event_type: &str,
        ) -> Result<(), AstralError> {
            self.events
                .lock()
                .unwrap()
                .push((card_id, event_type.to_string()));
            Ok(())
        }

        async fn rebuild_card_snapshot(&self, _card_id: i64) {}

        async fn rebuild_rule_set_snapshot(&self, _rule_set_id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn evict_card_cache(&self, _card_id: i64) {}
    }

    /// 顺序追踪用 Fake RuleRepository（记录调用顺序与参数，便于断言编排）
    struct FakeRuleRepository {
        calls: Mutex<Vec<String>>,
        next_id: Mutex<i64>,
        rule: Mutex<Option<RuleRecord>>,
        last_new: Mutex<Option<NewRule>>,
        last_patch: Mutex<Option<RulePatch>>,
    }

    impl FakeRuleRepository {
        fn new(rule: Option<RuleRecord>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                next_id: Mutex::new(42),
                rule: Mutex::new(rule),
                last_new: Mutex::new(None),
                last_patch: Mutex::new(None),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn last_new(&self) -> NewRule {
            self.last_new.lock().unwrap().clone().unwrap()
        }

        fn last_patch(&self) -> RulePatch {
            // RulePatch 未实现 Clone：逐字段复制（字段均为 Clone）。
            let guard = self.last_patch.lock().unwrap();
            let patch = guard.as_ref().expect("update_rule must have been called");
            RulePatch {
                effect: patch.effect.clone(),
                resource_type: patch.resource_type.clone(),
                action_code: patch.action_code.clone(),
                priority: patch.priority,
                condition_json: patch.condition_json.clone(),
                valid_from: patch.valid_from.clone(),
                valid_to: patch.valid_to.clone(),
            }
        }
    }

    #[async_trait]
    impl RuleRepository for FakeRuleRepository {
        async fn count_rules(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_rules(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<RuleRecord>, AstralError> {
            Ok(vec![])
        }

        async fn list_rules_by_card(&self, _card_id: i64) -> Result<Vec<RuleRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get_rule(&self, rule_id: i64) -> Result<Option<RuleRecord>, AstralError> {
            self.calls.lock().unwrap().push(format!("get:{rule_id}"));
            Ok(self.rule.lock().unwrap().clone())
        }

        async fn create_rule(
            &self,
            new: &NewRule,
            _context: &DirectRuleMutationContext,
        ) -> Result<i64, AstralError> {
            let mut next = self.next_id.lock().unwrap();
            *next += 1;
            let id = *next;
            self.calls.lock().unwrap().push(format!("create:{id}"));
            *self.last_new.lock().unwrap() = Some(new.clone());
            Ok(id)
        }

        async fn update_rule(
            &self,
            rule_id: i64,
            patch: &RulePatch,
            _context: &DirectRuleMutationContext,
        ) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push(format!(
                "update:{rule_id}:priority={}",
                patch.priority.unwrap_or(-1)
            ));
            // RulePatch 未实现 Clone（repository 层类型，测试不得改动），
            // 在 fake 内逐字段复制以记录 service 实际下发的补丁值。
            *self.last_patch.lock().unwrap() = Some(RulePatch {
                effect: patch.effect.clone(),
                resource_type: patch.resource_type.clone(),
                action_code: patch.action_code.clone(),
                priority: patch.priority,
                condition_json: patch.condition_json.clone(),
                valid_from: patch.valid_from.clone(),
                valid_to: patch.valid_to.clone(),
            });
            Ok(())
        }

        async fn get_rule_card_id(&self, rule_id: i64) -> Result<Option<i64>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("card_id:{rule_id}"));
            Ok(Some(7))
        }

        async fn delete_rule(
            &self,
            rule_id: i64,
            _context: &DirectRuleMutationContext,
        ) -> Result<bool, AstralError> {
            self.calls.lock().unwrap().push(format!("delete:{rule_id}"));
            Ok(true)
        }

        async fn delete_rules_by_card(
            &self,
            card_id: i64,
            _context: &DirectRuleMutationContext,
        ) -> Result<(), AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_by_card:{card_id}"));
            Ok(())
        }

        async fn check_effect(
            &self,
            _card_id: i64,
            _resource_type: &str,
            _action_code: &str,
            _resource_id: Option<i64>,
        ) -> Result<Option<String>, AstralError> {
            Ok(None)
        }

        async fn delete_rules_by_source(
            &self,
            _source_type: &str,
            _source_id: i64,
            _context: &DirectRuleMutationContext,
        ) -> Result<u64, AstralError> {
            Ok(0)
        }

        async fn count_user_rules(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_user_rules(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<RuleRecord>, AstralError> {
            Ok(vec![])
        }

        async fn find_manual_rule_card_for_user(
            &self,
            _rule_id: i64,
            _user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }
    }

    fn sample_rule(id: i64) -> RuleRecord {
        RuleRecord {
            rule_id: id,
            card_id: 7,
            tenant_id: None,
            resource_type: "learn_course".into(),
            resource_id: None,
            action_code: "read".into(),
            effect: "ALLOW".into(),
            condition_json: None,
            priority: 100,
            source_type: "MANUAL".into(),
            source_id: None,
            valid_from: None,
            valid_to: None,
            enabled: Some(1),
            created_at: None,
            updated_at: None,
        }
    }

    /// 构建测试用 service（副作用 no-op，不连 DB）
    fn make_service(
        fake: Arc<FakeRuleRepository>,
        se: Arc<RecordingSideEffects>,
    ) -> RuleWriteService {
        RuleWriteService::new(fake, se)
    }

    #[test]
    fn public_rule_source_allowlist_rejects_template_and_accepts_card_owned() {
        assert!(matches!(
            validate_public_rule_source_type(Some("TEMPLATE")),
            Err(AstralError::Validation(message)) if message.contains("TEMPLATE")
        ));
        assert_eq!(
            validate_public_rule_source_type(Some("manual")).unwrap(),
            "MANUAL"
        );
        assert_eq!(
            validate_public_rule_source_type(Some("CARD_ONLY")).unwrap(),
            "CARD_ONLY"
        );
        assert_eq!(validate_public_rule_source_type(None).unwrap(), "MANUAL");
    }

    #[tokio::test]
    async fn create_rule_creates_then_reads_back() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(43))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        let row = svc
            .create_rule(
                &CreateRuleRequest {
                    card_id: 7,
                    effect: "ALLOW".into(),
                    resource_type: "learn_course".into(),
                    action_code: "read".into(),
                    priority: None,
                    condition_json: None,
                    valid_from: None,
                    valid_to: None,
                    source_type: None,
                    resource_id: None,
                    enabled: None,
                },
                &mutation_context(),
            )
            .await
            .unwrap();

        // 编排顺序：create → get（read-back）→ request_card_projection
        let calls = fake.calls();
        assert_eq!(calls[0], "create:43");
        assert_eq!(calls[1], "get:43");
        assert_eq!(row.rule_id, 43);
        assert_eq!(se.events(), vec![(7, "RULE_CREATED".to_string())]);
    }

    #[tokio::test]
    async fn create_rule_accepts_lowercased_allow_and_normalizes_source_effect() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(44))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        svc.create_rule(
            &CreateRuleRequest {
                card_id: 7,
                effect: " allow ".into(),
                resource_type: "learn_course".into(),
                action_code: "read".into(),
                priority: None,
                condition_json: None,
                valid_from: None,
                valid_to: None,
                source_type: None,
                resource_id: None,
                enabled: None,
            },
            &mutation_context(),
        )
        .await
        .expect("case-insensitive ALLOW must be accepted");

        // 写入 source 的必须是归一化后的 ALLOW，而不是原始入参
        assert_eq!(fake.last_new().effect, "ALLOW");
    }

    #[tokio::test]
    async fn create_rule_rejects_deny_unknown_and_empty_without_side_effects() {
        for rejected in ["DENY", "deny", "GRANT", "", "   "] {
            let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(45))));
            let se = Arc::new(RecordingSideEffects::new());
            let svc = make_service(fake.clone(), se.clone());

            let error = svc
                .create_rule(
                    &CreateRuleRequest {
                        card_id: 7,
                        effect: rejected.into(),
                        resource_type: "learn_course".into(),
                        action_code: "read".into(),
                        priority: None,
                        condition_json: None,
                        valid_from: None,
                        valid_to: None,
                        source_type: None,
                        resource_id: None,
                        enabled: None,
                    },
                    &mutation_context(),
                )
                .await
                .expect_err("non-ALLOW effect must be rejected");

            assert!(
                matches!(&error, AstralError::Validation(message) if message.contains("ALLOW")),
                "rejected={rejected:?} unexpected={error:?}"
            );
            // 事故链：验证失败时无任何 repository 调用、无 durable 投影事件
            assert!(fake.calls().is_empty(), "rejected={rejected:?}");
            assert!(se.events().is_empty(), "rejected={rejected:?}");
        }
    }

    #[tokio::test]
    async fn create_rule_rejects_unregistered_resource_without_side_effects() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(46))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        let error = svc
            .create_rule(
                &CreateRuleRequest {
                    card_id: 7,
                    effect: "ALLOW".into(),
                    resource_type: "no_such_resource".into(),
                    action_code: "read".into(),
                    priority: None,
                    condition_json: None,
                    valid_from: None,
                    valid_to: None,
                    source_type: None,
                    resource_id: None,
                    enabled: None,
                },
                &mutation_context(),
            )
            .await
            .expect_err("unregistered resource must be rejected fail-closed");

        assert!(
            matches!(&error, AstralError::Validation(message) if message.contains("ResourceRegistry")),
            "unexpected={error:?}"
        );
        // 事故链：校验先于 SoD/source mutation，无任何 repository 调用与投影事件
        assert!(fake.calls().is_empty());
        assert!(se.events().is_empty());
    }

    #[tokio::test]
    async fn create_rule_rejects_unregistered_action_without_side_effects() {
        for action in ["no_such_action", "", "   "] {
            let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(47))));
            let se = Arc::new(RecordingSideEffects::new());
            let svc = make_service(fake.clone(), se.clone());

            let error = svc
                .create_rule(
                    &CreateRuleRequest {
                        card_id: 7,
                        effect: "ALLOW".into(),
                        resource_type: "learn_course".into(),
                        action_code: action.into(),
                        priority: None,
                        condition_json: None,
                        valid_from: None,
                        valid_to: None,
                        source_type: None,
                        resource_id: None,
                        enabled: None,
                    },
                    &mutation_context(),
                )
                .await
                .expect_err("unregistered/blank action must be rejected fail-closed");

            assert!(
                matches!(&error, AstralError::Validation(message)
                    if message.contains("ResourceRegistry")),
                "rejected={action:?} unexpected={error:?}"
            );
            assert!(fake.calls().is_empty(), "rejected={action:?}");
            assert!(se.events().is_empty(), "rejected={action:?}");
        }
    }

    #[tokio::test]
    async fn create_rule_rejects_blank_resource_without_side_effects() {
        for resource in ["", "   ", "\t\n"] {
            let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(48))));
            let se = Arc::new(RecordingSideEffects::new());
            let svc = make_service(fake.clone(), se.clone());

            let error = svc
                .create_rule(
                    &CreateRuleRequest {
                        card_id: 7,
                        effect: "ALLOW".into(),
                        resource_type: resource.into(),
                        action_code: "read".into(),
                        priority: None,
                        condition_json: None,
                        valid_from: None,
                        valid_to: None,
                        source_type: None,
                        resource_id: None,
                        enabled: None,
                    },
                    &mutation_context(),
                )
                .await
                .expect_err("blank resource must be rejected fail-closed");

            assert!(
                matches!(&error, AstralError::Validation(message)
                    if message.contains("ResourceRegistry")),
                "rejected={resource:?} unexpected={error:?}"
            );
            assert!(fake.calls().is_empty(), "rejected={resource:?}");
            assert!(se.events().is_empty(), "rejected={resource:?}");
        }
    }

    #[tokio::test]
    async fn create_rule_trims_and_persists_normalized_resource_action() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(49))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        svc.create_rule(
            &CreateRuleRequest {
                card_id: 7,
                effect: "ALLOW".into(),
                resource_type: "  learn_course  ".into(),
                action_code: " read ".into(),
                priority: None,
                condition_json: None,
                valid_from: None,
                valid_to: None,
                source_type: None,
                resource_id: None,
                enabled: None,
            },
            &mutation_context(),
        )
        .await
        .expect("registered resource/action with surrounding whitespace must be accepted");

        // 写入 source 的必须是归一化（trim）后的二元组，而不是原始入参
        let persisted = fake.last_new();
        assert_eq!(persisted.resource_type, "learn_course");
        assert_eq!(persisted.action_code, "read");
        assert_eq!(persisted.effect, "ALLOW");
    }

    #[tokio::test]
    async fn update_rule_defaults_priority_to_100() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(9))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        svc.update_rule(
            9,
            &UpdateRuleRequest {
                card_id: 7,
                effect: "ALLOW".into(),
                resource_type: "learn_course".into(),
                action_code: "read".into(),
                priority: None,
                condition_json: None,
                valid_from: None,
                valid_to: None,
            },
            &mutation_context(),
        )
        .await
        .unwrap();

        let calls = fake.calls();
        // 编排顺序：get（锁定真实 card_id）→ update → get（read-back）
        // 优先级缺省 → patch.priority = 100
        assert_eq!(calls[0], "get:9");
        assert_eq!(calls[1], "update:9:priority=100");
        assert_eq!(calls[2], "get:9");
        assert_eq!(se.events(), vec![(7, "RULE_UPDATED".to_string())]);
    }

    #[tokio::test]
    async fn update_rule_rejects_deny_before_any_transaction_or_projection() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(10))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        let error = svc
            .update_rule(
                10,
                &UpdateRuleRequest {
                    card_id: 7,
                    effect: "DENY".into(),
                    resource_type: "learn_course".into(),
                    action_code: "read".into(),
                    priority: None,
                    condition_json: None,
                    valid_from: None,
                    valid_to: None,
                },
                &mutation_context(),
            )
            .await
            .expect_err("DENY must be rejected on update too");

        assert!(matches!(error, AstralError::Validation(message) if message.contains("ALLOW")));
        // 校验先于读取/事务：无任何 repository 调用与投影事件
        assert!(fake.calls().is_empty());
        assert!(se.events().is_empty());
    }

    #[tokio::test]
    async fn update_rule_rejects_unregistered_resource_or_action_before_any_transaction() {
        for (resource, action) in [
            ("no_such_resource", "read"),
            ("learn_course", "no_such_action"),
            ("  ", "read"),
            ("learn_course", ""),
        ] {
            let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(11))));
            let se = Arc::new(RecordingSideEffects::new());
            let svc = make_service(fake.clone(), se.clone());

            let error = svc
                .update_rule(
                    11,
                    &UpdateRuleRequest {
                        card_id: 7,
                        effect: "ALLOW".into(),
                        resource_type: resource.into(),
                        action_code: action.into(),
                        priority: None,
                        condition_json: None,
                        valid_from: None,
                        valid_to: None,
                    },
                    &mutation_context(),
                )
                .await
                .expect_err("unregistered/blank resource-action must be rejected on update");

            assert!(
                matches!(&error, AstralError::Validation(message)
                    if message.contains("ResourceRegistry")),
                "rejected=({resource:?},{action:?}) unexpected={error:?}"
            );
            // 校验先于读取/事务：无任何 repository 调用与投影事件
            assert!(
                fake.calls().is_empty(),
                "rejected=({resource:?},{action:?})"
            );
            assert!(se.events().is_empty(), "rejected=({resource:?},{action:?})");
        }
    }

    #[tokio::test]
    async fn update_rule_trims_and_writes_normalized_patch_values() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(12))));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        svc.update_rule(
            12,
            &UpdateRuleRequest {
                card_id: 7,
                effect: " allow ".into(),
                resource_type: "  learn_course ".into(),
                action_code: " read ".into(),
                priority: None,
                condition_json: None,
                valid_from: None,
                valid_to: None,
            },
            &mutation_context(),
        )
        .await
        .expect("registered resource/action with whitespace must be accepted on update");

        // 写入 patch 的必须是归一化（trim）后的值；effect 同样归一为 ALLOW
        let patch = fake.last_patch();
        assert_eq!(patch.resource_type.as_deref(), Some("learn_course"));
        assert_eq!(patch.action_code.as_deref(), Some("read"));
        assert_eq!(patch.effect.as_deref(), Some("ALLOW"));
        assert_eq!(se.events(), vec![(7, "RULE_UPDATED".to_string())]);
    }

    #[tokio::test]
    async fn delete_rule_fetches_card_id_before_delete() {
        let fake = Arc::new(FakeRuleRepository::new(None));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        svc.delete_rule(9, &mutation_context()).await.unwrap();

        // 先取 card_id（删除后无法回查），再删除
        let calls = fake.calls();
        assert_eq!(calls[0], "card_id:9");
        assert_eq!(calls[1], "delete:9");
        assert_eq!(se.events(), vec![(7, "REVOKE".to_string())]);
    }

    #[tokio::test]
    async fn delete_rules_by_card_delegates_to_repository() {
        let fake = Arc::new(FakeRuleRepository::new(None));
        let se = Arc::new(RecordingSideEffects::new());
        let svc = make_service(fake.clone(), se.clone());

        svc.delete_rules_by_card(7, &mutation_context())
            .await
            .unwrap();

        assert_eq!(fake.calls(), vec!["delete_by_card:7".to_string()]);
        assert_eq!(se.events(), vec![(7, "REVOKE".to_string())]);
    }
}
