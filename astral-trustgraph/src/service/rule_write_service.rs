//! 权限规则写路径编排 — RuleWriteService
//!
//! Direct permission-rule source changes are written by the repository in one
//! transaction with V6 projection, audit correlation, and grant-ledger deltas.

use std::sync::Arc;

use astral_types::AstralError;
use async_trait::async_trait;
use sqlx::MySqlPool;

#[async_trait]
pub trait GrantSodValidator: Send + Sync {
    async fn check_grant(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
    ) -> Result<astral_db::SodCheckResult, AstralError>;
}

pub struct SqlxGrantSodValidator {
    db: MySqlPool,
}

impl SqlxGrantSodValidator {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl GrantSodValidator for SqlxGrantSodValidator {
    async fn check_grant(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
    ) -> Result<astral_db::SodCheckResult, AstralError> {
        astral_db::check_grant_sod_conflict(&self.db, card_id, resource_type, action_code)
            .await
            .map_err(|error| AstralError::Database(format!("SoD grant validation failed: {error}")))
    }
}

pub(crate) fn reject_sod_conflict(
    result: astral_db::SodCheckResult,
    resource_type: &str,
    action_code: &str,
) -> Result<(), AstralError> {
    if result.has_conflict {
        return Err(AstralError::Permission(format!(
            "SoD grant conflict: permission '{resource_type}:{action_code}' conflicts with '{}' under policy '{}'",
            result.conflict_permission.unwrap_or_default(),
            result.conflict_policy.unwrap_or_default()
        )));
    }
    Ok(())
}

const PUBLIC_RULE_SOURCE_TYPE: &str = "MANUAL";

use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
use crate::repository::rule_repository::{NewRule, RulePatch, RuleRecord, RuleRepository};
use crate::service::personal_permission_service::validate_registry_resource_action;

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

/// Direct-rule source orchestration with an explicit CREATE SoD validator.
pub struct RuleWriteService {
    repo: Arc<dyn RuleRepository>,
    grant_sod_validator: Arc<dyn GrantSodValidator>,
}

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
    if normalized == PUBLIC_RULE_SOURCE_TYPE {
        Ok(PUBLIC_RULE_SOURCE_TYPE.to_owned())
    } else {
        Err(AstralError::Validation(format!(
            "source_type must be MANUAL; CARD_ONLY and TEMPLATE are not accepted for new permission-rule writes (received {normalized})"
        )))
    }
}

impl RuleWriteService {
    pub fn new(
        repo: Arc<dyn RuleRepository>,
        grant_sod_validator: Arc<dyn GrantSodValidator>,
    ) -> Self {
        Self {
            repo,
            grant_sod_validator,
        }
    }

    async fn validate_manual_grant(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
    ) -> Result<(), AstralError> {
        let result = self
            .grant_sod_validator
            .check_grant(card_id, resource_type, action_code)
            .await?;
        reject_sod_conflict(result, resource_type, action_code)
    }

    /// Validate the grant, commit source/ledger/audit, then read back the rule.
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
        if enabled != 1 {
            return Err(AstralError::Validation(
                "canonical direct rules require enabled=1; withdraw a grant by deleting it".into(),
            ));
        }
        let priority = req.priority.unwrap_or(100);
        self.validate_manual_grant(req.card_id, &resource_type, &action_code)
            .await?;

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
        Ok(row)
    }

    /// Validate and commit the source/ledger change, then read back the rule.
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
        if existing.source_type != PUBLIC_RULE_SOURCE_TYPE {
            return Err(AstralError::Validation(
                "permission-rule updates require MANUAL source_type; historical CARD_ONLY rows are read/delete-only"
                    .into(),
            ));
        }
        // UPDATE uses the mandatory transaction-level SoD gate after the repository
        // locks the exact source/card scope and proves the published before-image.
        // A pool precheck cannot carry this identity safely, so it is intentionally
        // not used as a decision point here.
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
        Ok(row)
    }

    /// Delete through the repository-owned source, revocation and ledger transaction.
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
    use crate::repository::rule_repository::NewRule;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// 测试用操作上下文（Gateway 已验证 actor；不使用 request-id 头）。
    fn mutation_context() -> DirectRuleMutationContext {
        DirectRuleMutationContext::user(17, None).expect("positive actor must be accepted")
    }

    /// Explicit, no-DB SoD validator used by service tests.
    struct RecordingGrantSodValidator {
        events: Mutex<Vec<(i64, String)>>,
        has_conflict: bool,
        unavailable: bool,
    }

    impl RecordingGrantSodValidator {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                has_conflict: false,
                unavailable: false,
            }
        }

        fn events(&self) -> Vec<(i64, String)> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GrantSodValidator for RecordingGrantSodValidator {
        async fn check_grant(
            &self,
            card_id: i64,
            resource_type: &str,
            action_code: &str,
        ) -> Result<astral_db::SodCheckResult, AstralError> {
            self.events
                .lock()
                .unwrap()
                .push((card_id, format!("{resource_type}:{action_code}")));
            if self.unavailable {
                return Err(AstralError::Database(
                    "published SoD evidence unavailable".into(),
                ));
            }
            Ok(astral_db::SodCheckResult {
                has_conflict: self.has_conflict,
                conflict_policy: Some("separation".into()),
                conflict_permission: Some("learn_course:delete".into()),
                conflict_type: Some("STATIC".into()),
            })
        }
    }

    #[derive(Clone, Copy)]
    enum UpdateFailure {
        Conflict,
        EvidenceUnavailable,
    }

    /// 顺序追踪用 Fake RuleRepository（记录调用顺序与参数，便于断言编排）
    struct FakeRuleRepository {
        calls: Mutex<Vec<String>>,
        next_id: Mutex<i64>,
        rule: Mutex<Option<RuleRecord>>,
        last_new: Mutex<Option<NewRule>>,
        last_patch: Mutex<Option<RulePatch>>,
        update_failure: Option<UpdateFailure>,
    }

    impl FakeRuleRepository {
        fn new(rule: Option<RuleRecord>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                next_id: Mutex::new(42),
                rule: Mutex::new(rule),
                last_new: Mutex::new(None),
                last_patch: Mutex::new(None),
                update_failure: None,
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
            match self.update_failure {
                Some(UpdateFailure::Conflict) => {
                    return Err(AstralError::Permission("transactional SoD conflict".into()));
                }
                Some(UpdateFailure::EvidenceUnavailable) => {
                    return Err(AstralError::Database(
                        "transactional SoD evidence unavailable".into(),
                    ));
                }
                None => {}
            }
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

    /// Service orchestration fixture; repository transaction behavior is tested separately.
    fn make_service(
        fake: Arc<FakeRuleRepository>,
        sod: Arc<RecordingGrantSodValidator>,
    ) -> RuleWriteService {
        RuleWriteService::new(fake, sod)
    }

    #[test]
    fn public_rule_source_accepts_only_manual() {
        assert!(matches!(
            validate_public_rule_source_type(Some("TEMPLATE")),
            Err(AstralError::Validation(message)) if message.contains("TEMPLATE")
        ));
        assert_eq!(
            validate_public_rule_source_type(Some("manual")).unwrap(),
            "MANUAL"
        );
        assert!(matches!(
            validate_public_rule_source_type(Some("CARD_ONLY")),
            Err(AstralError::Validation(message)) if message.contains("MANUAL")
        ));
        assert_eq!(validate_public_rule_source_type(None).unwrap(), "MANUAL");
    }

    fn create_request() -> CreateRuleRequest {
        CreateRuleRequest {
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
        }
    }

    fn update_request() -> UpdateRuleRequest {
        UpdateRuleRequest {
            card_id: 7,
            effect: "ALLOW".into(),
            resource_type: "learn_course".into(),
            action_code: "read".into(),
            priority: None,
            condition_json: None,
            valid_from: None,
            valid_to: None,
        }
    }

    #[tokio::test]
    async fn sod_conflict_or_unavailable_evidence_prevents_create_and_update() {
        for unavailable in [false, true] {
            let mut repository = FakeRuleRepository::new(Some(sample_rule(9)));
            repository.update_failure = Some(if unavailable {
                UpdateFailure::EvidenceUnavailable
            } else {
                UpdateFailure::Conflict
            });
            let fake = Arc::new(repository);
            let sod = Arc::new(RecordingGrantSodValidator {
                has_conflict: !unavailable,
                unavailable,
                ..RecordingGrantSodValidator::new()
            });
            let service = make_service(fake.clone(), sod.clone());
            let create = service
                .create_rule(&create_request(), &mutation_context())
                .await
                .unwrap_err();
            let update = service
                .update_rule(9, &update_request(), &mutation_context())
                .await
                .unwrap_err();
            for error in [create, update] {
                if unavailable {
                    assert!(matches!(error, AstralError::Database(_)));
                } else {
                    assert!(matches!(error, AstralError::Permission(_)));
                }
            }
            assert_eq!(fake.calls(), vec!["get:9", "update:9:priority=100"]);
            assert!(fake.last_patch.lock().unwrap().is_none());
            assert_eq!(sod.events(), vec![(7, "learn_course:read".into())]);
        }
    }

    #[tokio::test]
    async fn disabled_or_nonmanual_sources_never_reach_grant_validation_or_mutation() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(9))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let service = make_service(fake.clone(), sod.clone());
        for enabled in [0, -1, 2] {
            let request = CreateRuleRequest {
                enabled: Some(enabled),
                ..create_request()
            };
            assert!(matches!(
                service.create_rule(&request, &mutation_context()).await,
                Err(AstralError::Validation(_))
            ));
        }
        for source in ["CARD_ONLY", "TEMPLATE"] {
            let request = CreateRuleRequest {
                source_type: Some(source.into()),
                ..create_request()
            };
            assert!(matches!(
                service.create_rule(&request, &mutation_context()).await,
                Err(AstralError::Validation(_))
            ));
        }
        assert!(fake.calls().is_empty());
        assert!(sod.events().is_empty());
    }

    #[tokio::test]
    async fn historical_card_only_update_is_rejected_before_sod_and_source_write() {
        let rule = RuleRecord {
            source_type: "CARD_ONLY".into(),
            ..sample_rule(9)
        };
        let fake = Arc::new(FakeRuleRepository::new(Some(rule)));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let service = make_service(fake.clone(), sod.clone());
        assert!(matches!(
            service
                .update_rule(9, &update_request(), &mutation_context())
                .await,
            Err(AstralError::Validation(_))
        ));
        assert_eq!(fake.calls(), vec!["get:9"]);
        assert!(sod.events().is_empty());
    }

    #[tokio::test]
    async fn create_rule_creates_then_reads_back() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(43))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

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

        let calls = fake.calls();
        assert_eq!(calls[0], "create:43");
        assert_eq!(calls[1], "get:43");
        assert_eq!(row.rule_id, 43);
        assert_eq!(sod.events(), vec![(7, "learn_course:read".to_string())]);
    }

    #[tokio::test]
    async fn create_rule_accepts_lowercased_allow_and_normalizes_source_effect() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(44))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

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
            let sod = Arc::new(RecordingGrantSodValidator::new());
            let svc = make_service(fake.clone(), sod.clone());

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
            assert!(sod.events().is_empty(), "rejected={rejected:?}");
        }
    }

    #[tokio::test]
    async fn create_rule_rejects_unregistered_resource_without_side_effects() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(46))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

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
        assert!(sod.events().is_empty());
    }

    #[tokio::test]
    async fn create_rule_rejects_unregistered_action_without_side_effects() {
        for action in ["no_such_action", "", "   "] {
            let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(47))));
            let sod = Arc::new(RecordingGrantSodValidator::new());
            let svc = make_service(fake.clone(), sod.clone());

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
            assert!(sod.events().is_empty(), "rejected={action:?}");
        }
    }

    #[tokio::test]
    async fn create_rule_rejects_blank_resource_without_side_effects() {
        for resource in ["", "   ", "\t\n"] {
            let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(48))));
            let sod = Arc::new(RecordingGrantSodValidator::new());
            let svc = make_service(fake.clone(), sod.clone());

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
            assert!(sod.events().is_empty(), "rejected={resource:?}");
        }
    }

    #[tokio::test]
    async fn create_rule_trims_and_persists_normalized_resource_action() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(49))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

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
        let sod = Arc::new(RecordingGrantSodValidator {
            unavailable: true,
            ..RecordingGrantSodValidator::new()
        });
        let svc = make_service(fake.clone(), sod.clone());

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
        assert!(sod.events().is_empty());
    }

    #[tokio::test]
    async fn update_rule_rejects_deny_before_any_transaction_or_projection() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(10))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

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
        assert!(sod.events().is_empty());
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
            let sod = Arc::new(RecordingGrantSodValidator::new());
            let svc = make_service(fake.clone(), sod.clone());

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
            assert!(
                sod.events().is_empty(),
                "rejected=({resource:?},{action:?})"
            );
        }
    }

    #[tokio::test]
    async fn update_rule_trims_and_writes_normalized_patch_values() {
        let fake = Arc::new(FakeRuleRepository::new(Some(sample_rule(12))));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

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
        assert!(sod.events().is_empty());
    }

    #[tokio::test]
    async fn delete_rule_fetches_card_id_before_delete() {
        let fake = Arc::new(FakeRuleRepository::new(None));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

        svc.delete_rule(9, &mutation_context()).await.unwrap();

        // 先取 card_id（删除后无法回查），再删除
        let calls = fake.calls();
        assert_eq!(calls[0], "card_id:9");
        assert_eq!(calls[1], "delete:9");
        assert!(sod.events().is_empty());
    }

    #[tokio::test]
    async fn delete_rules_by_card_delegates_to_repository() {
        let fake = Arc::new(FakeRuleRepository::new(None));
        let sod = Arc::new(RecordingGrantSodValidator::new());
        let svc = make_service(fake.clone(), sod.clone());

        svc.delete_rules_by_card(7, &mutation_context())
            .await
            .unwrap();

        assert_eq!(fake.calls(), vec!["delete_by_card:7".to_string()]);
        assert!(sod.events().is_empty());
    }
}
