//! 用户个人权限编排 — PersonalPermissionService
//!
//! Personal grants are validated by the injected SoD port and written through the
//! direct-rule source transaction; projection and audit evidence stay transaction-owned.

use std::sync::Arc;

use astral_types::{AstralError, ResourceRegistry};

use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
use crate::repository::rule_repository::{NewRule, RuleRepository};
use crate::service::rule_write_service::{reject_sod_conflict, GrantSodValidator};

/// 授予结果（handler 组装 DTO 用；字段为 service 归一化后的持久化值）
#[derive(Debug, Clone)]
pub struct GrantOutcome {
    pub rule_id: i64,
    pub card_id: i64,
    /// 归一化（trim）且已通过 ResourceRegistry 校验的资源类型
    pub resource_type: String,
    /// 归一化（trim）且已通过 ResourceRegistry 校验的动作
    pub action_code: String,
    /// 归一化后的 effect（恒为 "ALLOW"）
    pub effect: String,
    pub priority: i32,
}

/// Grant 前的 ResourceRegistry 校验：resource_type/action_code 去除首尾空白后
/// 必须命中注册表（资源已注册且动作属于该资源），否则 fail-closed 拒绝。
///
/// 未注册资源/动作一旦写入 source，只会生成永不匹配的死规则或污染授权状态；
/// 校验必须先于任何 repository/SoD 副作用。返回归一化后的二元组，
/// 调用方必须把返回值写入 source，而不是原始入参。
pub(crate) fn validate_registry_resource_action(
    resource_type: &str,
    action_code: &str,
) -> Result<(String, String), AstralError> {
    let resource = resource_type.trim();
    let action = action_code.trim();
    if resource.is_empty() || action.is_empty() {
        return Err(AstralError::Validation(
            "resource_type and action_code must be non-empty and registered in ResourceRegistry"
                .into(),
        ));
    }
    ResourceRegistry::global()
        .validate(resource, action)
        .map(|()| (resource.to_string(), action.to_string()))
        .map_err(|error| {
            AstralError::Validation(format!(
                "resource/action must be registered in ResourceRegistry: {error}"
            ))
        })
}

/// PersonalPermissionService
pub struct PersonalPermissionService {
    rule_repo: Arc<dyn RuleRepository>,
    grant_sod_validator: Arc<dyn GrantSodValidator>,
}

impl PersonalPermissionService {
    pub fn new(
        rule_repo: Arc<dyn RuleRepository>,
        grant_sod_validator: Arc<dyn GrantSodValidator>,
    ) -> Self {
        Self {
            rule_repo,
            grant_sod_validator,
        }
    }

    async fn validate_grant(
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

    /// Validate SoD and commit a MANUAL grant for the resolved authorization card.
    pub async fn grant(
        &self,
        card_id: i64,
        resource_type: &str,
        action_code: &str,
        effect: &str,
        priority: Option<i32>,
        context: &DirectRuleMutationContext,
    ) -> Result<GrantOutcome, AstralError> {
        // fail-closed：canonical 个人授权只接受 ALLOW；先于任何 repository/SoD 副作用。
        let effect = crate::service::validate_canonical_grant_effect(effect)?;
        // ResourceRegistry 校验先于任何 source mutation：未注册资源/动作一律拒绝。
        let (resource_type, action_code) =
            validate_registry_resource_action(resource_type, action_code)?;
        self.validate_grant(card_id, &resource_type, &action_code)
            .await?;
        let priority = priority.unwrap_or(0);
        let rule_id = self
            .rule_repo
            .create_rule(
                &NewRule {
                    card_id,
                    resource_type: resource_type.clone(),
                    resource_id: None,
                    action_code: action_code.clone(),
                    effect: effect.clone(),
                    condition_json: None,
                    priority,
                    valid_from: None,
                    valid_to: None,
                    source_type: "MANUAL".into(),
                    enabled: 1,
                },
                context,
            )
            .await?;

        tracing::info!(
            card_id,
            rule_id,
            resource = %resource_type,
            action = %action_code,
            "permission granted to user"
        );

        Ok(GrantOutcome {
            rule_id,
            card_id,
            resource_type,
            action_code,
            effect,
            priority,
        })
    }

    /// 撤销用户权限：解析实际承载卡（MANUAL 或历史 CARD_ONLY 且属于该用户），
    /// 再由仓储原子删除并追加撤权 delta、source correlation 与审计。
    ///
    /// 归属校验在此重复执行（防御纵深）：handler 已先解析同一张卡并完成
    /// `require_card_scope` 管理范围校验（ACTIVE GlobalAdmin 例外），
    /// service 侧不信任调用方转述，删除前以仓储解析结果为准。
    pub async fn revoke(
        &self,
        user_id: i64,
        rule_id: i64,
        context: &DirectRuleMutationContext,
    ) -> Result<(), AstralError> {
        // 校验规则属于该用户的某张卡（对齐现有 handler 语义：MANUAL source_type）
        self.rule_repo
            .find_manual_rule_card_for_user(rule_id, user_id)
            .await?
            .ok_or_else(|| {
                AstralError::Validation(format!(
                    "rule {rule_id} does not belong to user {user_id} or is not MANUAL"
                ))
            })?;

        let deleted = self.rule_repo.delete_rule(rule_id, context).await?;
        if !deleted {
            return Err(AstralError::NotFound(format!("rule {rule_id} not found")));
        }
        tracing::warn!(user_id, rule_id, "permission revoked from user");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
    use crate::repository::rule_repository::{RulePatch, RuleRecord};
    use crate::service::rule_write_service::GrantSodValidator;

    /// 测试用操作上下文（Gateway 已验证 actor；不使用 request-id 头）。
    fn mutation_context() -> DirectRuleMutationContext {
        DirectRuleMutationContext::user(17, None).expect("positive actor must be accepted")
    }

    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Test-only SoD grant validator with an explicit conflict switch.
    struct RecordingGrantSodValidator {
        has_conflict: bool,
        unavailable: bool,
    }

    #[async_trait]
    impl GrantSodValidator for RecordingGrantSodValidator {
        async fn check_grant(
            &self,
            _card_id: i64,
            _resource_type: &str,
            _action_code: &str,
        ) -> Result<astral_db::SodCheckResult, AstralError> {
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

    fn grant_sod_validator() -> Arc<dyn GrantSodValidator> {
        Arc::new(RecordingGrantSodValidator {
            has_conflict: false,
            unavailable: false,
        })
    }

    /// Fake RuleRepository：记录 create/delete 与写入的规则，归属校验可配置
    struct FakeRuleRepository {
        calls: Mutex<Vec<String>>,
        next_id: Mutex<i64>,
        manual_card: Mutex<Option<i64>>,
        last_new: Mutex<Option<NewRule>>,
    }

    impl FakeRuleRepository {
        fn new(manual_card: Option<i64>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                next_id: Mutex::new(100),
                manual_card: Mutex::new(manual_card),
                last_new: Mutex::new(None),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn last_new(&self) -> NewRule {
            self.last_new.lock().unwrap().clone().unwrap()
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

        async fn get_rule(&self, _rule_id: i64) -> Result<Option<RuleRecord>, AstralError> {
            Ok(None)
        }

        async fn create_rule(
            &self,
            new: &NewRule,
            _context: &DirectRuleMutationContext,
        ) -> Result<i64, AstralError> {
            let mut next = self.next_id.lock().unwrap();
            *next += 1;
            let id = *next;
            self.calls
                .lock()
                .unwrap()
                .push(format!("create:{id}:card={}", new.card_id));
            *self.last_new.lock().unwrap() = Some(new.clone());
            Ok(id)
        }

        async fn update_rule(
            &self,
            rule_id: i64,
            _patch: &RulePatch,
            _context: &DirectRuleMutationContext,
        ) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push(format!("update:{rule_id}"));
            Ok(())
        }

        async fn get_rule_card_id(&self, rule_id: i64) -> Result<Option<i64>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("card_id:{rule_id}"));
            Ok(Some(7))
        }

        async fn find_manual_rule_card_for_user(
            &self,
            rule_id: i64,
            user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("find_manual:{rule_id}:user={user_id}"));
            Ok(*self.manual_card.lock().unwrap())
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
            source_type: &str,
            source_id: i64,
            _context: &DirectRuleMutationContext,
        ) -> Result<u64, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_by_source:{source_type}:{source_id}"));
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
    }

    #[tokio::test]
    async fn grant_conflict_or_unavailable_evidence_never_reaches_source_repository() {
        for unavailable in [false, true] {
            let repo = Arc::new(FakeRuleRepository::new(Some(7)));
            let validator = Arc::new(RecordingGrantSodValidator {
                has_conflict: !unavailable,
                unavailable,
            });
            let service = PersonalPermissionService::new(repo.clone(), validator);
            let error = service
                .grant(
                    7,
                    "learn_question",
                    "read",
                    "ALLOW",
                    None,
                    &mutation_context(),
                )
                .await
                .unwrap_err();
            if unavailable {
                assert!(matches!(error, AstralError::Database(_)));
            } else {
                assert!(matches!(error, AstralError::Permission(_)));
            }
            assert!(repo.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn grant_inserts_manual_rule_then_rebuilds() {
        let repo = Arc::new(FakeRuleRepository::new(Some(7)));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        let outcome = svc
            .grant(
                7,
                "learn_question",
                "read",
                "ALLOW",
                None,
                &mutation_context(),
            )
            .await
            .unwrap();

        assert_eq!(outcome.card_id, 7);
        assert!(outcome.rule_id > 100);
        // 写入的规则必须是 MANUAL 源、默认 priority 0（对齐 handler 语义）
        let new = repo.last_new();
        assert_eq!(new.source_type, "MANUAL");
        assert_eq!(new.priority, 0);
        assert_eq!(new.card_id, 7);
        assert_eq!(new.resource_type, "learn_question");
        assert_eq!(new.action_code, "read");
        assert_eq!(new.effect, "ALLOW");
        assert_eq!(repo.calls(), vec!["create:101:card=7"]);
    }

    #[tokio::test]
    async fn grant_accepts_lowercased_allow_and_persists_normalized_effect() {
        let repo = Arc::new(FakeRuleRepository::new(Some(7)));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        svc.grant(
            7,
            "learn_question",
            "read",
            " allow ",
            None,
            &mutation_context(),
        )
        .await
        .expect("case-insensitive ALLOW must be accepted");
        // 写入 source 的必须是归一化后的 ALLOW
        assert_eq!(repo.last_new().effect, "ALLOW");
    }

    #[tokio::test]
    async fn grant_rejects_deny_unknown_and_empty_without_side_effects() {
        for rejected in ["DENY", "deny", "GRANT", "", "   "] {
            let repo = Arc::new(FakeRuleRepository::new(Some(7)));
            let sod = grant_sod_validator();
            let svc = PersonalPermissionService::new(repo.clone(), sod);

            let error = svc
                .grant(
                    7,
                    "learn_question",
                    "read",
                    rejected,
                    None,
                    &mutation_context(),
                )
                .await
                .expect_err("non-ALLOW grant must be rejected");

            assert!(
                matches!(&error, AstralError::Validation(message) if message.contains("ALLOW")),
                "rejected={rejected:?} unexpected={error:?}"
            );
            // Validation failure is rejected before a repository source mutation.
            assert!(repo.calls().is_empty(), "rejected={rejected:?}");
        }
    }

    #[tokio::test]
    async fn revoke_checks_ownership_then_deletes_and_rebuilds() {
        let repo = Arc::new(FakeRuleRepository::new(Some(7)));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        svc.revoke(5, 99, &mutation_context()).await.unwrap();

        // Verify ownership before the repository's source-transaction delete.
        assert_eq!(repo.calls(), vec!["find_manual:99:user=5", "delete:99"]);
    }

    #[tokio::test]
    async fn revoke_rejects_foreign_or_non_manual_rule() {
        // 归属校验失败（规则不属于该用户 / 非 MANUAL）
        let repo = Arc::new(FakeRuleRepository::new(None));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        let err = svc.revoke(5, 99, &mutation_context()).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
        // 不执行删除、不触发投影事件（安全默认：DENY 优先）
        assert_eq!(repo.calls(), vec!["find_manual:99:user=5"]);
    }

    // ===== ResourceRegistry 校验（先于任何 repository 调用） =====

    #[tokio::test]
    async fn grant_rejects_unregistered_resource_before_repository_calls() {
        let repo = Arc::new(FakeRuleRepository::new(Some(7)));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        let error = svc
            .grant(
                7,
                "unregistered_resource",
                "read",
                "ALLOW",
                None,
                &mutation_context(),
            )
            .await
            .expect_err("unregistered resource must be rejected");

        assert!(
            matches!(&error, AstralError::Validation(message) if message.contains("ResourceRegistry")),
            "unexpected error {error:?}"
        );
        // 事故链：registry 校验失败时零 repository 调用、零 durable 投影事件
        assert!(repo.calls().is_empty());
    }

    #[tokio::test]
    async fn grant_rejects_action_not_registered_for_resource() {
        // learn_question 已注册，但不含动作 "fly"
        let repo = Arc::new(FakeRuleRepository::new(Some(7)));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        let error = svc
            .grant(
                7,
                "learn_question",
                "fly",
                "ALLOW",
                None,
                &mutation_context(),
            )
            .await
            .expect_err("unregistered action must be rejected");

        assert!(
            matches!(&error, AstralError::Validation(message) if message.contains("ResourceRegistry")),
            "unexpected error {error:?}"
        );
        assert!(repo.calls().is_empty());
    }

    #[tokio::test]
    async fn grant_rejects_blank_resource_or_action() {
        for (resource, action) in [
            ("", "read"),
            ("   ", "read"),
            ("learn_question", ""),
            ("learn_question", "   "),
        ] {
            let repo = Arc::new(FakeRuleRepository::new(Some(7)));
            let sod = grant_sod_validator();
            let svc = PersonalPermissionService::new(repo.clone(), sod);

            let error = svc
                .grant(7, resource, action, "ALLOW", None, &mutation_context())
                .await
                .expect_err("blank resource/action must be rejected");

            assert!(
                matches!(&error, AstralError::Validation(_)),
                "resource={resource:?} action={action:?} unexpected={error:?}"
            );
            assert!(repo.calls().is_empty(), "resource={resource:?}");
        }
    }

    #[tokio::test]
    async fn grant_persists_trimmed_registry_validated_resource_and_action() {
        let repo = Arc::new(FakeRuleRepository::new(Some(7)));
        let sod = grant_sod_validator();
        let svc = PersonalPermissionService::new(repo.clone(), sod);

        let outcome = svc
            .grant(
                7,
                "  learn_question  ",
                " read ",
                "ALLOW",
                Some(3),
                &mutation_context(),
            )
            .await
            .expect("registry-valid grant must pass");

        // source 只落归一化（trim）后的 resource/action；ALLOW-only 由既有测试覆盖
        let new = repo.last_new();
        assert_eq!(new.resource_type, "learn_question");
        assert_eq!(new.action_code, "read");
        assert_eq!(new.priority, 3);
        // outcome 回显归一化持久化值（handler DTO 不回显原始入参）
        assert_eq!(outcome.resource_type, "learn_question");
        assert_eq!(outcome.action_code, "read");
        assert_eq!(outcome.effect, "ALLOW");
        assert_eq!(outcome.priority, 3);
    }

    #[test]
    fn registry_validation_rejects_known_unregistered_pairs_directly() {
        let ok = validate_registry_resource_action(" learn_question ", " read ")
            .expect("registered pair must pass");
        assert_eq!(ok, ("learn_question".to_string(), "read".to_string()));

        assert!(validate_registry_resource_action("no_such_resource", "read").is_err());
        assert!(validate_registry_resource_action("learn_subject", "no_such_action").is_err());
        assert!(validate_registry_resource_action("", "read").is_err());
        assert!(validate_registry_resource_action("learn_subject", "  ").is_err());
    }
}
