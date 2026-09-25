//! 策略模板编排 — TemplateService
//!
//! 模板规则同步由 TemplateRepository 在同一事务内完成：共享 RuleSet
//! source、RULE_SET durable projection 与 ACTIVE 绑定卡 CARD fanout 一起提交；
//! 快照重建、缓存失效和消息发布由 projection worker 负责。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::audit_log_repository::RuleSetMutationContext;

use crate::repository::template_repository::{TemplateRepository, TemplateRuleInput};

/// 模板同步结果
#[derive(Debug, Clone, Copy)]
pub struct SyncOutcome {
    pub total_cards: usize,
    pub synced: i64,
}

/// TemplateService
#[derive(Clone)]
pub struct TemplateService {
    repo: Arc<dyn TemplateRepository>,
}

impl TemplateService {
    pub fn new(repo: Arc<dyn TemplateRepository>) -> Self {
        Self { repo }
    }

    /// 事务性更新模板规则（删旧插新），返回插入数
    pub async fn update_template(
        &self,
        template_id: &str,
        rules: &[TemplateRuleInput],
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        self.repo.update_template(template_id, rules, context).await
    }

    /// 同步模板变更到共享规则集及所有活动绑定卡。
    pub async fn sync_template(
        &self,
        template_id: &str,
        context: &RuleSetMutationContext,
    ) -> Result<SyncOutcome, AstralError> {
        let synced = self
            .repo
            .sync_template_projection(template_id, context)
            .await?;
        let outcome = SyncOutcome {
            total_cards: synced,
            synced: synced as i64,
        };
        tracing::info!(
            template_id,
            total_cards = outcome.total_cards,
            synced = outcome.synced,
            "template projection synchronized"
        );
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Fake TemplateRepository：返回事务同步已经追加的卡片事件数量。
    struct FakeTemplateRepository {
        synced_cards: Mutex<usize>,
    }

    #[async_trait]
    impl TemplateRepository for FakeTemplateRepository {
        async fn count_templates(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_templates(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<crate::repository::template_repository::TemplateSummary>, AstralError>
        {
            Ok(vec![])
        }

        async fn get_template(
            &self,
            _template_id: &str,
        ) -> Result<crate::repository::template_repository::TemplateSummary, AstralError> {
            unimplemented!()
        }

        async fn create_template(
            &self,
            _template_id: &str,
            _rules: &[TemplateRuleInput],
            _context: &RuleSetMutationContext,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn update_template(
            &self,
            _template_id: &str,
            _rules: &[TemplateRuleInput],
            _context: &RuleSetMutationContext,
        ) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_template_rules(
            &self,
            _template_id: &str,
        ) -> Result<Vec<crate::repository::template_repository::TemplateRuleRecord>, AstralError>
        {
            Ok(vec![])
        }

        async fn sync_template_projection(
            &self,
            _template_id: &str,
            _context: &RuleSetMutationContext,
        ) -> Result<usize, AstralError> {
            Ok(*self.synced_cards.lock().unwrap())
        }

        async fn create_template_rule(
            &self,
            _template_id: &str,
            _rule: &TemplateRuleInput,
            _context: &RuleSetMutationContext,
        ) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn update_template_rule(
            &self,
            _rule_id: i64,
            _effect: Option<&str>,
            _resource: Option<&str>,
            _action: Option<&str>,
            _context: &RuleSetMutationContext,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn get_template_rule(
            &self,
            _rule_id: i64,
        ) -> Result<Option<crate::repository::template_repository::TemplateRuleRecord>, AstralError>
        {
            Ok(None)
        }

        async fn delete_template_rule(
            &self,
            _rule_id: i64,
            _context: &RuleSetMutationContext,
        ) -> Result<bool, AstralError> {
            Ok(false)
        }

        async fn compliance_overview(
            &self,
        ) -> Result<crate::repository::template_repository::ComplianceData, AstralError> {
            Ok(Default::default())
        }

        async fn compliance_report(&self) -> Result<(i64, i64, Option<f64>), AstralError> {
            Ok((0, 0, None))
        }
    }

    #[tokio::test]
    async fn sync_template_reports_transactional_card_fanout() {
        let repo = Arc::new(FakeTemplateRepository {
            synced_cards: Mutex::new(3),
        });
        let svc = TemplateService::new(repo);

        let context = RuleSetMutationContext::system("test:template-sync").unwrap();
        let outcome = svc.sync_template("__SUPERADMIN__", &context).await.unwrap();
        assert_eq!(outcome.total_cards, 3);
        assert_eq!(outcome.synced, 3);
    }
}
