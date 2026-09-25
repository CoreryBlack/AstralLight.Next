//! 委托编排 — DelegationWriteService
//!
//! 对齐 Java `DelegationService`：创建/撤销/更新委托时同步维护
//! DELEGATION 规则的完整生命周期，并在提交后重建被委托卡的快照。
//! 事务性委托+规则写收口在 `DelegationRepository` 的聚合方法内。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::delegation_repository::{
    validated_expiry_batch_limit, DelegationExpiryOutcome, DelegationMutationContext,
    DelegationRepository, NewDelegation,
};

/// 委托创建结果（handler 组装 DTO 用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateDelegationOutcome {
    pub delegation_id: i64,
    /// true=本次新建；false=命中幂等返回已有委托
    pub created: bool,
}

/// 新建委托请求（过期时间推算在 service 完成）
#[derive(Debug, Clone)]
pub struct CreateDelegationRequest {
    pub delegator_id: i64,
    pub delegate_id: i64,
    pub resource: String,
    pub action: String,
    pub expires_at: Option<String>,
}

/// 更新委托请求
#[derive(Debug, Clone)]
pub struct UpdateDelegationRequest {
    pub resource: String,
    pub action: String,
    pub expires_at: Option<String>,
}

/// 显式有界到期对账批次报告：候选数与各终态/失败计数一一对应；失败项逐条
/// 携带 delegation_id 与错误文本，不中止批次（source 保持不变，由调用方决策
/// 后续动作）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationExpiryBatchReport {
    pub candidates: usize,
    pub reconciled: usize,
    pub already_terminal: usize,
    pub not_yet_due: usize,
    pub failed: Vec<(i64, String)>,
}

/// DelegationWriteService
pub struct DelegationWriteService {
    repo: Arc<dyn DelegationRepository>,
}

impl DelegationWriteService {
    pub fn new(repo: Arc<dyn DelegationRepository>) -> Self {
        Self { repo }
    }

    pub async fn create_delegation(
        &self,
        req: &CreateDelegationRequest,
        context: &DelegationMutationContext,
    ) -> Result<CreateDelegationOutcome, AstralError> {
        let expires_ts = compute_expiry(req.expires_at.as_deref(), now_secs())?;
        let outcome = self
            .repo
            .create_with_rule(
                &NewDelegation {
                    delegator_card_id: req.delegator_id,
                    delegate_card_id: req.delegate_id,
                    resource_type: req.resource.clone(),
                    action_code: req.action.clone(),
                    effective_until_ts: expires_ts,
                },
                context,
            )
            .await?;

        if !outcome.created {
            tracing::info!(
                id = outcome.delegation_id,
                "delegation already exists, returning existing"
            );
        } else {
            tracing::info!(
                delegate_id = %req.delegate_id,
                "delegation created"
            );
        }
        Ok(CreateDelegationOutcome {
            delegation_id: outcome.delegation_id,
            created: outcome.created,
        })
    }

    /// 撤销：委托行读取、ownership/scope 校验和 source mutation 由 repository 单事务完成。
    pub async fn revoke_delegation(
        &self,
        delegation_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<(), AstralError> {
        let outcome = self.repo.revoke_with_rules(delegation_id, context).await?;
        if outcome.changed {
            tracing::warn!(delegation_id, "delegation revoked");
        }
        Ok(())
    }

    /// 更新：实际委托行的 delegator/delegate 只由 repository 的锁定行决定。
    pub async fn update_delegation(
        &self,
        delegation_id: i64,
        req: &UpdateDelegationRequest,
        context: &DelegationMutationContext,
    ) -> Result<(), AstralError> {
        let expires_ts = parse_expiry(req.expires_at.as_deref(), now_secs())?;
        let outcome = self
            .repo
            .update_with_rule(
                delegation_id,
                &req.resource,
                &req.action,
                expires_ts,
                context,
            )
            .await?;
        if outcome.changed {
            tracing::info!(delegation_id, "delegation updated");
        }
        Ok(())
    }

    /// 到期对账（显式有界、幂等）：先有界发现 ACTIVE 且 `effective_until` 已过
    /// 的候选（`batch_limit` 正数且不超过 repository 的显式上限，非法输入
    /// fail-closed），再逐条单事务收敛。没有后台循环/调度器 —— 由 worker/运维
    /// 显式调用。单条失败只计入报告，不影响其余候选；重复执行是幂等 no-op。
    pub async fn reconcile_expired_delegations(
        &self,
        batch_limit: i64,
    ) -> Result<DelegationExpiryBatchReport, AstralError> {
        // 边界校验前置到候选发现之前（与真实仓库单一事实源共享同一判定）。
        let limit = validated_expiry_batch_limit(batch_limit)?;
        let candidates = self.repo.list_expired_active_delegation_ids(limit).await?;
        let mut report = DelegationExpiryBatchReport {
            candidates: candidates.len(),
            ..Default::default()
        };
        for delegation_id in candidates {
            match self.repo.reconcile_expired_delegation(delegation_id).await {
                Ok(DelegationExpiryOutcome::Reconciled { delegate_card_id }) => {
                    report.reconciled += 1;
                    tracing::info!(
                        delegation_id,
                        delegate_card_id,
                        "delegation expiry reconciled"
                    );
                }
                Ok(DelegationExpiryOutcome::AlreadyTerminal) => {
                    report.already_terminal += 1;
                }
                Ok(DelegationExpiryOutcome::NotYetDue) => {
                    report.not_yet_due += 1;
                }
                Err(error) => {
                    tracing::warn!(
                        delegation_id,
                        error = %error,
                        "delegation expiry reconciliation failed; source left unchanged"
                    );
                    report.failed.push((delegation_id, error.to_string()));
                }
            }
        }
        Ok(report)
    }
}

/// 解析过期时间：请求未提供时默认 24 小时后（纯逻辑，可单测）。
pub fn compute_expiry(expires_at: Option<&str>, now_secs: i64) -> Result<i64, AstralError> {
    let expires_at = expires_at
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<i64>().map_err(|_| {
                AstralError::Validation("delegation expiry must be a UNIX timestamp".into())
            })
        })
        .transpose()?;
    let expiry = expires_at.unwrap_or_else(|| now_secs + 24 * 3600);
    if expiry <= now_secs {
        return Err(AstralError::Validation(
            "delegation expiry must be in the future".into(),
        ));
    }
    Ok(expiry)
}

fn parse_expiry(expires_at: Option<&str>, now_secs: i64) -> Result<i64, AstralError> {
    compute_expiry(expires_at, now_secs)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::delegation_repository::{
        DelegationCreateResult, DelegationMutationResult, DelegationRecord, DelegationViewRecord,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    fn context() -> DelegationMutationContext {
        let policy_context = astral_types::PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(1))
            .tenant_id(Some(20))
            .domain_id(Some(30))
            .action("update".into())
            .build();
        DelegationMutationContext::from_policy_context(&policy_context, Some("request-1")).unwrap()
    }

    /// 顺序追踪用 Fake DelegationRepository
    struct FakeDelegationRepository {
        calls: Mutex<Vec<String>>,
        next_id: Mutex<i64>,
        record: Mutex<Option<DelegationRecord>>,
        existing: Mutex<Option<i64>>,
        expiry_candidates: Mutex<Vec<i64>>,
        expiry_outcomes: Mutex<Vec<Result<DelegationExpiryOutcome, AstralError>>>,
    }

    impl FakeDelegationRepository {
        fn new(record: Option<DelegationRecord>, existing: Option<i64>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                next_id: Mutex::new(9),
                record: Mutex::new(record),
                existing: Mutex::new(existing),
                expiry_candidates: Mutex::new(Vec::new()),
                expiry_outcomes: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DelegationRepository for FakeDelegationRepository {
        async fn create_with_rule(
            &self,
            _new: &NewDelegation,
            _context: &DelegationMutationContext,
        ) -> Result<DelegationCreateResult, AstralError> {
            let mut next = self.next_id.lock().unwrap();
            *next += 1;
            let id = *next;
            self.calls
                .lock()
                .unwrap()
                .push(format!("create_with_rule:{id}"));
            if let Some(existing_id) = *self.existing.lock().unwrap() {
                Ok(DelegationCreateResult {
                    delegation_id: existing_id,
                    created: false,
                })
            } else {
                Ok(DelegationCreateResult {
                    delegation_id: id,
                    created: true,
                })
            }
        }

        async fn revoke_with_rules(
            &self,
            delegation_id: i64,
            _context: &DelegationMutationContext,
        ) -> Result<DelegationMutationResult, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("revoke_with_rules:{delegation_id}"));
            let record = self.record.lock().unwrap();
            Ok(DelegationMutationResult {
                changed: record.is_some(),
                delegate_card_id: record.as_ref().map(|record| record.delegate_card_id),
            })
        }

        async fn update_with_rule(
            &self,
            delegation_id: i64,
            _resource: &str,
            _action: &str,
            _expires: i64,
            _context: &DelegationMutationContext,
        ) -> Result<DelegationMutationResult, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("update_with_rule:{delegation_id}"));
            let record = self.record.lock().unwrap();
            Ok(DelegationMutationResult {
                changed: record.is_some(),
                delegate_card_id: record.as_ref().map(|record| record.delegate_card_id),
            })
        }

        async fn list_by_delegator(
            &self,
            _card_id: i64,
            _context: &DelegationMutationContext,
        ) -> Result<Vec<DelegationViewRecord>, AstralError> {
            self.calls.lock().unwrap().push("list_by_delegator".into());
            Ok(vec![])
        }

        async fn list_by_delegate(
            &self,
            _card_id: i64,
            _context: &DelegationMutationContext,
        ) -> Result<Vec<DelegationViewRecord>, AstralError> {
            self.calls.lock().unwrap().push("list_by_delegate".into());
            Ok(vec![])
        }

        async fn list_all(
            &self,
            _context: &DelegationMutationContext,
        ) -> Result<Vec<DelegationViewRecord>, AstralError> {
            self.calls.lock().unwrap().push("list_all".into());
            Ok(vec![])
        }

        async fn reconcile_expired_delegation(
            &self,
            delegation_id: i64,
        ) -> Result<DelegationExpiryOutcome, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("reconcile_expired_delegation:{delegation_id}"));
            let mut outcomes = self.expiry_outcomes.lock().unwrap();
            if outcomes.is_empty() {
                // 默认行为：候选总可收敛（模拟健康 ACTIVE + 已到期聚合）。
                return Ok(DelegationExpiryOutcome::Reconciled {
                    delegate_card_id: 3,
                });
            }
            outcomes.remove(0)
        }

        async fn list_expired_active_delegation_ids(
            &self,
            batch_limit: i64,
        ) -> Result<Vec<i64>, AstralError> {
            // 与真实仓库共享同一边界判定（单一事实源）。
            let limit = validated_expiry_batch_limit(batch_limit)?;
            self.calls
                .lock()
                .unwrap()
                .push(format!("list_expired_active_delegation_ids:{limit}"));
            Ok(self.expiry_candidates.lock().unwrap().clone())
        }
    }

    fn sample_record() -> DelegationRecord {
        DelegationRecord {
            delegation_id: 5,
            delegator_card_id: 1,
            delegate_card_id: 3,
            resource_type: "learn_course".into(),
            action_code: "read".into(),
            effective_from_ts: 1_699_000_000,
            effective_until_ts: Some(1_700_000_000),
            is_revokable: 1,
            status: "ACTIVE".into(),
        }
    }

    fn make_service(fake: Arc<FakeDelegationRepository>) -> DelegationWriteService {
        DelegationWriteService::new(fake)
    }

    #[tokio::test]
    async fn create_returns_existing_when_active() {
        let fake = Arc::new(FakeDelegationRepository::new(None, Some(5)));
        let svc = make_service(fake.clone());

        let outcome = svc
            .create_delegation(
                &CreateDelegationRequest {
                    delegator_id: 1,
                    delegate_id: 3,
                    resource: "learn_course".into(),
                    action: "read".into(),
                    expires_at: None,
                },
                &context(),
            )
            .await
            .unwrap();

        assert!(!outcome.created);
        assert_eq!(outcome.delegation_id, 5);
        assert_eq!(fake.calls(), vec!["create_with_rule:10".to_string()]);
    }

    #[tokio::test]
    async fn create_builds_rule_when_new() {
        let fake = Arc::new(FakeDelegationRepository::new(None, None));
        let svc = make_service(fake.clone());

        let outcome = svc
            .create_delegation(
                &CreateDelegationRequest {
                    delegator_id: 1,
                    delegate_id: 3,
                    resource: "learn_course".into(),
                    action: "read".into(),
                    expires_at: Some("4102444800".into()),
                },
                &context(),
            )
            .await
            .unwrap();

        assert!(outcome.created);
        assert_eq!(outcome.delegation_id, 10);
        assert_eq!(fake.calls(), vec!["create_with_rule:10".to_string()]);
    }

    #[tokio::test]
    async fn revoke_noops_when_delegation_missing() {
        let fake = Arc::new(FakeDelegationRepository::new(None, None));
        let svc = make_service(fake.clone());

        svc.revoke_delegation(5, &context()).await.unwrap();

        assert_eq!(fake.calls(), vec!["revoke_with_rules:5".to_string()]);
    }

    #[tokio::test]
    async fn revoke_cleans_rules_when_present() {
        let fake = Arc::new(FakeDelegationRepository::new(Some(sample_record()), None));
        let svc = make_service(fake.clone());

        svc.revoke_delegation(5, &context()).await.unwrap();

        assert_eq!(fake.calls(), vec!["revoke_with_rules:5".to_string()]);
    }

    #[tokio::test]
    async fn update_syncs_rule_when_present() {
        let fake = Arc::new(FakeDelegationRepository::new(Some(sample_record()), None));
        let svc = make_service(fake.clone());

        svc.update_delegation(
            5,
            &UpdateDelegationRequest {
                resource: "learn_quiz".into(),
                action: "write".into(),
                expires_at: Some("4102444800".into()),
            },
            &context(),
        )
        .await
        .unwrap();

        assert_eq!(fake.calls(), vec!["update_with_rule:5".to_string()]);
    }

    #[tokio::test]
    async fn reconciliation_batch_limit_is_validated_before_any_work() {
        let fake = Arc::new(FakeDelegationRepository::new(None, None));
        let svc = make_service(fake.clone());

        // 非正与超上限一律 fail-closed，绝不降级为“顺便全量扫描”。
        for bad in [0, -3, 501] {
            let error = svc.reconcile_expired_delegations(bad).await.unwrap_err();
            assert!(matches!(error, AstralError::Validation(_)));
        }
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_reports_aggregate_outcomes_and_failures_without_aborting() {
        let fake = Arc::new(FakeDelegationRepository::new(None, None));
        fake.expiry_candidates.lock().unwrap().extend([7, 8, 9, 10]);
        {
            let mut outcomes = fake.expiry_outcomes.lock().unwrap();
            outcomes.push(Ok(DelegationExpiryOutcome::Reconciled {
                delegate_card_id: 3,
            }));
            outcomes.push(Ok(DelegationExpiryOutcome::AlreadyTerminal));
            outcomes.push(Ok(DelegationExpiryOutcome::NotYetDue));
            outcomes.push(Err(AstralError::Validation("drift".into())));
        }
        let svc = make_service(fake.clone());

        let report = svc.reconcile_expired_delegations(50).await.unwrap();

        assert_eq!(report.candidates, 4);
        assert_eq!(report.reconciled, 1);
        assert_eq!(report.already_terminal, 1);
        assert_eq!(report.not_yet_due, 1);
        assert_eq!(
            report.failed,
            vec![(10, "Validation error: drift".to_string())]
        );
        // 显式有界：候选发现 + 每条候选恰好一次单事务收敛；无内部循环重试。
        assert_eq!(
            fake.calls(),
            vec![
                "list_expired_active_delegation_ids:50".to_string(),
                "reconcile_expired_delegation:7".to_string(),
                "reconcile_expired_delegation:8".to_string(),
                "reconcile_expired_delegation:9".to_string(),
                "reconcile_expired_delegation:10".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn reconciliation_repeat_with_no_candidates_is_a_full_noop() {
        let fake = Arc::new(FakeDelegationRepository::new(None, None));
        let svc = make_service(fake.clone());

        let first = svc.reconcile_expired_delegations(10).await.unwrap();
        let second = svc.reconcile_expired_delegations(10).await.unwrap();

        assert_eq!(first, DelegationExpiryBatchReport::default());
        assert_eq!(second, DelegationExpiryBatchReport::default());
        assert_eq!(
            fake.calls(),
            vec![
                "list_expired_active_delegation_ids:10".to_string(),
                "list_expired_active_delegation_ids:10".to_string(),
            ]
        );
    }
}
