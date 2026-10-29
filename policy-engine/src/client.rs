//! PermissionClient — 策略评估对外接口
//!
//! 组合 `PolicyEngine` + `RuleRepository` + 缓存，提供权限检查公共 API。
//! 业务代码不直接调用 `PolicyEngine`，而是通过本 client 进入。
//!
//! # 创建客户端
//!
//! ```ignore
//! // 使用数据库仓库（需导入 astral-db 中的 SqlxRuleRepository）
//! let repo = SqlxRuleRepository::from_env().await?;
//! let client = PermissionClient::new(repo);
//! ```
//!
//! # 执行权限检查
//!
//! ```ignore
//! let ctx = PolicyContext::builder()
//!     .card_id(Some(42))
//!     .action("read".into())
//!     .resource(Some("learn_subject".into()))
//!     .build();
//!
//! let decision = client.check(ctx).await?;
//! if !decision.allowed {
//!     eprintln!("Access denied: {}", decision.reason);
//! }
//! ```
//!
//! # 批量检查
//!
//! ```ignore
//! let requests = vec![
//!     ("learn_subject".into(), "read".into()),
//!     ("learn_exam".into(), "write".into()),
//! ];
//! let batch = client.batch_check(ctx, &requests).await?;
//! println!("Allowed {}/{}", batch.allowed, batch.total);
//! ```

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use astral_types::{PolicyContext, PolicyDecision, PolicyError};

use crate::engine::{PolicyEngine, RuleRepository};

/// 权限检查客户端
///
/// # 用法
///
/// ```ignore
/// let client = PermissionClient::new(repo);
/// let decision = client.check(ctx).await?;
/// assert!(!decision.allowed); // DEFAULT_DENY
/// ```
pub struct PermissionClient<R: RuleRepository> {
    engine: ArcSwap<PolicyEngine>,
    repo: Arc<R>,
}

/// 批量检查结果
#[derive(Debug, Clone)]
pub struct BatchResult {
    pub total: usize,
    pub allowed: usize,
    pub denied: usize,
    pub decisions: Vec<PolicyDecision>,
    pub elapsed_us: u128,
}

impl<R: RuleRepository> PermissionClient<R> {
    /// 创建新的权限检查客户端
    pub fn new(repo: R) -> Self {
        Self {
            engine: ArcSwap::new(Arc::new(PolicyEngine::new())),
            repo: Arc::new(repo),
        }
    }

    /// 创建并指定引擎实例（用于测试注入 mock）
    pub fn with_engine(repo: R, engine: PolicyEngine) -> Self {
        Self {
            engine: ArcSwap::new(Arc::new(engine)),
            repo: Arc::new(repo),
        }
    }

    /// 执行单次权限检查
    ///
    /// 流程：上下文校验 → 引擎评估 → 审计记录
    pub async fn check(&self, ctx: PolicyContext) -> Result<PolicyDecision, ClientError> {
        // Step 1: 校验上下文
        if ctx.action.is_empty() {
            return Err(ClientError::InvalidContext(
                "action must not be empty".into(),
            ));
        }

        // Step 2: 引擎评估
        let decision = self.engine.load().evaluate(&ctx, self.repo.as_ref()).await;

        // Step 3: 审计记录（如果要求审计）
        if decision.audit_required {
            tracing::info!(
                target = "permission_audit",
                user_id = ?ctx.user_id,
                card_id = ?ctx.card_id,
                resource = ?ctx.resource,
                action = %ctx.action,
                allowed = %decision.allowed,
                reason = %decision.reason,
                "permission_check_audit"
            );
        }

        Ok(decision)
    }

    /// 简化的权限检查（仅返回是否允许）
    pub async fn is_allowed(
        &self,
        resource: &str,
        action: &str,
        ctx: PolicyContext,
    ) -> Result<bool, ClientError> {
        // 浅克隆并覆盖 resource/action
        let merged = PolicyContext {
            resource: Some(resource.to_string()),
            action: action.to_string(),
            ..ctx
        };
        let decision = self.check(merged).await?;
        Ok(decision.allowed)
    }

    /// 批量检查（多个资源/动作，同上下文）
    pub async fn batch_check(
        &self,
        ctx: PolicyContext,
        requests: &[(String, String)], // (resource, action) 对
    ) -> Result<BatchResult, ClientError> {
        let start = Instant::now();
        let mut decisions = Vec::with_capacity(requests.len());
        let mut allowed = 0usize;
        let mut denied = 0usize;

        for (resource, action) in requests {
            let req_ctx = PolicyContext {
                resource: Some(resource.clone()),
                action: action.clone(),
                ..ctx.clone()
            };
            let decision = self.check(req_ctx).await?;
            if decision.allowed {
                allowed += 1;
            } else {
                denied += 1;
            }
            decisions.push(decision);
        }

        let elapsed_us = start.elapsed().as_micros();
        Ok(BatchResult {
            total: requests.len(),
            allowed,
            denied,
            decisions,
            elapsed_us,
        })
    }

    /// 热更新引擎配置（运行时替换）
    pub fn update_engine(&self, engine: PolicyEngine) {
        self.engine.store(Arc::new(engine));
    }
}

/// 客户端错误
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Invalid permission context: {0}")]
    InvalidContext(String),

    #[error("Permission evaluation failed: {0}")]
    Evaluation(String),

    #[error("Repository error: {0}")]
    Repository(String),
}

impl From<PolicyError> for ClientError {
    fn from(e: PolicyError) -> Self {
        ClientError::Evaluation(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org_admission::OrgAuthorityRead;

    /// The client facade must preserve the strict evaluator's fail-closed behavior.
    struct MockRepo {
        card_active: bool,
    }

    #[async_trait::async_trait]
    impl RuleRepository for MockRepo {
        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            Ok(self.card_active)
        }

        async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
            Ok(false)
        }

        async fn load_published_card_authorization(
            &self,
            _scope: &astral_types::PublishedCardEvidenceScope,
        ) -> Result<Option<Arc<astral_types::PublishedCardAuthorization>>, PolicyError> {
            Ok(None)
        }

        async fn load_org_authorization(
            &self,
            _ctx: &PolicyContext,
        ) -> Result<OrgAuthorityRead, PolicyError> {
            Ok(OrgAuthorityRead::Unmanaged)
        }
    }

    fn valid_context() -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .tenant_id(Some(7))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build()
    }

    #[tokio::test]
    async fn check_without_current_published_evidence_fails_closed() {
        let client = PermissionClient::new(MockRepo { card_active: true });
        let decision = client.check(valid_context()).await.unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }

    #[tokio::test]
    async fn check_denies_inactive_card_before_reading_evidence() {
        let client = PermissionClient::new(MockRepo { card_active: false });
        let decision = client.check(valid_context()).await.unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "CARD_DISABLED");
    }

    #[tokio::test]
    async fn test_check_invalid_context() {
        let client = PermissionClient::new(MockRepo { card_active: true });
        let ctx = PolicyContext::builder().action(String::new()).build();

        let result = client.check(ctx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClientError::InvalidContext(_)
        ));
    }

    #[tokio::test]
    async fn batch_check_keeps_missing_evidence_fail_closed() {
        let client = PermissionClient::new(MockRepo { card_active: true });
        let requests = vec![
            ("learn_subject".into(), "read".into()),
            ("learn_exam".into(), "write".into()),
            ("audit".into(), "export".into()),
        ];

        let result = client
            .batch_check(valid_context(), &requests)
            .await
            .unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.allowed, 0);
        assert_eq!(result.denied, 3);
        assert!(result.elapsed_us > 0);
    }

    #[tokio::test]
    async fn simple_check_fails_closed_without_published_evidence() {
        let client = PermissionClient::new(MockRepo { card_active: true });
        assert!(!client
            .is_allowed("learn_subject", "read", valid_context())
            .await
            .unwrap());
    }
}
