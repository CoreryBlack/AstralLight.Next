//! V6 repository adapter over the validated memory mirror.

use std::sync::Arc;
use std::time::Duration;

use astral_types::PublishedCardAuthorization;
use sqlx::MySqlPool;

use super::{memory_projection_hub, MemoryEvidenceOutcome};

/// 内存镜像装饰器：命中 [`MemoryEvidenceOutcome::Serve`] 直接返回与 durable
/// 同源的已验证证据；否则整体回退 `inner`（既有 `CachedPublishedEvidence`
/// /`SqlxRuleRepository` 链）。其余端口全部逐方法转发，语义零改动。
///
/// 辅助授权端口（`load_org_authorization` / `is_active_global_admin`）在
/// hub 健康且辅助镜像已安装（或测试注入）时先问镜像；镜像不适用一律回落
/// `inner`，与既有 DB 链逐字节同语义。default-off：未安装镜像时零行为变化。
pub struct MemoryMirroredRuleRepository<R> {
    inner: R,
    refill_pool: Option<MySqlPool>,
}

impl<R> MemoryMirroredRuleRepository<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            refill_pool: None,
        }
    }

    /// Enable commit-proven strict refills on memory misses.
    pub fn with_durable_refill(mut self, pool: MySqlPool) -> Self {
        self.refill_pool = Some(pool);
        self
    }

    async fn strict_authority_read<T>(
        &self,
        read: impl std::future::Future<Output = Result<T, astral_types::PolicyError>>,
    ) -> Result<T, astral_types::PolicyError> {
        let Some(hub) = memory_projection_hub() else {
            return read.await;
        };
        let token = hub.strict_read_token().ok_or_else(|| {
            astral_types::PolicyError::Repository(
                "source writer or unknown outcome blocks authority read".to_owned(),
            )
        })?;
        let result = tokio::time::timeout(Duration::from_secs(3), read)
            .await
            .map_err(|_| {
                astral_types::PolicyError::Repository("strict authority read timed out".to_owned())
            })?;
        if !hub.strict_read_matches(token) {
            return Err(astral_types::PolicyError::Repository(
                "source mutation raced authority read".to_owned(),
            ));
        }
        result
    }

    fn auxiliary_mirror(
        &self,
    ) -> Option<crate::auxiliary_authorization_mirror::AuxiliaryAuthorizationMirror> {
        crate::auxiliary_authorization_mirror()
    }
}

#[async_trait::async_trait]
impl<R> policy_engine::RuleRepository for MemoryMirroredRuleRepository<R>
where
    R: policy_engine::RuleRepository + Send + Sync,
{
    async fn check_card_active(
        &self,
        ctx: &astral_types::PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        self.strict_authority_read(self.inner.check_card_active(ctx))
            .await
    }

    async fn is_active_global_admin(
        &self,
        user_id: i64,
    ) -> Result<bool, astral_types::PolicyError> {
        // 通道可证明时使用镜像；writer/未知与回填竞争均保持 fail-closed。
        if let (Some(hub), Some(mirror)) = (memory_projection_hub(), self.auxiliary_mirror()) {
            if let Some(result) = mirror.is_active_global_admin(hub, user_id).await {
                return result;
            }
        }
        self.strict_authority_read(self.inner.is_active_global_admin(user_id))
            .await
    }

    async fn load_published_card_authorization(
        &self,
        scope: &astral_types::PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, astral_types::PolicyError> {
        if let Some(hub) = memory_projection_hub() {
            if let MemoryEvidenceOutcome::Serve(evidence) = hub.try_memory_evidence(scope) {
                return Ok(Some(evidence));
            }
            if let Some(pool) = &self.refill_pool {
                return hub.strict_refill(pool, scope).await.map(Some);
            }
        }
        self.strict_authority_read(self.inner.load_published_card_authorization(scope))
            .await
    }

    async fn load_org_authorization(
        &self,
        ctx: &astral_types::PolicyContext,
    ) -> Result<policy_engine::org_admission::OrgAuthorityRead, astral_types::PolicyError> {
        // 严格回源同样需要前后源状态 token；不能绕过活动 writer 或未知提交。
        if let (Some(hub), Some(mirror)) = (memory_projection_hub(), self.auxiliary_mirror()) {
            if let Some(read) = mirror.load_org_authorization(hub, ctx).await {
                return Ok(read);
            }
        }
        self.strict_authority_read(self.inner.load_org_authorization(ctx))
            .await
    }
}
