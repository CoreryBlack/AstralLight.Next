//! V6 repository adapter over the validated memory mirror.

use std::sync::Arc;
use std::time::Duration;

use astral_types::{
    AuthorizationFenceProof, CertifiedAuthorizationState, PolicyContext,
    PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use policy_engine::{AuthorizationFenceProvider, PublishedEvidenceReadMode};
use sqlx::MySqlPool;

use super::{memory_projection_hub, MemoryEvidenceOutcome};

/// 内存镜像装饰器：只有显式注入全局 authority provider 后，才允许命中
/// certified-memory 热路径；未注入 provider 时完全绕过 hub，继续使用 inner
/// 的严格 durable reader。provider 负责证明签名/信任根，PolicyEngine 负责
/// 每次请求的 F0/F1 独立 nonce、内容绑定和 frontier 对账。
pub struct MemoryMirroredRuleRepository<R> {
    inner: R,
    refill_pool: Option<MySqlPool>,
    authority_provider: Option<Arc<dyn AuthorizationFenceProvider>>,
}

impl<R> MemoryMirroredRuleRepository<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            refill_pool: None,
            authority_provider: None,
        }
    }

    /// Enable commit-proven strict refills on memory misses.
    pub fn with_durable_refill(mut self, pool: MySqlPool) -> Self {
        self.refill_pool = Some(pool);
        self
    }

    /// Opt into the certified-memory path. This is deliberately explicit: a
    /// local hub without a real global authority provider never becomes an
    /// authorization source merely because it contains a durable-looking state.
    pub fn with_authority_provider(
        mut self,
        provider: Arc<dyn AuthorizationFenceProvider>,
    ) -> Self {
        self.authority_provider = Some(provider);
        self
    }

    /// Optional runtime wiring. `None` preserves the durable-only path.
    pub fn with_authority_provider_opt(
        self,
        provider: Option<Arc<dyn AuthorizationFenceProvider>>,
    ) -> Self {
        match provider {
            Some(provider) => self.with_authority_provider(provider),
            None => self,
        }
    }

    fn certified_memory_enabled(&self) -> bool {
        self.authority_provider.is_some()
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
}

#[async_trait::async_trait]
impl<R> policy_engine::RuleRepository for MemoryMirroredRuleRepository<R>
where
    R: policy_engine::RuleRepository + Send + Sync,
{
    async fn check_card_active(
        &self,
        ctx: &PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        self.strict_authority_read(self.inner.check_card_active(ctx))
            .await
    }

    async fn is_active_global_admin(
        &self,
        user_id: i64,
    ) -> Result<bool, astral_types::PolicyError> {
        // GlobalAdmin is itself a positive authorization prerequisite. Until the
        // auxiliary mirror has a certified authority provider, keep this port on
        // the durable owner and never treat a local epoch/TTL as global proof.
        self.strict_authority_read(self.inner.is_active_global_admin(user_id))
            .await
    }

    /// Positive-authorization readiness gate, fail-closed by construction.
    ///
    /// - Provider present: this wrapper's certified-memory path may only become
    ///   ready once the reconciliation supervisor has proven the node
    ///   `SERVING`; the inner's own readiness contract still applies on top.
    /// - Provider absent: this wrapper never serves certified memory
    ///   (`published_evidence_read_mode` stays `DurableOnly`), so it must not
    ///   turn the trait's permissive default into readiness on its own.
    ///   Readiness is explicitly the inner's established authority contract:
    ///   a strict inner (`SqlxRuleRepository` default, authority-required)
    ///   without a provider reports not-ready and stays denied, while an
    ///   explicitly configured DurableOnly inner
    ///   (`with_authority_required(false)`) remains ready. There is no other
    ///   safe signal that separates a strict inner from a DurableOnly-mode
    ///   inner (both report `DurableOnly` without their own provider), so the
    ///   inner's readiness contract is the only admissible source of truth
    ///   here and configured DurableOnly repositories are not denied.
    fn positive_authorization_ready(&self) -> bool {
        match &self.authority_provider {
            Some(_) => {
                memory_projection_hub().is_some_and(|hub| {
                    hub.authority_state() == astral_types::AuthorizationAuthorityState::Serving
                }) && self.inner.positive_authorization_ready()
            }
            None => self.inner.positive_authorization_ready(),
        }
    }

    fn published_evidence_read_mode(&self) -> PublishedEvidenceReadMode {
        if self.certified_memory_enabled() {
            PublishedEvidenceReadMode::CertifiedMemory
        } else {
            PublishedEvidenceReadMode::DurableOnly
        }
    }

    async fn read_authorization_fence(
        &self,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
        if let Some(hub) = memory_projection_hub() {
            hub.begin_authority_fence_sync()
                .map_err(astral_types::PolicyError::Repository)?;
        }
        match &self.authority_provider {
            Some(provider) => {
                match provider
                    .read_authorization_fence(scope, request_nonce)
                    .await
                {
                    Ok(proof) => Ok(proof),
                    Err(error) => {
                        if let Some(hub) = memory_projection_hub() {
                            hub.mark_authority_pending(error.to_string());
                        }
                        Err(error)
                    }
                }
            }
            None => {
                self.inner
                    .read_authorization_fence(scope, request_nonce)
                    .await
            }
        }
    }

    async fn read_request_authorization_fence(
        &self,
        context: &PolicyContext,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
        let result = match &self.authority_provider {
            Some(provider) => {
                provider
                    .read_request_authorization_fence(context, scope, request_nonce)
                    .await
            }
            None => {
                self.inner
                    .read_request_authorization_fence(context, scope, request_nonce)
                    .await
            }
        };
        if let Err(error) = &result {
            if let Some(hub) = memory_projection_hub() {
                hub.mark_authority_pending(error.to_string());
            }
        }
        result
    }

    async fn read_org_authorization_fence(
        &self,
        context: &PolicyContext,
        evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
        match &self.authority_provider {
            Some(provider) => {
                provider
                    .read_org_authorization_fence(context, evidence, request_nonce)
                    .await
            }
            None => {
                self.inner
                    .read_org_authorization_fence(context, evidence, request_nonce)
                    .await
            }
        }
    }

    fn certify_authorization_evidence(
        &self,
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        scope: &PublishedCardEvidenceScope,
        now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, astral_types::PolicyError> {
        let certified = match &self.authority_provider {
            Some(provider) => {
                provider.certify_authorization_evidence(proof, evidence, scope, now_seconds)?
            }
            None => {
                return self.inner.certify_authorization_evidence(
                    proof,
                    evidence,
                    scope,
                    now_seconds,
                );
            }
        };
        if let Some(hub) = memory_projection_hub() {
            hub.install_certified_authorization_state(scope, certified.clone())
                .map_err(astral_types::PolicyError::Repository)?;
            // Certification only installs the scope root. The reconciliation
            // supervisor owns the durable/transport health half and is the only
            // caller allowed to advance the node to SERVING.
        }
        Ok(certified)
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, astral_types::PolicyError> {
        // A hub hit is usable only after the caller explicitly installed a
        // provider capable of certifying the returned evidence. Without that
        // capability, the old memory shortcut is disabled entirely.
        if self.certified_memory_enabled() {
            if let Some(hub) = memory_projection_hub() {
                if let MemoryEvidenceOutcome::Serve(evidence) =
                    hub.try_certified_memory_evidence(scope)
                {
                    return Ok(Some(evidence));
                }
                if let Some(pool) = &self.refill_pool {
                    return hub.strict_refill(pool, scope).await.map(Some);
                }
            }
        }
        self.strict_authority_read(self.inner.load_published_card_authorization(scope))
            .await
    }

    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<policy_engine::org_admission::OrgAuthorityRead, astral_types::PolicyError> {
        // ORG_SCOPE is a positive admission prerequisite. The existing auxiliary
        // mirror has only local epoch semantics, so it remains disabled here until
        // it can consume the same certified global fence as card evidence.
        self.strict_authority_read(self.inner.load_org_authorization(ctx))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_cache::CachedPublishedEvidenceRuleRepository;
    use crate::repository::SqlxRuleRepository;
    use policy_engine::RuleRepository;

    /// Fail-closed test provider: the readiness tests below only observe the
    /// synchronous readiness/read-mode conclusions, so the fence/certify ports
    /// stay explicitly unavailable — the test never pretends to own a trust
    /// root.
    struct NeverAuthorizingProvider;

    #[async_trait::async_trait]
    impl AuthorizationFenceProvider for NeverAuthorizingProvider {
        async fn read_authorization_fence(
            &self,
            _scope: &PublishedCardEvidenceScope,
            _request_nonce: &str,
        ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
            Err(astral_types::PolicyError::Repository(
                "test provider never issues fence proofs".to_owned(),
            ))
        }

        fn certify_authorization_evidence(
            &self,
            _proof: AuthorizationFenceProof,
            _evidence: Arc<PublishedCardAuthorization>,
            _scope: &PublishedCardEvidenceScope,
            _now_seconds: i64,
        ) -> Result<CertifiedAuthorizationState, astral_types::PolicyError> {
            Err(astral_types::PolicyError::Repository(
                "test provider never certifies evidence".to_owned(),
            ))
        }
    }

    fn test_pool() -> MySqlPool {
        MySqlPool::connect_lazy("mysql://unused@localhost/unused").unwrap()
    }

    /// A strict inner (`SqlxRuleRepository` default: authority-required, no
    /// provider) must not become positive-authorization ready through this
    /// wrapper, in isolation or in the production assembly shape
    /// `MemoryMirrored(CachedPublished(Sqlx))`. The wrapper's own
    /// certified-memory path stays off without a provider, so readiness is
    /// exactly the inner's established authority contract.
    #[tokio::test]
    async fn memory_mirror_keeps_strict_providerless_inner_not_ready() {
        let pool = test_pool();
        let strict_inner = SqlxRuleRepository::new(pool.clone());
        assert!(!strict_inner.positive_authorization_ready());

        let mirrored = MemoryMirroredRuleRepository::new(strict_inner);
        assert!(!mirrored.positive_authorization_ready());
        assert_eq!(
            mirrored.published_evidence_read_mode(),
            PublishedEvidenceReadMode::DurableOnly
        );

        // Production chain shape: the cache wrapper in the middle must not
        // reintroduce the trait's permissive default either.
        let chained =
            MemoryMirroredRuleRepository::new(CachedPublishedEvidenceRuleRepository::new(
                SqlxRuleRepository::new(pool.clone()),
                pool.clone(),
            ));
        assert!(!chained.positive_authorization_ready());
        assert_eq!(
            chained.published_evidence_read_mode(),
            PublishedEvidenceReadMode::DurableOnly
        );
    }

    /// An explicitly configured DurableOnly inner
    /// (`with_authority_required(false)`, the established compatibility
    /// contract) remains ready through this wrapper without a provider, and
    /// the configured repositories are not accidentally denied. Read mode
    /// stays `DurableOnly` because this wrapper never serves certified memory
    /// on its own.
    #[tokio::test]
    async fn memory_mirror_keeps_durable_only_inner_ready_without_provider() {
        let pool = test_pool();
        let durable_only_inner =
            SqlxRuleRepository::new(pool.clone()).with_authority_required(false);
        assert!(durable_only_inner.positive_authorization_ready());

        let mirrored = MemoryMirroredRuleRepository::new(durable_only_inner);
        assert!(mirrored.positive_authorization_ready());
        assert_eq!(
            mirrored.published_evidence_read_mode(),
            PublishedEvidenceReadMode::DurableOnly
        );

        // Production chain shape: the cache wrapper must not deny a configured
        // DurableOnly repository either.
        let chained =
            MemoryMirroredRuleRepository::new(CachedPublishedEvidenceRuleRepository::new(
                SqlxRuleRepository::new(pool.clone()).with_authority_required(false),
                pool.clone(),
            ));
        assert!(chained.positive_authorization_ready());
        assert_eq!(
            chained.published_evidence_read_mode(),
            PublishedEvidenceReadMode::DurableOnly
        );
    }

    /// With a provider wired, readiness additionally requires the node to be
    /// proven `SERVING` by the reconciliation supervisor. The astral-db lib
    /// test binary at most installs the global hub in `Warming`
    /// (`global_install_is_first_wins`); it is never `SERVING`, so this
    /// assertion is deterministic: even an inner that reports ready under the
    /// DurableOnly contract stays not-ready until the runtime owner proves
    /// serving.
    #[tokio::test]
    async fn memory_mirror_with_provider_stays_not_ready_until_hub_serving() {
        let pool = test_pool();
        let durable_only_inner = SqlxRuleRepository::new(pool).with_authority_required(false);
        let mirrored = MemoryMirroredRuleRepository::new(durable_only_inner)
            .with_authority_provider(Arc::new(NeverAuthorizingProvider));
        assert_eq!(
            mirrored.published_evidence_read_mode(),
            PublishedEvidenceReadMode::CertifiedMemory
        );
        assert!(!mirrored.positive_authorization_ready());
    }
}
