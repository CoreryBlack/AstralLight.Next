//! Strict V6 authorization repository and physical-card validation bridge.

use std::sync::Arc;

use astral_types::org_scope::OrgAdmissionResult;
use astral_types::{
    AuthorizationFenceProof, CertifiedAuthorizationState, PolicyContext,
    PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use policy_engine::{AuthorizationFenceProvider, OrgAuthorityRead, RuleRepository};
use sqlx::MySqlPool;
use time::OffsetDateTime;

use crate::authorization_fence_repository::SqlxAuthorizationFenceProvider;
use crate::eligibility::CardEligibilityService;
use crate::org_scope_repository::{
    probe_org_scope_gate, OrgAdmissionQuery, OrgScopeGateState, OrgScopeRepository,
    SqlxOrgScopeRepository,
};

/// sqlx 实现的 RuleRepository
pub struct SqlxRuleRepository {
    pool: MySqlPool,
    /// Default-off ORG_SCOPE admission switch, frozen by the process that constructs
    /// this repository. A managed tenant remains fail-closed when this is false.
    org_scope_enabled: bool,
    /// Optional authority proof adapter. None keeps the durable evidence read
    /// mode, but Strict readiness still rejects positive authorization until a
    /// verified provider is present.
    authority_provider: Option<Arc<SqlxAuthorizationFenceProvider>>,
    /// Strict deployments cannot silently turn a missing authority provider into
    /// a positive durable-only authorization result.
    authority_required: bool,
}

impl SqlxRuleRepository {
    /// Creates a production repository with ORG_SCOPE admission disabled.
    ///
    /// Call [`Self::with_org_scope_enabled`] only after the hosting process has
    /// parsed its deployment configuration successfully. Keeping the default
    /// disabled means a managed tenant cannot silently use card evidence alone
    /// in a service that has not admitted the organization runtime.
    pub fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            org_scope_enabled: false,
            authority_provider: None,
            authority_required: true,
        }
    }

    /// Freeze whether this repository requires a verified external authority
    /// provider before positive authorization can be returned.
    pub fn with_authority_required(mut self, required: bool) -> Self {
        self.authority_required = required;
        self
    }

    /// Freezes the deployment-approved ORG_SCOPE admission state into this
    /// repository instance. This is deliberately not read from the environment
    /// on each authorization request.
    pub fn with_org_scope_enabled(mut self, enabled: bool) -> Self {
        self.org_scope_enabled = enabled;
        self
    }

    /// Explicitly inject the verifier for the externally issued global authority
    /// proof. This does not create an issuer and is intentionally absent from
    /// `new`, so certified memory remains opt-in.
    pub fn with_authority_provider(
        mut self,
        provider: Arc<SqlxAuthorizationFenceProvider>,
    ) -> Self {
        self.authority_provider = Some(provider);
        self
    }

    /// Optional runtime wiring for the explicitly selected durable-only
    /// compatibility mode. In Strict mode, `None` remains not-ready for
    /// positive authorization; this setter does not create a provider.
    pub fn with_authority_provider_opt(
        self,
        provider: Option<Arc<SqlxAuthorizationFenceProvider>>,
    ) -> Self {
        match provider {
            Some(provider) => self.with_authority_provider(provider),
            None => self,
        }
    }

    pub async fn from_env() -> Result<Self, sqlx::Error> {
        let url = std::env::var("DATABASE_URL").map_err(|_| {
            sqlx::Error::Configuration(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DATABASE_URL is required",
            )))
        })?;
        let pool = crate::connect_configured_pool(&url).await?;
        Ok(Self::new(pool))
    }
}

/// 运行期物理双卡资格校验所需的最小上下文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardActiveContext {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub user_card_tenant_id: i64,
    pub user_card_domain_id: i64,
}

impl CardActiveContext {
    pub(crate) fn is_positive(&self) -> bool {
        self.user_id > 0
            && self.identity_card_id > 0
            && self.user_card_id > 0
            && self.user_card_tenant_id > 0
            && self.user_card_domain_id > 0
    }
}

/// Map the strict published-card evidence error vocabulary onto EXISTING
/// `PolicyError` variants without ever inventing an "empty result" success.
///
/// Every variant keeps a stable family code prefix so callers can classify
/// pending vs. corrupt vs. transport failure from the message alone, while the
/// reader's own `code=published_card_evidence.*` fragments are preserved
/// verbatim for audit correlation. NotReady/Corrupt/Query map onto
/// `Repository` (PENDING/DENY semantics upstream); InvalidRequest is a caller
/// contract fault and maps onto `InvalidContext`.
fn published_card_evidence_error_to_policy_error(
    error: crate::authorization_projection_repository::AuthorizationEvidenceError,
) -> astral_types::PolicyError {
    use crate::authorization_projection_repository::AuthorizationEvidenceError as EvidenceError;
    match error {
        EvidenceError::NotReady(message) => astral_types::PolicyError::Repository(format!(
            "published_card_evidence_not_ready;{message}"
        )),
        EvidenceError::Corrupt(message) => astral_types::PolicyError::Repository(format!(
            "published_card_evidence_corrupt;{message}"
        )),
        EvidenceError::InvalidRequest(message) => astral_types::PolicyError::InvalidContext(
            format!("published_card_evidence_invalid_request;{message}"),
        ),
        EvidenceError::Query(query) => astral_types::PolicyError::Repository(format!(
            "published_card_evidence_query_failed;{query}"
        )),
    }
}

fn unix_now_seconds() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// 运行期物理双卡校验，带时间感知资格缓存（委托 `CardEligibilityService`）。
///
/// PolicyEngine 的 CARD_CONTEXT 只负责校验物理双卡事实；正式授权还必须通过
/// 独立的 V6 published evidence 门禁。此入口不把 ELIGIBILITY head 当作授权
/// proof；资格失效仍由资格缓存与其 source generation 校验处理。
pub async fn check_card_active_cached(
    pool: &MySqlPool,
    context: &CardActiveContext,
) -> Result<bool, astral_types::PolicyError> {
    check_card_active_cached_with_options(pool, context, 300, 60, false).await
}

/// 物理卡校验的可配置入口。Chat 使用更短 TTL 并要求投影 READY；PolicyEngine
/// 使用默认参数，以便由引擎自身返回 AUTHORIZATION_PENDING。
///
/// 投影门禁使用 ELIGIBILITY head（`authorization_projection_head` 中
/// `aggregate_type='ELIGIBILITY'`）；head 缺失或未 READY 时按配置拒绝。
pub async fn check_card_active_cached_with_options(
    pool: &MySqlPool,
    context: &CardActiveContext,
    base_ttl_seconds: u64,
    jitter_max_seconds: u64,
    require_projection_ready: bool,
) -> Result<bool, astral_types::PolicyError> {
    CardEligibilityService::check_cached(
        pool,
        context,
        astral_types::CardEligibilityCheckOptions {
            base_ttl_seconds,
            jitter_max_seconds,
            require_projection_ready,
        },
    )
    .await
}

#[async_trait::async_trait]
impl RuleRepository for SqlxRuleRepository {
    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, astral_types::PolicyError> {
        let (Some(tenant_id), Some(user_id), Some(identity_card_id), Some(card_id)) = (
            ctx.tenant_id,
            ctx.user_id,
            ctx.identity_card_id,
            ctx.card_id,
        ) else {
            return Ok(OrgAuthorityRead::Pending {
                code: "org_scope.pending.context_missing".to_owned(),
            });
        };

        match probe_org_scope_gate(&self.pool, tenant_id).await {
            OrgScopeGateState::SchemaUnmanaged | OrgScopeGateState::TenantUnmanaged => {
                Ok(OrgAuthorityRead::Unmanaged)
            }
            OrgScopeGateState::Pending => Ok(OrgAuthorityRead::Unavailable {
                code: "org_scope.pending.gate_unavailable".to_owned(),
            }),
            OrgScopeGateState::TenantManaged { .. } if !self.org_scope_enabled => {
                Ok(OrgAuthorityRead::Disabled)
            }
            OrgScopeGateState::TenantManaged { .. } => {
                let org_repository = SqlxOrgScopeRepository::new(self.pool.clone());
                let query = OrgAdmissionQuery {
                    tenant_id,
                    user_id,
                    card_id,
                    identity_card_id: Some(identity_card_id),
                    now_unix_seconds: unix_now_seconds(),
                };
                match org_repository.load_admission_evidence(&query).await {
                    Ok(OrgAdmissionResult::Evidence(evidence)) => {
                        Ok(OrgAuthorityRead::Ready(evidence))
                    }
                    Ok(OrgAdmissionResult::Pending { code, .. }) => Ok(OrgAuthorityRead::Pending {
                        code: code.as_machine_code().to_owned(),
                    }),
                    Err(error) => {
                        tracing::warn!(
                            tenant_id,
                            user_id,
                            card_id,
                            error = %error,
                            "org scope evidence read unavailable; failing closed"
                        );
                        Ok(OrgAuthorityRead::Unavailable {
                            code: "org_scope.pending.reader_unavailable".to_owned(),
                        })
                    }
                }
            }
        }
    }

    /// 检查卡片上下文是否有效（含状态/用户/有效期交叉校验）。
    ///
    /// 物理双卡校验与时间感知缓存统一由共享 helper 承担，避免 Chat
    /// WebSocket 和 PolicyEngine 各自维护一套资格 SQL。
    async fn check_card_active(
        &self,
        ctx: &PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        let Some(user_id) = ctx.user_id else {
            return Ok(false);
        };
        let Some(identity_card_id) = ctx.identity_card_id else {
            return Ok(false);
        };
        let Some(user_card_id) = ctx.card_id else {
            return Ok(false);
        };
        let Some(user_card_tenant_id) = ctx.tenant_id else {
            return Ok(false);
        };
        let Some(user_card_domain_id) = ctx.domain_id else {
            return Ok(false);
        };
        check_card_active_cached(
            &self.pool,
            &CardActiveContext {
                user_id,
                identity_card_id,
                user_card_id,
                user_card_tenant_id,
                user_card_domain_id,
            },
        )
        .await
    }

    /// Global control-plane authority is source-of-truth state, not a card
    /// grant or a cached management-scope convenience. This deliberately bypasses
    /// TrustGraph's five-second handler cache so a formal policy decision observes
    /// an ACTIVE row at both the ownership gate and its final ALLOW recheck.
    async fn is_active_global_admin(
        &self,
        user_id: i64,
    ) -> Result<bool, astral_types::PolicyError> {
        if user_id <= 0 {
            return Ok(false);
        }
        crate::is_active_global_admin(&self.pool, user_id)
            .await
            .map_err(|error| {
                astral_types::PolicyError::Repository(format!(
                    "global_admin_gate_query_failed;{error}"
                ))
            })
    }

    fn published_evidence_read_mode(&self) -> policy_engine::PublishedEvidenceReadMode {
        self.authority_provider.as_ref().map_or(
            policy_engine::PublishedEvidenceReadMode::DurableOnly,
            |_| policy_engine::PublishedEvidenceReadMode::CertifiedMemory,
        )
    }

    fn positive_authorization_ready(&self) -> bool {
        if !self.authority_required {
            return true;
        }
        self.authority_provider.is_some()
            && crate::memory_projection_hub::memory_projection_hub()
                .is_some_and(|hub| hub.positive_authorization_ready())
    }

    async fn read_authorization_fence(
        &self,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
        let Some(provider) = &self.authority_provider else {
            return Err(astral_types::PolicyError::Repository(
                "global authorization fence provider is unavailable".to_owned(),
            ));
        };
        provider
            .read_authorization_fence(scope, request_nonce)
            .await
    }

    async fn read_request_authorization_fence(
        &self,
        context: &PolicyContext,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
        let provider = self.authority_provider.as_ref().ok_or_else(|| {
            astral_types::PolicyError::Repository(
                "request authority provider is unavailable".into(),
            )
        })?;
        provider
            .read_request_authorization_fence(context, scope, request_nonce)
            .await
    }

    async fn read_org_authorization_fence(
        &self,
        context: &PolicyContext,
        evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, astral_types::PolicyError> {
        let provider = self.authority_provider.as_ref().ok_or_else(|| {
            astral_types::PolicyError::Repository(
                "organization authorization fence provider is unavailable".to_owned(),
            )
        })?;
        provider
            .read_org_authorization_fence(context, evidence, request_nonce)
            .await
    }

    fn certify_authorization_evidence(
        &self,
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        scope: &PublishedCardEvidenceScope,
        now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, astral_types::PolicyError> {
        let Some(provider) = &self.authority_provider else {
            return Err(astral_types::PolicyError::Repository(
                "authorization evidence certifier is unavailable".to_owned(),
            ));
        };
        provider.certify_authorization_evidence(proof, evidence, scope, now_seconds)
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, astral_types::PolicyError> {
        crate::authorization_projection_repository::load_published_card_grant_evidence(
            &self.pool, scope,
        )
        .await
        .map(|evidence| Some(std::sync::Arc::new(evidence)))
        .map_err(published_card_evidence_error_to_policy_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn strict_repository_with_missing_provider_cannot_serve_positive_authorization() {
        let pool = MySqlPool::connect_lazy("mysql://unused@localhost/unused").unwrap();
        let repository = SqlxRuleRepository::new(pool);

        assert_eq!(
            RuleRepository::published_evidence_read_mode(&repository),
            policy_engine::PublishedEvidenceReadMode::DurableOnly
        );
        assert!(!RuleRepository::positive_authorization_ready(&repository));
    }

    #[tokio::test]
    async fn durable_only_readiness_requires_explicit_opt_in() {
        let pool = MySqlPool::connect_lazy("mysql://unused@localhost/unused").unwrap();
        let repository = SqlxRuleRepository::new(pool).with_authority_required(false);

        assert_eq!(
            RuleRepository::published_evidence_read_mode(&repository),
            policy_engine::PublishedEvidenceReadMode::DurableOnly
        );
        assert!(RuleRepository::positive_authorization_ready(&repository));
    }
    #[test]
    fn published_card_evidence_errors_map_to_explicit_policy_errors() {
        use crate::authorization_projection_repository::AuthorizationEvidenceError;

        let not_ready =
            published_card_evidence_error_to_policy_error(AuthorizationEvidenceError::NotReady(
                "code=published_card_evidence.current_pointer_missing;tenant=7;card=17".into(),
            ));
        match not_ready {
            astral_types::PolicyError::Repository(message) => {
                assert!(message.starts_with("published_card_evidence_not_ready;"));
                assert!(message.contains("code=published_card_evidence.current_pointer_missing"));
            }
            other => panic!("NotReady must map onto Repository, got {other:?}"),
        }

        let corrupt =
            published_card_evidence_error_to_policy_error(AuthorizationEvidenceError::Corrupt(
                "code=published_card_evidence.pointer_moved_under_read".into(),
            ));
        match corrupt {
            astral_types::PolicyError::Repository(message) => {
                assert!(message.starts_with("published_card_evidence_corrupt;"));
                assert!(message.contains("pointer_moved_under_read"));
            }
            other => panic!("Corrupt must map onto Repository, got {other:?}"),
        }

        let invalid_request = published_card_evidence_error_to_policy_error(
            AuthorizationEvidenceError::InvalidRequest(
                "code=published_card_evidence.invalid_scope;detail=x".into(),
            ),
        );
        match invalid_request {
            astral_types::PolicyError::InvalidContext(message) => {
                assert!(message.starts_with("published_card_evidence_invalid_request;"));
                assert!(message.contains("invalid_scope"));
            }
            other => panic!("InvalidRequest must map onto InvalidContext, got {other:?}"),
        }

        let query = published_card_evidence_error_to_policy_error(
            AuthorizationEvidenceError::Query(sqlx::Error::RowNotFound),
        );
        match query {
            astral_types::PolicyError::Repository(message) => {
                assert!(message.starts_with("published_card_evidence_query_failed;"));
            }
            other => panic!("Query failure must map onto Repository, got {other:?}"),
        }
    }

    /// Shape guard: the SqlxRuleRepository published-card port must delegate to
    /// the strict pool reader with the scope forwarded unchanged and every
    /// error mapped explicitly — no legacy snapshot/raw-source/cache fallback
    /// may exist on this path, and successes cannot become an empty collection.
    #[test]
    fn sqlx_published_card_port_delegates_to_strict_reader_without_legacy_fallback() {
        let source = include_str!("authorization.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let body = source
            .split("async fn load_published_card_authorization")
            .nth(1)
            .map(str::trim)
            .expect("published-card port override must exist inside the trait impl");

        for required in [
            "crate::authorization_projection_repository::load_published_card_grant_evidence(",
            "&self.pool",
            "scope",
            ".map(|evidence| Some(std::sync::Arc::new(evidence)))",
            ".map_err(published_card_evidence_error_to_policy_error)",
        ] {
            assert!(
                body.contains(required),
                "published-card port must contain `{required}`"
            );
        }
        for forbidden in [
            "permission_rule_snapshot",
            "rule_set_snapshot",
            "redis_conn",
            "UTC_TIMESTAMP",
        ] {
            assert!(
                !body.contains(forbidden),
                "published-card port must not fall back to legacy cache/snapshot paths ({forbidden})"
            );
        }
    }

    /// The strict pool wrapper owns ONE short transaction with an explicit
    /// commit before returning; the typed result is a whole evidence object,
    /// so an absent current pointer surfaces as an error rather than an empty
    /// authorization set.
    #[test]
    fn strict_pool_reader_commits_explicitly_and_never_returns_empty_success() {
        let source =
            include_str!("../authorization_projection_repository.rs").replace("\r\n", "\n");
        let body = source
            .split("pub async fn load_published_card_grant_evidence(\n    pool")
            .nth(1)
            .and_then(|body| body.split("Bridge from the pure compiler kernel").next())
            .expect("pool-level strict reader must exist");

        // The typed result carries the evidence-error vocabulary directly;
        // transport failures use the declared From<sqlx::Error> conversion.
        assert!(body.contains("-> Result<PublishedCardAuthorization, AuthorizationEvidenceError>"));
        assert!(body.contains("let mut tx = pool.begin().await?;"));
        let begin = body.find("pool.begin()").expect("transaction begin");
        let read = body
            .find("load_published_card_grant_evidence_in_tx(&mut tx, scope)")
            .expect("transaction-scoped reader call");
        let commit = body.find("tx.commit().await?").expect("explicit commit");
        assert!(
            begin < read && read < commit,
            "read must run inside begin..commit"
        );
        // The returned contract is one verified evidence object per scope,
        // not a collection that could degenerate into an empty ALLOW.
        assert!(!body.contains("Ok(vec![") && !body.contains("Ok(Vec::new())"));
    }
}
