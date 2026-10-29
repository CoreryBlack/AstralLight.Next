//! Published authorization evidence and identity read ports.
//!
//! Every repository implementation must provide the current strict read path.
//! There are no permissive defaults: missing identity, ORG_SCOPE, global-admin,
//! or published-evidence checks must be represented by an explicit fail-closed
//! result from the authoritative owner.

use astral_types::{
    PolicyContext, PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
};

use crate::org_admission::OrgAuthorityRead;

/// Authoritative read ports consumed by `PolicyEngine::evaluate`.
#[async_trait::async_trait]
pub trait RuleRepository: Send + Sync {
    /// Verify the selected user-card context against authoritative identity facts.
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError>;

    /// Fresh server-side GlobalAdmin proof for resolver-classified control-plane requests.
    /// Implementations must query the authoritative source, never a client role or stale cache.
    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError>;

    /// Load the complete CURRENT V6 published authorization evidence for this scope.
    /// `Ok(None)`, errors, malformed data, or non-Ready evidence never authorize.
    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError>;

    /// Resolve the authoritative ORG_SCOPE state for the request.
    /// `Unmanaged` is valid only when the owner has established that the tenant is
    /// outside durable ORG_SCOPE management; it is not a permissive default.
    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError>;
}
