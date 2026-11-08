//! Published authorization evidence and identity read ports.
//!
//! Every repository implementation must provide the current strict read path.
//! There are no permissive defaults: missing identity, ORG_SCOPE, global-admin,
//! or published-evidence checks must be represented by an explicit fail-closed
//! result from the authoritative owner.

use std::sync::Arc;

use astral_types::{
    AuthorizationFenceProof, CertifiedAuthorizationState, PolicyContext, PolicyError,
    PublishedCardAuthorization, PublishedCardEvidenceScope,
};

use crate::org_admission::OrgAuthorityRead;

/// Published-evidence read mode selected by the repository owner.
///
/// `DurableOnly` keeps the existing strict source/pointer double-read path. A
/// repository may select `CertifiedMemory` only when its memory adapter is
/// backed by a real authority-fence provider and can certify every evidence
/// object before it becomes a positive authorization input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishedEvidenceReadMode {
    DurableOnly,
    CertifiedMemory,
}

/// Authority provider owned by the global authorization authority.
///
/// Implementations must authenticate the returned proof against their fixed
/// trust root before returning it. The policy engine still binds the proof to
/// the exact evidence content through `certify_authorization_evidence`; a
/// local heartbeat, cache entry, or transport ACK is not an implementation.
#[async_trait::async_trait]
pub trait AuthorizationFenceProvider: Send + Sync {
    async fn read_authorization_fence(
        &self,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError>;

    /// Authenticate an administrative publication and membership identity against
    /// the same global authority. The conservative default never authorizes ORG
    /// evidence through a card publication certificate.
    /// Bind a fresh card proof to the immutable verified policy request. Existing
    /// diagnostic providers retain their scope-only port; production providers
    /// override this method and persist the request binding at the authority.
    async fn read_request_authorization_fence(
        &self,
        _context: &PolicyContext,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        self.read_authorization_fence(scope, request_nonce).await
    }

    async fn read_org_authorization_fence(
        &self,
        _context: &PolicyContext,
        _evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(PolicyError::Repository(
            "organization authorization fence provider is unavailable".to_owned(),
        ))
    }

    fn certify_authorization_evidence(
        &self,
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        scope: &PublishedCardEvidenceScope,
        now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError>;
}

/// Authoritative read ports consumed by `PolicyEngine::evaluate`.
#[async_trait::async_trait]
pub trait RuleRepository: Send + Sync {
    /// Verify the selected user-card context against authoritative identity facts.
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError>;

    /// Fresh server-side GlobalAdmin proof for resolver-classified control-plane requests.
    /// Implementations must query the authoritative source, never a client role or stale cache.
    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError>;

    /// Select the published-evidence path. The conservative default is the
    /// durable path; memory-serving adapters must explicitly opt into
    /// `CertifiedMemory` after wiring an authority-fence provider.
    fn published_evidence_read_mode(&self) -> PublishedEvidenceReadMode {
        PublishedEvidenceReadMode::DurableOnly
    }

    /// Whether this repository's certified-memory path has completed the node-level
    /// authority reconciliation required before a positive ALLOW can be returned.
    /// Durable repositories may remain ready by default; a local memory adapter
    /// must override this until `COLD -> WARMING -> FENCE_SYNCING -> SERVING` is
    /// proven by the runtime owner.
    fn positive_authorization_ready(&self) -> bool {
        true
    }

    /// A current authority proof for one exact evidence scope. Implementations
    /// must issue a fresh proof for every call; local heartbeat or cache state
    /// is not a proof of the global frontier.
    async fn read_authorization_fence(
        &self,
        _scope: &PublishedCardEvidenceScope,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(PolicyError::Repository(
            "global authorization fence provider is unavailable".to_owned(),
        ))
    }

    /// Bind a fresh card proof to the immutable verified policy request. Existing
    /// diagnostic providers retain their scope-only port; production providers
    /// override this method and persist the request binding at the authority.
    async fn read_request_authorization_fence(
        &self,
        _context: &PolicyContext,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        self.read_authorization_fence(scope, request_nonce).await
    }

    async fn read_org_authorization_fence(
        &self,
        _context: &PolicyContext,
        _evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(PolicyError::Repository(
            "organization authorization fence provider is unavailable".to_owned(),
        ))
    }

    /// Verify the proof's trust root and bind it to the complete evidence. The
    /// default is fail-closed so a certified-memory adapter cannot be assembled
    /// accidentally from an unverified signature or a bare content hash.
    fn certify_authorization_evidence(
        &self,
        _proof: AuthorizationFenceProof,
        _evidence: Arc<PublishedCardAuthorization>,
        _scope: &PublishedCardEvidenceScope,
        _now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError> {
        Err(PolicyError::Repository(
            "authorization evidence certifier is unavailable".to_owned(),
        ))
    }

    /// `Ok(None)`, errors, malformed data, or non-Ready evidence never authorize.
    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, PolicyError>;

    /// Resolve the authoritative ORG_SCOPE state for the request.
    /// `Unmanaged` is valid only when the owner has established that the tenant is
    /// outside durable ORG_SCOPE management; it is not a permissive default.
    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError>;
}
