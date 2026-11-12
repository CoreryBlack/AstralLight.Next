//! Startup-frozen authorization read surfaces.
//!
//! memory—v1: every V6/V7 read profile (durable SQL, DB-backed mirror,
//! certified memory) has been physically retired from this surface. The
//! `AuthorizationReadSurface` enum is deliberately uninhabited: no value can
//! ever be constructed until the new single-node memory root is installed and
//! a successor request path lands, so the type system itself is the
//! fail-closed boundary. The durable owners for sessions, mutations, audit,
//! and cold data are unchanged.

use std::sync::{Arc, OnceLock};

use astral_common::config::AuthorizationReadProfile;
use astral_types::{PolicyContext, PolicyDecision, PolicyError};
use policy_engine::{PolicyEngine, PolicyEvaluation};
use sqlx::MySqlPool;

use crate::{
    certified_memory_authority::CertifiedMemoryStore, ResourceOwnershipResolution, SodCheckResult,
    SqlxAuthorizationFenceProvider,
};

/// memory—v1: Test the remaining certified store's invalidation behavior.
#[cfg(test)]
pub(crate) fn invalidate_certified_store(store: &CertifiedMemoryStore) {
    if let Err(error) = store.mark_unknown() {
        tracing::error!(%error, "certified-memory invalidation failed");
    }
}

/// memory—v1: Request handle kept only for signature compatibility with
/// callers still wired to the retired read path. It cannot be constructed in
/// production: `begin_request` always refuses and no surface value exists.
pub struct AuthorizationReadRequest {
    _no_installed_root: (),
}

impl AuthorizationReadRequest {
    /// memory—v1: A retired request cannot establish resource ownership.
    pub async fn resolve_ownership(
        &self,
        _resource: &str,
        _path: &str,
        _method: &str,
        _query_target_id: Option<i64>,
        _actor_card_id: Option<i64>,
        _actor_user_id: Option<i64>,
    ) -> ResourceOwnershipResolution {
        ResourceOwnershipResolution::Unavailable {
            code: "legacy_authorization_profile.retired",
        }
    }

    /// memory—v1: A retired request cannot produce positive authorization.
    pub async fn evaluate_with_admission(
        &self,
        _engine: &PolicyEngine,
        _context: &PolicyContext,
    ) -> PolicyEvaluation {
        PolicyEvaluation::without_admission(PolicyEngine::authorization_pending(
            "legacy_authorization_profile.retired",
        ))
    }

    /// memory—v1: A retired request cannot admit separation-of-duty checks.
    pub async fn check_sod(
        &self,
        _context: &PolicyContext,
        _decision: &PolicyDecision,
    ) -> Result<SodCheckResult, PolicyError> {
        Err(PolicyError::Repository(
            "legacy_authorization_profile.retired".to_owned(),
        ))
    }

    /// memory—v1: No request passes the mutation commit fence until the new
    /// root is installed and every source owner proves its COMMIT.
    pub fn ensure_mutation_commit_fence(&self) -> Result<(), PolicyError> {
        Err(PolicyError::Repository(
            "legacy_authorization_profile.retired".to_owned(),
        ))
    }

    /// memory—v1: A retired request never carries a current read token.
    pub fn ensure_current(&self) -> Result<(), PolicyError> {
        Err(PolicyError::Repository(
            "legacy_authorization_profile.retired".to_owned(),
        ))
    }
}

/// memory—v1: The V6/V7 variants (durable SQL, DB-backed mirror, certified
/// memory) have been physically removed. The enum is uninhabited so that no
/// retired read surface can be constructed, not even behind a feature flag.
pub enum AuthorizationReadSurface {}

impl AuthorizationReadSurface {
    /// memory—v1: Nothing can be invalidated; no certified store is installed.
    pub(crate) fn invalidate_certified_memory(&self) {
        match *self {}
    }

    /// memory—v1: No surface exists, hence no profile can be serving.
    pub const fn profile(&self) -> AuthorizationReadProfile {
        match *self {}
    }

    /// memory—v1: No surface exists, hence certified memory is never active.
    pub const fn is_certified_memory(&self) -> bool {
        match *self {}
    }

    /// memory—v1: Every profile is refused until the new root is installed.
    pub fn build(
        _profile: AuthorizationReadProfile,
        _pool: MySqlPool,
        _org_scope_enabled: bool,
        _authority_required: bool,
        _authority_provider: Option<Arc<SqlxAuthorizationFenceProvider>>,
        _certified_store: Option<Arc<CertifiedMemoryStore>>,
    ) -> Result<Self, String> {
        Err("memory-v1 authorization surface requires a verified installed root".to_owned())
    }

    /// memory—v1: A retired surface cannot start an authorization request.
    pub fn begin_request(self: &Arc<Self>) -> Result<AuthorizationReadRequest, PolicyError> {
        Err(PolicyError::Repository(
            "legacy_authorization_profile.retired".to_owned(),
        ))
    }

    /// memory—v1: Direct calls on retired surfaces remain pending.
    pub async fn evaluate_with_admission(
        &self,
        _engine: &PolicyEngine,
        _context: &PolicyContext,
    ) -> PolicyEvaluation {
        PolicyEvaluation::without_admission(PolicyEngine::authorization_pending(
            "legacy_authorization_profile.retired",
        ))
    }

    /// memory—v1: A retired surface cannot establish resource ownership.
    pub async fn resolve_ownership(
        &self,
        _resource: &str,
        _path: &str,
        _method: &str,
        _query_target_id: Option<i64>,
        _actor_card_id: Option<i64>,
        _actor_user_id: Option<i64>,
    ) -> ResourceOwnershipResolution {
        ResourceOwnershipResolution::Unavailable {
            code: "legacy_authorization_profile.retired",
        }
    }

    /// memory—v1: A retired surface cannot admit separation-of-duty checks.
    pub async fn check_sod(
        &self,
        _context: &PolicyContext,
        _decision: &PolicyDecision,
    ) -> Result<SodCheckResult, PolicyError> {
        Err(PolicyError::Repository(
            "legacy_authorization_profile.retired".to_owned(),
        ))
    }

    /// memory—v1: Retired surfaces are never ready for positive authorization.
    pub fn positive_authorization_ready(&self) -> bool {
        false
    }
}

static AUTHORIZATION_READ_SURFACE: OnceLock<Arc<AuthorizationReadSurface>> = OnceLock::new();

/// memory—v1: Direct installation is refused; no surface value can even be
/// built to pass in.
pub fn install_authorization_read_surface(
    _surface: Arc<AuthorizationReadSurface>,
) -> Result<Arc<AuthorizationReadSurface>, String> {
    Err("V6/V7 authorization read surfaces are retired".to_owned())
}

pub fn authorization_read_surface() -> Option<Arc<AuthorizationReadSurface>> {
    AUTHORIZATION_READ_SURFACE.get().cloned()
}

/// Install or reuse the process-frozen surface when one exists. Once a process selects a
/// profile, a later runtime may only reuse that profile; it cannot silently
/// replace it or downgrade to SQL/mirror.
///
/// memory—v1: refused for every profile until the new root is installed.
pub fn ensure_authorization_read_surface(
    profile: AuthorizationReadProfile,
    pool: MySqlPool,
    org_scope_enabled: bool,
    authority_required: bool,
    authority_provider: Option<Arc<SqlxAuthorizationFenceProvider>>,
    certified_store: Option<Arc<CertifiedMemoryStore>>,
) -> Result<Arc<AuthorizationReadSurface>, String> {
    if let Some(existing) = authorization_read_surface() {
        if existing.profile() != profile {
            return Err(format!(
                "authorization read surface profile mismatch: installed={:?}, requested={profile:?}",
                existing.profile()
            ));
        }
        return Ok(existing);
    }
    let surface = build_authorization_read_surface(
        profile,
        pool,
        org_scope_enabled,
        authority_required,
        authority_provider,
        certified_store,
    )?;
    let installed = AUTHORIZATION_READ_SURFACE.get_or_init(|| surface);
    if installed.profile() != profile {
        return Err(format!(
            "authorization read surface profile mismatch after installation: installed={:?}, requested={profile:?}",
            installed.profile()
        ));
    }
    Ok(Arc::clone(installed))
}

/// memory—v1: refused for every profile until the new root is installed.
pub fn build_authorization_read_surface(
    profile: AuthorizationReadProfile,
    pool: MySqlPool,
    org_scope_enabled: bool,
    authority_required: bool,
    authority_provider: Option<Arc<SqlxAuthorizationFenceProvider>>,
    certified_store: Option<Arc<CertifiedMemoryStore>>,
) -> Result<Arc<AuthorizationReadSurface>, String> {
    Ok(Arc::new(AuthorizationReadSurface::build(
        profile,
        pool,
        org_scope_enabled,
        authority_required,
        authority_provider,
        certified_store,
    )?))
}

/// Build a stable repository error for a certified profile whose composition
/// root was not installed. This is used by listener middleware as a 503/PENDING
/// boundary, never as a reason to fall back to a durable mirror.
pub fn certified_surface_unavailable() -> PolicyError {
    PolicyError::Repository("certified_memory.read_surface_unavailable".to_owned())
}

#[cfg(test)]
mod retired_surface_tests {
    use super::*;

    // memory—v1: Construction through every profile and entry point is refused
    // while the new root is not installed.
    #[tokio::test]
    async fn every_profile_construction_is_refused() {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy_with(sqlx::mysql::MySqlConnectOptions::new());
        for profile in [AuthorizationReadProfile::SingleNodeMemory] {
            assert!(AuthorizationReadSurface::build(
                profile,
                pool.clone(),
                false,
                false,
                None,
                None
            )
            .is_err());
            assert!(build_authorization_read_surface(
                profile,
                pool.clone(),
                false,
                false,
                None,
                None
            )
            .is_err());
            assert!(ensure_authorization_read_surface(
                profile,
                pool.clone(),
                false,
                false,
                None,
                None
            )
            .is_err());
        }
        assert!(authorization_read_surface().is_none());
    }

    // memory—v1: A retired request handle (constructible only inside this
    // module) refuses every authorization call.
    #[tokio::test]
    async fn retired_request_refuses_every_authorization_call() {
        let request = AuthorizationReadRequest {
            _no_installed_root: (),
        };
        let context = PolicyContext::builder().action("read".into()).build();
        let evaluation = request
            .evaluate_with_admission(&PolicyEngine::new(), &context)
            .await;

        assert!(!evaluation.decision.allowed);
        assert!(evaluation.admission().is_none());
        assert!(matches!(
            request
                .resolve_ownership("resource", "/", "GET", None, None, None)
                .await,
            ResourceOwnershipResolution::Unavailable { .. }
        ));
        assert!(request
            .check_sod(&context, &evaluation.decision)
            .await
            .is_err());
        assert!(request.ensure_current().is_err());
        assert!(request.ensure_mutation_commit_fence().is_err());
    }
}
