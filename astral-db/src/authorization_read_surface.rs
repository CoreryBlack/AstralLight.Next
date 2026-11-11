//! Startup-frozen authorization read surfaces.
//!
//! The surface is the only composition point for policy authorization reads. It
//! keeps profile selection out of request handlers while preserving the durable
//! owners for sessions, mutations, audit, and cold data.

use std::sync::{Arc, OnceLock};

use astral_common::config::AuthorizationReadProfile;
use astral_types::{
    DomainScopeRequirement, PolicyContext, PolicyDecision, PolicyError, PublishedCardEvidenceScope,
};
use policy_engine::{PolicyEngine, PolicyEvaluation};
use sqlx::MySqlPool;
use time::OffsetDateTime;

use crate::{
    certified_memory_authority::{CertifiedMemoryReadToken, CertifiedMemoryStore},
    CachedPublishedEvidenceRuleRepository, CertifiedMemoryProofRepository,
    CertifiedMemorySodRepository, CertifiedOwnershipRequest, MemoryMirroredRuleRepository,
    ResourceOwnershipResolution, SodCheckResult, SqlxAuthorizationFenceProvider,
    SqlxRuleRepository,
};

pub(crate) fn invalidate_certified_store(store: &CertifiedMemoryStore) {
    if let Err(error) = store.mark_unknown() {
        tracing::error!(%error, "certified-memory invalidation failed");
    }
}

pub struct AuthorizationReadRequest {
    surface: Arc<AuthorizationReadSurface>,
    token: Option<CertifiedMemoryReadToken>,
}

impl AuthorizationReadRequest {
    pub async fn resolve_ownership(
        &self,
        resource: &str,
        path: &str,
        method: &str,
        query_target_id: Option<i64>,
        actor_card_id: Option<i64>,
        actor_user_id: Option<i64>,
    ) -> ResourceOwnershipResolution {
        match self.surface.as_ref() {
            AuthorizationReadSurface::Durable { pool, .. }
            | AuthorizationReadSurface::DbBackedMirror { pool, .. } => {
                crate::resolve_resource_ownership(
                    pool,
                    resource,
                    path,
                    method,
                    query_target_id,
                    actor_card_id,
                    actor_user_id,
                )
                .await
            }
            AuthorizationReadSurface::CertifiedMemory(repository) => {
                let Some(token) = self.token.as_ref() else {
                    return ResourceOwnershipResolution::Unavailable {
                        code: "resource_ownership.certified_memory_token_missing",
                    };
                };
                let request = CertifiedOwnershipRequest {
                    resource: resource.to_owned(),
                    path: path.to_owned(),
                    method: method.to_owned(),
                    query_target_id,
                    actor_card_id,
                    actor_user_id,
                    now_unix: OffsetDateTime::now_utc().unix_timestamp(),
                };
                crate::resolve_resource_ownership_certified_with_token(
                    &repository.certified_store(),
                    &request,
                    token,
                )
                .unwrap_or(ResourceOwnershipResolution::Unavailable {
                    code: "resource_ownership.certified_memory_unavailable",
                })
            }
        }
    }

    pub async fn evaluate_with_admission(
        &self,
        engine: &PolicyEngine,
        context: &PolicyContext,
    ) -> PolicyEvaluation {
        match self.surface.as_ref() {
            AuthorizationReadSurface::Durable { repository, .. } => {
                engine.evaluate_with_admission(context, repository).await
            }
            AuthorizationReadSurface::DbBackedMirror { repository, .. } => {
                engine.evaluate_with_admission(context, repository).await
            }
            AuthorizationReadSurface::CertifiedMemory(repository) => {
                let Some(token) = self.token.as_ref() else {
                    return PolicyEvaluation::without_admission(
                        policy_engine::PolicyEngine::authorization_pending(
                            "certified_memory.request_token_missing",
                        ),
                    );
                };
                let repository = repository.with_request_token(token.clone());
                engine.evaluate_with_admission(context, &repository).await
            }
        }
    }

    pub async fn check_sod(
        &self,
        context: &PolicyContext,
        decision: &PolicyDecision,
    ) -> Result<SodCheckResult, PolicyError> {
        match self.surface.as_ref() {
            AuthorizationReadSurface::Durable { pool, .. }
            | AuthorizationReadSurface::DbBackedMirror { pool, .. } => {
                let result = match crate::load_org_sod_admission_mirrored(pool, context, decision)
                    .await
                    .map_err(|error| PolicyError::Repository(error.to_string()))?
                {
                    Some(admission) => {
                        crate::check_sod_conflict_with_context_and_org(
                            pool,
                            context,
                            &admission,
                            context.resource_owner_id,
                        )
                        .await
                    }
                    None => {
                        crate::check_sod_conflict_with_context(
                            pool,
                            context,
                            context.resource_owner_id,
                        )
                        .await
                    }
                };
                result.map_err(|error| PolicyError::Repository(error.to_string()))
            }
            AuthorizationReadSurface::CertifiedMemory(repository) => {
                let token = self.token.as_ref().ok_or_else(|| {
                    PolicyError::Repository("certified_memory.request_token_missing".to_owned())
                })?;
                let sod = CertifiedMemorySodRepository::with_read_token(
                    repository.certified_store(),
                    token.clone(),
                );
                let scope = PublishedCardEvidenceScope {
                    tenant_id: context.tenant_id.ok_or_else(|| {
                        PolicyError::Repository("certified_memory.sod_context_missing".to_owned())
                    })?,
                    card_id: context.card_id.ok_or_else(|| {
                        PolicyError::Repository("certified_memory.sod_context_missing".to_owned())
                    })?,
                    user_filter: None,
                    domain: DomainScopeRequirement::Unconstrained,
                };
                let org_contributions = if decision.org_provenance.is_some() {
                    let admission = sod.load_org_admission(context, decision)?;
                    Some(
                        crate::collect_org_sod_contributions(context, &admission)
                            .map_err(|error| PolicyError::Repository(error.to_string()))?,
                    )
                } else {
                    None
                };
                let read_set = sod.load_read_set(&scope)?;
                crate::evaluate_certified_sod(
                    crate::CertifiedSodInput {
                        policies: read_set.policies,
                        evidence: read_set.evidence.as_ref().clone(),
                        org_contributions,
                    },
                    context,
                    context.resource_owner_id,
                )
            }
        }
    }

    /// Reject certified-memory mutations until the request token is fenced
    /// through the transaction's proven COMMIT on every source owner.
    pub fn ensure_mutation_commit_fence(&self) -> Result<(), PolicyError> {
        ensure_mutation_commit_fence_for_profile(self.surface.profile())
    }

    pub fn ensure_current(&self) -> Result<(), PolicyError> {
        match (self.surface.as_ref(), self.token.as_ref()) {
            (AuthorizationReadSurface::CertifiedMemory(repository), Some(token)) => repository
                .certified_store()
                .validate_read_token(token, OffsetDateTime::now_utc().unix_timestamp())
                .map_err(|error| {
                    PolicyError::Repository(format!(
                        "certified_memory.request_token_failed;{error}"
                    ))
                }),
            (AuthorizationReadSurface::CertifiedMemory(_), None) => Err(PolicyError::Repository(
                "certified_memory.request_token_missing".to_owned(),
            )),
            _ => Ok(()),
        }
    }
}

fn ensure_mutation_commit_fence_for_profile(
    profile: AuthorizationReadProfile,
) -> Result<(), PolicyError> {
    match profile {
        AuthorizationReadProfile::CertifiedMemory => Err(PolicyError::Repository(
            "certified_memory.mutation_commit_fence_unavailable".to_owned(),
        )),
        AuthorizationReadProfile::Durable | AuthorizationReadProfile::DbBackedMirror => Ok(()),
        AuthorizationReadProfile::SingleNodeMemory => Err(PolicyError::Repository(
            "single_node_memory.root_not_installed".to_owned(),
        )),
    }
}

///
/// Each variant owns its concrete repository so the generic `PolicyEngine`
/// entry point remains available without a dynamic repository object. The
/// request path only borrows this already-frozen value.
pub enum AuthorizationReadSurface {
    Durable {
        repository: CachedPublishedEvidenceRuleRepository<SqlxRuleRepository>,
        pool: MySqlPool,
    },
    DbBackedMirror {
        repository:
            MemoryMirroredRuleRepository<CachedPublishedEvidenceRuleRepository<SqlxRuleRepository>>,
        pool: MySqlPool,
    },
    CertifiedMemory(CertifiedMemoryProofRepository<SqlxAuthorizationFenceProvider>),
}

impl AuthorizationReadSurface {
    /// Close certified positive reads when a required runtime owner or
    /// transport fails. Durable and mirror profiles have their own gates.
    pub(crate) fn invalidate_certified_memory(&self) {
        if let Self::CertifiedMemory(repository) = self {
            invalidate_certified_store(&repository.certified_store());
        }
    }

    pub const fn profile(&self) -> AuthorizationReadProfile {
        match self {
            Self::Durable { .. } => AuthorizationReadProfile::Durable,
            Self::DbBackedMirror { .. } => AuthorizationReadProfile::DbBackedMirror,
            Self::CertifiedMemory(_) => AuthorizationReadProfile::CertifiedMemory,
        }
    }

    pub const fn is_certified_memory(&self) -> bool {
        matches!(self, Self::CertifiedMemory(_))
    }

    /// Construct one surface from startup-frozen inputs.
    ///
    /// `CertifiedMemory` deliberately requires both a verified authority
    /// provider and a currently-serving certified store. Missing either input is
    /// a startup error; it never silently selects the mirror or SQL path.
    pub fn build(
        profile: AuthorizationReadProfile,
        pool: MySqlPool,
        org_scope_enabled: bool,
        authority_required: bool,
        authority_provider: Option<Arc<SqlxAuthorizationFenceProvider>>,
        certified_store: Option<Arc<CertifiedMemoryStore>>,
    ) -> Result<Self, String> {
        let sql = || {
            SqlxRuleRepository::new(pool.clone())
                .with_org_scope_enabled(org_scope_enabled)
                .with_authority_provider_opt(authority_provider.clone())
                .with_authority_required(authority_required)
        };

        match profile {
            AuthorizationReadProfile::Durable => Ok(Self::Durable {
                repository: CachedPublishedEvidenceRuleRepository::new(sql(), pool.clone()),
                pool,
            }),
            AuthorizationReadProfile::DbBackedMirror => {
                let inner = CachedPublishedEvidenceRuleRepository::new(sql(), pool.clone());
                let mirror = MemoryMirroredRuleRepository::new(inner)
                    .with_authority_provider_opt(authority_provider.clone().map(|provider| {
                        provider as Arc<dyn policy_engine::AuthorizationFenceProvider>
                    }))
                    .with_durable_refill(pool.clone());
                Ok(Self::DbBackedMirror {
                    repository: mirror,
                    pool,
                })
            }
            AuthorizationReadProfile::CertifiedMemory => {
                let provider = authority_provider.ok_or_else(|| {
                    "certified-memory authorization surface requires an authority provider"
                        .to_owned()
                })?;
                let store = certified_store.ok_or_else(|| {
                    "certified-memory authorization surface requires a certified memory store"
                        .to_owned()
                })?;
                store
                    .begin_read(OffsetDateTime::now_utc().unix_timestamp())
                    .map_err(|error| format!("certified-memory store is not serving: {error:?}"))?;
                Ok(Self::CertifiedMemory(CertifiedMemoryProofRepository::new(
                    store, provider,
                )))
            }
            AuthorizationReadProfile::SingleNodeMemory => Err(
                "single-node-memory authorization surface requires an installed local root"
                    .to_owned(),
            ),
        }
    }

    pub fn begin_request(self: &Arc<Self>) -> Result<AuthorizationReadRequest, PolicyError> {
        let token = match self.as_ref() {
            Self::CertifiedMemory(repository) => Some(
                repository
                    .certified_store()
                    .begin_read(OffsetDateTime::now_utc().unix_timestamp())
                    .map_err(|error| {
                        PolicyError::Repository(format!(
                            "certified_memory.request_begin_failed;{error}"
                        ))
                    })?,
            ),
            Self::Durable { .. } | Self::DbBackedMirror { .. } => None,
        };
        Ok(AuthorizationReadRequest {
            surface: Arc::clone(self),
            token,
        })
    }

    pub async fn evaluate_with_admission(
        &self,
        engine: &PolicyEngine,
        context: &PolicyContext,
    ) -> PolicyEvaluation {
        match self {
            Self::Durable { repository, .. } => {
                engine.evaluate_with_admission(context, repository).await
            }
            Self::DbBackedMirror { repository, .. } => {
                engine.evaluate_with_admission(context, repository).await
            }
            Self::CertifiedMemory(_) => PolicyEvaluation::without_admission(
                policy_engine::PolicyEngine::authorization_pending(
                    "certified_memory.request_token_missing",
                ),
            ),
        }
    }

    pub async fn resolve_ownership(
        &self,
        resource: &str,
        path: &str,
        method: &str,
        query_target_id: Option<i64>,
        actor_card_id: Option<i64>,
        actor_user_id: Option<i64>,
    ) -> ResourceOwnershipResolution {
        match self {
            Self::Durable { pool, .. } | Self::DbBackedMirror { pool, .. } => {
                crate::resolve_resource_ownership(
                    pool,
                    resource,
                    path,
                    method,
                    query_target_id,
                    actor_card_id,
                    actor_user_id,
                )
                .await
            }
            Self::CertifiedMemory(_) => ResourceOwnershipResolution::Unavailable {
                code: "resource_ownership.certified_memory_token_missing",
            },
        }
    }

    pub async fn check_sod(
        &self,
        context: &PolicyContext,
        decision: &PolicyDecision,
    ) -> Result<SodCheckResult, PolicyError> {
        match self {
            Self::Durable { pool, .. } | Self::DbBackedMirror { pool, .. } => {
                let result = match crate::load_org_sod_admission_mirrored(pool, context, decision)
                    .await
                    .map_err(|error| PolicyError::Repository(error.to_string()))?
                {
                    Some(admission) => {
                        crate::check_sod_conflict_with_context_and_org(
                            pool,
                            context,
                            &admission,
                            context.resource_owner_id,
                        )
                        .await
                    }
                    None => {
                        crate::check_sod_conflict_with_context(
                            pool,
                            context,
                            context.resource_owner_id,
                        )
                        .await
                    }
                };
                result.map_err(|error| PolicyError::Repository(error.to_string()))
            }
            Self::CertifiedMemory(_) => Err(PolicyError::Repository(
                "certified_memory.request_token_missing".to_owned(),
            )),
        }
    }

    pub fn positive_authorization_ready(&self) -> bool {
        match self {
            Self::Durable { repository, .. } => {
                policy_engine::RuleRepository::positive_authorization_ready(repository)
            }
            Self::DbBackedMirror { repository, .. } => {
                policy_engine::RuleRepository::positive_authorization_ready(repository)
            }
            Self::CertifiedMemory(repository) => {
                policy_engine::RuleRepository::positive_authorization_ready(repository)
            }
        }
    }
}

static AUTHORIZATION_READ_SURFACE: OnceLock<Arc<AuthorizationReadSurface>> = OnceLock::new();

/// Install the surface once per process and return the canonical instance.
///
/// A composite single-node process may let Identity and TrustGraph race to
/// install the same startup profile. The first owner wins; later callers reuse
/// that immutable instance rather than replacing it mid-flight.
pub fn install_authorization_read_surface(
    surface: Arc<AuthorizationReadSurface>,
) -> Arc<AuthorizationReadSurface> {
    Arc::clone(AUTHORIZATION_READ_SURFACE.get_or_init(|| surface))
}

pub fn authorization_read_surface() -> Option<Arc<AuthorizationReadSurface>> {
    AUTHORIZATION_READ_SURFACE.get().cloned()
}

/// Install or reuse the process-frozen surface when one exists. Once a process selects a
/// profile, a later runtime may only reuse that profile; it cannot silently
/// replace it or downgrade to SQL/mirror.
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
mod mutation_fence_tests {
    use super::*;

    #[test]
    fn certified_memory_mutation_requires_commit_fence() {
        assert!(ensure_mutation_commit_fence_for_profile(
            AuthorizationReadProfile::CertifiedMemory
        )
        .is_err());
        assert!(
            ensure_mutation_commit_fence_for_profile(AuthorizationReadProfile::Durable).is_ok()
        );
        assert!(
            ensure_mutation_commit_fence_for_profile(AuthorizationReadProfile::DbBackedMirror)
                .is_ok()
        );
    }
}
