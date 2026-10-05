//! Final deny-only checks shared by HTTP and remote integration admission.

use astral_db::{
    check_sod_conflict_with_context, check_sod_conflict_with_context_and_org,
    load_org_sod_admission_mirrored, memory_projection_hub, AuthorityReadFence, SodCheckResult,
};
use astral_types::{PolicyContext, PolicyDecision};
use sqlx::MySqlPool;

pub(crate) fn capture_fence() -> Result<Option<AuthorityReadFence>, &'static str> {
    match memory_projection_hub() {
        None => Ok(None),
        Some(hub) => hub
            .capture_authority_fence()
            .map(Some)
            .ok_or("AUTHORIZATION_PENDING"),
    }
}

pub(crate) fn fence_holds(fence: Option<AuthorityReadFence>) -> bool {
    match fence {
        None => memory_projection_hub().is_none(),
        Some(fence) => {
            memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(fence))
        }
    }
}

pub(crate) async fn check_sod(
    db: &MySqlPool,
    ctx: &PolicyContext,
    decision: &PolicyDecision,
) -> Result<SodCheckResult, sqlx::Error> {
    match load_org_sod_admission_mirrored(db, ctx, decision).await? {
        Some(admission) => {
            check_sod_conflict_with_context_and_org(db, ctx, &admission, ctx.resource_owner_id)
                .await
        }
        None => check_sod_conflict_with_context(db, ctx, ctx.resource_owner_id).await,
    }
}
