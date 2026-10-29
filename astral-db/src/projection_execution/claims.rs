use sqlx::MySqlPool;

use super::{
    transitions::{audit_owned_lane_in_tx, commit_owned_transition},
    OwnedDeltaClaim, OwnedStableEventOutcome,
};
use crate::{DeltaEventAppendRequest, DeltaEventClaimScope, GrantRepositoryError};

/// Claim exactly the immutable receipt, installing one aggregate slot atomically.
pub async fn claim_owned_delta_event_by_stable_event(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
    owner: &str,
    lease_seconds: i64,
) -> Result<OwnedStableEventOutcome, GrantRepositoryError> {
    let mut tx = pool.begin().await?;
    let outcome =
        crate::grant_repository::claim_owned_exact_in_tx(&mut tx, request, owner, lease_seconds)
            .await?;
    if let OwnedStableEventOutcome::Claimed(claimed) = &outcome {
        audit_owned_lane_in_tx(&mut tx, &claimed.lease, "CLAIM").await?;
        commit_owned_transition(tx, "CLAIM").await?;
    } else {
        // Busy, binding rejection and observation never install or retain a lane.
        tx.rollback().await?;
    }
    Ok(outcome)
}

/// Recover a bounded durable candidate set through the same exact-claim protocol.
pub async fn claim_next_owned_delta_event(
    pool: &MySqlPool,
    scope: DeltaEventClaimScope,
    owner: &str,
    lease_seconds: i64,
) -> Result<Option<OwnedDeltaClaim>, GrantRepositoryError> {
    claim_next_scoped(pool, scope, None, owner, lease_seconds).await
}

/// Discover within one aggregate while retaining the identical ownership protocol.
pub async fn claim_next_owned_delta_event_in_partition(
    pool: &MySqlPool,
    scope: DeltaEventClaimScope,
    aggregate: &crate::ProjectionAggregateIdentity,
    owner: &str,
    lease_seconds: i64,
) -> Result<Option<OwnedDeltaClaim>, GrantRepositoryError> {
    claim_next_scoped(pool, scope, Some(aggregate), owner, lease_seconds).await
}

async fn claim_next_scoped(
    pool: &MySqlPool,
    scope: DeltaEventClaimScope,
    aggregate: Option<&crate::ProjectionAggregateIdentity>,
    owner: &str,
    lease_seconds: i64,
) -> Result<Option<OwnedDeltaClaim>, GrantRepositoryError> {
    for receipt in crate::grant_repository::owned_candidate_receipts(pool, scope, aggregate).await?
    {
        match claim_owned_delta_event_by_stable_event(pool, &receipt, owner, lease_seconds).await? {
            OwnedStableEventOutcome::Claimed(claimed) => return Ok(Some(*claimed)),
            OwnedStableEventOutcome::AlreadyProcessed { .. }
            | OwnedStableEventOutcome::Busy { .. }
            | OwnedStableEventOutcome::TerminalGated { .. }
            | OwnedStableEventOutcome::InDoubt { .. } => {}
        }
    }
    Ok(None)
}
