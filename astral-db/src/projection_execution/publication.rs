use sqlx::{MySql, Transaction};

use super::transitions::{clear_owned_lane_in_tx, lock_owned_lane_in_tx};
use super::OwnedDeltaLease;
use crate::{
    AuthorizationProjectionError, DeltaProjectorPublishCommand, DeltaProjectorPublishOutcome,
};

/// Publish under the exact live aggregate capability and clear its slot atomically.
pub async fn project_owned_authorization_delta_in_tx(
    tx: &mut Transaction<'_, MySql>,
    command: &DeltaProjectorPublishCommand,
    lease: &OwnedDeltaLease,
) -> Result<DeltaProjectorPublishOutcome, AuthorizationProjectionError> {
    if lease.identity() != &command.delta_lease_identity
        || lease.aggregate_identity() != &command.expectation.identity
        || lease.operation_id() != command.expectation.operation_id
        || lease.identity().event_id != command.expectation.event_id
    {
        return Err(AuthorizationProjectionError::IdentityMismatch(
            "code=projection_execution.publication_capability_mismatch".to_owned(),
        ));
    }
    if !lock_owned_lane_in_tx(tx, lease).await? {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=projection_execution.publication_lane_lost".to_owned(),
        ));
    }
    let outcome =
        crate::authorization_projection_repository::project_delta_core_in_tx(tx, command, lease)
            .await?;
    if !clear_owned_lane_in_tx(tx, lease).await? {
        return Err(AuthorizationProjectionError::LeaseCasFailed(
            "code=projection_execution.publication_slot_clear_failed".to_owned(),
        ));
    }
    Ok(outcome)
}
