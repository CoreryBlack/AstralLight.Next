//! Frozen execution mode and aggregate-owned authorization projection capabilities.

use std::sync::OnceLock;

use crate::{
    ClaimedDeltaEvent, DeltaEventClaim, DeltaLeaseIdentity, DeltaLeaseToken,
    ProjectionAggregateIdentity,
};

mod claims;
mod completion;
mod publication;
mod schema;
mod transitions;

pub use claims::{
    claim_next_owned_delta_event, claim_next_owned_delta_event_in_partition,
    claim_owned_delta_event_by_stable_event,
};
pub use completion::{
    load_owned_delta_completion, OwnedCompletionIdentity, OwnedDeltaCompletionProof,
};
pub use publication::project_owned_authorization_delta_in_tx;
pub use schema::validate_projection_owned_schema;
pub use transitions::{
    begin_owned_delta_execution, extend_owned_delta_execution_lease, fail_owned_delta_event,
    load_owned_claimed_delta_event, owned_delta_lease_is_retired,
    owned_execution_outcome_is_unknown, quarantine_owned_delta_event, release_owned_delta_event,
};

static PROJECTION_EXECUTION_MODE: OnceLock<ProjectionExecutionMode> = OnceLock::new();

/// Process-wide ownership protocol, frozen before connecting workers or serving requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionExecutionMode {
    /// Compatibility path with request-side publication and event leases.
    LegacyHybrid,
    /// Only workers execute, under an aggregate capability and active-event slot.
    WorkerOwned,
}

impl ProjectionExecutionMode {
    fn from_environment_value(value: Option<&str>) -> Result<Self, ProjectionExecutionModeError> {
        match value {
            None | Some("legacy-hybrid") => Ok(Self::LegacyHybrid),
            Some("worker-owned") => Ok(Self::WorkerOwned),
            Some(_) => Err(ProjectionExecutionModeError::InvalidEnvironment),
        }
    }
}

/// Invalid or conflicting execution-mode configuration; startup must stop.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionExecutionModeError {
    /// Another value was already frozen in this process.
    #[error("projection execution mode is already frozen to a different value")]
    AlreadyFrozen,
    /// Configuration values are exact and must not be silently normalized.
    #[error("invalid ASTRAL_PROJECTION_EXECUTION_MODE; expected legacy-hybrid or worker-owned")]
    InvalidEnvironment,
}

fn freeze_mode(
    cell: &OnceLock<ProjectionExecutionMode>,
    mode: ProjectionExecutionMode,
) -> Result<ProjectionExecutionMode, ProjectionExecutionModeError> {
    let frozen = *cell.get_or_init(|| mode);
    if frozen == mode {
        Ok(frozen)
    } else {
        Err(ProjectionExecutionModeError::AlreadyFrozen)
    }
}

/// Freeze configuration only; schema validation happens after connection and before execution.
pub fn freeze_projection_execution_mode(
    mode: ProjectionExecutionMode,
) -> Result<ProjectionExecutionMode, ProjectionExecutionModeError> {
    freeze_mode(&PROJECTION_EXECUTION_MODE, mode)
}

/// Read the frozen mode. Unconfigured library callers retain the default compatibility path.
pub fn projection_execution_mode() -> ProjectionExecutionMode {
    PROJECTION_EXECUTION_MODE
        .get()
        .copied()
        .unwrap_or(ProjectionExecutionMode::LegacyHybrid)
}

/// Parse and freeze the startup environment. Unknown and non-Unicode values are refused.
pub fn freeze_projection_execution_mode_from_env(
) -> Result<ProjectionExecutionMode, ProjectionExecutionModeError> {
    let value = match std::env::var("ASTRAL_PROJECTION_EXECUTION_MODE") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ProjectionExecutionModeError::InvalidEnvironment);
        }
    };
    freeze_projection_execution_mode(ProjectionExecutionMode::from_environment_value(
        value.as_deref(),
    )?)
}

/// Exact committed-receipt claim outcome. Admission alone never proves publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedStableEventOutcome {
    /// Both aggregate capability and event lease were installed in one transaction.
    Claimed(Box<OwnedDeltaClaim>),
    /// A completed event was found; callers still need its full durable completion proof.
    AlreadyProcessed {
        /// Immutable event identity.
        event_id: String,
    },
    /// The aggregate, predecessor, event lease, or retry schedule is not claimable.
    Busy {
        /// Immutable event identity.
        event_id: String,
    },
    /// Operator intervention or a separately proven recovery action is required.
    TerminalGated {
        /// Immutable event identity.
        event_id: String,
        /// Durable status that prevented a claim.
        status: String,
    },
    /// An earlier execution outcome cannot yet be safely replayed.
    InDoubt {
        /// Immutable event identity.
        event_id: String,
        /// Non-secret reconciliation reason.
        reason: String,
    },
}

/// One exact event paired with its opaque aggregate-owned execution capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedDeltaClaim {
    /// Installed event lease and immutable event identity.
    pub claim: DeltaEventClaim,
    /// Strict durable readback used as the compilation input.
    pub event: ClaimedDeltaEvent,
    /// Aggregate epoch, token and active-slot capability.
    pub lease: OwnedDeltaLease,
}

/// Unforgeable outside this module; event tokens alone cannot authorize owned publication.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedDeltaLease {
    lane_identity: ProjectionAggregateIdentity,
    lane_epoch: i64,
    lane_owner: String,
    lane_token: DeltaLeaseToken,
    active_event_id: String,
    operation_id: String,
    event_identity: DeltaLeaseIdentity,
    execution_failures: u32,
}

impl OwnedDeltaLease {
    pub(super) fn from_owned_claim(
        lane_identity: ProjectionAggregateIdentity,
        lane_epoch: i64,
        lane_token: DeltaLeaseToken,
        claim: &DeltaEventClaim,
        execution_failures: u32,
    ) -> Result<Self, crate::GrantRepositoryError> {
        if lane_epoch <= 0
            || lane_identity.tenant_id != claim.tenant_id
            || lane_identity.aggregate_type != claim.aggregate_type
            || lane_identity.aggregate_id != claim.aggregate_id
            || claim.delta_event_id <= 0
            || claim.event_id.is_empty()
            || claim.operation_id.is_empty()
            || claim.lease_owner.is_empty()
        {
            return Err(crate::GrantRepositoryError::ScopeViolation(
                "code=projection_execution.claim_lane_binding_mismatch".to_owned(),
            ));
        }
        Ok(Self {
            lane_identity,
            lane_epoch,
            lane_owner: claim.lease_owner.clone(),
            lane_token,
            active_event_id: claim.event_id.clone(),
            operation_id: claim.operation_id.clone(),
            event_identity: DeltaLeaseIdentity {
                delta_event_id: claim.delta_event_id,
                event_id: claim.event_id.clone(),
                lease_owner: claim.lease_owner.clone(),
                lease_token: claim.lease_token.clone(),
            },
            execution_failures,
        })
    }

    /// Exact live event identity; its token remains redacted in diagnostic output.
    pub fn identity(&self) -> &DeltaLeaseIdentity {
        &self.event_identity
    }

    /// Source operation correlated with this exact contribution event.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Authoritative persisted failure count observed when claiming this episode.
    pub fn execution_failures(&self) -> u32 {
        self.execution_failures
    }

    /// Tenant-bound aggregate sharing one current pointer and publication owner.
    pub fn aggregate_identity(&self) -> &ProjectionAggregateIdentity {
        &self.lane_identity
    }

    /// Monotonic ownership episode, distinct from the publication generation.
    pub fn ownership_epoch(&self) -> i64 {
        self.lane_epoch
    }
}

impl std::fmt::Debug for OwnedDeltaLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedDeltaLease")
            .field("lane_identity", &self.lane_identity)
            .field("lane_epoch", &self.lane_epoch)
            .field("lane_owner", &self.lane_owner)
            .field("active_event_id", &self.active_event_id)
            .field("operation_id", &self.operation_id)
            .field("event_identity", &self.event_identity)
            .field("execution_failures", &self.execution_failures)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_mode_is_default_off_and_strictly_parsed() {
        for (value, expected) in [
            (None, ProjectionExecutionMode::LegacyHybrid),
            (Some("legacy-hybrid"), ProjectionExecutionMode::LegacyHybrid),
            (Some("worker-owned"), ProjectionExecutionMode::WorkerOwned),
        ] {
            assert_eq!(
                ProjectionExecutionMode::from_environment_value(value),
                Ok(expected)
            );
        }
        for value in ["", "true", "WORKER-OWNED", "worker-owned ", " worker-owned"] {
            assert_eq!(
                ProjectionExecutionMode::from_environment_value(Some(value)),
                Err(ProjectionExecutionModeError::InvalidEnvironment)
            );
        }
    }

    #[test]
    fn mode_freeze_is_idempotent_and_rejects_in_process_switching() {
        let cell = OnceLock::new();
        assert_eq!(
            freeze_mode(&cell, ProjectionExecutionMode::WorkerOwned),
            Ok(ProjectionExecutionMode::WorkerOwned)
        );
        assert_eq!(
            freeze_mode(&cell, ProjectionExecutionMode::WorkerOwned),
            Ok(ProjectionExecutionMode::WorkerOwned)
        );
        assert_eq!(
            freeze_mode(&cell, ProjectionExecutionMode::LegacyHybrid),
            Err(ProjectionExecutionModeError::AlreadyFrozen)
        );
        assert_eq!(cell.get(), Some(&ProjectionExecutionMode::WorkerOwned));
    }
}
