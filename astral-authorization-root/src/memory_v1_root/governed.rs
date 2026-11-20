//! memory—v1: Reserve and prepare one exact serving-root successor for the durable owner.

use std::sync::{Arc, MutexGuard, TryLockError};

use crate::memory_v1_db_rows::{BinaryId, Table, UserCardStatus};
use crate::memory_v1_fence::{FenceDeclaration, FenceGuard};
use crate::memory_v1_session_authority::MemoryV1SessionAuthority;

use super::{
    CandidateError, GovernanceFrontier, GovernancePrefix, ManagementMutationV2, MutationError,
    PreparedSnapshot, ProductionAdmission, RootError, RootMetadata, RootOwner, RootSnapshot,
    RuntimeError,
};

/// memory—v1: An unpublished successor and its exclusive serving write reservation.
/// The composition owner must not publish it until the matching journal record is durable.
#[must_use]
pub struct PreparedGovernedMutation<'a> {
    owner: &'a RootOwner,
    before: Arc<RootSnapshot>,
    next: PreparedSnapshot<'a>,
    disable: Option<(&'a MemoryV1SessionAuthority, BinaryId)>,
    fence: Option<(BinaryId, FenceGuard)>,
    _reservation: MutexGuard<'a, ()>,
}

impl RootOwner {
    /// memory—v1: Reserve the live root observed by the admitted request and prepare its
    /// exact successor. Its facts remain private until publication; an owned
    /// Fence advertises the window for an existing rule set. The session
    /// authority is required only for card disable.
    pub fn prepare_governed_mutation<'a>(
        &'a self,
        admission: &ProductionAdmission,
        expected: &RootMetadata,
        mutation: &ManagementMutationV2,
        session_authority: Option<&'a MemoryV1SessionAuthority>,
    ) -> Result<PreparedGovernedMutation<'a>, MutationError> {
        if matches!(mutation, ManagementMutationV2::ContextLoad { .. }) {
            return Err(MutationError::ContextLoadNotGovernable);
        }
        let runtime = &self.runtime;
        let reservation = runtime
            .serving_writer
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => MutationError::ConcurrentModification,
                TryLockError::Poisoned(_) => MutationError::Runtime(RuntimeError::Poisoned),
            })?;
        let before = {
            let _guard = runtime
                .mutation_lock
                .read()
                .map_err(|_| MutationError::Runtime(RuntimeError::Poisoned))?;
            let live =
                self.validate_production_admission(admission)
                    .map_err(|error| match error {
                        RootError::ProductionAdmissionMismatch => {
                            MutationError::ConcurrentModification
                        }
                        _ => MutationError::Runtime(RuntimeError::OwnerGone),
                    })?;
            if &live != expected {
                return Err(MutationError::ConcurrentModification);
            }
            if live.version == u64::MAX {
                return Err(MutationError::VersionOverflow);
            }
            runtime.current.load_full()
        };
        let disable = match mutation {
            ManagementMutationV2::UserCardStatus {
                user_card_id,
                status: UserCardStatus::Disabled,
            } => {
                let authority =
                    session_authority
                        .filter(|authority| {
                            runtime.session_authority.get().is_some_and(|bound| {
                                Arc::ptr_eq(bound, authority.authority_token())
                            }) && authority.can_coordinate_disable()
                        })
                        .ok_or(MutationError::CardDisableRequiresSessionCoordinator)?;
                Some((authority, *user_card_id))
            }
            _ => None,
        };
        let fence = Self::governed_fence_target(&before, mutation)?
            .map(|rule_set_id| {
                let selected = before
                    .objects
                    .selected_version(rule_set_id)
                    .map_err(MutationError::Candidate)?
                    .ok_or(MutationError::ConcurrentModification)?;
                let guard = self.begin_owned_modification_fence(
                    rule_set_id,
                    &FenceDeclaration {
                        rule_set_version: selected.version_bytes.clone(),
                        root_version: expected.version,
                        digest: expected.digest,
                    },
                )?;
                Ok::<_, MutationError>((rule_set_id, guard))
            })
            .transpose()?;
        let next = Self::prepare_mutation_snapshot(runtime, &before, mutation)?;
        Ok(PreparedGovernedMutation {
            owner: self,
            before,
            next,
            disable,
            fence,
            _reservation: reservation,
        })
    }

    // memory—v1: Existing rule-set modifications are fenced. A creation has
    // no served version or dependencies to suspend. Confirmation IDs are
    // resolved from the exact predecessor, not from a caller-supplied target.
    pub(super) fn governed_fence_target(
        before: &RootSnapshot,
        mutation: &ManagementMutationV2,
    ) -> Result<Option<BinaryId>, MutationError> {
        match mutation {
            ManagementMutationV2::VersionPublish { rule_set_id, .. }
            | ManagementMutationV2::RuleSetRetire { rule_set_id } => Ok(Some(*rule_set_id)),
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id, ..
            } => before
                .objects
                .change_confirmation(*confirmation_id)
                .map(|row| Some(row.rule_set_id))
                .ok_or(MutationError::Candidate(CandidateError::UnknownId {
                    table: Table::RuleSetChangeConfirmation,
                    id: *confirmation_id,
                })),
            _ => Ok(None),
        }
    }
}

impl PreparedGovernedMutation<'_> {
    /// memory—v1: Publish the prevalidated successor against the very same root observation.
    /// Keep the registry guard and write reservation through CAS. A card disable holds the
    /// session writer before the root writer so neither stale credentials nor a lock cycle
    /// can be introduced by the commit.
    /// memory—v1: Read the governance frontier of the exact prepared predecessor.
    pub fn predecessor_frontier(&self) -> GovernanceFrontier {
        self.before.frontier
    }

    /// memory—v1: The composition may attach only the successive, verified
    /// journal boundary to this exact successor. The proof is checked by the
    /// composition against the durable receipt before calling this method.
    pub fn publish_with_prefix(
        &self,
        prefix: GovernancePrefix,
    ) -> Result<RootMetadata, MutationError> {
        if !prefix.follows(self.before.frontier) {
            return Err(MutationError::ConcurrentModification);
        }
        self.publish_snapshot(Arc::new(RootSnapshot {
            frontier: GovernanceFrontier::Published(prefix),
            ..self.next.snapshot.as_ref().clone()
        }))
    }

    pub fn publish(&self) -> Result<RootMetadata, MutationError> {
        self.publish_snapshot(Arc::clone(&self.next.snapshot))
    }

    // memory—v1: Keep the same root/registry/fence/session order for both callers.
    fn publish_snapshot(&self, snapshot: Arc<RootSnapshot>) -> Result<RootMetadata, MutationError> {
        let runtime = &self.owner.runtime;
        let publish = || {
            let _guard = runtime
                .mutation_lock
                .write()
                .map_err(|_| MutationError::Runtime(RuntimeError::Poisoned))?;
            let live = runtime.current.load_full();
            if !Arc::ptr_eq(&live, &self.before) {
                return Err(MutationError::ConcurrentModification);
            }
            if let Some((rule_set_id, fence)) = &self.fence {
                runtime.fences.verify_guard(*rule_set_id, fence)?;
            }
            RootOwner::publish_mutation_snapshot(runtime, &self.before, snapshot)
        };
        if let Some((authority, card)) = self.disable {
            authority.publish_card_disable(card, publish)
        } else {
            publish()
        }
    }

    /// memory—v1: Once the journal outcome is unknown, withdraw positive
    /// admission before the fence and reservation are released. Recovery must
    /// establish a new serving root from the durable prefix.
    pub fn require_reconciliation(&self) {
        let runtime = &self.owner.runtime;
        let _guard = runtime
            .mutation_lock
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = runtime.current.load_full();
        RootOwner::publish_invalid_snapshot(runtime, &current);
    }
}
