//! memory—v1: Prepare an additive snapshot without blocking authorization reads.

use crate::memory_v1_hamt::{ContextDelta, ContextLoadError};
use crate::memory_v1_root_digest::prepare_context_load_digest;

use super::{
    AdoptionGrade, Arc, GovernanceFrontier, ManagementMutationV2, MutationError,
    MutationPrecondition, RootMetadata, RootOwner, RootRuntime, RootSnapshot, RootStatus,
    RuntimeError,
};

#[derive(Clone, Copy)]
pub(super) enum LoadScope {
    Candidate,
    Isolated,
    #[cfg(feature = "test-support")]
    VerifiedColdFixture(RootMetadata),
}

impl RootOwner {
    // memory—v1: Reserve the writer, prepare against one immutable predecessor,
    // and hold the root lock only to check and publish. This primitive is not a
    // source-coverage proof and must not be called by a production read-miss path.
    pub(super) fn execute_context_load(
        runtime: &RootRuntime,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
        scope: LoadScope,
        phase: &mut impl FnMut(&'static str),
    ) -> Result<RootMetadata, MutationError> {
        let ManagementMutationV2::ContextLoad { rows, selections } = mutation else {
            return Err(MutationError::ContextLoadNotGovernable);
        };
        let _reservation = runtime
            .serving_writer
            .try_lock()
            .map_err(|_| MutationError::ConcurrentModification)?;
        let before = runtime.current.load_full();
        match (scope, before.metadata.status) {
            (LoadScope::Candidate | LoadScope::Isolated, RootStatus::Candidate) => {}
            (LoadScope::Isolated, RootStatus::Serving)
                if before
                    .adoption
                    .as_ref()
                    .is_some_and(|record| record.grade == AdoptionGrade::IsolatedTest) => {}
            #[cfg(feature = "test-support")]
            (LoadScope::VerifiedColdFixture(expected), RootStatus::Serving)
                if expected == before.metadata => {}
            #[cfg(feature = "test-support")]
            (LoadScope::VerifiedColdFixture(_), RootStatus::Candidate) => {
                return Err(MutationError::ConcurrentModification)
            }
            (_, RootStatus::Serving) => return Err(MutationError::ConcurrentModification),
            _ => return Err(MutationError::Runtime(RuntimeError::OwnerGone)),
        }
        if before.metadata.version == u64::MAX {
            RootOwner::try_publish_exhausted_snapshot(runtime, &before);
            return Err(MutationError::VersionOverflow);
        }
        if before.metadata.version != precondition.evaluated_root_version {
            return Err(MutationError::ConcurrentModification);
        }
        phase("start_prepare");
        super::capacity::mutation_fits(&before.objects, mutation)
            .map_err(MutationError::Candidate)?;
        let delta =
            ContextDelta::prepare(&before.objects, rows, selections).map_err(
                |error| match error {
                    ContextLoadError::Candidate(error) => MutationError::Candidate(error),
                    ContextLoadError::Conflict(reason) => {
                        MutationError::Runtime(RuntimeError::UnsafeMerge(reason))
                    }
                    ContextLoadError::Digest(error) => {
                        MutationError::Runtime(RuntimeError::Digest(error))
                    }
                },
            )?;
        phase("merge");
        let serving = before.metadata.status == RootStatus::Serving;
        let objects = delta
            .apply(&before.objects, serving)
            .map_err(MutationError::Candidate)?;
        phase("index");
        let digest_index = prepare_context_load_digest(&before.digest_index, &delta, &objects)?;
        phase("digest");
        let (budget, row_count) = objects.budget_and_row_count();
        let next = Arc::new(RootSnapshot {
            metadata: RootMetadata {
                version: before.metadata.version + 1,
                digest: digest_index.digest(),
                budget,
                row_count,
                ..before.metadata
            },
            frontier: match scope {
                #[cfg(feature = "test-support")]
                LoadScope::VerifiedColdFixture(_) => before.frontier,
                _ => GovernanceFrontier::Unproven,
            },
            // Context loading produces no new governance frame. Preserve the
            // published bytes for the writer that is still confirming them.
            reservation: before.reservation.clone(),
            objects,
            digest_index,
            adoption: before.adoption.clone(),
        });
        let (_, selections) = delta.facts();
        let registry_version = if serving && !selections.is_empty() {
            let registry = runtime
                .registry
                .read_for_publication()
                .map_err(MutationError::Registry)?;
            for selection in selections {
                let selected = next
                    .objects
                    .selected_version(selection.rule_set_id)
                    .map_err(MutationError::Candidate)?
                    .ok_or(MutationError::Runtime(RuntimeError::InconsistentCandidate))?;
                let content = crate::memory_v1_rules::parse_version(selected).map_err(|error| {
                    MutationError::Candidate(crate::memory_v1_hamt::CandidateError::RuleIntegrity(
                        error,
                    ))
                })?;
                registry
                    .validate_rules(&content)
                    .map_err(MutationError::Registry)?;
            }
            Some(registry.version())
        } else {
            None
        };
        let affected_rule_sets = delta.affected_rule_sets();
        phase("prepared");
        let guard = runtime
            .mutation_lock
            .write()
            .map_err(|_| MutationError::Runtime(RuntimeError::Poisoned))?;
        phase("lock_acquired");
        let live = runtime.current.load_full();
        if !Arc::ptr_eq(&live, &before) {
            return Err(MutationError::ConcurrentModification);
        }
        // Check the same registry generation under root → registry ordering.
        let registry_guard = if let Some(version) = registry_version {
            let registry = runtime
                .registry
                .try_read_for_publication()
                .map_err(MutationError::Registry)?;
            if registry.version() != version {
                return Err(MutationError::ConcurrentModification);
            }
            Some(registry)
        } else {
            None
        };
        // Fence openers also hold the root read lock; none can open between this check and CAS.
        if serving
            && affected_rule_sets
                .iter()
                .any(|&id| runtime.fences.is_active(id))
        {
            return Err(MutationError::ModificationFenceRequired);
        }
        phase("publish_ready");
        let result = Self::publish_mutation_snapshot(runtime, &before, next);
        phase("cas");
        drop(registry_guard);
        drop(guard);
        phase("lock_released");
        result
    }
}
