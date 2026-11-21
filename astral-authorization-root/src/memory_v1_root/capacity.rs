//! memory—v1: Working-set estimates for private construction, not authorization facts.

use super::ManagementMutationV2 as Mutation;
use crate::memory_v1_db_rows::{
    BindingConfirmationRow, CandidateRows, CurrentSelection, RuleSetChangeConfirmationRow,
    RuleSetVersionRow,
};
use crate::memory_v1_hamt::{CandidateError, HamtCandidate};

// Include HAMT/digest nodes, validation indexes, and simultaneous copies while parsing.
// These are planning weights, not claims about allocator layout or an OOM guarantee.
const ROW_WORK: usize = 2048;
const FIELD_COPIES: usize = 8;

type Fit<T> = Result<T, CandidateError>;

// memory—v1: Reject overflow just like an observation that cannot cover the work.
fn add(a: usize, b: usize) -> Fit<usize> {
    a.checked_add(b)
        .ok_or(CandidateError::WorkingMemoryUnavailable)
}

fn payload<const N: usize>(fields: [&[u8]; N]) -> Fit<usize> {
    fields
        .into_iter()
        .try_fold(0, |sum, field| add(sum, field.len()))
}

fn version(r: &RuleSetVersionRow) -> Fit<usize> {
    payload([
        &r.version_bytes,
        &r.content_bytes,
        &r.timestamp_bytes,
        &r.hash_input_bytes,
        &r.hash_bytes,
    ])
}

fn confirmation(r: &BindingConfirmationRow) -> Fit<usize> {
    payload([
        &r.version_bytes,
        &r.scope_bytes,
        &r.operation_id,
        &r.confirmed_at_bytes,
    ])
}

fn change(r: &RuleSetChangeConfirmationRow) -> Fit<usize> {
    payload([
        &r.version_bytes,
        &r.affected_scope_bytes,
        &r.operation_id,
        &r.confirmed_at_bytes,
    ])
}

// memory—v1: Available bytes are sampled after the input and old root are resident.
fn admit(probe: fn() -> Option<usize>, rows: usize, fields: usize) -> Fit<()> {
    let needed = rows
        .checked_mul(ROW_WORK)
        .and_then(|n| n.checked_add(fields.checked_mul(FIELD_COPIES)?))
        .ok_or(CandidateError::WorkingMemoryUnavailable)?;
    if probe().is_some_and(|free| needed <= free) {
        Ok(())
    } else {
        Err(CandidateError::WorkingMemoryUnavailable)
    }
}

pub(super) fn rows_fit(
    probe: fn() -> Option<usize>,
    rows: &CandidateRows,
    selections: &[CurrentSelection],
) -> Fit<()> {
    let count = rows
        .table_counts()
        .total()
        .ok_or(CandidateError::WorkingMemoryUnavailable)?;
    let mut bytes = 0;
    for r in &rows.rule_sets {
        bytes = add(bytes, r.current_version_bytes.len())?;
    }
    for r in selections {
        bytes = add(bytes, r.version_bytes.len())?;
    }
    for r in &rows.rule_set_versions {
        bytes = add(bytes, version(r)?)?;
    }
    for r in &rows.binding_confirmations {
        bytes = add(bytes, confirmation(r)?)?;
    }
    for r in &rows.rule_set_change_confirmations {
        bytes = add(bytes, change(r)?)?;
    }
    admit(probe, add(count, selections.len())?, bytes)
}

// memory—v1: All mutation writers, including replay, prepare through this seam.
pub(super) fn mutation_fits(candidate: &HamtCandidate, mutation: &Mutation) -> Fit<()> {
    let Some(probe) = candidate.headroom() else {
        return Ok(());
    };
    let (rows, bytes) = match mutation {
        Mutation::BindingCreate {
            confirmation: c, ..
        } => (2, confirmation(c)?),
        Mutation::ConfirmationCreate { row } => (1, confirmation(row)?),
        Mutation::ConfirmationRevoke {
            confirmation_id, ..
        } => (
            1,
            candidate
                .confirmation(*confirmation_id)
                .map_or(Ok(0), confirmation)?,
        ),
        Mutation::RuleSetChangeConfirmationRevoke {
            confirmation_id, ..
        } => (
            1,
            candidate
                .change_confirmation(*confirmation_id)
                .map_or(Ok(0), change)?,
        ),
        Mutation::ConfirmationBatch { rows } => (
            rows.len(),
            rows.iter()
                .try_fold(0, |sum, row| add(sum, confirmation(row)?))?,
        ),
        Mutation::RuleSetCreate {
            rule_set,
            version: v,
            change_confirmation: c,
        } => (
            4,
            add(
                add(version(v)?, change(c)?)?,
                rule_set.current_version_bytes.len(),
            )?,
        ),
        Mutation::VersionPublish {
            version_row,
            change_confirmation: c,
            new_current_version,
            ..
        } => (
            4,
            add(
                add(version(version_row)?, change(c)?)?,
                new_current_version.len(),
            )?,
        ),
        Mutation::ContextLoad { rows, selections } => return rows_fit(probe, rows, selections),
        Mutation::BindingRemove { .. }
        | Mutation::UserCardCreate { .. }
        | Mutation::UserCardStatus { .. }
        | Mutation::RuleSetRetire { .. } => (1, 0),
    };
    admit(probe, rows, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // memory—v1: Resource failure consumes neither the install slot nor the predecessor.
    fn refused_install_and_refused_removal_publish_nothing() {
        use super::super::{
            tests::serving_ready, MutationError, MutationPrecondition, RootError, RootRegistry,
        };
        use crate::memory_v1_hamt::CandidateBudget;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        static AVAILABLE: AtomicBool = AtomicBool::new(true);
        let probe = || AVAILABLE.load(Ordering::Relaxed).then_some(1024 * 1024);
        let (rows, selections) = serving_ready();
        let limits = CandidateBudget {
            max_table_rows: 100,
            max_bindings_per_read: 16,
        };
        let registry = RootRegistry::new();
        assert!(matches!(
            registry.install_with_capacity(
                rows.clone(),
                selections.clone(),
                limits,
                super::super::GovernanceFrontier::Baseline,
                Some(|| None),
                &mut |_| {}
            ),
            Err(RootError::Candidate(
                CandidateError::WorkingMemoryUnavailable
            ))
        ));
        assert!(matches!(registry.handle(), Err(RootError::NotInstalled)));
        let mutation = Mutation::BindingRemove {
            binding_id: rows.bindings[0].binding_id,
            removed_at: 10,
            removed_by: rows.users[0].user_id,
        };
        let owner = registry
            .install_with_capacity(
                rows,
                selections,
                limits,
                super::super::GovernanceFrontier::Baseline,
                Some(probe),
                &mut |_| {},
            )
            .unwrap();
        let before = owner.runtime.current.load_full();
        let pre = MutationPrecondition {
            evaluated_root_version: before.metadata.version,
        };
        AVAILABLE.store(false, Ordering::Relaxed);
        assert!(matches!(
            owner.execute_recovery_mutation(&mutation, &pre),
            Err(MutationError::Candidate(
                CandidateError::WorkingMemoryUnavailable
            ))
        ));
        assert!(Arc::ptr_eq(&before, &owner.runtime.current.load_full()));
        AVAILABLE.store(true, Ordering::Relaxed);
        let after = owner.execute_recovery_mutation(&mutation, &pre).unwrap();
        assert_eq!(after.version, before.metadata.version + 1);
        assert_ne!(after.digest, before.metadata.digest);
    }

    #[test]
    fn headroom_must_cover_the_complete_estimate() {
        assert!(admit(|| Some(ROW_WORK + FIELD_COPIES), 1, 1).is_ok());
        for result in [
            admit(|| Some(ROW_WORK), 1, 1),
            admit(|| None, 1, 0),
            admit(|| Some(usize::MAX), usize::MAX, 0),
            admit(|| Some(usize::MAX), 0, usize::MAX),
        ] {
            assert_eq!(result, Err(CandidateError::WorkingMemoryUnavailable));
        }
    }
}
