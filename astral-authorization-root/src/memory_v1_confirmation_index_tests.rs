//! memory—v1: Differential tests for change-confirmation derived counters.

use super::{ChangeConfirmationIndex, ChangeSummary, VersionSummary};
use crate::memory_v1_db_rows::RuleSetChangeConfirmationRow;
use crate::memory_v1_rules::{classify_change_confirmations, ChangeConfirmationState};

// memory—v1: Supply a complete active confirmation on a deterministic rule set.
fn confirmation(id: u8, version: u8) -> RuleSetChangeConfirmationRow {
    RuleSetChangeConfirmationRow {
        confirmation_id: [id; 16],
        rule_set_id: [1; 16],
        version_bytes: vec![version],
        confirmer_user_id: [2; 16],
        affected_scope_bytes: vec![3],
        operation_id: vec![4],
        confirmed_at_bytes: vec![5],
        revoked_at: None,
        revoked_by: None,
    }
}

// memory—v1: Compare every selected version with the independent full scan.
fn assert_matches(index: &ChangeConfirmationIndex, rows: &[RuleSetChangeConfirmationRow]) {
    for version in [&[][..], &[1][..], &[2][..], &[3][..]] {
        assert_eq!(
            index.state([1; 16], version),
            classify_change_confirmations(rows.iter(), [1; 16], version),
            "selection {version:?} for {rows:?}"
        );
    }
    assert_eq!(index.state([9; 16], &[1]), ChangeConfirmationState::Missing);
}

#[test]
// memory—v1: Classify mixed versions and malformed rows identically, regardless
// of insertion order; verify removal and reconstruction at every step.
fn counters_match_full_scan_across_insertions_and_removals() {
    let active = confirmation(10, 1);
    let second = confirmation(11, 1);
    let previous = confirmation(12, 2);
    let mut withdrawn = confirmation(13, 1);
    withdrawn.revoked_at = Some(10);
    withdrawn.revoked_by = Some([2; 16]);
    let mut invalid = confirmation(14, 1);
    invalid.affected_scope_bytes.clear();
    let mut half_time = confirmation(15, 2);
    half_time.revoked_at = Some(10);
    let mut half_actor = confirmation(16, 3);
    half_actor.revoked_by = Some([2; 16]);
    let mut invalid_withdrawn = confirmation(17, 2);
    invalid_withdrawn.operation_id.clear();
    invalid_withdrawn.revoked_at = Some(10);
    invalid_withdrawn.revoked_by = Some([2; 16]);

    let inputs = [
        active,
        second,
        previous,
        withdrawn,
        invalid,
        half_time,
        half_actor,
        invalid_withdrawn,
    ];
    for reversed in [false, true] {
        let mut input = inputs.to_vec();
        if reversed {
            input.reverse();
        }
        let mut rows = Vec::new();
        let mut index = ChangeConfirmationIndex::default();
        assert_matches(&index, &rows);
        for row in &input {
            index.insert(row).unwrap();
            rows.push(row.clone());
            assert_matches(&index, &rows);
            assert_eq!(index, ChangeConfirmationIndex::from_rows(&rows).unwrap());
        }
        for row in &input {
            index.remove(row).unwrap();
            let position = rows.iter().position(|item| item == row).unwrap();
            rows.remove(position);
            assert_matches(&index, &rows);
            assert_eq!(index, ChangeConfirmationIndex::from_rows(&rows).unwrap());
        }
        assert_eq!(index, ChangeConfirmationIndex::default());
    }
}

#[test]
// memory—v1: Revoking one of several confirmations retains active evidence;
// revoking the last withdraws it without changing other versions.
fn replacement_transitions_match_full_scan() {
    let first = confirmation(10, 1);
    let second = confirmation(11, 1);
    let other = confirmation(12, 2);
    let mut rows = vec![first, second, other];
    let mut index = ChangeConfirmationIndex::from_rows(&rows).unwrap();
    for position in 0..2 {
        let old = rows[position].clone();
        let mut revoked = old.clone();
        revoked.revoked_at = Some(10);
        revoked.revoked_by = Some([2; 16]);
        index.remove(&old).unwrap();
        index.insert(&revoked).unwrap();
        rows[position] = revoked;
        assert_matches(&index, &rows);
        assert_eq!(index, ChangeConfirmationIndex::from_rows(&rows).unwrap());
    }
    assert_eq!(
        index.state([1; 16], &[1]),
        ChangeConfirmationState::Withdrawn
    );
    assert_eq!(index.state([1; 16], &[2]), ChangeConfirmationState::Active);
}

#[test]
// memory—v1: Counter overflow and underflow reject the operation without
// changing the original index, including changes attempted on other counters.
fn counter_failures_leave_index_unchanged() {
    let row = confirmation(10, 1);
    let mut missing = ChangeConfirmationIndex::default();
    let before = missing.clone();
    assert_eq!(missing.remove(&row), Err(()));
    assert_eq!(missing, before);

    let mut overflow = ChangeConfirmationIndex::default();
    let mut summary = ChangeSummary::default();
    summary.versions.insert(
        vec![1],
        VersionSummary {
            current_seen: 1,
            active_valid: usize::MAX,
            active_invalid: 0,
        },
    );
    overflow.summaries.insert([1; 16], summary);
    let before = overflow.clone();
    assert_eq!(overflow.insert(&row), Err(()));
    assert_eq!(overflow, before);

    let mut half_overflow = ChangeConfirmationIndex::default();
    let mut summary = ChangeSummary {
        half_tombstone_rows: usize::MAX,
        ..ChangeSummary::default()
    };
    summary.versions.insert(
        vec![1],
        VersionSummary {
            current_seen: 1,
            active_valid: 0,
            active_invalid: 0,
        },
    );
    half_overflow.summaries.insert([1; 16], summary);
    let before = half_overflow.clone();
    let mut half = row.clone();
    half.revoked_at = Some(10);
    assert_eq!(half_overflow.insert(&half), Err(()));
    assert_eq!(half_overflow, before);

    let mut underflow = ChangeConfirmationIndex::default();
    let mut summary = ChangeSummary::default();
    summary.versions.insert(
        vec![1],
        VersionSummary {
            current_seen: 1,
            active_valid: 0,
            active_invalid: 0,
        },
    );
    underflow.summaries.insert([1; 16], summary);
    let before = underflow.clone();
    assert_eq!(underflow.remove(&row), Err(()));
    assert_eq!(underflow, before);
}
