//! memory—v1: Derived rule-set change-confirmation classification index.
//!
//! This module stores only bounded counters derived from the immutable candidate
//! facts. It does not validate foreign-key ownership; callers validate that
//! boundary before building or updating the index. A row is grouped by its own
//! `rule_set_id`, so a state lookup never crosses rule-set ownership boundaries.

use im::HashMap;

use crate::memory_v1_db_rows::{BinaryId, RuleSetChangeConfirmationRow};
use crate::memory_v1_rules::{change_confirmation_valid, ChangeConfirmationState};

/// memory—v1: Counts needed to classify one rule set's change confirmations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ChangeSummary {
    /// Number of rows whose revocation markers contain only one half.
    half_tombstone_rows: usize,
    /// Counts grouped by the exact version bytes stored on each row.
    versions: HashMap<Vec<u8>, VersionSummary>,
}

/// memory—v1: Counts needed to classify one exact confirmation version.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct VersionSummary {
    /// Number of rows, active or completely revoked, for this version.
    current_seen: usize,
    /// Number of active rows passing `change_confirmation_valid`.
    active_valid: usize,
    /// Number of active rows failing `change_confirmation_valid`.
    active_invalid: usize,
}

/// memory—v1: Pure derived index for rule-set change-confirmation states.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChangeConfirmationIndex {
    /// The key is the owning row's rule-set identifier.
    summaries: HashMap<BinaryId, ChangeSummary>,
}

impl ChangeConfirmationIndex {
    /// memory—v1: Build counters from one immutable fact snapshot. Any error
    /// discards the private partial index rather than publishing it.
    pub(crate) fn from_rows<'a>(
        rows: impl IntoIterator<Item = &'a RuleSetChangeConfirmationRow>,
    ) -> Result<Self, ()> {
        let mut index = Self::default();
        for row in rows {
            index.insert_in_place(row)?;
        }
        Ok(index)
    }

    /// memory—v1: Classify an exact selected version from the derived counters.
    pub(crate) fn state(&self, rule_set_id: BinaryId, version: &[u8]) -> ChangeConfirmationState {
        if version.is_empty() {
            return ChangeConfirmationState::Invalid;
        }

        let Some(summary) = self.summaries.get(&rule_set_id) else {
            return ChangeConfirmationState::Missing;
        };
        if summary.half_tombstone_rows != 0 {
            return ChangeConfirmationState::Invalid;
        }

        let Some(version_summary) = summary.versions.get(version) else {
            return ChangeConfirmationState::Missing;
        };
        if version_summary.active_invalid != 0 {
            ChangeConfirmationState::Invalid
        } else if version_summary.active_valid != 0 {
            ChangeConfirmationState::Active
        } else if version_summary.current_seen != 0 {
            ChangeConfirmationState::Withdrawn
        } else {
            ChangeConfirmationState::Missing
        }
    }

    /// memory—v1: Add one fact using checked counters and atomic local commit.
    pub(crate) fn insert(&mut self, row: &RuleSetChangeConfirmationRow) -> Result<(), ()> {
        let mut next = self.clone();
        next.insert_in_place(row)?;
        *self = next;
        Ok(())
    }

    /// memory—v1: Remove one fact using checked counters and atomic local commit.
    pub(crate) fn remove(&mut self, row: &RuleSetChangeConfirmationRow) -> Result<(), ()> {
        let mut next = self.clone();
        next.remove_in_place(row)?;
        *self = next;
        Ok(())
    }

    // memory—v1: Update a private index; callers discard it on any failure.
    fn insert_in_place(&mut self, row: &RuleSetChangeConfirmationRow) -> Result<(), ()> {
        let summary = self.summaries.entry(row.rule_set_id).or_default();
        let version_summary = summary
            .versions
            .entry(row.version_bytes.clone())
            .or_default();

        version_summary.current_seen = version_summary.current_seen.checked_add(1).ok_or(())?;
        if row.revoked_at.is_some() != row.revoked_by.is_some() {
            summary.half_tombstone_rows = summary.half_tombstone_rows.checked_add(1).ok_or(())?;
        } else if row.revoked_at.is_none()
            && change_confirmation_valid(row, row.rule_set_id, &row.version_bytes)
        {
            version_summary.active_valid = version_summary.active_valid.checked_add(1).ok_or(())?;
        } else if row.revoked_at.is_none() {
            version_summary.active_invalid =
                version_summary.active_invalid.checked_add(1).ok_or(())?;
        }
        Ok(())
    }

    // memory—v1: Decrement checked counters and discard empty index buckets.
    fn remove_in_place(&mut self, row: &RuleSetChangeConfirmationRow) -> Result<(), ()> {
        let mut summary = self.summaries.get(&row.rule_set_id).cloned().ok_or(())?;
        let mut version_summary = summary
            .versions
            .get(&row.version_bytes)
            .cloned()
            .ok_or(())?;

        version_summary.current_seen = version_summary.current_seen.checked_sub(1).ok_or(())?;
        if row.revoked_at.is_some() != row.revoked_by.is_some() {
            summary.half_tombstone_rows = summary.half_tombstone_rows.checked_sub(1).ok_or(())?;
        } else if row.revoked_at.is_none()
            && change_confirmation_valid(row, row.rule_set_id, &row.version_bytes)
        {
            version_summary.active_valid = version_summary.active_valid.checked_sub(1).ok_or(())?;
        } else if row.revoked_at.is_none() {
            version_summary.active_invalid =
                version_summary.active_invalid.checked_sub(1).ok_or(())?;
        }

        if version_summary.current_seen == 0
            && version_summary.active_valid == 0
            && version_summary.active_invalid == 0
        {
            summary.versions.remove(&row.version_bytes);
        } else {
            summary
                .versions
                .insert(row.version_bytes.clone(), version_summary);
        }
        if summary.half_tombstone_rows == 0 && summary.versions.is_empty() {
            self.summaries.remove(&row.rule_set_id);
        } else {
            self.summaries.insert(row.rule_set_id, summary);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "memory_v1_confirmation_index_tests.rs"]
mod tests;
