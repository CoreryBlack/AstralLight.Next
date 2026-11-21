//! memory—v1: Live rule-set sources retain a selected body, not an archive.

use im::{HashMap, OrdSet};
use sha2::{Digest, Sha256};

use super::{BinaryId, CandidateError, CandidateRows, HamtCandidate, RuleSetVersionRow};
use crate::memory_v1_digest::{
    Change, ColdDigestBuilder, DigestError, DigestIndex, Key, MAX_ROW_BYTES, MAX_VERSION_BYTES,
};
use crate::memory_v1_hamt_runtime::{
    binding_change, card_change, change_confirmation_change, confirmation_change, identity_change,
    rule_set_change, tenant_change, user_change, version_change, RuntimeError,
};

impl HamtCandidate {
    // memory—v1: Check each archival body before parsing; archive size is not a key limit.
    pub(crate) fn check_source_capacity(rows: &CandidateRows) -> Result<(), RuntimeError> {
        let limit = || RuntimeError::Digest(DigestError::LimitExceeded);
        for row in &rows.rule_set_versions {
            if row.version_bytes.len() > MAX_VERSION_BYTES {
                return Err(limit());
            }
            [
                row.version_bytes.len(),
                row.content_bytes.len(),
                row.timestamp_bytes.len(),
                row.hash_input_bytes.len(),
                row.hash_bytes.len(),
            ]
            .into_iter()
            .try_fold(row.rule_set_id.len(), usize::checked_add)
            .filter(|n| *n <= MAX_ROW_BYTES)
            .ok_or_else(limit)?;
        }
        Ok(())
    }

    // memory—v1: Only a validated graph with matching explicit pointers may
    // drop bodies. Incomplete offline candidates retain their diagnostic view.
    pub(crate) fn project_sources(&mut self) -> Result<(), CandidateError> {
        if self.has_valid_current_pointers() {
            self.source_projection = true;
            for id in self.rule_sets.keys().copied().collect::<Vec<_>>() {
                self.compact_source(id)?;
            }
        }
        Ok(())
    }

    // memory—v1: The caller has already prepared the selection and its plan.
    pub(crate) fn compact_source(&mut self, id: BinaryId) -> Result<(), CandidateError> {
        if !self.source_projection {
            return Ok(());
        }
        let selected = &self
            .selections
            .get(&id)
            .ok_or(CandidateError::InconsistentBinding)?
            .row;
        let versions = self
            .versions
            .get(&id)
            .ok_or(CandidateError::InconsistentBinding)?;
        if versions.len() == 1 {
            return Ok(());
        }
        for (version, row) in versions {
            if version != &selected.version_bytes {
                crate::memory_v1_rules::parse_version(row)
                    .map_err(CandidateError::RuleIntegrity)?;
                self.archived_ids
                    .entry(id)
                    .or_default()
                    .insert(version.clone());
            }
        }
        let mut current = HashMap::new();
        current.insert(selected.version_bytes.clone(), selected.clone());
        self.versions.insert(id, current);
        Ok(())
    }

    // memory—v1: These identities are charged to the original source row budget.
    pub(super) fn was_archived(&self, id: BinaryId, version: &[u8]) -> bool {
        self.archived_ids
            .get(&id)
            .is_some_and(|ids| ids.contains(version))
    }

    // memory—v1: A foreign-key reference needs an identity, not an evaluable body.
    pub(super) fn knows_version_id(&self, id: BinaryId, version: &[u8]) -> bool {
        self.version(id, version).is_some() || self.was_archived(id, version)
    }

    // memory—v1: Diagnostic candidates may not become serving roots.
    pub(crate) fn uses_source_slots(&self) -> bool {
        self.source_projection
    }

    // memory—v1: Protect the exact, ordered identities used to reject reuse
    // without retaining the old bodies in the digest's copy of the fields.
    pub(crate) fn source_change(&self, row: &RuleSetVersionRow) -> Change {
        let change = version_change(row);
        if !self.source_projection {
            return change;
        }
        let Change::Put { mut fields, .. } = change else {
            unreachable!()
        };
        let mut hash = Sha256::new();
        hash.update(b"astrallight/memory-v1/source-slot/archived-version-ids/1\0");
        for version in self
            .archived_ids
            .get(&row.rule_set_id)
            .into_iter()
            .flat_map(OrdSet::iter)
        {
            hash.update((version.len() as u64).to_be_bytes());
            hash.update(version);
        }
        fields.push(Some(hash.finalize().to_vec()));
        Change::Put {
            key: Key::source_slot(row.rule_set_id),
            fields,
        }
    }

    // memory—v1: Cold and diagnostic rebuilds use the same slot encoder as CAS.
    pub(crate) fn rebuild_source_digest(&self) -> Result<DigestIndex, RuntimeError> {
        // Stream borrowed rows; do not clone the whole graph into a second cold capture.
        let mut builder = ColdDigestBuilder::new();
        let mut push = |change| {
            let Change::Put { key, fields } = change else {
                unreachable!()
            };
            builder.push(key, fields).map_err(RuntimeError::Digest)
        };
        for row in self.users.values() {
            push(user_change(row))?;
        }
        for row in self.identities.values() {
            push(identity_change(row))?;
        }
        for row in self.tenants.values() {
            push(tenant_change(row))?;
        }
        for row in self.cards.values() {
            push(card_change(row))?;
        }
        for row in self.rule_sets.values() {
            push(rule_set_change(row))?;
        }
        for row in self
            .versions
            .values()
            .flat_map(|versions| versions.values())
        {
            push(self.source_change(row))?;
        }
        for row in self.bindings.values() {
            push(binding_change(row))?;
        }
        for row in self.confirmations.values() {
            push(confirmation_change(row))?;
        }
        for row in self.change_confirmations.values() {
            push(change_confirmation_change(row))?;
        }
        for (id, selection) in &self.selections {
            push(Change::select_current(
                *id,
                selection.row.version_bytes.clone(),
            ))?;
        }
        builder.finish().map_err(RuntimeError::Digest)
    }
}
