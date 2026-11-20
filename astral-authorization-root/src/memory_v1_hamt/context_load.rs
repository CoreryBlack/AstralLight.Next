//! memory—v1: Additive context loads on a private, structurally shared candidate.
//!
//! Equal facts are not writes. The delta is the exact set inserted into the
//! candidate and is also the only input to digest preparation.

use std::collections::BTreeSet;

use crate::memory_v1_digest::{
    DigestError, MAX_ROOT_DIGEST_KEYS, MAX_ROW_BYTES, MAX_VERSION_BYTES,
};

use super::{
    count_rows, index, Arc, BinaryId, BindingConfirmationState, CandidateError, CandidateRows,
    ChangeConfirmationState, CurrentSelection, HamtCandidate, Table, TenantRow, ValidationError,
};

pub(crate) struct ContextDelta {
    rows: CandidateRows,
    selections: Vec<CurrentSelection>,
}

#[derive(Debug)]
pub(crate) enum ContextLoadError {
    Candidate(CandidateError),
    Conflict(&'static str),
    Digest(DigestError),
}

impl From<CandidateError> for ContextLoadError {
    fn from(error: CandidateError) -> Self {
        Self::Candidate(error)
    }
}

// memory—v1: Match exact current values and reject duplicates, even when the
// duplicated value already exists. Only admitted additions are cloned.
fn additions<'a, T: Clone + Eq + 'a, K: Ord>(
    rows: &[T],
    key: impl Fn(&T) -> K,
    stored: impl Fn(&T) -> Option<&'a T>,
) -> Result<Vec<T>, ContextLoadError> {
    let mut seen = BTreeSet::new();
    let mut new = Vec::new();
    for row in rows {
        if !seen.insert(key(row)) {
            return Err(ContextLoadError::Conflict("duplicate context load key"));
        }
        match stored(row) {
            Some(old) if old == row => {}
            Some(_) => {
                return Err(ContextLoadError::Conflict(
                    "context load disagrees with a served fact",
                ))
            }
            None => new.push(row.clone()),
        }
    }
    Ok(new)
}

// memory—v1: Bound borrowed fields before copying anything. Reserve a fixed
// upper bound per row for IDs and machine fields; exact digest accounting is
// checked again by the builder. Equal repeats also consume this input budget.
fn validate_batch_bytes(
    rows: &CandidateRows,
    selections: &[CurrentSelection],
    mut remaining: usize,
) -> Result<(), ContextLoadError> {
    const FIXED_ROW_BYTES: usize = 128;
    let exhausted = || ContextLoadError::Digest(DigestError::LimitExceeded);
    let mut charge = |lengths: &[usize]| -> Result<(), ContextLoadError> {
        let bytes = lengths
            .iter()
            .try_fold(FIXED_ROW_BYTES, |sum, &len| sum.checked_add(len))
            .ok_or_else(exhausted)?;
        if bytes > MAX_ROW_BYTES {
            return Err(exhausted());
        }
        remaining = remaining.checked_sub(bytes).ok_or_else(exhausted)?;
        Ok(())
    };
    for _ in 0..(rows.users.len()
        + rows.identity_cards.len()
        + rows.tenants.len()
        + rows.user_cards.len()
        + rows.bindings.len())
    {
        charge(&[])?;
    }
    for row in &rows.rule_sets {
        charge(&[row.current_version_bytes.len()])?;
    }
    for row in &rows.rule_set_versions {
        if row.version_bytes.len() > MAX_VERSION_BYTES {
            return Err(exhausted());
        }
        charge(&[
            row.version_bytes.len(),
            row.content_bytes.len(),
            row.timestamp_bytes.len(),
            row.hash_input_bytes.len(),
            row.hash_bytes.len(),
        ])?;
    }
    for row in &rows.binding_confirmations {
        charge(&[
            row.version_bytes.len(),
            row.scope_bytes.len(),
            row.operation_id.len(),
            row.confirmed_at_bytes.len(),
        ])?;
    }
    for row in &rows.rule_set_change_confirmations {
        charge(&[
            row.version_bytes.len(),
            row.affected_scope_bytes.len(),
            row.operation_id.len(),
            row.confirmed_at_bytes.len(),
        ])?;
    }
    for row in selections {
        if row.version_bytes.len() > MAX_VERSION_BYTES {
            return Err(exhausted());
        }
        charge(&[row.version_bytes.len()])?;
    }
    Ok(())
}

impl ContextDelta {
    // memory—v1: Bound batch shape before preparing any additions.
    pub(crate) fn prepare(
        before: &HamtCandidate,
        rows: &CandidateRows,
        selections: &[CurrentSelection],
        remaining_bytes: usize,
    ) -> Result<Self, ContextLoadError> {
        let limit = before.budget.max_table_rows.min(MAX_ROOT_DIGEST_KEYS);
        let row_count = count_rows(rows, limit)?;
        if selections.len() > MAX_ROOT_DIGEST_KEYS.saturating_sub(row_count) {
            return Err(ContextLoadError::Digest(DigestError::LimitExceeded));
        }
        validate_batch_bytes(rows, selections, remaining_bytes)?;
        let rows = CandidateRows {
            users: additions(&rows.users, |r| r.user_id, |r| before.user(r.user_id))?,
            identity_cards: additions(
                &rows.identity_cards,
                |r| r.identity_card_id,
                |r| before.identity_card(r.identity_card_id),
            )?,
            tenants: additions(
                &rows.tenants,
                |r| r.tenant_id,
                |r| before.tenant(r.tenant_id),
            )?,
            user_cards: additions(
                &rows.user_cards,
                |r| r.user_card_id,
                |r| before.user_card(r.user_card_id),
            )?,
            rule_sets: additions(
                &rows.rule_sets,
                |r| r.rule_set_id,
                |r| before.rule_set(r.rule_set_id),
            )?,
            rule_set_versions: additions(
                &rows.rule_set_versions,
                |r| (r.rule_set_id, r.version_bytes.clone()),
                |r| before.version(r.rule_set_id, &r.version_bytes),
            )?,
            bindings: additions(
                &rows.bindings,
                |r| r.binding_id,
                |r| before.binding_for_digest(r.binding_id),
            )?,
            binding_confirmations: additions(
                &rows.binding_confirmations,
                |r| r.confirmation_id,
                |r| before.confirmation(r.confirmation_id),
            )?,
            rule_set_change_confirmations: additions(
                &rows.rule_set_change_confirmations,
                |r| r.confirmation_id,
                |r| before.change_confirmation(r.confirmation_id),
            )?,
        };
        let mut current = BTreeSet::new();
        let mut select = Vec::new();
        for selection in selections {
            if !current.insert(selection.rule_set_id) {
                return Err(ContextLoadError::Conflict(
                    "duplicate context load selection",
                ));
            }
            match before.selections.get(&selection.rule_set_id) {
                Some(old) if old.row.version_bytes == selection.version_bytes => {}
                Some(_) => {
                    return Err(ContextLoadError::Conflict(
                        "context load would move a served selection",
                    ))
                }
                None => select.push(selection.clone()),
            }
        }
        if count_rows(&rows, limit)? == 0 && select.is_empty() {
            return Err(ContextLoadError::Conflict("context load adds nothing"));
        }
        Ok(Self {
            rows,
            selections: select,
        })
    }

    /// memory—v1: Borrow the exact validated additions for the shared row encoders.
    pub(crate) fn facts(&self) -> (&CandidateRows, &[CurrentSelection]) {
        (&self.rows, &self.selections)
    }

    // memory—v1: Only relevant rule sets prevent a load from publishing through an active fence.
    pub(crate) fn affected_rule_sets(&self) -> BTreeSet<BinaryId> {
        self.rows
            .bindings
            .iter()
            .map(|row| row.rule_set_id)
            .chain(
                self.rows
                    .binding_confirmations
                    .iter()
                    .map(|row| row.rule_set_id),
            )
            .chain(
                self.rows
                    .rule_set_change_confirmations
                    .iter()
                    .map(|row| row.rule_set_id),
            )
            .chain(self.selections.iter().map(|row| row.rule_set_id))
            .collect()
    }

    // memory—v1: Derive related indexes in dependency order. No existing row or
    // index bucket is overwritten by source data and all errors discard `next`.
    pub(crate) fn apply(
        &self,
        before: &HamtCandidate,
        serving: bool,
    ) -> Result<HamtCandidate, CandidateError> {
        let mut next = before.clone();
        let rows = &self.rows;
        next.row_count = before
            .row_count
            .checked_add(count_rows(rows, next.budget.max_table_rows)?)
            .filter(|count| *count <= next.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: next.budget.max_table_rows,
            })?;
        for row in &rows.users {
            next.users.insert(row.user_id, Arc::new(row.clone()));
        }
        for row in &rows.identity_cards {
            if next.user(row.user_id).is_none() {
                return Err(unknown(Table::User, row.user_id));
            }
            if next
                .identity_by_user
                .insert(row.user_id, row.identity_card_id)
                .is_some()
            {
                return Err(CandidateError::Rows(
                    ValidationError::DuplicateIdentityCard {
                        user_id: row.user_id,
                    },
                ));
            }
            next.identities
                .insert(row.identity_card_id, Arc::new(row.clone()));
        }
        for row in &rows.users {
            if next.identity_for_user(row.user_id).is_none() {
                return Err(CandidateError::MissingIdentityCard {
                    user_id: row.user_id,
                });
            }
        }
        for row in &rows.tenants {
            next.tenants.insert(row.tenant_id, Arc::new(row.clone()));
            if let Some(parent) = row.parent_tenant_id {
                index(&mut next.children_by_tenant, parent, row.tenant_id);
            }
        }
        next.validate_added_tenants(before, &rows.tenants)?;
        for row in &rows.user_cards {
            if next.user(row.user_id).is_none() {
                return Err(unknown(Table::User, row.user_id));
            }
            next.require_tenant(row.tenant_id)?;
            index(&mut next.cards_by_user, row.user_id, row.user_card_id);
            index(&mut next.cards_by_tenant, row.tenant_id, row.user_card_id);
            next.card_dependencies.insert(row.user_card_id, 0);
            next.cards.insert(row.user_card_id, Arc::new(row.clone()));
        }
        for row in &rows.rule_sets {
            next.require_tenant(row.owner_tenant_id)?;
            next.rule_set_dependencies.insert(row.rule_set_id, 0);
            next.rule_sets
                .insert(row.rule_set_id, Arc::new(row.clone()));
        }
        for row in &rows.rule_set_versions {
            next.require_rule_set(row.rule_set_id)?;
            crate::memory_v1_db_rows::validate_version_lengths(row)
                .map_err(CandidateError::Rows)?;
            next.versions
                .entry(row.rule_set_id)
                .or_default()
                .insert(row.version_bytes.clone(), Arc::new(row.clone()));
        }
        let mut changed_cards = BTreeSet::new();
        let mut changed_sets = BTreeSet::new();
        let mut selected_sets = BTreeSet::new();
        let mut changed_bindings = BTreeSet::new();
        for selection in &self.selections {
            let row = next
                .rule_set(selection.rule_set_id)
                .ok_or_else(|| unknown(Table::RuleSet, selection.rule_set_id))?;
            if serving && row.current_version_bytes != selection.version_bytes {
                return Err(CandidateError::InconsistentBinding);
            }
            next.prepare_selection(selection.rule_set_id, &selection.version_bytes)?;
            changed_sets.insert(selection.rule_set_id);
            selected_sets.insert(selection.rule_set_id);
        }
        for row in &rows.bindings {
            // A different binding ID is not proof of a newer grant.
            if before.binding_was_removed(row.user_card_id, row.rule_set_id)? {
                return Err(CandidateError::InconsistentBinding);
            }
            next.insert_context_binding(row.clone())?;
            changed_cards.insert(row.user_card_id);
            changed_bindings.insert(row.binding_id);
        }
        for row in &rows.binding_confirmations {
            if let Some(binding) = before.binding_for_digest(row.binding_id) {
                if before.binding_confirmation_state(binding)?
                    == BindingConfirmationState::Withdrawn
                {
                    return Err(CandidateError::InconsistentBinding);
                }
            }
            next.insert_context_confirmation(row.clone())?;
            let binding = next
                .binding_for_digest(row.binding_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            changed_cards.insert(binding.user_card_id);
            changed_bindings.insert(row.binding_id);
        }
        for row in &rows.rule_set_change_confirmations {
            if row.revoked_at.is_some() || row.revoked_by.is_some() {
                // Without a source-prefix proof the missing history stays unavailable.
                return Err(CandidateError::InconsistentBinding);
            }
            if before.rule_set(row.rule_set_id).is_some()
                && before.change_confirmation_state(row.rule_set_id, &row.version_bytes)?
                    == ChangeConfirmationState::Withdrawn
            {
                return Err(CandidateError::InconsistentBinding);
            }
            next.insert_context_change_confirmation(row.clone())?;
            changed_sets.insert(row.rule_set_id);
        }
        for binding_id in changed_bindings {
            next.refresh_binding_confirmation_state(binding_id)?;
            if serving {
                let binding = next
                    .binding_for_digest(binding_id)
                    .ok_or(CandidateError::InconsistentBinding)?;
                if next.binding_confirmation_state(binding)? == BindingConfirmationState::Invalid
                    || next.selected_version(binding.rule_set_id)?.is_none()
                {
                    return Err(CandidateError::InconsistentBinding);
                }
            }
        }
        if serving {
            for rule_set_id in rows
                .rule_sets
                .iter()
                .map(|row| row.rule_set_id)
                .chain(selected_sets)
            {
                let selected = next
                    .selected_version(rule_set_id)?
                    .ok_or(CandidateError::InconsistentBinding)?;
                if next.change_confirmation_state(rule_set_id, &selected.version_bytes)?
                    != ChangeConfirmationState::Active
                {
                    return Err(CandidateError::InconsistentBinding);
                }
            }
        }
        for id in changed_cards {
            if before.user_card(id).is_some() {
                next.advance_card_dependency(id)?;
            }
        }
        for id in changed_sets {
            if before.rule_set(id).is_some() {
                next.advance_rule_set_dependency(id)?;
            }
        }
        Ok(next)
    }
}

impl HamtCandidate {
    // memory—v1: Match removal by relationship, not just the supplied row ID.
    fn binding_was_removed(
        &self,
        card: BinaryId,
        rule_set: BinaryId,
    ) -> Result<bool, CandidateError> {
        for id in self.bindings_by_card.get(&card).into_iter().flatten() {
            let row = self
                .binding_for_digest(*id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if row.user_card_id != card {
                return Err(CandidateError::InconsistentBinding);
            }
            if row.rule_set_id == rule_set && (row.removed_at.is_some() || row.removed_by.is_some())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // memory—v1: Old paths are already closed and cannot point into the delta.
    // Traverse each new parent chain at most once, stopping at a proved old node.
    fn validate_added_tenants(
        &mut self,
        before: &Self,
        added: &[TenantRow],
    ) -> Result<(), CandidateError> {
        if added.is_empty() {
            return Ok(());
        }
        let mut complete = BTreeSet::new();
        for row in added {
            let mut path = BTreeSet::new();
            let mut current = Some(row.tenant_id);
            while let Some(id) = current {
                if before.tenant(id).is_some() || complete.contains(&id) {
                    break;
                }
                if !path.insert(id) {
                    return Err(CandidateError::TenantCycle { tenant_id: id });
                }
                current = self
                    .tenant(id)
                    .ok_or_else(|| unknown(Table::Tenant, id))?
                    .parent_tenant_id;
            }
            complete.extend(path);
        }
        self.tenant_tree_version = self
            .tenant_tree_version
            .checked_add(1)
            .ok_or(CandidateError::InconsistentBinding)?;
        Ok(())
    }
}

// memory—v1: Report the exact absent reference on the private candidate.
fn unknown(table: Table, id: BinaryId) -> CandidateError {
    CandidateError::UnknownId { table, id }
}
