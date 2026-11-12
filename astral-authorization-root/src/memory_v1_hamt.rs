//! Offline HAMT-backed candidates over supplied memory-v1 rows.
//!
//! These structures only index and check the supplied data. They do not establish
//! coverage, provenance, hash integrity, confirmation validity, or an ALLOW.
//! Parent links and reverse impact sets describe relationships, not permissions.
//! There is no database, network, read gate, or service-root installation here.

use std::sync::Arc;

use im::{HashMap, HashSet};

use crate::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingRow, CandidateRows, CurrentSelection, IdentityCardRow,
    RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, Table, TenantRow, UserCardRow,
    UserRow, ValidationError,
};

/// Limits applied to a supplied candidate and each binding-bearing query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateBudget {
    /// Maximum combined number of rows across all nine supplied tables.
    pub max_table_rows: usize,
    /// Maximum number of bindings returned or traversed by one query.
    pub max_bindings_per_read: usize,
}

/// A rejected offline candidate operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateError {
    /// A supplied row violates the candidate SQL constraints.
    Rows(ValidationError),
    /// A supplied user has no identity card.
    MissingIdentityCard { user_id: BinaryId },
    /// The supplied tenant parent graph contains a cycle.
    TenantCycle { tenant_id: BinaryId },
    /// A referenced entity is absent from the supplied candidate.
    UnknownId { table: Table, id: BinaryId },
    /// A selected or replacement version is absent from the supplied candidate.
    UnknownVersion {
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
    },
    /// An append would replace an already supplied version.
    DuplicateVersion {
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
    },
    /// The combined table row count exceeds the configured limit or overflows.
    RowBudgetExceeded { max: usize },
    /// The query would traverse more bindings than its configured limit.
    BindingBudgetExceeded { max: usize, actual: usize },
}

/// One card and its supplied bindings; no permission decision is implied.
pub struct CardCandidate<'a> {
    /// The requested user-card row.
    pub card: &'a UserCardRow,
    /// All bindings directly attached to that card, in unspecified order.
    pub bindings: Vec<&'a BindingRow>,
}

/// Directly related IDs for a rule set; these are not effective permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSetImpactCandidate {
    /// Direct binding IDs.
    pub binding_ids: HashSet<BinaryId>,
    /// Cards referenced by those bindings.
    pub card_ids: HashSet<BinaryId>,
    /// Users owning those cards.
    pub user_ids: HashSet<BinaryId>,
    /// Tenants containing those cards, without parent expansion.
    pub tenant_ids: HashSet<BinaryId>,
}

/// Immutable, locally checked candidate rows and relationship indexes.
///
/// Cloning shares HAMT nodes and row allocations. A version operation creates a
/// new candidate without mutating an earlier one. Collection iteration order is
/// unspecified. This candidate has no authority or completeness semantics.
#[derive(Clone, Debug)]
pub struct HamtCandidate {
    budget: CandidateBudget,
    row_count: usize,
    users: HashMap<BinaryId, Arc<UserRow>>,
    identities: HashMap<BinaryId, Arc<IdentityCardRow>>,
    identity_by_user: HashMap<BinaryId, BinaryId>,
    tenants: HashMap<BinaryId, Arc<TenantRow>>,
    cards: HashMap<BinaryId, Arc<UserCardRow>>,
    rule_sets: HashMap<BinaryId, Arc<RuleSetRow>>,
    versions: HashMap<BinaryId, HashMap<Vec<u8>, Arc<RuleSetVersionRow>>>,
    bindings: HashMap<BinaryId, Arc<BindingRow>>,
    confirmations: HashMap<BinaryId, Arc<BindingConfirmationRow>>,
    change_confirmations: HashMap<BinaryId, Arc<RuleSetChangeConfirmationRow>>,
    cards_by_user: HashMap<BinaryId, HashSet<BinaryId>>,
    cards_by_tenant: HashMap<BinaryId, HashSet<BinaryId>>,
    children_by_tenant: HashMap<BinaryId, HashSet<BinaryId>>,
    bindings_by_card: HashMap<BinaryId, HashSet<BinaryId>>,
    bindings_by_rule_set: HashMap<BinaryId, HashSet<BinaryId>>,
    confirmations_by_binding: HashMap<BinaryId, HashSet<BinaryId>>,
    changes_by_rule_set: HashMap<BinaryId, HashSet<BinaryId>>,
    selections: HashMap<BinaryId, Arc<Vec<u8>>>,
}

// memory—v1: Insert an ID in a persistent relationship index.
fn index(index: &mut HashMap<BinaryId, HashSet<BinaryId>>, key: BinaryId, value: BinaryId) {
    let mut values = index.get(&key).cloned().unwrap_or_default();
    values.insert(value);
    index.insert(key, values);
}

// memory—v1: Count all supplied table rows without arithmetic wraparound.
fn count_rows(rows: &CandidateRows, max: usize) -> Result<usize, CandidateError> {
    [
        rows.users.len(),
        rows.identity_cards.len(),
        rows.tenants.len(),
        rows.user_cards.len(),
        rows.rule_sets.len(),
        rows.rule_set_versions.len(),
        rows.bindings.len(),
        rows.binding_confirmations.len(),
        rows.rule_set_change_confirmations.len(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, n| {
        sum.checked_add(n)
            .filter(|total| *total <= max)
            .ok_or(CandidateError::RowBudgetExceeded { max })
    })
}

impl HamtCandidate {
    /// memory—v1: Validate the supplied rows and build persistent candidate indexes.
    ///
    /// Every supplied user must have exactly one identity card, tenant ancestry
    /// must be acyclic, and every explicit selection must name a supplied version.
    /// No selection is required. All nine tables and all historical records remain.
    pub fn build(
        rows: CandidateRows,
        selections: Vec<CurrentSelection>,
        budget: CandidateBudget,
    ) -> Result<Self, CandidateError> {
        let row_count = count_rows(&rows, budget.max_table_rows)?;
        let checked = rows
            .build_candidate(&selections)
            .map_err(CandidateError::Rows)?;
        for selection in &selections {
            if matches!(
                checked.current(selection.rule_set_id),
                Some(crate::memory_v1_db_rows::CurrentVersion::Missing { .. })
            ) {
                return Err(CandidateError::UnknownVersion {
                    rule_set_id: selection.rule_set_id,
                    version_bytes: selection.version_bytes.clone(),
                });
            }
        }
        let mut candidate = Self {
            budget,
            row_count,
            users: HashMap::new(),
            identities: HashMap::new(),
            identity_by_user: HashMap::new(),
            tenants: HashMap::new(),
            cards: HashMap::new(),
            rule_sets: HashMap::new(),
            versions: HashMap::new(),
            bindings: HashMap::new(),
            confirmations: HashMap::new(),
            change_confirmations: HashMap::new(),
            cards_by_user: HashMap::new(),
            cards_by_tenant: HashMap::new(),
            children_by_tenant: HashMap::new(),
            bindings_by_card: HashMap::new(),
            bindings_by_rule_set: HashMap::new(),
            confirmations_by_binding: HashMap::new(),
            changes_by_rule_set: HashMap::new(),
            selections: HashMap::new(),
        };
        for row in rows.users {
            candidate.users.insert(row.user_id, Arc::new(row));
        }
        for row in rows.identity_cards {
            candidate
                .identity_by_user
                .insert(row.user_id, row.identity_card_id);
            candidate
                .identities
                .insert(row.identity_card_id, Arc::new(row));
        }
        for id in candidate.users.keys() {
            if !candidate.identity_by_user.contains_key(id) {
                return Err(CandidateError::MissingIdentityCard { user_id: *id });
            }
        }
        for row in rows.tenants {
            if let Some(parent) = row.parent_tenant_id {
                index(&mut candidate.children_by_tenant, parent, row.tenant_id);
            }
            candidate.tenants.insert(row.tenant_id, Arc::new(row));
        }
        let mut complete: HashSet<BinaryId> = HashSet::new();
        for id in candidate.tenants.keys() {
            let mut path = HashSet::new();
            let mut current = *id;
            while !complete.contains(&current) {
                if path.insert(current).is_some() {
                    return Err(CandidateError::TenantCycle { tenant_id: current });
                }
                match candidate
                    .tenants
                    .get(&current)
                    .and_then(|row| row.parent_tenant_id)
                {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            complete.extend(path);
        }
        for row in rows.user_cards {
            index(&mut candidate.cards_by_user, row.user_id, row.user_card_id);
            index(
                &mut candidate.cards_by_tenant,
                row.tenant_id,
                row.user_card_id,
            );
            candidate.cards.insert(row.user_card_id, Arc::new(row));
        }
        for row in rows.rule_sets {
            candidate.rule_sets.insert(row.rule_set_id, Arc::new(row));
        }
        for row in rows.rule_set_versions {
            let mut versions = candidate
                .versions
                .get(&row.rule_set_id)
                .cloned()
                .unwrap_or_default();
            let rule_set_id = row.rule_set_id;
            versions.insert(row.version_bytes.clone(), Arc::new(row));
            candidate.versions.insert(rule_set_id, versions);
        }
        for row in rows.bindings {
            index(
                &mut candidate.bindings_by_card,
                row.user_card_id,
                row.binding_id,
            );
            index(
                &mut candidate.bindings_by_rule_set,
                row.rule_set_id,
                row.binding_id,
            );
            candidate.bindings.insert(row.binding_id, Arc::new(row));
        }
        for row in rows.binding_confirmations {
            index(
                &mut candidate.confirmations_by_binding,
                row.binding_id,
                row.confirmation_id,
            );
            candidate
                .confirmations
                .insert(row.confirmation_id, Arc::new(row));
        }
        for row in rows.rule_set_change_confirmations {
            index(
                &mut candidate.changes_by_rule_set,
                row.rule_set_id,
                row.confirmation_id,
            );
            candidate
                .change_confirmations
                .insert(row.confirmation_id, Arc::new(row));
        }
        for selection in selections {
            candidate
                .selections
                .insert(selection.rule_set_id, Arc::new(selection.version_bytes));
        }
        Ok(candidate)
    }

    /// memory—v1: Return the configured limits and combined nine-table row count.
    pub fn budget_and_row_count(&self) -> (CandidateBudget, usize) {
        (self.budget, self.row_count)
    }

    /// memory—v1: Look up a supplied user by ID.
    pub fn user(&self, id: BinaryId) -> Option<&UserRow> {
        self.users.get(&id).map(Arc::as_ref)
    }

    /// memory—v1: Look up a supplied identity card by ID.
    pub fn identity_card(&self, id: BinaryId) -> Option<&IdentityCardRow> {
        self.identities.get(&id).map(Arc::as_ref)
    }

    /// memory—v1: Look up the supplied identity card of a user.
    pub fn identity_for_user(&self, id: BinaryId) -> Option<&IdentityCardRow> {
        self.identity_by_user
            .get(&id)
            .and_then(|card| self.identity_card(*card))
    }

    /// memory—v1: Look up a supplied tenant by ID.
    pub fn tenant(&self, id: BinaryId) -> Option<&TenantRow> {
        self.tenants.get(&id).map(Arc::as_ref)
    }

    /// memory—v1: Look up a supplied user card by ID.
    pub fn user_card(&self, id: BinaryId) -> Option<&UserCardRow> {
        self.cards.get(&id).map(Arc::as_ref)
    }

    /// memory—v1: Look up a supplied rule set by ID.
    pub fn rule_set(&self, id: BinaryId) -> Option<&RuleSetRow> {
        self.rule_sets.get(&id).map(Arc::as_ref)
    }

    /// memory—v1: Look up any supplied version, including historical versions.
    pub fn version(&self, rule_set_id: BinaryId, version: &[u8]) -> Option<&RuleSetVersionRow> {
        self.versions
            .get(&rule_set_id)?
            .get(version)
            .map(Arc::as_ref)
    }

    /// memory—v1: Return the version index for a supplied rule set, if any.
    pub fn versions(
        &self,
        rule_set_id: BinaryId,
    ) -> Option<&HashMap<Vec<u8>, Arc<RuleSetVersionRow>>> {
        self.versions.get(&rule_set_id)
    }

    /// memory—v1: Return the caller-selected supplied version, if one was selected.
    pub fn selected_version(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<Option<&RuleSetVersionRow>, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        Ok(self
            .selections
            .get(&rule_set_id)
            .and_then(|version| self.version(rule_set_id, version)))
    }

    /// memory—v1: Return a user's direct card IDs, or an error for an unknown user.
    pub fn user_cards(
        &self,
        user_id: BinaryId,
    ) -> Result<Option<&HashSet<BinaryId>>, CandidateError> {
        if !self.users.contains_key(&user_id) {
            return Err(CandidateError::UnknownId {
                table: Table::User,
                id: user_id,
            });
        }
        Ok(self.cards_by_user.get(&user_id))
    }

    /// memory—v1: Return a tenant's direct card IDs without inheritance.
    pub fn tenant_cards(
        &self,
        tenant_id: BinaryId,
    ) -> Result<Option<&HashSet<BinaryId>>, CandidateError> {
        self.require_tenant(tenant_id)?;
        Ok(self.cards_by_tenant.get(&tenant_id))
    }

    /// memory—v1: Return direct child tenant IDs without inferring permissions.
    pub fn tenant_children(
        &self,
        tenant_id: BinaryId,
    ) -> Result<Option<&HashSet<BinaryId>>, CandidateError> {
        self.require_tenant(tenant_id)?;
        Ok(self.children_by_tenant.get(&tenant_id))
    }

    /// memory—v1: Return ancestor tenant IDs from immediate parent to root.
    pub fn tenant_ancestors(&self, tenant_id: BinaryId) -> Result<Vec<BinaryId>, CandidateError> {
        self.require_tenant(tenant_id)?;
        let mut result = Vec::new();
        let mut next = self
            .tenants
            .get(&tenant_id)
            .and_then(|row| row.parent_tenant_id);
        while let Some(parent) = next {
            result.push(parent);
            next = self
                .tenants
                .get(&parent)
                .and_then(|row| row.parent_tenant_id);
        }
        Ok(result)
    }

    /// memory—v1: Read one card and all its bindings, rejecting over-budget reads.
    pub fn card_candidate(&self, card_id: BinaryId) -> Result<CardCandidate<'_>, CandidateError> {
        let card = self.user_card(card_id).ok_or(CandidateError::UnknownId {
            table: Table::UserCard,
            id: card_id,
        })?;
        let ids = self.bindings_by_card.get(&card_id);
        self.check_bindings(ids.map_or(0, HashSet::len))?;
        let bindings = ids
            .into_iter()
            .flat_map(|ids| ids.iter())
            .map(|id| self.bindings[id].as_ref())
            .collect();
        Ok(CardCandidate { card, bindings })
    }

    /// memory—v1: Look up one binding under the per-read binding budget.
    pub fn binding(&self, binding_id: BinaryId) -> Result<Option<&BindingRow>, CandidateError> {
        let binding = self.bindings.get(&binding_id);
        self.check_bindings(usize::from(binding.is_some()))?;
        Ok(binding.map(Arc::as_ref))
    }

    /// memory—v1: Return every supplied confirmation for a binding, across versions.
    pub fn binding_confirmations(
        &self,
        binding_id: BinaryId,
    ) -> Result<Vec<&BindingConfirmationRow>, CandidateError> {
        if !self.bindings.contains_key(&binding_id) {
            return Err(CandidateError::UnknownId {
                table: Table::Binding,
                id: binding_id,
            });
        }
        self.check_bindings(1)?;
        Ok(self
            .confirmations_by_binding
            .get(&binding_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .map(|id| self.confirmations[id].as_ref())
            .collect())
    }

    /// memory—v1: Return every supplied change-confirmation row for a rule set.
    pub fn change_confirmations(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<Vec<&RuleSetChangeConfirmationRow>, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        Ok(self
            .changes_by_rule_set
            .get(&rule_set_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .map(|id| self.change_confirmations[id].as_ref())
            .collect())
    }

    /// memory—v1: Compute direct reverse relationships within the binding budget.
    pub fn rule_set_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RuleSetImpactCandidate, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        let bindings = self.bindings_by_rule_set.get(&rule_set_id);
        self.check_bindings(bindings.map_or(0, HashSet::len))?;
        let mut result = RuleSetImpactCandidate {
            binding_ids: HashSet::new(),
            card_ids: HashSet::new(),
            user_ids: HashSet::new(),
            tenant_ids: HashSet::new(),
        };
        for id in bindings.into_iter().flat_map(|ids| ids.iter()) {
            let binding = &self.bindings[id];
            let card = &self.cards[&binding.user_card_id];
            result.binding_ids.insert(*id);
            result.card_ids.insert(card.user_card_id);
            result.user_ids.insert(card.user_id);
            result.tenant_ids.insert(card.tenant_id);
        }
        Ok(result)
    }

    /// memory—v1: Append one complete version row without overwriting history.
    pub fn append_version(&self, row: RuleSetVersionRow) -> Result<Self, CandidateError> {
        self.require_rule_set(row.rule_set_id)?;
        if self.version(row.rule_set_id, &row.version_bytes).is_some() {
            return Err(CandidateError::DuplicateVersion {
                rule_set_id: row.rule_set_id,
                version_bytes: row.version_bytes,
            });
        }
        let row_count = self
            .row_count
            .checked_add(1)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        self.validate_version_row(&row)?;
        let mut next = self.clone();
        let mut versions = next
            .versions
            .get(&row.rule_set_id)
            .cloned()
            .unwrap_or_default();
        let rule_set_id = row.rule_set_id;
        versions.insert(row.version_bytes.clone(), Arc::new(row));
        next.versions.insert(rule_set_id, versions);
        next.row_count = row_count;
        Ok(next)
    }

    /// memory—v1: Change or clear a selection without altering confirmation rows.
    ///
    /// A selected version must already exist. This does not re-confirm cards or
    /// establish that either the selection or a confirmation has any authority.
    pub fn with_selection(
        &self,
        rule_set_id: BinaryId,
        version: Option<&[u8]>,
    ) -> Result<Self, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        if let Some(bytes) = version {
            if self.version(rule_set_id, bytes).is_none() {
                return Err(CandidateError::UnknownVersion {
                    rule_set_id,
                    version_bytes: bytes.to_vec(),
                });
            }
        }
        let mut next = self.clone();
        match version {
            Some(bytes) => {
                next.selections
                    .insert(rule_set_id, Arc::new(bytes.to_vec()));
            }
            None => {
                next.selections.remove(&rule_set_id);
            }
        }
        Ok(next)
    }

    // memory—v1: Reuse SQL row validation for an isolated complete version row.
    fn validate_version_row(&self, row: &RuleSetVersionRow) -> Result<(), CandidateError> {
        let rule_set = self.rule_sets[&row.rule_set_id].as_ref().clone();
        let rows = CandidateRows {
            tenants: vec![TenantRow {
                tenant_id: rule_set.owner_tenant_id,
                parent_tenant_id: None,
            }],
            rule_sets: vec![rule_set],
            rule_set_versions: vec![row.clone()],
            ..CandidateRows::default()
        };
        rows.build_candidate(&[]).map_err(CandidateError::Rows)?;
        Ok(())
    }

    // memory—v1: Require a rule set from the supplied candidate.
    fn require_rule_set(&self, id: BinaryId) -> Result<(), CandidateError> {
        if self.rule_sets.contains_key(&id) {
            Ok(())
        } else {
            Err(CandidateError::UnknownId {
                table: Table::RuleSet,
                id,
            })
        }
    }

    // memory—v1: Require a tenant from the supplied candidate.
    fn require_tenant(&self, id: BinaryId) -> Result<(), CandidateError> {
        if self.tenants.contains_key(&id) {
            Ok(())
        } else {
            Err(CandidateError::UnknownId {
                table: Table::Tenant,
                id,
            })
        }
    }

    // memory—v1: Reject a binding-bearing read before traversing any bindings.
    fn check_bindings(&self, actual: usize) -> Result<(), CandidateError> {
        if actual > self.budget.max_bindings_per_read {
            Err(CandidateError::BindingBudgetExceeded {
                max: self.budget.max_bindings_per_read,
                actual,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::BindingLayer;

    // memory—v1: Generate distinct binary IDs without assuming an encoding.
    fn id(value: u8) -> BinaryId {
        let mut id = [0; 16];
        id[0] = 0x80;
        id[15] = value;
        id
    }

    // memory—v1: Construct a complete opaque candidate version.
    fn version(rule: u8, value: u8) -> RuleSetVersionRow {
        RuleSetVersionRow {
            rule_set_id: id(rule),
            version_bytes: vec![value],
            content_bytes: vec![value, 0],
            timestamp_bytes: vec![0xff],
            hash_input_bytes: vec![0, value],
            hash_bytes: vec![0x80],
        }
    }

    // memory—v1: Build rows covering all tables, shared rules and historical references.
    fn rows() -> CandidateRows {
        CandidateRows {
            users: vec![UserRow { user_id: id(1) }, UserRow { user_id: id(2) }],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: id(3),
                    user_id: id(1),
                },
                IdentityCardRow {
                    identity_card_id: id(4),
                    user_id: id(2),
                },
            ],
            tenants: vec![
                TenantRow {
                    tenant_id: id(5),
                    parent_tenant_id: None,
                },
                TenantRow {
                    tenant_id: id(6),
                    parent_tenant_id: Some(id(5)),
                },
                TenantRow {
                    tenant_id: id(7),
                    parent_tenant_id: Some(id(6)),
                },
            ],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(8),
                    user_id: id(1),
                    tenant_id: id(5),
                },
                UserCardRow {
                    user_card_id: id(9),
                    user_id: id(2),
                    tenant_id: id(7),
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    rule_set_id: id(10),
                    owner_tenant_id: id(5),
                },
                RuleSetRow {
                    rule_set_id: id(11),
                    owner_tenant_id: id(6),
                },
            ],
            rule_set_versions: vec![version(10, 1), version(10, 2), version(11, 1)],
            bindings: vec![
                BindingRow {
                    binding_id: id(12),
                    user_card_id: id(8),
                    rule_set_id: id(10),
                    binding_layer: BindingLayer::Base,
                },
                BindingRow {
                    binding_id: id(13),
                    user_card_id: id(9),
                    rule_set_id: id(10),
                    binding_layer: BindingLayer::Overlay,
                },
                BindingRow {
                    binding_id: id(14),
                    user_card_id: id(8),
                    rule_set_id: id(11),
                    binding_layer: BindingLayer::Overlay,
                },
            ],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: id(15),
                binding_id: id(12),
                rule_set_id: id(10),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                scope_bytes: vec![0xff],
                operation_id: vec![0],
                confirmed_at_bytes: vec![0x80],
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: id(15),
                rule_set_id: id(10),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![0],
                operation_id: vec![0xff],
                confirmed_at_bytes: vec![0],
            }],
        }
    }

    // memory—v1: Provide a small explicit test budget.
    fn budget() -> CandidateBudget {
        CandidateBudget {
            max_table_rows: 100,
            max_bindings_per_read: 10,
        }
    }

    // memory—v1: Construct a selected candidate for subsequent checks.
    fn candidate() -> HamtCandidate {
        HamtCandidate::build(
            rows(),
            vec![CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![2],
            }],
            budget(),
        )
        .unwrap()
    }

    #[test]
    // memory—v1: Enforce SQL constraints, exact identity-card presence and acyclic parentage.
    fn validation_rejects_invalid_candidate_rows() {
        let mut input = rows();
        input.identity_cards.pop();
        assert!(
            matches!(HamtCandidate::build(input, vec![], budget()), Err(CandidateError::MissingIdentityCard { user_id }) if user_id == id(2))
        );
        let mut input = rows();
        input.identity_cards.push(IdentityCardRow {
            identity_card_id: id(99),
            user_id: id(1),
        });
        assert!(matches!(
            HamtCandidate::build(input, vec![], budget()),
            Err(CandidateError::Rows(
                ValidationError::DuplicateIdentityCard { .. }
            ))
        ));
        let mut input = rows();
        input.tenants[0].parent_tenant_id = Some(id(7));
        assert!(matches!(
            HamtCandidate::build(input, vec![], budget()),
            Err(CandidateError::TenantCycle { .. })
        ));
        let mut input = rows();
        input.bindings[0].user_card_id = id(99);
        assert!(matches!(
            HamtCandidate::build(input, vec![], budget()),
            Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::Binding,
                ..
            }))
        ));
        assert!(matches!(
            HamtCandidate::build(
                rows(),
                vec![CurrentSelection {
                    rule_set_id: id(10),
                    version_bytes: vec![99]
                }],
                budget()
            ),
            Err(CandidateError::UnknownVersion { .. })
        ));
    }

    #[test]
    // memory—v1: Return direct structural relationships and complete historical rows.
    fn indexed_reads_preserve_history_and_relationships() {
        let candidate = candidate();
        assert_eq!(candidate.budget_and_row_count().1, 19);
        assert_eq!(candidate.user(id(1)).unwrap().user_id, id(1));
        assert_eq!(candidate.identity_card(id(3)).unwrap().user_id, id(1));
        assert_eq!(
            candidate.identity_for_user(id(1)).unwrap().identity_card_id,
            id(3)
        );
        assert_eq!(
            candidate.tenant_ancestors(id(7)).unwrap(),
            vec![id(6), id(5)]
        );
        assert!(candidate
            .tenant_children(id(5))
            .unwrap()
            .unwrap()
            .contains(&id(6)));
        assert!(candidate
            .tenant_cards(id(7))
            .unwrap()
            .unwrap()
            .contains(&id(9)));
        assert!(candidate
            .user_cards(id(1))
            .unwrap()
            .unwrap()
            .contains(&id(8)));
        assert_eq!(candidate.card_candidate(id(8)).unwrap().bindings.len(), 2);
        assert_eq!(
            candidate
                .selected_version(id(10))
                .unwrap()
                .unwrap()
                .version_bytes,
            vec![2]
        );
        assert_eq!(candidate.version(id(10), &[1]).unwrap(), &version(10, 1));
        assert_eq!(
            candidate.binding_confirmations(id(12)).unwrap()[0].version_bytes,
            vec![1]
        );
        assert_eq!(
            candidate.change_confirmations(id(10)).unwrap()[0].version_bytes,
            vec![1]
        );
        let impact = candidate.rule_set_impact(id(10)).unwrap();
        assert_eq!(impact.binding_ids.len(), 2);
        assert!(impact.card_ids.contains(&id(8)) && impact.card_ids.contains(&id(9)));
        assert!(impact.user_ids.contains(&id(1)) && impact.user_ids.contains(&id(2)));
        assert!(impact.tenant_ids.contains(&id(5)) && impact.tenant_ids.contains(&id(7)));
        assert!(!impact.tenant_ids.contains(&id(6)));
        assert!(matches!(
            candidate.tenant_children(id(99)),
            Err(CandidateError::UnknownId {
                table: Table::Tenant,
                ..
            })
        ));
    }

    #[test]
    // memory—v1: Reject whole reads and new rows at their configured limits.
    fn budgets_fail_without_partial_results() {
        let mut limits = budget();
        limits.max_table_rows = 18;
        assert!(matches!(
            HamtCandidate::build(rows(), vec![], limits),
            Err(CandidateError::RowBudgetExceeded { max: 18 })
        ));
        limits.max_table_rows = 19;
        limits.max_bindings_per_read = 1;
        let candidate = HamtCandidate::build(rows(), vec![], limits).unwrap();
        assert!(matches!(
            candidate.card_candidate(id(8)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 2 })
        ));
        assert!(matches!(
            candidate.rule_set_impact(id(10)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 2 })
        ));
        assert_eq!(candidate.card_candidate(id(9)).unwrap().bindings.len(), 1);
        assert!(matches!(
            candidate.append_version(version(10, 3)),
            Err(CandidateError::RowBudgetExceeded { max: 19 })
        ));
        let mut limits = budget();
        limits.max_bindings_per_read = 0;
        let candidate = HamtCandidate::build(rows(), vec![], limits).unwrap();
        assert!(matches!(
            candidate.binding(id(12)),
            Err(CandidateError::BindingBudgetExceeded { max: 0, actual: 1 })
        ));
        assert!(matches!(
            candidate.binding_confirmations(id(12)),
            Err(CandidateError::BindingBudgetExceeded { max: 0, actual: 1 })
        ));
    }

    #[test]
    // memory—v1: Share unaffected HAMT indexes and row allocations across local changes.
    fn version_changes_share_structure_and_preserve_old_candidates() {
        let old = candidate();
        let appended = old.append_version(version(10, 3)).unwrap();
        assert_eq!(old.version(id(10), &[2]).unwrap().content_bytes, vec![2, 0]);
        assert!(old.version(id(10), &[3]).is_none());
        assert_eq!(appended.version(id(10), &[3]).unwrap(), &version(10, 3));
        assert!(old.users.ptr_eq(&appended.users));
        assert!(old.bindings.ptr_eq(&appended.bindings));
        assert!(old
            .bindings_by_rule_set
            .ptr_eq(&appended.bindings_by_rule_set));
        assert!(old.confirmations.ptr_eq(&appended.confirmations));
        assert!(old.versions[&id(11)].ptr_eq(&appended.versions[&id(11)]));
        assert!(Arc::ptr_eq(
            &old.versions[&id(10)][&vec![1]],
            &appended.versions[&id(10)][&vec![1]]
        ));
        assert!(Arc::ptr_eq(
            &old.versions[&id(10)][&vec![2]],
            &appended.versions[&id(10)][&vec![2]]
        ));
        let selected = appended.with_selection(id(10), Some(&[3])).unwrap();
        assert_eq!(
            selected
                .selected_version(id(10))
                .unwrap()
                .unwrap()
                .version_bytes,
            vec![3]
        );
        assert_eq!(
            selected.binding_confirmations(id(12)).unwrap()[0].version_bytes,
            vec![1]
        );
        assert_eq!(
            selected.change_confirmations(id(10)).unwrap()[0].version_bytes,
            vec![1]
        );
        assert_eq!(
            old.selected_version(id(10)).unwrap().unwrap().version_bytes,
            vec![2]
        );
        assert!(appended.versions.ptr_eq(&selected.versions));
        assert!(appended.bindings_by_card.ptr_eq(&selected.bindings_by_card));
        assert!(selected
            .with_selection(id(10), None)
            .unwrap()
            .selected_version(id(10))
            .unwrap()
            .is_none());
    }

    #[test]
    // memory—v1: Reject unknown or invalid incremental version operations.
    fn version_changes_enforce_references_and_row_constraints() {
        let candidate = candidate();
        assert!(matches!(
            candidate.append_version(version(10, 1)),
            Err(CandidateError::DuplicateVersion { .. })
        ));
        assert!(matches!(
            candidate.append_version(version(99, 1)),
            Err(CandidateError::UnknownId {
                table: Table::RuleSet,
                ..
            })
        ));
        assert!(matches!(
            candidate.with_selection(id(10), Some(&[99])),
            Err(CandidateError::UnknownVersion { .. })
        ));
        let mut invalid = version(10, 3);
        invalid.timestamp_bytes = vec![0; 256];
        assert!(matches!(
            candidate.append_version(invalid),
            Err(CandidateError::Rows(ValidationError::FieldTooLong { .. }))
        ));
    }
}
