//! Offline HAMT-backed candidates over supplied memory-v1 rows.
//!
//! These structures only index and check the supplied data. They do not establish
//! coverage, provenance, hash integrity, confirmation validity, or an ALLOW.
//! Parent links and reverse impact sets describe relationships, not permissions.
//! There is no database, network, read gate, or service-root installation here.

use std::sync::Arc;

use im::{HashMap, HashSet};

use crate::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, Table,
    TableCounts, TenantRow, UserCardRow, UserRow, ValidationError,
};
use crate::memory_v1_rules::{confirmation_matches, parse_version, MemoryV1RuleError};

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
    /// The candidate contains no facts and cannot be adopted as a serving root.
    EmptyCandidate,
    /// A supplied user has no identity card.
    MissingIdentityCard { user_id: BinaryId },
    /// The supplied tenant parent graph contains a cycle.
    TenantCycle { tenant_id: BinaryId },
    /// A referenced entity is absent from the supplied candidate.
    UnknownId { table: Table, id: BinaryId },
    /// §4.5 double-bind prohibition: (card, ruleset) already has a binding.
    DoubleBinding {
        user_card_id: BinaryId,
        rule_set_id: BinaryId,
    },
    /// §4.5 one-OVERLAY-per-card: this card already has an OVERLAY binding.
    DoubleOverlay { user_card_id: BinaryId },
    /// A selected or replacement version is absent from the supplied candidate.
    UnknownVersion {
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
    },
    /// A selected version failed the closed memory—v1 rule/hash contract.
    RuleIntegrity(MemoryV1RuleError),
    /// A binding could not resolve its selected rule-set version.
    InconsistentBinding,
    /// A binding has no structurally matching confirmation for its selected version.
    MissingConfirmation {
        binding_id: BinaryId,
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
    /// A card read would allocate more confirmation references than its row budget.
    ConfirmationBudgetExceeded { max: usize },
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

    /// memory—v1: Row count of each table held by this candidate.
    pub fn table_counts(&self) -> TableCounts {
        TableCounts {
            users: self.users.len(),
            identity_cards: self.identities.len(),
            tenants: self.tenants.len(),
            user_cards: self.cards.len(),
            rule_sets: self.rule_sets.len(),
            rule_set_versions: self
                .versions
                .values()
                .map(HashMap::len)
                .fold(0_usize, usize::saturating_add),
            bindings: self.bindings.len(),
            binding_confirmations: self.confirmations.len(),
            rule_set_change_confirmations: self.change_confirmations.len(),
        }
    }

    /// memory—v1: Whether every rule set holds exactly one stored version.
    ///
    /// That is the only case in which the candidate schema, which has no
    /// current-version pointer and defines no version order, names one current
    /// version without inference.
    pub fn has_single_version_per_rule_set(&self) -> bool {
        self.rule_sets.keys().all(|id| {
            self.versions
                .get(id)
                .is_some_and(|versions| versions.len() == 1)
        })
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

    /// memory—v1 §4.10: every tenant strictly below `tenant_id` in the
    /// supplied tree, cycle-safe and sorted for deterministic comparison.
    ///
    /// Resolution supports the `self+descendants` scope; it grants nothing by
    /// itself and never crosses into another company's tree.
    pub fn tenant_descendants(&self, tenant_id: BinaryId) -> Result<Vec<BinaryId>, CandidateError> {
        self.require_tenant(tenant_id)?;
        let mut seen = std::collections::HashSet::new();
        let mut queue: Vec<BinaryId> = self
            .children_by_tenant
            .get(&tenant_id)
            .map(|children| children.iter().copied().collect())
            .unwrap_or_default();
        let mut result = Vec::new();
        while let Some(next) = queue.pop() {
            if seen.insert(next) {
                result.push(next);
                if let Some(children) = self.children_by_tenant.get(&next) {
                    queue.extend(children.iter().copied());
                }
            }
        }
        result.sort_unstable();
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

    /// memory—v1: Bound aggregate confirmation references before allocating card results.
    pub(crate) fn check_card_confirmation_budget(
        &self,
        bindings: &[&BindingRow],
    ) -> Result<(), CandidateError> {
        let max = self.budget.max_table_rows;
        let mut total = 0usize;
        for binding in bindings {
            for count in [
                self.confirmations_by_binding
                    .get(&binding.binding_id)
                    .map_or(0, HashSet::len),
                self.changes_by_rule_set
                    .get(&binding.rule_set_id)
                    .map_or(0, HashSet::len),
            ] {
                total = total
                    .checked_add(count)
                    .filter(|sum| *sum <= max)
                    .ok_or(CandidateError::ConfirmationBudgetExceeded { max })?;
            }
        }
        Ok(())
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

    /// memory—v1: Validate every selected rule version and binding confirmation
    /// required for a serving authorization root.
    ///
    /// The structural candidate checks have already run during construction. This
    /// second gate checks the frozen rule grammar, canonical version hash and the
    /// selected-version confirmation edge for every binding. Confirmation rows
    /// remain traceability inputs; this gate does not infer confirmer authority.
    pub fn validate_for_serving(&self) -> Result<(), CandidateError> {
        if self.row_count == 0
            || self.users.is_empty()
            || self.identities.is_empty()
            || self.tenants.is_empty()
            || self.cards.is_empty()
            || self.rule_sets.is_empty()
            || self.versions.is_empty()
            || self.bindings.is_empty()
        {
            return Err(CandidateError::EmptyCandidate);
        }
        for rule_set_id in self.rule_sets.keys() {
            let Some(version) =
                self.selected_version(*rule_set_id)
                    .map_err(|_| CandidateError::UnknownId {
                        table: Table::RuleSet,
                        id: *rule_set_id,
                    })?
            else {
                return Err(CandidateError::UnknownVersion {
                    rule_set_id: *rule_set_id,
                    version_bytes: Vec::new(),
                });
            };
            parse_version(version).map_err(CandidateError::RuleIntegrity)?;
        }
        for binding in self.bindings.values() {
            let selected = self
                .selected_version(binding.rule_set_id)
                .map_err(|_| CandidateError::InconsistentBinding)?
                .ok_or(CandidateError::UnknownVersion {
                    rule_set_id: binding.rule_set_id,
                    version_bytes: Vec::new(),
                })?;
            let mut confirmations = self
                .confirmations_by_binding
                .get(&binding.binding_id)
                .into_iter()
                .flat_map(|ids| ids.iter())
                .filter_map(|id| self.confirmations.get(id).map(Arc::as_ref));
            let confirmed = confirmations.any(|confirmation| {
                confirmation_matches(
                    confirmation,
                    binding.binding_id,
                    binding.rule_set_id,
                    &selected.version_bytes,
                )
            });
            if !confirmed {
                return Err(CandidateError::MissingConfirmation {
                    binding_id: binding.binding_id,
                    rule_set_id: binding.rule_set_id,
                    version_bytes: selected.version_bytes.clone(),
                });
            }
        }
        Ok(())
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

    /// memory—v1 §4.12: Update the current-version pointer on a rule set.
    ///
    /// The target version must already exist (B-3.1: explicit pointer, never
    /// inferred from max version or timestamps).
    pub fn with_current_version(
        &self,
        rule_set_id: BinaryId,
        version_bytes: &[u8],
    ) -> Result<Self, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        if self.version(rule_set_id, version_bytes).is_none() {
            return Err(CandidateError::UnknownVersion {
                rule_set_id,
                version_bytes: version_bytes.to_vec(),
            });
        }
        let mut next = self.clone();
        next.selections
            .insert(rule_set_id, Arc::new(version_bytes.to_vec()));
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.2: Insert a new binding row (structure only).
    ///
    /// Enforces the §4.5 double-bind prohibition (one binding per
    /// card+ruleset pair) and the §4.5 one-OVERLAY-per-card constraint.
    pub fn with_binding_insert(&self, row: BindingRow) -> Result<Self, CandidateError> {
        if self.user_card(row.user_card_id).is_none() {
            return Err(CandidateError::UnknownId {
                table: crate::memory_v1_db_rows::Table::UserCard,
                id: row.user_card_id,
            });
        }
        self.require_rule_set(row.rule_set_id)?;
        let row_count = self
            .row_count
            .checked_add(1)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        // §4.5 double-bind prohibition: (user_card_id, rule_set_id) must be unique.
        for existing in self.bindings.values() {
            if existing.user_card_id == row.user_card_id && existing.rule_set_id == row.rule_set_id
            {
                return Err(CandidateError::DoubleBinding {
                    user_card_id: row.user_card_id,
                    rule_set_id: row.rule_set_id,
                });
            }
            // §4.5: at most one OVERLAY binding per user card.
            if existing.binding_layer == BindingLayer::Overlay
                && row.binding_layer == BindingLayer::Overlay
                && existing.user_card_id == row.user_card_id
            {
                return Err(CandidateError::DoubleOverlay {
                    user_card_id: row.user_card_id,
                });
            }
        }
        let mut next = self.clone();
        next.row_count = row_count;
        next.bindings.insert(row.binding_id, Arc::new(row.clone()));
        index(&mut next.bindings_by_card, row.user_card_id, row.binding_id);
        index(
            &mut next.bindings_by_rule_set,
            row.rule_set_id,
            row.binding_id,
        );
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.2: Mark a binding as removed (REMOVE verb).
    ///
    /// The binding row is retained as a tombstone (append-only principle);
    /// evaluation skips removed bindings deterministically.
    pub fn with_binding_removed(
        &self,
        binding_id: BinaryId,
        removed_at: i64,
        removed_by: BinaryId,
    ) -> Result<Self, CandidateError> {
        let existing = self
            .bindings
            .get(&binding_id)
            .ok_or(CandidateError::UnknownId {
                table: crate::memory_v1_db_rows::Table::Binding,
                id: binding_id,
            })?
            .clone();
        let mut row = (*existing).clone();
        row.removed_at = Some(removed_at);
        row.removed_by = Some(removed_by);
        let mut next = self.clone();
        next.bindings.insert(binding_id, Arc::new(row));
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.4: Insert a new confirmation row.
    pub fn with_confirmation_insert(
        &self,
        row: BindingConfirmationRow,
    ) -> Result<Self, CandidateError> {
        let row_count = self
            .row_count
            .checked_add(1)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        let mut next = self.clone();
        next.row_count = row_count;
        next.confirmations
            .insert(row.confirmation_id, Arc::new(row.clone()));
        index(
            &mut next.confirmations_by_binding,
            row.binding_id,
            row.confirmation_id,
        );
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.4: Mark a confirmation as revoked (REVOKE verb).
    pub fn with_confirmation_revoked(
        &self,
        confirmation_id: BinaryId,
        revoked_at: i64,
        revoked_by: BinaryId,
    ) -> Result<Self, CandidateError> {
        let existing = self
            .confirmations
            .get(&confirmation_id)
            .ok_or(CandidateError::UnknownId {
                table: crate::memory_v1_db_rows::Table::BindingConfirmation,
                id: confirmation_id,
            })?
            .clone();
        let mut row = (*existing).clone();
        row.revoked_at = Some(revoked_at);
        row.revoked_by = Some(revoked_by);
        let mut next = self.clone();
        next.confirmations.insert(confirmation_id, Arc::new(row));
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.3: Update a user card's lifecycle status.
    pub fn with_user_card_status(
        &self,
        user_card_id: BinaryId,
        status: crate::memory_v1_db_rows::UserCardStatus,
    ) -> Result<Self, CandidateError> {
        let existing = self
            .cards
            .get(&user_card_id)
            .ok_or(CandidateError::UnknownId {
                table: crate::memory_v1_db_rows::Table::UserCard,
                id: user_card_id,
            })?
            .clone();
        let mut row = (*existing).clone();
        row.status = status;
        let mut next = self.clone();
        next.cards.insert(user_card_id, Arc::new(row));
        Ok(next)
    }

    /// memory—v1 §4.12: Insert a new rule set with its initial version and pointer.
    pub fn with_rule_set_create(
        &self,
        rule_set_row: crate::memory_v1_db_rows::RuleSetRow,
        version_row: RuleSetVersionRow,
    ) -> Result<Self, CandidateError> {
        let row_count = self
            .row_count
            .checked_add(2)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        let mut next = self.clone();
        next.row_count = row_count;
        next.rule_sets
            .insert(rule_set_row.rule_set_id, Arc::new(rule_set_row.clone()));
        next.versions
            .entry(rule_set_row.rule_set_id)
            .or_default()
            .insert(
                version_row.version_bytes.clone(),
                Arc::new(version_row.clone()),
            );
        next.selections.insert(
            rule_set_row.rule_set_id,
            Arc::new(version_row.version_bytes.clone()),
        );
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.3: Check whether a user card is active.
    pub fn is_user_card_active(&self, user_card_id: BinaryId) -> bool {
        self.cards
            .get(&user_card_id)
            .map(|card| card.status == crate::memory_v1_db_rows::UserCardStatus::Active)
            .unwrap_or(false)
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
        use crate::memory_v1_db_rows::UserCardStatus;
use crate::memory_v1_db_rows::BindingLayer;
    use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

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
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(9),
                    user_id: id(2),
                    tenant_id: id(7),
                    status: UserCardStatus::Active,
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    rule_set_id: id(10),
                    owner_tenant_id: id(5),
                    current_version_bytes: Vec::new(),
                },
                RuleSetRow {
                    rule_set_id: id(11),
                    owner_tenant_id: id(6),
                    current_version_bytes: Vec::new(),
                },
            ],
            rule_set_versions: vec![version(10, 1), version(10, 2), version(11, 1)],
            bindings: vec![
                BindingRow {
                    binding_id: id(12),
                    user_card_id: id(8),
                    rule_set_id: id(10),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(13),
                    user_card_id: id(9),
                    rule_set_id: id(10),
                    binding_layer: BindingLayer::Overlay,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(14),
                    user_card_id: id(8),
                    rule_set_id: id(11),
                    binding_layer: BindingLayer::Overlay,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
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
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: id(15),
                rule_set_id: id(10),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![0],
                operation_id: vec![0xff],
                confirmed_at_bytes: vec![0],
                revoked_at: None,
                revoked_by: None,
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

    // memory—v1: Repeated rule-set references consume one aggregate read budget.
    #[test]
    fn confirmation_budget_counts_repeated_rule_set_references() {
        let mut candidate = candidate();
        let first = candidate.binding(id(12)).unwrap().unwrap();
        candidate
            .check_card_confirmation_budget(&[first, first])
            .unwrap();
        candidate.budget.max_table_rows = 3;
        let first = candidate.binding(id(12)).unwrap().unwrap();
        assert_eq!(
            candidate.check_card_confirmation_budget(&[first, first]),
            Err(CandidateError::ConfirmationBudgetExceeded { max: 3 })
        );
        candidate.budget.max_table_rows = 4;
        let first = candidate.binding(id(12)).unwrap().unwrap();
        candidate
            .check_card_confirmation_budget(&[first, first])
            .unwrap();
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
