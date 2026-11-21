//! Offline HAMT-backed candidates over supplied memory-v1 rows.
//!
//! These structures only index and check the supplied data. They do not establish
//! coverage, provenance, hash integrity, confirmation validity, or an ALLOW.
//! Parent links and reverse impact sets describe relationships, not permissions.
//! There is no database, network, read gate, or service-root installation here.

use std::collections::HashMap as TransientHashMap;
use std::sync::Arc;

mod checked_bindings;
mod context_load;
mod membership;
mod source_slots;
pub(crate) use context_load::{ContextDelta, ContextLoadError};
use membership::{add_member, Members, Membership};

use im::{HashMap, HashSet};

use crate::memory_v1_confirmation_index::ChangeConfirmationIndex;
use crate::memory_v1_db_rows::{
    binding_is_active, confirmation_lengths, require_tombstone_pair, BinaryId,
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow,
    Table, TableCounts, TenantRow, UserCardRow, UserCardStatus, UserRow, ValidationError,
};
use crate::memory_v1_registry::{RegistryError, RegistryReadGuard};
use crate::memory_v1_rules::{
    binding_confirmation_valid, change_confirmation_valid, classify_binding_confirmations,
    classify_change_confirmations, parse_version, BindingConfirmationState,
    ChangeConfirmationState, MemoryV1RuleError, PreparedRuleSet,
};

#[derive(Debug)]
struct SelectedRuleVersion {
    row: Arc<RuleSetVersionRow>,
    // Offline candidates may carry malformed rule content. Keep the error so
    // serving validation and evaluation still reject it at the existing gates.
    prepared: Result<PreparedRuleSet, MemoryV1RuleError>,
}

impl SelectedRuleVersion {
    // memory—v1: Derive the match plan from the exact canonical row it accompanies.
    fn new(row: Arc<RuleSetVersionRow>) -> Self {
        let prepared = PreparedRuleSet::prepare(&row);
        Self { row, prepared }
    }
}

/// Limits applied to a supplied candidate and each binding-bearing query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateBudget {
    /// Maximum combined number of rows across all nine supplied tables.
    pub max_table_rows: usize,
    /// Maximum number of bindings returned or traversed by one query.
    /// Historical APIs count historical rows; current-only queries count their
    /// complete unremoved relationship sets.
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
    /// A current rule refers to an unavailable, inactive or unknown registry entry.
    Registry(RegistryError),
    /// A binding or authorization dependency cannot be validated consistently.
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
    /// memory—v1: Insufficient or unknown headroom for a complete operation.
    WorkingMemoryUnavailable,
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
    checked_bindings: Option<Arc<checked_bindings::CheckedBindings>>,
    budget: CandidateBudget,
    // Optional process memory sampler; bounded offline candidates keep their caller limits.
    headroom: Option<fn() -> Option<usize>>,
    row_count: usize,
    users: HashMap<BinaryId, Arc<UserRow>>,
    identities: HashMap<BinaryId, Arc<IdentityCardRow>>,
    identity_by_user: HashMap<BinaryId, BinaryId>,
    tenants: HashMap<BinaryId, Arc<TenantRow>>,
    cards: HashMap<BinaryId, Arc<UserCardRow>>,
    rule_sets: HashMap<BinaryId, Arc<RuleSetRow>>,
    versions: HashMap<BinaryId, HashMap<Vec<u8>, Arc<RuleSetVersionRow>>>,
    source_projection: bool,
    archived_ids: HashMap<BinaryId, im::OrdSet<Vec<u8>>>,
    bindings: HashMap<BinaryId, Arc<BindingRow>>,
    confirmations: HashMap<BinaryId, Arc<BindingConfirmationRow>>,
    change_confirmations: HashMap<BinaryId, Arc<RuleSetChangeConfirmationRow>>,
    cards_by_user: HashMap<BinaryId, HashSet<BinaryId>>,
    cards_by_tenant: HashMap<BinaryId, HashSet<BinaryId>>,
    children_by_tenant: HashMap<BinaryId, HashSet<BinaryId>>,
    bindings_by_card: Membership,
    unremoved_bindings_by_card: Membership,
    bindings_by_rule_set: Membership,
    unremoved_bindings_by_rule_set: Membership,
    confirmations_by_binding: Membership,
    binding_confirmation_states: HashMap<BinaryId, BindingConfirmationState>,
    changes_by_rule_set: Membership,
    change_confirmation_index: ChangeConfirmationIndex,
    selections: HashMap<BinaryId, Arc<SelectedRuleVersion>>,
    // Monotonic generations travel with each immutable candidate snapshot.
    card_dependencies: HashMap<BinaryId, u64>,
    rule_set_dependencies: HashMap<BinaryId, u64>,
    tenant_tree_version: u64,
}

// A retirement proof is deliberately confined to this child module. The root
// cannot construct it, replace its candidate, or borrow that candidate mutably.
// Its guarantee depends on this constructor retaining the unchanged persistent
// collections and replacing only the existing rule-set row and its generation.
mod retirement {
    use super::{
        binding_is_active, Arc, BinaryId, CandidateError, HamtCandidate, Members, RuleSetStatus,
        Table,
    };

    pub(crate) struct ValidatedRetirement {
        next: HamtCandidate,
    }

    pub(crate) struct PublishableRetirement {
        next: HamtCandidate,
    }

    impl ValidatedRetirement {
        #[cfg(test)]
        // memory—v1: Preserve the candidate-only operation for contract tests.
        pub(super) fn into_candidate(self) -> HamtCandidate {
            self.next
        }

        // memory—v1: Independently check confirmation indexes on the exact
        // next candidate before releasing it to the root publication path.
        pub(crate) fn validate_confirmations(
            self,
        ) -> Result<PublishableRetirement, CandidateError> {
            self.next.validate_confirmation_indexes()?;
            Ok(PublishableRetirement { next: self.next })
        }
    }

    impl PublishableRetirement {
        // memory—v1: Digest preparation can only read the sealed candidate.
        pub(crate) fn candidate(&self) -> &HamtCandidate {
            &self.next
        }

        // memory—v1: Consume the proof when moving its exact candidate into CAS.
        pub(crate) fn into_published_candidate(self) -> HamtCandidate {
            self.next
        }
    }

    // memory—v1: Check all current binding indexes, the target relationship
    // and its budget, then retain the verified immutable binding facts in next.
    pub(super) fn prepare(
        current: &HamtCandidate,
        rule_set_id: BinaryId,
    ) -> Result<ValidatedRetirement, CandidateError> {
        current.require_active_rule_set(rule_set_id)?;
        current.validate_binding_indexes()?;
        let rule_set = current
            .rule_set(rule_set_id)
            .ok_or(CandidateError::InconsistentBinding)?;
        if rule_set.rule_set_id != rule_set_id
            || !current
                .tenant(rule_set.owner_tenant_id)
                .is_some_and(|tenant| tenant.tenant_id == rule_set.owner_tenant_id)
        {
            return Err(CandidateError::InconsistentBinding);
        }
        let ids = current.unremoved_bindings_by_rule_set.get(&rule_set_id);
        current.check_bindings(ids.map_or(0, Members::len))?;
        for id in ids.into_iter().flat_map(|ids| ids.iter()) {
            let binding = current
                .bindings
                .get(id)
                .ok_or(CandidateError::InconsistentBinding)?;
            let card = current
                .user_card(binding.user_card_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if binding.binding_id != *id
                || binding.rule_set_id != rule_set_id
                || binding.removed_at.is_some()
                || binding.removed_by.is_some()
                || card.user_card_id != binding.user_card_id
                || card.tenant_id != rule_set.owner_tenant_id
                || !current
                    .user(card.user_id)
                    .is_some_and(|user| user.user_id == card.user_id)
                || !current
                    .identity_for_user(card.user_id)
                    .is_some_and(|identity| {
                        identity.user_id == card.user_id
                            && current.identity_by_user.get(&card.user_id)
                                == Some(&identity.identity_card_id)
                    })
                || !current
                    .tenant(card.tenant_id)
                    .is_some_and(|tenant| tenant.tenant_id == card.tenant_id)
                || binding_is_active(binding, Some(card))
            {
                return Err(CandidateError::InconsistentBinding);
            }
        }
        let generation = current
            .rule_set_dependencies
            .get(&rule_set_id)
            .copied()
            .ok_or(CandidateError::UnknownId {
                table: Table::RuleSet,
                id: rule_set_id,
            })?
            .checked_add(1)
            .ok_or(CandidateError::InconsistentBinding)?;
        let mut row = rule_set.clone();
        row.status = RuleSetStatus::Retired;
        let mut rule_sets = current.rule_sets.clone();
        rule_sets.insert(rule_set_id, Arc::new(row));
        let mut rule_set_dependencies = current.rule_set_dependencies.clone();
        rule_set_dependencies.insert(rule_set_id, generation);
        let next = HamtCandidate {
            rule_sets,
            rule_set_dependencies,
            ..current.clone()
        };
        Ok(ValidatedRetirement { next })
    }
}

pub(crate) use retirement::PublishableRetirement;

// memory—v1: Update the private bucket through the persistent map's copy-on-write path.
fn index(index: &mut HashMap<BinaryId, HashSet<BinaryId>>, key: BinaryId, value: BinaryId) {
    index.entry(key).or_default().insert(value);
}

// memory—v1: Count an index without allocating a reconstructed copy. Empty
// buckets are invalid, and overflow must not make an incomplete index look exact.
fn count_nonempty(mut sizes: impl Iterator<Item = usize>) -> Option<usize> {
    sizes.try_fold(0usize, |total, size| {
        if size == 0 {
            None
        } else {
            total.checked_add(size)
        }
    })
}

// memory—v1: Validate complete membership counts for binding and confirmation indexes.
fn index_membership_count(index: &Membership) -> Option<usize> {
    count_nonempty(index.values().map(Members::len))
}

// memory—v1: Count all supplied table rows without arithmetic wraparound.
pub(crate) fn count_rows(rows: &CandidateRows, max: usize) -> Result<usize, CandidateError> {
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
            checked_bindings: None,
            budget,
            headroom: None,
            row_count,
            users: HashMap::new(),
            identities: HashMap::new(),
            identity_by_user: HashMap::new(),
            tenants: HashMap::new(),
            cards: HashMap::new(),
            rule_sets: HashMap::new(),
            versions: HashMap::new(),
            source_projection: false,
            archived_ids: HashMap::new(),
            bindings: HashMap::new(),
            confirmations: HashMap::new(),
            change_confirmations: HashMap::new(),
            cards_by_user: HashMap::new(),
            cards_by_tenant: HashMap::new(),
            children_by_tenant: HashMap::new(),
            bindings_by_card: HashMap::new(),
            unremoved_bindings_by_card: HashMap::new(),
            bindings_by_rule_set: HashMap::new(),
            unremoved_bindings_by_rule_set: HashMap::new(),
            confirmations_by_binding: HashMap::new(),
            binding_confirmation_states: HashMap::new(),
            changes_by_rule_set: HashMap::new(),
            change_confirmation_index: ChangeConfirmationIndex::default(),
            selections: HashMap::new(),
            card_dependencies: HashMap::new(),
            rule_set_dependencies: HashMap::new(),
            tenant_tree_version: 0,
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
            candidate.card_dependencies.insert(row.user_card_id, 0);
            candidate.cards.insert(row.user_card_id, Arc::new(row));
        }
        for row in rows.rule_sets {
            candidate.rule_set_dependencies.insert(row.rule_set_id, 0);
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
        // Rows were checked for paired removal markers above. Historical rows
        // remain indexed but do not occupy the current relationship slots.
        let mut binding_pairs = std::collections::BTreeSet::new();
        for row in &rows.bindings {
            if row.removed_at.is_none()
                && !binding_pairs.insert((row.user_card_id, row.rule_set_id))
            {
                return Err(CandidateError::DoubleBinding {
                    user_card_id: row.user_card_id,
                    rule_set_id: row.rule_set_id,
                });
            }
        }
        for row in rows.bindings {
            if row.removed_at.is_none()
                && row.binding_layer == BindingLayer::Overlay
                && candidate
                    .bindings_by_card
                    .get(&row.user_card_id)
                    .into_iter()
                    .flat_map(|ids| ids.iter())
                    .filter_map(|id| candidate.bindings.get(id))
                    .any(|existing| {
                        existing.removed_at.is_none()
                            && existing.binding_layer == BindingLayer::Overlay
                    })
            {
                return Err(CandidateError::DoubleOverlay {
                    user_card_id: row.user_card_id,
                });
            }
            add_member(
                &mut candidate.bindings_by_card,
                row.user_card_id,
                row.binding_id,
            );
            if row.removed_at.is_none() {
                add_member(
                    &mut candidate.unremoved_bindings_by_card,
                    row.user_card_id,
                    row.binding_id,
                );
                add_member(
                    &mut candidate.unremoved_bindings_by_rule_set,
                    row.rule_set_id,
                    row.binding_id,
                );
            }
            add_member(
                &mut candidate.bindings_by_rule_set,
                row.rule_set_id,
                row.binding_id,
            );
            candidate.bindings.insert(row.binding_id, Arc::new(row));
        }
        for row in rows.binding_confirmations {
            add_member(
                &mut candidate.confirmations_by_binding,
                row.binding_id,
                row.confirmation_id,
            );
            candidate
                .confirmations
                .insert(row.confirmation_id, Arc::new(row));
        }
        for row in rows.rule_set_change_confirmations {
            add_member(
                &mut candidate.changes_by_rule_set,
                row.rule_set_id,
                row.confirmation_id,
            );
            candidate
                .change_confirmations
                .insert(row.confirmation_id, Arc::new(row));
        }
        for selection in selections {
            candidate.prepare_selection(selection.rule_set_id, &selection.version_bytes)?;
        }
        candidate.change_confirmation_index = ChangeConfirmationIndex::from_rows(
            candidate.change_confirmations.values().map(Arc::as_ref),
        )
        .map_err(|_| CandidateError::InconsistentBinding)?;
        for binding_id in candidate.bindings.keys().copied().collect::<Vec<_>>() {
            candidate.refresh_binding_confirmation_state(binding_id)?;
        }
        candidate.check_publication_indexes(false)?;
        Ok(candidate)
    }

    // memory—v1: Prove exact coverage without rebuilding the indexes. Each
    // binding must appear under its expected keys; equal membership counts then
    // exclude extra IDs and foreign keys. Empty buckets remain invalid.
    pub(crate) fn validate_binding_indexes(&self) -> Result<(), CandidateError> {
        let mut unremoved_count = 0usize;
        for (id, row) in &self.bindings {
            if *id != row.binding_id
                || !self.cards.contains_key(&row.user_card_id)
                || !self.rule_sets.contains_key(&row.rule_set_id)
                || !self
                    .bindings_by_card
                    .get(&row.user_card_id)
                    .is_some_and(|ids| ids.contains(id))
                || !self
                    .bindings_by_rule_set
                    .get(&row.rule_set_id)
                    .is_some_and(|ids| ids.contains(id))
            {
                return Err(CandidateError::InconsistentBinding);
            }
            match (row.removed_at, row.removed_by) {
                (None, None) => {
                    if !self
                        .unremoved_bindings_by_card
                        .get(&row.user_card_id)
                        .is_some_and(|ids| ids.contains(id))
                        || !self
                            .unremoved_bindings_by_rule_set
                            .get(&row.rule_set_id)
                            .is_some_and(|ids| ids.contains(id))
                    {
                        return Err(CandidateError::InconsistentBinding);
                    }
                    unremoved_count = unremoved_count
                        .checked_add(1)
                        .ok_or(CandidateError::InconsistentBinding)?;
                }
                (Some(_), Some(_)) => {}
                _ => return Err(CandidateError::InconsistentBinding),
            }
        }
        if index_membership_count(&self.bindings_by_card) != Some(self.bindings.len())
            || index_membership_count(&self.bindings_by_rule_set) != Some(self.bindings.len())
            || index_membership_count(&self.unremoved_bindings_by_card) != Some(unremoved_count)
            || index_membership_count(&self.unremoved_bindings_by_rule_set) != Some(unremoved_count)
        {
            return Err(CandidateError::InconsistentBinding);
        }
        Ok(())
    }

    // memory—v1: Prove both confirmation indexes cover exactly their source
    // rows. Membership plus equal counts rejects missing, foreign and dangling
    // IDs. Group checked facts temporarily to classify complete binding histories
    // without retrieving those rows again through the persistent indexes.
    pub(crate) fn validate_confirmation_indexes(&self) -> Result<(), CandidateError> {
        let mut histories: TransientHashMap<BinaryId, Vec<&BindingConfirmationRow>> =
            TransientHashMap::new();
        for (id, row) in &self.confirmations {
            if *id != row.confirmation_id
                || !self.bindings.contains_key(&row.binding_id)
                || !self
                    .confirmations_by_binding
                    .get(&row.binding_id)
                    .is_some_and(|ids| ids.contains(id))
            {
                return Err(CandidateError::InconsistentBinding);
            }
            histories
                .entry(row.binding_id)
                .or_default()
                .push(row.as_ref());
        }
        if index_membership_count(&self.confirmations_by_binding) != Some(self.confirmations.len())
            || self.binding_confirmation_states.len() != self.bindings.len()
        {
            return Err(CandidateError::InconsistentBinding);
        }
        for binding in self.bindings.values() {
            let binding_id = binding.binding_id;
            let binding = self
                .bindings
                .get(&binding_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            let state = classify_binding_confirmations(
                histories
                    .get(&binding_id)
                    .into_iter()
                    .flat_map(|rows| rows.iter().copied()),
                binding_id,
                binding.rule_set_id,
            );
            if self.binding_confirmation_states.get(&binding_id) != Some(&state) {
                return Err(CandidateError::InconsistentBinding);
            }
        }
        self.validate_change_confirmation_indexes()
    }

    // memory—v1: Check all source-change facts, reverse memberships and derived counters.
    fn validate_change_confirmation_indexes(&self) -> Result<(), CandidateError> {
        for (id, row) in &self.change_confirmations {
            if *id != row.confirmation_id
                || !self.rule_sets.contains_key(&row.rule_set_id)
                || !self
                    .changes_by_rule_set
                    .get(&row.rule_set_id)
                    .is_some_and(|ids| ids.contains(id))
            {
                return Err(CandidateError::InconsistentBinding);
            }
        }
        if index_membership_count(&self.changes_by_rule_set)
            != Some(self.change_confirmations.len())
        {
            return Err(CandidateError::InconsistentBinding);
        }
        let expected =
            ChangeConfirmationIndex::from_rows(self.change_confirmations.values().map(Arc::as_ref))
                .map_err(|_| CandidateError::InconsistentBinding)?;
        if self.change_confirmation_index != expected {
            return Err(CandidateError::InconsistentBinding);
        }
        Ok(())
    }

    // memory—v1: Reclassify one binding from its complete, checked history. The
    // caller first proves the relationship index covers every source row.
    fn compute_binding_confirmation_state(
        &self,
        binding_id: BinaryId,
    ) -> Result<BindingConfirmationState, CandidateError> {
        let binding = self
            .bindings
            .get(&binding_id)
            .ok_or(CandidateError::InconsistentBinding)?;
        let mut inconsistent = false;
        let mut rows = self
            .confirmations_by_binding
            .get(&binding_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| match self.confirmations.get(id) {
                Some(row) if row.confirmation_id == *id && row.binding_id == binding_id => {
                    Some(row.as_ref())
                }
                _ => {
                    inconsistent = true;
                    None
                }
            });
        let state = classify_binding_confirmations(rows.by_ref(), binding_id, binding.rule_set_id);
        // Classification may stop early on Invalid. Drain the remaining IDs so a
        // dangling or foreign row cannot hide behind an earlier invalid fact.
        rows.for_each(drop);
        if inconsistent {
            Err(CandidateError::InconsistentBinding)
        } else {
            Ok(state)
        }
    }

    // memory—v1: Update the derived state only on this private candidate; root
    // publication later independently checks it against the complete facts.
    fn refresh_binding_confirmation_state(
        &mut self,
        binding_id: BinaryId,
    ) -> Result<(), CandidateError> {
        let state = self.compute_binding_confirmation_state(binding_id)?;
        self.binding_confirmation_states.insert(binding_id, state);
        Ok(())
    }

    // memory—v1: Read the already checked state for exactly this binding fact.
    pub(crate) fn binding_confirmation_state(
        &self,
        binding: &BindingRow,
    ) -> Result<BindingConfirmationState, CandidateError> {
        if !self
            .bindings
            .get(&binding.binding_id)
            .is_some_and(|stored| stored.as_ref() == binding)
        {
            return Err(CandidateError::InconsistentBinding);
        }
        self.binding_confirmation_states
            .get(&binding.binding_id)
            .copied()
            .ok_or(CandidateError::InconsistentBinding)
    }

    // memory—v1: Read the classification for this rule set and exact selection;
    // the index is rebuilt from source facts before adoption and publication.
    pub(crate) fn change_confirmation_state(
        &self,
        rule_set_id: BinaryId,
        version: &[u8],
    ) -> Result<ChangeConfirmationState, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        Ok(self.change_confirmation_index.state(rule_set_id, version))
    }

    #[cfg(test)]
    // memory—v1: Lower the synthetic read budget without changing fixture rows.
    pub(crate) fn set_max_table_rows_for_test(&mut self, max: usize) {
        self.budget.max_table_rows = max;
    }

    #[cfg(test)]
    // memory—v1: Inject a wrong derived binding state for publication tests.
    pub(crate) fn corrupt_binding_confirmation_state_for_test(&mut self, binding_id: BinaryId) {
        self.binding_confirmation_states
            .insert(binding_id, BindingConfirmationState::Invalid);
    }

    #[cfg(test)]
    // memory—v1: Omit derived change states to test the publication gate.
    pub(crate) fn omit_change_confirmation_index_for_test(&mut self) {
        self.change_confirmation_index = ChangeConfirmationIndex::default();
    }

    #[cfg(test)]
    // memory—v1: Inject an omitted relationship to test the publication gate.
    pub(crate) fn omit_unremoved_binding_for_test(&mut self, card_id: BinaryId) {
        self.unremoved_bindings_by_card.remove(&card_id);
    }

    #[cfg(test)]
    // memory—v1: Inject an omitted impact relationship for publication tests.
    pub(crate) fn omit_unremoved_rule_set_binding_for_test(&mut self, rule_set_id: BinaryId) {
        self.unremoved_bindings_by_rule_set.remove(&rule_set_id);
    }

    #[cfg(test)]
    // memory—v1: Remove one binding index bucket in a synthetic root snapshot.
    pub(crate) fn omit_binding_index_for_test(
        &mut self,
        which: usize,
        card_id: BinaryId,
        rule_set_id: BinaryId,
    ) {
        match which {
            0 => self.bindings_by_card.remove(&card_id),
            1 => self.bindings_by_rule_set.remove(&rule_set_id),
            2 => self.unremoved_bindings_by_card.remove(&card_id),
            3 => self.unremoved_bindings_by_rule_set.remove(&rule_set_id),
            _ => panic!("unknown binding index"),
        };
    }

    #[cfg(test)]
    // memory—v1: Compare every field used by binding index validation.
    pub(crate) fn assert_retirement_relationships_unchanged_for_test(&self, next: &Self) {
        assert_eq!(self.bindings, next.bindings);
        assert_eq!(self.cards, next.cards);
        assert_eq!(self.rule_sets.len(), next.rule_sets.len());
        assert!(self
            .rule_sets
            .keys()
            .all(|key| next.rule_sets.contains_key(key)));
        assert_eq!(self.bindings_by_card, next.bindings_by_card);
        assert_eq!(self.bindings_by_rule_set, next.bindings_by_rule_set);
        assert_eq!(
            self.unremoved_bindings_by_card,
            next.unremoved_bindings_by_card
        );
        assert_eq!(
            self.unremoved_bindings_by_rule_set,
            next.unremoved_bindings_by_rule_set
        );
    }

    #[cfg(test)]
    // memory—v1: Inject a dangling confirmation reference for publication tests.
    pub(crate) fn insert_dangling_confirmation_for_test(&mut self, binding_id: BinaryId) {
        add_member(&mut self.confirmations_by_binding, binding_id, [0; 16]);
    }

    #[cfg(test)]
    // memory—v1: Inject a dangling change-confirmation reference for publication tests.
    pub(crate) fn insert_dangling_change_for_test(&mut self, rule_set_id: BinaryId) {
        add_member(&mut self.changes_by_rule_set, rule_set_id, [0; 16]);
    }

    /// memory—v1: Return the configured limits and combined nine-table row count.
    pub fn budget_and_row_count(&self) -> (CandidateBudget, usize) {
        (self.budget, self.row_count)
    }

    pub(crate) fn card_dependency_generation(&self, id: BinaryId) -> Option<u64> {
        self.card_dependencies.get(&id).copied()
    }

    pub(crate) fn rule_set_dependency_generation(&self, id: BinaryId) -> Option<u64> {
        self.rule_set_dependencies.get(&id).copied()
    }

    // memory—v1 §15.10.3: MAX is an exhausted dependency generation. It may
    // remain in an immutable snapshot for diagnostics, but it can never prove
    // freshness for a positive authorization decision.
    pub(crate) fn card_dependency_exhausted(&self, id: BinaryId) -> bool {
        self.card_dependencies
            .get(&id)
            .is_some_and(|generation| *generation == u64::MAX)
    }

    // memory—v1 §15.10.3: A rule-set generation at MAX has no successor and
    // therefore cannot support a fresh authorization dependency.
    pub(crate) fn rule_set_dependency_exhausted(&self, id: BinaryId) -> bool {
        self.rule_set_dependencies
            .get(&id)
            .is_some_and(|generation| *generation == u64::MAX)
    }

    // memory—v1 §15.10.3: Limit the blast radius to one card and its active
    // rule-set relationships. Historical removed bindings do not make an
    // unrelated card unavailable. A missing or dangling relationship is not
    // treated as safe because the affected scope cannot be proven.
    pub(crate) fn card_authorization_dependency_exhausted(
        &self,
        id: BinaryId,
    ) -> Result<bool, CandidateError> {
        let card = self.unremoved_card_candidate(id)?.0;
        let generation = self
            .card_dependency_generation(id)
            .ok_or(CandidateError::InconsistentBinding)?;
        if generation == u64::MAX {
            return Ok(true);
        }
        for binding in card.bindings {
            if binding.user_card_id != id {
                return Err(CandidateError::InconsistentBinding);
            }
            if binding.removed_at.is_some() != binding.removed_by.is_some() {
                return Err(CandidateError::InconsistentBinding);
            }
            if !binding_is_active(binding, Some(card.card)) {
                continue;
            }
            self.rule_set(binding.rule_set_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            let rule_set_generation = self
                .rule_set_dependency_generation(binding.rule_set_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if rule_set_generation == u64::MAX {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn set_card_dependency_generation_for_test(
        &mut self,
        id: BinaryId,
        generation: u64,
    ) {
        self.card_dependencies.insert(id, generation);
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn set_rule_set_dependency_generation_for_test(
        &mut self,
        id: BinaryId,
        generation: u64,
    ) {
        self.rule_set_dependencies.insert(id, generation);
    }

    fn advance_card_dependency(&mut self, id: BinaryId) -> Result<(), CandidateError> {
        let generation =
            self.card_dependencies
                .get(&id)
                .copied()
                .ok_or(CandidateError::UnknownId {
                    table: Table::UserCard,
                    id,
                })?;
        self.card_dependencies.insert(
            id,
            // The legacy error shape has no generation-exhaustion variant;
            // refuse the candidate instead of reusing a dependency generation.
            generation
                .checked_add(1)
                .ok_or(CandidateError::InconsistentBinding)?,
        );
        Ok(())
    }

    fn advance_rule_set_dependency(&mut self, id: BinaryId) -> Result<(), CandidateError> {
        let generation =
            self.rule_set_dependencies
                .get(&id)
                .copied()
                .ok_or(CandidateError::UnknownId {
                    table: Table::RuleSet,
                    id,
                })?;
        self.rule_set_dependencies.insert(
            id,
            // The legacy error shape has no generation-exhaustion variant;
            // refuse the candidate instead of reusing a dependency generation.
            generation
                .checked_add(1)
                .ok_or(CandidateError::InconsistentBinding)?,
        );
        Ok(())
    }

    // memory—v1: The tenant-tree generation travels with the immutable graph.
    pub(crate) fn tenant_tree_version(&self) -> u64 {
        self.tenant_tree_version
    }

    #[cfg(test)]
    // memory—v1: Inject exhaustion into one synthetic immutable snapshot.
    pub(crate) fn exhaust_tenant_tree_for_test(&mut self) {
        self.tenant_tree_version = u64::MAX;
    }

    #[cfg(test)]
    pub(crate) fn digest_inputs(&self) -> (CandidateRows, Vec<CurrentSelection>) {
        let rows = CandidateRows {
            users: self.users.values().map(|row| (**row).clone()).collect(),
            identity_cards: self
                .identities
                .values()
                .map(|row| (**row).clone())
                .collect(),
            tenants: self.tenants.values().map(|row| (**row).clone()).collect(),
            user_cards: self.cards.values().map(|row| (**row).clone()).collect(),
            rule_sets: self.rule_sets.values().map(|row| (**row).clone()).collect(),
            rule_set_versions: self
                .versions
                .values()
                .flat_map(|versions| versions.values().map(|row| (**row).clone()))
                .collect(),
            bindings: self.bindings.values().map(|row| (**row).clone()).collect(),
            binding_confirmations: self
                .confirmations
                .values()
                .map(|row| (**row).clone())
                .collect(),
            rule_set_change_confirmations: self
                .change_confirmations
                .values()
                .map(|row| (**row).clone())
                .collect(),
        };
        let selections = self
            .selections
            .iter()
            .map(|(rule_set_id, selection)| CurrentSelection {
                rule_set_id: *rule_set_id,
                version_bytes: selection.row.version_bytes.clone(),
            })
            .collect();
        (rows, selections)
    }

    /// memory—v1: Row count of each table held by this candidate.
    pub fn table_counts(&self) -> TableCounts {
        TableCounts {
            users: self.users.len(),
            identity_cards: self.identities.len(),
            tenants: self.tenants.len(),
            user_cards: self.cards.len(),
            rule_sets: self.rule_sets.len(),
            rule_set_versions: self.versions.values().map(HashMap::len).sum::<usize>()
                + self
                    .archived_ids
                    .values()
                    .map(im::OrdSet::len)
                    .sum::<usize>(),
            bindings: self.bindings.len(),
            binding_confirmations: self.confirmations.len(),
            rule_set_change_confirmations: self.change_confirmations.len(),
        }
    }

    /// memory—v1 §4.13: Every root selection must match its explicit row pointer.
    pub fn has_valid_current_pointers(&self) -> bool {
        self.selections.len() == self.rule_sets.len()
            && self.rule_sets.iter().all(|(id, rule_set)| {
                !rule_set.current_version_bytes.is_empty()
                    && self.selections.get(id).is_some_and(|selection| {
                        selection.row.version_bytes == rule_set.current_version_bytes
                    })
                    && self.version(*id, &rule_set.current_version_bytes).is_some()
            })
    }

    /// memory—v1: Whether every rule set holds exactly one stored version.
    /// This legacy diagnostic does not establish the current-version pointer.
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

    /// memory—v1: Look up a retained body. Only diagnostic candidates can retain historical bodies.
    pub fn version(&self, rule_set_id: BinaryId, version: &[u8]) -> Option<&RuleSetVersionRow> {
        self.versions
            .get(&rule_set_id)?
            .get(version)
            .map(Arc::as_ref)
    }

    // memory—v1: Inspect one already validated row while preparing a root
    // publication. This is not an authorization read or a public query.
    pub(crate) fn binding_for_digest(&self, id: BinaryId) -> Option<&BindingRow> {
        self.bindings.get(&id).map(Arc::as_ref)
    }

    // memory—v1: Look up the exact confirmation row for digest publication.
    pub(crate) fn confirmation(&self, id: BinaryId) -> Option<&BindingConfirmationRow> {
        self.confirmations.get(&id).map(Arc::as_ref)
    }

    // memory—v1: Look up the exact change-confirmation row for digest publication.
    pub(crate) fn change_confirmation(
        &self,
        id: BinaryId,
    ) -> Option<&RuleSetChangeConfirmationRow> {
        self.change_confirmations.get(&id).map(Arc::as_ref)
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
            .map(|selected| selected.row.as_ref()))
    }

    // memory—v1: Bind a borrowed plan to the exact selected row from this snapshot.
    pub(crate) fn prepared_selected_rules(
        &self,
        row: &RuleSetVersionRow,
    ) -> Option<&PreparedRuleSet> {
        let selected = self.selections.get(&row.rule_set_id)?;
        if !std::ptr::eq(selected.row.as_ref(), row) {
            return None;
        }
        selected.prepared.as_ref().ok()
    }

    // memory—v1: No mutable cache or content-address lookup. The plan is
    // replaced with the selection and shared with unchanged snapshots.
    fn prepare_selection(
        &mut self,
        rule_set_id: BinaryId,
        version: &[u8],
    ) -> Result<(), CandidateError> {
        if self
            .selections
            .get(&rule_set_id)
            .is_some_and(|selection| selection.row.version_bytes == version)
        {
            return Ok(());
        }
        let row = self
            .versions
            .get(&rule_set_id)
            .and_then(|versions| versions.get(version))
            .ok_or_else(|| CandidateError::UnknownVersion {
                rule_set_id,
                version_bytes: version.to_vec(),
            })?;
        self.selections.insert(
            rule_set_id,
            Arc::new(SelectedRuleVersion::new(Arc::clone(row))),
        );
        Ok(())
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
        self.check_bindings(ids.map_or(0, Members::len))?;
        let bindings = ids
            .into_iter()
            .flat_map(|ids| ids.iter())
            .map(|id| self.bindings[id].as_ref())
            .collect();
        Ok(CardCandidate { card, bindings })
    }

    // memory—v1: Read only unremoved relationships under the binding budget.
    // Exact index coverage is proved when this immutable snapshot is published.
    // The separate presence bit retains the historical meaning without traversal.
    pub(crate) fn unremoved_card_candidate(
        &self,
        card_id: BinaryId,
    ) -> Result<(CardCandidate<'_>, bool), CandidateError> {
        let card = self.user_card(card_id).ok_or(CandidateError::UnknownId {
            table: Table::UserCard,
            id: card_id,
        })?;
        let ids = self.unremoved_bindings_by_card.get(&card_id);
        self.check_bindings(ids.map_or(0, Members::len))?;
        let mut bindings = Vec::with_capacity(ids.map_or(0, Members::len));
        for id in ids.into_iter().flat_map(|ids| ids.iter()) {
            let binding = self
                .bindings
                .get(id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if binding.binding_id != *id
                || binding.user_card_id != card_id
                || binding.removed_at.is_some()
                || binding.removed_by.is_some()
            {
                return Err(CandidateError::InconsistentBinding);
            }
            bindings.push(binding.as_ref());
        }
        let has_history = self
            .bindings_by_card
            .get(&card_id)
            .is_some_and(|ids| !ids.is_empty());
        Ok((CardCandidate { card, bindings }, has_history))
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
                    .map_or(0, Members::len),
                self.changes_by_rule_set
                    .get(&binding.rule_set_id)
                    .map_or(0, Members::len),
            ] {
                total = total
                    .checked_add(count)
                    .filter(|sum| *sum <= max)
                    .ok_or(CandidateError::ConfirmationBudgetExceeded { max })?;
            }
        }
        self.check_read_workspace(total)
    }

    /// memory—v1: Return every supplied confirmation for a binding, across versions.
    /// A dangling or misindexed row is rejected rather than panicking.
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
        self.confirmations_by_binding
            .get(&binding_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .map(|id| {
                let row = self
                    .confirmations
                    .get(id)
                    .ok_or(CandidateError::InconsistentBinding)?;
                if row.confirmation_id != *id || row.binding_id != binding_id {
                    return Err(CandidateError::InconsistentBinding);
                }
                Ok(row.as_ref())
            })
            .collect()
    }

    /// memory—v1: Resolve the binding that owns a confirmation row.
    pub fn binding_for_confirmation(
        &self,
        confirmation_id: BinaryId,
    ) -> Result<&BindingRow, CandidateError> {
        let confirmation =
            self.confirmations
                .get(&confirmation_id)
                .ok_or(CandidateError::UnknownId {
                    table: Table::BindingConfirmation,
                    id: confirmation_id,
                })?;
        if confirmation.confirmation_id != confirmation_id {
            return Err(CandidateError::InconsistentBinding);
        }
        self.binding(confirmation.binding_id)?
            .ok_or(CandidateError::InconsistentBinding)
    }

    /// memory—v1: Return every supplied change-confirmation row for a rule set.
    /// A dangling or misindexed row is rejected rather than panicking.
    pub fn change_confirmations(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<Vec<&RuleSetChangeConfirmationRow>, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        self.changes_by_rule_set
            .get(&rule_set_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .map(|id| {
                let row = self
                    .change_confirmations
                    .get(id)
                    .ok_or(CandidateError::InconsistentBinding)?;
                if row.confirmation_id != *id || row.rule_set_id != rule_set_id {
                    return Err(CandidateError::InconsistentBinding);
                }
                Ok(row.as_ref())
            })
            .collect()
    }

    /// memory—v1: Compute direct reverse relationships within the binding budget.
    pub fn rule_set_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RuleSetImpactCandidate, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        let bindings = self.bindings_by_rule_set.get(&rule_set_id);
        self.check_bindings(bindings.map_or(0, Members::len))?;
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

    /// memory—v1 §4.11/§4.12/§4.13: Compute the conservative impact set
    /// for a rule-set change. This is a structural SoD guard, not an authority
    /// decision. The historical `rule_set_impact` contract remains unchanged.
    ///
    /// Every binding that has not been fully marked REMOVED is included,
    /// including bindings on disabled cards, bindings with revoked confirmations,
    /// and bindings outside their validity window. Those relationships may become
    /// effective again after a lifecycle action or at a later time, while a
    /// historical removed binding is no longer part of the rule-set relation.
    /// The unremoved relationship count is checked against the binding budget;
    /// removed history does not exhaust the budget for the current impact set.
    /// Missing relationships, a tenant mismatch, a half tombstone or a budget
    /// overflow are returned as bad data so the request layer fails closed as
    /// PENDING.
    pub fn rule_set_change_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RuleSetImpactCandidate, CandidateError> {
        self.require_rule_set(rule_set_id)?;
        let rule_set = self
            .rule_set(rule_set_id)
            .ok_or(CandidateError::InconsistentBinding)?;
        if self.tenant(rule_set.owner_tenant_id).is_none() {
            return Err(CandidateError::InconsistentBinding);
        }
        let bindings = self.unremoved_bindings_by_rule_set.get(&rule_set_id);
        self.check_bindings(bindings.map_or(0, Members::len))?;
        let mut result = RuleSetImpactCandidate {
            binding_ids: HashSet::new(),
            card_ids: HashSet::new(),
            user_ids: HashSet::new(),
            tenant_ids: HashSet::new(),
        };
        for id in bindings.into_iter().flat_map(|ids| ids.iter()) {
            let binding = self
                .bindings
                .get(id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if binding.binding_id != *id
                || binding.rule_set_id != rule_set_id
                || binding.removed_at.is_some()
                || binding.removed_by.is_some()
            {
                return Err(CandidateError::InconsistentBinding);
            }
            let card = self
                .user_card(binding.user_card_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if self.user(card.user_id).is_none()
                || self.tenant(card.tenant_id).is_none()
                || card.tenant_id != rule_set.owner_tenant_id
            {
                return Err(CandidateError::InconsistentBinding);
            }
            result.binding_ids.insert(*id);
            result.card_ids.insert(card.user_card_id);
            result.user_ids.insert(card.user_id);
            result.tenant_ids.insert(card.tenant_id);
        }
        Ok(result)
    }

    // memory—v1 §4.9: Validate every current rule against one stable registry.
    // Historical versions remain immutable archives and are not serving inputs.
    pub(crate) fn validate_current_registry(
        &self,
        registry: &RegistryReadGuard<'_>,
    ) -> Result<(), CandidateError> {
        for rule_set_id in self.rule_sets.keys() {
            let version =
                self.selected_version(*rule_set_id)?
                    .ok_or(CandidateError::UnknownVersion {
                        rule_set_id: *rule_set_id,
                        version_bytes: Vec::new(),
                    })?;
            let content = parse_version(version).map_err(CandidateError::RuleIntegrity)?;
            registry
                .validate_rules(&content)
                .map_err(CandidateError::Registry)?;
        }
        Ok(())
    }

    /// memory—v1: Validate selected versions and their active change confirmations
    /// for a serving authorization root. This check does not infer confirmer
    /// authority or prove that candidate rows came from a trusted source.
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
            let change_confirmation_state = classify_change_confirmations(
                self.change_confirmations(*rule_set_id)?,
                *rule_set_id,
                &version.version_bytes,
            );
            if change_confirmation_state != ChangeConfirmationState::Active {
                return Err(CandidateError::Rows(
                    ValidationError::MissingVersionReference {
                        table: Table::RuleSetChangeConfirmation,
                        rule_set_id: *rule_set_id,
                        version_bytes: version.version_bytes.clone(),
                    },
                ));
            }
        }
        for binding in self.bindings.values() {
            // memory—v1 §4.12 B-2.2: tombstoned bindings are deliberate
            // withdrawals and need no confirmation to serve.
            if binding.removed_at.is_some() {
                continue;
            }
            let card = self
                .user_card(binding.user_card_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            let rule_set = self
                .rule_set(binding.rule_set_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if card.tenant_id != rule_set.owner_tenant_id
                || (binding_is_active(binding, Some(card))
                    && rule_set.status == RuleSetStatus::Retired)
            {
                return Err(CandidateError::InconsistentBinding);
            }
            let selected = self
                .selected_version(binding.rule_set_id)
                .map_err(|_| CandidateError::InconsistentBinding)?
                .ok_or(CandidateError::UnknownVersion {
                    rule_set_id: binding.rule_set_id,
                    version_bytes: Vec::new(),
                })?;
            // memory—v1 §4.11/§4.12: Reject bad active rows even when another
            // confirmation is valid; all-revoked is a legitimate withdrawal.
            // The classifier must also reject dangling or foreign references
            // when this public validation method is called on its own.
            if self.compute_binding_confirmation_state(binding.binding_id)?
                == BindingConfirmationState::Invalid
            {
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
        self.require_active_rule_set(row.rule_set_id)?;
        if row.version_bytes.is_empty()
            || row.content_bytes.is_empty()
            || row.timestamp_bytes.is_empty()
            || row.hash_input_bytes.is_empty()
            || row.hash_bytes.is_empty()
        {
            return Err(CandidateError::Rows(
                ValidationError::MissingVersionReference {
                    table: Table::RuleSetVersion,
                    rule_set_id: row.rule_set_id,
                    version_bytes: row.version_bytes.clone(),
                },
            ));
        }
        if self.knows_version_id(row.rule_set_id, &row.version_bytes) {
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
        crate::memory_v1_rules::parse_version(&row).map_err(CandidateError::RuleIntegrity)?;
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
        self.require_active_rule_set(rule_set_id)?;
        if let Some(bytes) = version {
            if self.version(rule_set_id, bytes).is_none() {
                return Err(CandidateError::UnknownVersion {
                    rule_set_id,
                    version_bytes: bytes.to_vec(),
                });
            }
        }
        let mut next = self.clone();
        next.advance_rule_set_dependency(rule_set_id)?;
        match version {
            Some(bytes) => next.prepare_selection(rule_set_id, bytes)?,
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
        self.require_active_rule_set(rule_set_id)?;
        if self.version(rule_set_id, version_bytes).is_none() {
            return Err(CandidateError::UnknownVersion {
                rule_set_id,
                version_bytes: version_bytes.to_vec(),
            });
        }
        let mut next = self.clone();
        next.advance_rule_set_dependency(rule_set_id)?;
        let mut rule_set = self
            .rule_sets
            .get(&rule_set_id)
            .expect("checked rule set")
            .as_ref()
            .clone();
        rule_set.current_version_bytes = version_bytes.to_vec();
        next.rule_sets.insert(rule_set_id, Arc::new(rule_set));
        next.prepare_selection(rule_set_id, version_bytes)?;
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.2: Insert a new binding row (structure only).
    ///
    /// Enforces the §4.5 double-bind prohibition and one-OVERLAY-per-card
    /// constraint for nonremoved bindings, including those on disabled cards.
    pub fn with_binding_insert(&self, row: BindingRow) -> Result<Self, CandidateError> {
        let row_count = self.rows_after_insert()?;
        let mut next = self.clone();
        next.advance_card_dependency(row.user_card_id)?;
        next.insert_context_binding(row)?;
        next.row_count = row_count;
        Ok(next)
    }

    // memory—v1: Insert a checked binding on a private candidate.
    fn insert_context_binding(&mut self, row: BindingRow) -> Result<(), CandidateError> {
        if self.bindings.contains_key(&row.binding_id) {
            return Err(CandidateError::Rows(ValidationError::DuplicateId {
                table: Table::Binding,
                id: row.binding_id,
            }));
        }
        if let (Some(from), Some(until)) = (row.valid_from, row.valid_until) {
            if from >= until {
                return Err(CandidateError::Rows(
                    ValidationError::InvalidBindingWindow {
                        binding_id: row.binding_id,
                    },
                ));
            }
        }
        require_tombstone_pair(
            Table::Binding,
            row.binding_id,
            row.removed_at.is_some(),
            row.removed_by.is_some(),
            "removed_at",
            "removed_by",
        )
        .map_err(CandidateError::Rows)?;
        if row.removed_at.is_some() || row.removed_by.is_some() {
            return Err(CandidateError::InconsistentBinding);
        }
        let card = self
            .user_card(row.user_card_id)
            .ok_or(CandidateError::UnknownId {
                table: Table::UserCard,
                id: row.user_card_id,
            })?;
        let rule_set = self
            .rule_set(row.rule_set_id)
            .ok_or(CandidateError::UnknownId {
                table: Table::RuleSet,
                id: row.rule_set_id,
            })?;
        if card.tenant_id != rule_set.owner_tenant_id || rule_set.status != RuleSetStatus::Active {
            return Err(CandidateError::InconsistentBinding);
        }
        // A disabled card still reserves its nonremoved binding slots; enabling
        // it later must not uncover conflicts. Confirmation revocation also does
        // not remove a binding. Complete tombstones alone release the slots.
        // The card index retains tombstones and bounds this scan to the only
        // relationships that can conflict with the proposed binding.
        for binding_id in self
            .bindings_by_card
            .get(&row.user_card_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
        {
            let existing = self
                .bindings
                .get(binding_id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if existing.user_card_id != row.user_card_id {
                return Err(CandidateError::InconsistentBinding);
            }
            match (existing.removed_at, existing.removed_by) {
                (Some(_), Some(_)) => continue,
                (None, None) => {}
                _ => return Err(CandidateError::InconsistentBinding),
            }
            if existing.rule_set_id == row.rule_set_id {
                return Err(CandidateError::DoubleBinding {
                    user_card_id: row.user_card_id,
                    rule_set_id: row.rule_set_id,
                });
            }
            // §4.5: at most one OVERLAY binding per user card.
            if existing.binding_layer == BindingLayer::Overlay
                && row.binding_layer == BindingLayer::Overlay
            {
                return Err(CandidateError::DoubleOverlay {
                    user_card_id: row.user_card_id,
                });
            }
        }
        self.bindings.insert(row.binding_id, Arc::new(row.clone()));
        self.binding_confirmation_states
            .insert(row.binding_id, BindingConfirmationState::Invalid);
        add_member(&mut self.bindings_by_card, row.user_card_id, row.binding_id);
        add_member(
            &mut self.unremoved_bindings_by_card,
            row.user_card_id,
            row.binding_id,
        );
        add_member(
            &mut self.bindings_by_rule_set,
            row.rule_set_id,
            row.binding_id,
        );
        add_member(
            &mut self.unremoved_bindings_by_rule_set,
            row.rule_set_id,
            row.binding_id,
        );
        Ok(())
    }

    /// memory—v1 §4.12 B-2.2: Mark a binding as removed (REMOVE verb).
    ///
    /// The binding row is retained as a tombstone (append-only principle);
    /// evaluation skips removed bindings deterministically. An already removed
    /// binding is rejected as inconsistent, even when the supplied facts match.
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
        if existing.removed_at.is_some() || existing.removed_by.is_some() {
            return Err(CandidateError::InconsistentBinding);
        }
        let mut row = (*existing).clone();
        row.removed_at = Some(removed_at);
        row.removed_by = Some(removed_by);
        let mut card_ids = self
            .unremoved_bindings_by_card
            .get(&row.user_card_id)
            .cloned()
            .ok_or(CandidateError::InconsistentBinding)?;
        let mut rule_set_ids = self
            .unremoved_bindings_by_rule_set
            .get(&row.rule_set_id)
            .cloned()
            .ok_or(CandidateError::InconsistentBinding)?;
        if card_ids.remove(&binding_id).is_none() || rule_set_ids.remove(&binding_id).is_none() {
            return Err(CandidateError::InconsistentBinding);
        }
        let mut next = self.clone();
        next.advance_card_dependency(row.user_card_id)?;
        if card_ids.is_empty() {
            next.unremoved_bindings_by_card.remove(&row.user_card_id);
        } else {
            next.unremoved_bindings_by_card
                .insert(row.user_card_id, card_ids);
        }
        if rule_set_ids.is_empty() {
            next.unremoved_bindings_by_rule_set.remove(&row.rule_set_id);
        } else {
            next.unremoved_bindings_by_rule_set
                .insert(row.rule_set_id, rule_set_ids);
        }
        next.bindings.insert(binding_id, Arc::new(row));
        Ok(next)
    }

    // memory—v1 §4.11/§4.12: A new confirmation may only follow a complete
    // withdrawal (or create the first confirmation for a newly built binding).
    fn require_no_active_binding_confirmation(
        &self,
        binding_id: BinaryId,
    ) -> Result<(), CandidateError> {
        for id in self
            .confirmations_by_binding
            .get(&binding_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
        {
            let existing = self
                .confirmations
                .get(id)
                .ok_or(CandidateError::InconsistentBinding)?;
            if existing.confirmation_id != *id || existing.binding_id != binding_id {
                return Err(CandidateError::InconsistentBinding);
            }
            if existing.revoked_at.is_none() || existing.revoked_by.is_none() {
                return Err(CandidateError::InconsistentBinding);
            }
        }
        Ok(())
    }

    // memory—v1: Check target structure and ID availability for a proposed
    // confirmation without constructing a mutation or granting authorization.
    pub(crate) fn confirmation_target_is_available(
        &self,
        binding_id: BinaryId,
        confirmation_id: BinaryId,
    ) -> bool {
        if confirmation_id == [0; 16] || self.confirmations.contains_key(&confirmation_id) {
            return false;
        }
        let Some(binding) = self.bindings.get(&binding_id) else {
            return false;
        };
        if binding.removed_at.is_some()
            || binding.removed_by.is_some()
            || !self.is_user_card_active(binding.user_card_id)
            || self.require_active_rule_set(binding.rule_set_id).is_err()
        {
            return false;
        }
        self.require_no_active_binding_confirmation(binding_id)
            .is_ok()
    }

    /// memory—v1 §4.12 B-2.4: Insert a new confirmation row.
    pub fn with_confirmation_insert(
        &self,
        row: BindingConfirmationRow,
    ) -> Result<Self, CandidateError> {
        let row_count = self.rows_after_insert()?;
        let binding_id = row.binding_id;
        let mut next = self.clone();
        let card = next.insert_context_confirmation(row)?;
        next.advance_card_dependency(card)?;
        next.row_count = row_count;
        next.refresh_binding_confirmation_state(binding_id)?;
        Ok(next)
    }

    // memory—v1: Insert a checked confirmation on a private candidate.
    fn insert_context_confirmation(
        &mut self,
        row: BindingConfirmationRow,
    ) -> Result<BinaryId, CandidateError> {
        require_tombstone_pair(
            Table::BindingConfirmation,
            row.confirmation_id,
            row.revoked_at.is_some(),
            row.revoked_by.is_some(),
            "revoked_at",
            "revoked_by",
        )
        .map_err(CandidateError::Rows)?;
        if row.revoked_at.is_some() || row.revoked_by.is_some() {
            return Err(CandidateError::InconsistentBinding);
        }
        confirmation_lengths(
            Table::BindingConfirmation,
            &row.version_bytes,
            &row.scope_bytes,
            &row.operation_id,
            &row.confirmed_at_bytes,
            "scope_bytes",
        )
        .map_err(CandidateError::Rows)?;
        if !self.users.contains_key(&row.confirmer_user_id) {
            return Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::BindingConfirmation,
                field: "confirmer_user_id",
                id: row.confirmer_user_id,
            }));
        }
        if self.confirmations.contains_key(&row.confirmation_id) {
            return Err(CandidateError::Rows(ValidationError::DuplicateId {
                table: Table::BindingConfirmation,
                id: row.confirmation_id,
            }));
        }
        let binding = self
            .bindings
            .get(&row.binding_id)
            .ok_or(CandidateError::UnknownId {
                table: Table::Binding,
                id: row.binding_id,
            })?;
        match (binding.removed_at, binding.removed_by) {
            (None, None) => {}
            (Some(_), Some(_)) => return Err(CandidateError::InconsistentBinding),
            _ => return Err(CandidateError::InconsistentBinding),
        }
        if binding.rule_set_id != row.rule_set_id {
            return Err(CandidateError::Rows(ValidationError::MissingBindingPair {
                binding_id: row.binding_id,
                rule_set_id: row.rule_set_id,
            }));
        }
        self.require_active_rule_set(row.rule_set_id)?;
        if !self.knows_version_id(row.rule_set_id, &row.version_bytes) {
            return Err(CandidateError::UnknownVersion {
                rule_set_id: row.rule_set_id,
                version_bytes: row.version_bytes.clone(),
            });
        }
        if !binding_confirmation_valid(&row, row.binding_id, row.rule_set_id) {
            let field = if row.confirmer_user_id == [0; 16] {
                "confirmer_user_id"
            } else if row.scope_bytes.is_empty() {
                "scope_bytes"
            } else if row.operation_id.is_empty() {
                "operation_id"
            } else {
                "confirmed_at_bytes"
            };
            return Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::BindingConfirmation,
                field,
                id: row.binding_id,
            }));
        }
        self.require_no_active_binding_confirmation(row.binding_id)?;
        let card = binding.user_card_id;
        self.confirmations
            .insert(row.confirmation_id, Arc::new(row.clone()));
        add_member(
            &mut self.confirmations_by_binding,
            row.binding_id,
            row.confirmation_id,
        );
        Ok(card)
    }

    /// memory—v1 §4.12 B-2.4: Mark a confirmation as revoked (REVOKE verb).
    ///
    /// An already revoked confirmation is rejected as inconsistent, even when
    /// the supplied facts match; its original tombstone remains unchanged.
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
        if existing.revoked_at.is_some() || existing.revoked_by.is_some() {
            return Err(CandidateError::InconsistentBinding);
        }
        let mut row = (*existing).clone();
        row.revoked_at = Some(revoked_at);
        row.revoked_by = Some(revoked_by);
        let binding_id = row.binding_id;
        let card_id = self.binding_for_confirmation(confirmation_id)?.user_card_id;
        let mut next = self.clone();
        next.advance_card_dependency(card_id)?;
        next.confirmations.insert(confirmation_id, Arc::new(row));
        next.refresh_binding_confirmation_state(binding_id)?;
        Ok(next)
    }

    /// memory—v1 §4.12 B-2.4: Mark one rule-set change confirmation as revoked.
    ///
    /// This only constructs a candidate; it does not authorize or publish the
    /// change. Existing or incomplete tombstones are rejected unchanged.
    pub fn with_change_confirmation_revoked(
        &self,
        confirmation_id: BinaryId,
        revoked_at: i64,
        revoked_by: BinaryId,
    ) -> Result<Self, CandidateError> {
        let existing =
            self.change_confirmations
                .get(&confirmation_id)
                .ok_or(CandidateError::UnknownId {
                    table: Table::RuleSetChangeConfirmation,
                    id: confirmation_id,
                })?;
        if existing.confirmation_id != confirmation_id
            || existing.revoked_at.is_some()
            || existing.revoked_by.is_some()
        {
            return Err(CandidateError::InconsistentBinding);
        }
        let mut row = (**existing).clone();
        row.revoked_at = Some(revoked_at);
        row.revoked_by = Some(revoked_by);
        let mut next = self.clone();
        next.advance_rule_set_dependency(row.rule_set_id)?;
        next.change_confirmation_index
            .remove(existing.as_ref())
            .and_then(|()| next.change_confirmation_index.insert(&row))
            .map_err(|_| CandidateError::InconsistentBinding)?;
        next.change_confirmations
            .insert(confirmation_id, Arc::new(row));
        Ok(next)
    }

    /// memory—v1 §4.11/§4.5 (N-16): Insert one rule-set change confirmation.
    ///
    /// 首版与每次版本发布同事务确认（发布+确认单一根 CAS）；插入前校验版本
    /// 引用与结构有效性，坏数据在发布前即被拒绝。
    pub fn with_change_confirmation_insert(
        &self,
        row: RuleSetChangeConfirmationRow,
    ) -> Result<Self, CandidateError> {
        let row_count = self.rows_after_insert()?;
        let rule_set = row.rule_set_id;
        let mut next = self.clone();
        next.insert_context_change_confirmation(row)?;
        next.advance_rule_set_dependency(rule_set)?;
        next.row_count = row_count;
        Ok(next)
    }

    // memory—v1: Insert a checked change confirmation on a private candidate.
    fn insert_context_change_confirmation(
        &mut self,
        row: RuleSetChangeConfirmationRow,
    ) -> Result<(), CandidateError> {
        require_tombstone_pair(
            Table::RuleSetChangeConfirmation,
            row.confirmation_id,
            row.revoked_at.is_some(),
            row.revoked_by.is_some(),
            "revoked_at",
            "revoked_by",
        )
        .map_err(CandidateError::Rows)?;
        confirmation_lengths(
            Table::RuleSetChangeConfirmation,
            &row.version_bytes,
            &row.affected_scope_bytes,
            &row.operation_id,
            &row.confirmed_at_bytes,
            "affected_scope_bytes",
        )
        .map_err(CandidateError::Rows)?;
        if !self.users.contains_key(&row.confirmer_user_id) {
            return Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::RuleSetChangeConfirmation,
                field: "confirmer_user_id",
                id: row.confirmer_user_id,
            }));
        }
        self.require_active_rule_set(row.rule_set_id)?;
        if !self.knows_version_id(row.rule_set_id, &row.version_bytes) {
            return Err(CandidateError::UnknownVersion {
                rule_set_id: row.rule_set_id,
                version_bytes: row.version_bytes.clone(),
            });
        }
        if self.change_confirmations.contains_key(&row.confirmation_id) {
            return Err(CandidateError::Rows(
                crate::memory_v1_db_rows::ValidationError::DuplicateId {
                    table: crate::memory_v1_db_rows::Table::RuleSetChangeConfirmation,
                    id: row.confirmation_id,
                },
            ));
        }
        if !change_confirmation_valid(&row, row.rule_set_id, &row.version_bytes) {
            let field = if row.confirmer_user_id == [0; 16] {
                "confirmer_user_id"
            } else if row.affected_scope_bytes.is_empty() {
                "affected_scope_bytes"
            } else if row.operation_id.is_empty() {
                "operation_id"
            } else {
                "confirmed_at_bytes"
            };
            return Err(CandidateError::Rows(
                crate::memory_v1_db_rows::ValidationError::MissingReference {
                    table: crate::memory_v1_db_rows::Table::RuleSetChangeConfirmation,
                    field,
                    id: row.rule_set_id,
                },
            ));
        }
        self.change_confirmation_index
            .insert(&row)
            .map_err(|_| CandidateError::InconsistentBinding)?;
        self.change_confirmations
            .insert(row.confirmation_id, Arc::new(row.clone()));
        add_member(
            &mut self.changes_by_rule_set,
            row.rule_set_id,
            row.confirmation_id,
        );
        Ok(())
    }

    /// memory—v1 §4.11 N-10: Insert a BATCH of binding confirmations atomically.
    ///
    /// 一次 T2 批量确认 = 单次根 CAS 原子发布；任一条目无效（未知绑定、规则集
    /// 不匹配、坏数据、重复 ID）则整批拒绝，不产生部分插入。
    pub fn with_confirmations_batch(
        &self,
        rows: &[BindingConfirmationRow],
    ) -> Result<Self, CandidateError> {
        if rows.is_empty() {
            return Err(CandidateError::InconsistentBinding);
        }
        let row_count = self
            .row_count
            .checked_add(rows.len())
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        let mut seen: std::collections::HashSet<BinaryId> = std::collections::HashSet::new();
        let mut affected_cards = std::collections::HashSet::new();
        for row in rows {
            require_tombstone_pair(
                Table::BindingConfirmation,
                row.confirmation_id,
                row.revoked_at.is_some(),
                row.revoked_by.is_some(),
                "revoked_at",
                "revoked_by",
            )
            .map_err(CandidateError::Rows)?;
            if row.revoked_at.is_some() || row.revoked_by.is_some() {
                return Err(CandidateError::InconsistentBinding);
            }
            confirmation_lengths(
                Table::BindingConfirmation,
                &row.version_bytes,
                &row.scope_bytes,
                &row.operation_id,
                &row.confirmed_at_bytes,
                "scope_bytes",
            )
            .map_err(CandidateError::Rows)?;
            if !self.users.contains_key(&row.confirmer_user_id) {
                return Err(CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::BindingConfirmation,
                    field: "confirmer_user_id",
                    id: row.confirmer_user_id,
                }));
            }
            let binding = self
                .bindings
                .get(&row.binding_id)
                .ok_or(CandidateError::UnknownId {
                    table: crate::memory_v1_db_rows::Table::Binding,
                    id: row.binding_id,
                })?;
            match (binding.removed_at, binding.removed_by) {
                (None, None) => {}
                (Some(_), Some(_)) => return Err(CandidateError::InconsistentBinding),
                _ => return Err(CandidateError::InconsistentBinding),
            }
            affected_cards.insert(binding.user_card_id);
            if binding.rule_set_id != row.rule_set_id {
                return Err(CandidateError::Rows(
                    crate::memory_v1_db_rows::ValidationError::MissingBindingPair {
                        binding_id: row.binding_id,
                        rule_set_id: row.rule_set_id,
                    },
                ));
            }
            self.require_active_rule_set(row.rule_set_id)?;
            if !self.knows_version_id(row.rule_set_id, &row.version_bytes) {
                return Err(CandidateError::UnknownVersion {
                    rule_set_id: row.rule_set_id,
                    version_bytes: row.version_bytes.clone(),
                });
            }
            if !seen.insert(row.confirmation_id)
                || self.confirmations.contains_key(&row.confirmation_id)
            {
                return Err(CandidateError::Rows(
                    crate::memory_v1_db_rows::ValidationError::DuplicateId {
                        table: crate::memory_v1_db_rows::Table::BindingConfirmation,
                        id: row.confirmation_id,
                    },
                ));
            }
            if !binding_confirmation_valid(row, row.binding_id, row.rule_set_id) {
                let field = if row.confirmer_user_id == [0; 16] {
                    "confirmer_user_id"
                } else if row.scope_bytes.is_empty() {
                    "scope_bytes"
                } else if row.operation_id.is_empty() {
                    "operation_id"
                } else {
                    "confirmed_at_bytes"
                };
                return Err(CandidateError::Rows(
                    crate::memory_v1_db_rows::ValidationError::MissingReference {
                        table: crate::memory_v1_db_rows::Table::BindingConfirmation,
                        field,
                        id: row.binding_id,
                    },
                ));
            }
        }
        // memory—v1: Check set conflicts only after all individual rows have
        // passed validation, before building or publishing any candidate state.
        let mut seen_bindings = std::collections::HashSet::new();
        for row in rows {
            if !seen_bindings.insert(row.binding_id) {
                return Err(CandidateError::InconsistentBinding);
            }
            self.require_no_active_binding_confirmation(row.binding_id)?;
        }
        let mut next = self.clone();
        for card_id in affected_cards {
            next.advance_card_dependency(card_id)?;
        }
        next.row_count = row_count;
        for row in rows {
            next.confirmations
                .insert(row.confirmation_id, Arc::new(row.clone()));
            add_member(
                &mut next.confirmations_by_binding,
                row.binding_id,
                row.confirmation_id,
            );
            next.refresh_binding_confirmation_state(row.binding_id)?;
        }
        Ok(next)
    }

    // memory—v1: Verify the exact card indexes and generations before extending
    // them. The reverse indexes cannot manufacture a user/tenant relationship.
    fn validate_card_indexes(&self) -> Result<(), CandidateError> {
        if count_nonempty(self.cards_by_user.values().map(HashSet::len)) != Some(self.cards.len())
            || count_nonempty(self.cards_by_tenant.values().map(HashSet::len))
                != Some(self.cards.len())
            || self.card_dependencies.len() != self.cards.len()
        {
            return Err(CandidateError::InconsistentBinding);
        }
        for (id, row) in &self.cards {
            if *id != row.user_card_id
                || !self.users.contains_key(&row.user_id)
                || !self.tenants.contains_key(&row.tenant_id)
                || !self.card_dependencies.contains_key(id)
                || !self
                    .cards_by_user
                    .get(&row.user_id)
                    .is_some_and(|ids| ids.contains(id))
                || !self
                    .cards_by_tenant
                    .get(&row.tenant_id)
                    .is_some_and(|ids| ids.contains(id))
            {
                return Err(CandidateError::InconsistentBinding);
            }
        }
        Ok(())
    }

    // memory—v1: An existing card is the only root fact relating a user to a
    // tenant. Neither input IDs nor the independent existence of those rows
    // establish that relationship. This is not an admission or an ALLOW.
    pub(crate) fn validate_user_card_create_target(
        &self,
        card_id: BinaryId,
        user_id: BinaryId,
        tenant_id: BinaryId,
    ) -> Result<(), CandidateError> {
        if card_id == [0; 16] || user_id == [0; 16] || tenant_id == [0; 16] {
            return Err(CandidateError::InconsistentBinding);
        }
        if self.cards.contains_key(&card_id) {
            return Err(CandidateError::Rows(ValidationError::DuplicateId {
                table: Table::UserCard,
                id: card_id,
            }));
        }
        let user = self.user(user_id).ok_or(CandidateError::UnknownId {
            table: Table::User,
            id: user_id,
        })?;
        let identity = self
            .identity_for_user(user_id)
            .ok_or(CandidateError::MissingIdentityCard { user_id })?;
        let tenant = self.tenant(tenant_id).ok_or(CandidateError::UnknownId {
            table: Table::Tenant,
            id: tenant_id,
        })?;
        if user.user_id != user_id
            || identity.user_id != user_id
            || identity.identity_card_id == [0; 16]
            || self.identity_by_user.get(&user_id) != Some(&identity.identity_card_id)
            || tenant.tenant_id != tenant_id
        {
            return Err(CandidateError::InconsistentBinding);
        }
        self.validate_card_indexes()?;
        if !self.cards_by_user.get(&user_id).is_some_and(|ids| {
            ids.iter().any(|id| {
                self.cards
                    .get(id)
                    .is_some_and(|card| card.user_id == user_id && card.tenant_id == tenant_id)
            })
        }) {
            return Err(CandidateError::InconsistentBinding);
        }
        Ok(())
    }

    // memory—v1: Insert a separate, unbound active card in a private candidate.
    pub(crate) fn with_user_card_create(&self, row: UserCardRow) -> Result<Self, CandidateError> {
        self.validate_user_card_create_target(row.user_card_id, row.user_id, row.tenant_id)?;
        if row.status != UserCardStatus::Active {
            return Err(CandidateError::InconsistentBinding);
        }
        let row_count = self
            .row_count
            .checked_add(1)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        let mut next = self.clone();
        next.row_count = row_count;
        index(&mut next.cards_by_user, row.user_id, row.user_card_id);
        index(&mut next.cards_by_tenant, row.tenant_id, row.user_card_id);
        next.card_dependencies.insert(row.user_card_id, 0);
        next.cards.insert(row.user_card_id, Arc::new(row));
        next.validate_card_indexes()?;
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
        if status == UserCardStatus::Active {
            self.validate_binding_indexes()?;
            let (card, _) = self.unremoved_card_candidate(user_card_id)?;
            for binding in card.bindings {
                let rule_set = self
                    .rule_set(binding.rule_set_id)
                    .ok_or(CandidateError::InconsistentBinding)?;
                if rule_set.owner_tenant_id != existing.tenant_id
                    || rule_set.status != RuleSetStatus::Active
                {
                    return Err(CandidateError::InconsistentBinding);
                }
            }
        }
        let mut row = (*existing).clone();
        row.status = status;
        let mut next = self.clone();
        next.advance_card_dependency(user_card_id)?;
        next.cards.insert(user_card_id, Arc::new(row));
        Ok(next)
    }

    #[cfg(test)]
    // memory—v1 §4.12 B-2.5: Prepare a retirement on this candidate only.
    // Index consistency covers the supplied rows, not source completeness.
    pub(crate) fn with_rule_set_retired(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<Self, CandidateError> {
        retirement::prepare(self, rule_set_id).map(retirement::ValidatedRetirement::into_candidate)
    }

    // memory—v1: The opaque result owns exactly the retirement candidate whose
    // binding indexes were checked. It cannot be constructed by the root module.
    pub(crate) fn prepare_validated_retirement(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<retirement::ValidatedRetirement, CandidateError> {
        retirement::prepare(self, rule_set_id)
    }

    /// memory—v1 §4.12: Insert a new rule set with its initial version and pointer.
    pub fn with_rule_set_create(
        &self,
        rule_set_row: crate::memory_v1_db_rows::RuleSetRow,
        version_row: RuleSetVersionRow,
    ) -> Result<Self, CandidateError> {
        if self.rule_sets.contains_key(&rule_set_row.rule_set_id) {
            return Err(CandidateError::Rows(ValidationError::DuplicateId {
                table: Table::RuleSet,
                id: rule_set_row.rule_set_id,
            }));
        }
        if rule_set_row.status != RuleSetStatus::Active {
            return Err(CandidateError::InconsistentBinding);
        }
        if version_row.rule_set_id != rule_set_row.rule_set_id
            || rule_set_row.current_version_bytes != version_row.version_bytes
        {
            return Err(CandidateError::Rows(
                ValidationError::MissingVersionReference {
                    table: Table::RuleSetVersion,
                    rule_set_id: rule_set_row.rule_set_id,
                    version_bytes: rule_set_row.current_version_bytes.clone(),
                },
            ));
        }
        if !self.tenants.contains_key(&rule_set_row.owner_tenant_id) {
            return Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::RuleSet,
                field: "owner_tenant_id",
                id: rule_set_row.owner_tenant_id,
            }));
        }
        if version_row.version_bytes.is_empty()
            || version_row.content_bytes.is_empty()
            || version_row.timestamp_bytes.is_empty()
            || version_row.hash_input_bytes.is_empty()
            || version_row.hash_bytes.is_empty()
        {
            return Err(CandidateError::Rows(
                ValidationError::MissingVersionReference {
                    table: Table::RuleSetVersion,
                    rule_set_id: rule_set_row.rule_set_id,
                    version_bytes: version_row.version_bytes.clone(),
                },
            ));
        }
        let structural_rows = CandidateRows {
            tenants: vec![TenantRow {
                tenant_id: rule_set_row.owner_tenant_id,
                parent_tenant_id: None,
            }],
            rule_sets: vec![rule_set_row.clone()],
            rule_set_versions: vec![version_row.clone()],
            ..CandidateRows::default()
        };
        structural_rows
            .build_candidate(&[])
            .map_err(CandidateError::Rows)?;
        crate::memory_v1_rules::parse_version(&version_row)
            .map_err(CandidateError::RuleIntegrity)?;
        let row_count = self
            .row_count
            .checked_add(2)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })?;
        let mut next = self.clone();
        next.row_count = row_count;
        next.rule_set_dependencies
            .insert(rule_set_row.rule_set_id, 0);
        next.rule_sets
            .insert(rule_set_row.rule_set_id, Arc::new(rule_set_row.clone()));
        next.versions
            .entry(rule_set_row.rule_set_id)
            .or_default()
            .insert(
                version_row.version_bytes.clone(),
                Arc::new(version_row.clone()),
            );
        next.prepare_selection(rule_set_row.rule_set_id, &version_row.version_bytes)?;
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

    // memory—v1: A retired row is retained forever and cannot regain authority.
    fn require_active_rule_set(&self, id: BinaryId) -> Result<(), CandidateError> {
        match self.rule_set(id) {
            Some(row) if row.status == RuleSetStatus::Active => Ok(()),
            Some(_) => Err(CandidateError::InconsistentBinding),
            None => Err(CandidateError::UnknownId {
                table: Table::RuleSet,
                id,
            }),
        }
    }

    // memory—v1: Count a candidate writer's single new row before publication.
    fn rows_after_insert(&self) -> Result<usize, CandidateError> {
        self.row_count
            .checked_add(1)
            .filter(|count| *count <= self.budget.max_table_rows)
            .ok_or(CandidateError::RowBudgetExceeded {
                max: self.budget.max_table_rows,
            })
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
    // memory—v1: The production composition supplies the sampler, never the request.
    pub(crate) fn set_headroom(&mut self, probe: Option<fn() -> Option<usize>>) {
        self.headroom = probe;
    }

    pub(crate) fn headroom(&self) -> Option<fn() -> Option<usize>> {
        self.headroom
    }

    // memory—v1: Ordinary small reads use the process reserve. Larger reads must
    // fit in their entirety; this guard never clips a binding or a confirmation.
    pub(crate) fn check_read_workspace(&self, items: usize) -> Result<(), CandidateError> {
        if items > 256 {
            if let Some(probe) = self.headroom {
                let bytes = items
                    .checked_mul(512)
                    .ok_or(CandidateError::WorkingMemoryUnavailable)?;
                if !probe().is_some_and(|free| bytes <= free) {
                    return Err(CandidateError::WorkingMemoryUnavailable);
                }
            }
        }
        Ok(())
    }

    fn check_bindings(&self, actual: usize) -> Result<(), CandidateError> {
        if actual > self.budget.max_bindings_per_read {
            Err(CandidateError::BindingBudgetExceeded {
                max: self.budget.max_bindings_per_read,
                actual,
            })
        } else {
            self.check_read_workspace(actual)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::BindingLayer;
    use crate::memory_v1_db_rows::UserCardStatus;
    use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

    // memory—v1: Generate distinct binary IDs without assuming an encoding.
    fn id(value: u8) -> BinaryId {
        let mut id = [0; 16];
        id[0] = 0x80;
        id[15] = value;
        id
    }

    // memory—v1: Construct a complete version with matching canonical hash.
    fn version(rule: u8, value: u8) -> RuleSetVersionRow {
        let version_bytes = vec![value];
        let content_bytes =
            br#"{"rules":[{"ruleId":"R","resource":"document","action":"read","effect":"ALLOW"}]}"#
                .to_vec();
        let timestamp_bytes = vec![0xff];
        let hash_input_bytes = crate::memory_v1_rules::canonical_version_bytes(
            &version_bytes,
            &content_bytes,
            &timestamp_bytes,
        );
        let hash_bytes = crate::memory_v1_rules::version_digest(&hash_input_bytes);
        RuleSetVersionRow {
            rule_set_id: id(rule),
            version_bytes,
            content_bytes,
            timestamp_bytes,
            hash_input_bytes,
            hash_bytes,
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
                    status: RuleSetStatus::Active,
                },
                RuleSetRow {
                    rule_set_id: id(11),
                    owner_tenant_id: id(6),
                    current_version_bytes: Vec::new(),
                    status: RuleSetStatus::Active,
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

    // memory—v1: Retirement counts relationships, independently of confirmation
    // or time; disabled-card relationships survive and cannot be re-enabled.
    #[test]
    fn retirement_checks_active_relationships_and_preserves_disabled_history() {
        let mut input = rows();
        input.bindings.retain(|row| row.binding_id == id(12));
        input.bindings[0].valid_from = Some(1);
        input.bindings[0].valid_until = Some(2);
        input.binding_confirmations[0].revoked_at = Some(3);
        input.binding_confirmations[0].revoked_by = Some(id(1));
        let active = HamtCandidate::build(input.clone(), vec![], budget()).unwrap();
        assert!(matches!(
            active.with_rule_set_retired(id(10)),
            Err(CandidateError::InconsistentBinding)
        ));
        input.user_cards[0].status = UserCardStatus::Disabled;
        let disabled = HamtCandidate::build(input, vec![], budget()).unwrap();
        let before = disabled.rule_set_dependency_generation(id(10)).unwrap();
        let retired = disabled.with_rule_set_retired(id(10)).unwrap();
        assert_eq!(
            retired.rule_set(id(10)).unwrap().status,
            RuleSetStatus::Retired
        );
        assert_eq!(
            retired.rule_set_dependency_generation(id(10)),
            Some(before + 1)
        );
        assert_eq!(
            disabled.rule_set(id(10)).unwrap().status,
            RuleSetStatus::Active
        );
        assert!(retired.binding(id(12)).unwrap().is_some());
        assert!(retired
            .with_user_card_status(id(8), UserCardStatus::Active)
            .is_err());
        assert!(retired.with_rule_set_retired(id(10)).is_err());
        assert!(retired.append_version(version(10, 3)).is_err());
        assert!(retired.with_current_version(id(10), &[1]).is_err());
        assert!(retired.with_selection(id(10), Some(&[1])).is_err());
        let mut new_binding = rows().bindings[0].clone();
        new_binding.binding_id = id(40);
        assert!(retired.with_binding_insert(new_binding).is_err());
        let mut confirmation = rows().binding_confirmations[0].clone();
        confirmation.confirmation_id = id(41);
        assert!(retired
            .with_confirmation_insert(confirmation.clone())
            .is_err());
        assert!(retired.with_confirmations_batch(&[confirmation]).is_err());
        let removed = retired.with_binding_removed(id(12), 4, id(1)).unwrap();
        assert!(removed
            .with_user_card_status(id(8), UserCardStatus::Active)
            .is_ok());
    }

    #[test]
    // memory—v1: Missing rows, broken indexes, half tombstones, budgets and
    // exhausted generations never produce a new retirement snapshot.
    fn retirement_rejects_corrupt_candidate_and_exhausted_budget() {
        let mut input = rows();
        input.bindings.retain(|row| row.binding_id == id(12));
        input.user_cards[0].status = UserCardStatus::Disabled;
        let candidate = HamtCandidate::build(input, vec![], budget()).unwrap();
        let mut broken = candidate.clone();
        broken.cards.remove(&id(8));
        assert!(broken.with_rule_set_retired(id(10)).is_err());
        let mut broken = candidate.clone();
        let mut card = broken.cards[&id(8)].as_ref().clone();
        card.user_card_id = id(99);
        broken.cards.insert(id(8), Arc::new(card));
        assert!(broken.with_rule_set_retired(id(10)).is_err());
        let mut broken = candidate.clone();
        broken.identity_by_user.remove(&id(1));
        assert!(broken.with_rule_set_retired(id(10)).is_err());
        let mut broken = candidate.clone();
        broken.omit_unremoved_rule_set_binding_for_test(id(10));
        assert!(broken.with_rule_set_retired(id(10)).is_err());
        let mut broken = candidate.clone();
        let mut binding = broken.bindings[&id(12)].as_ref().clone();
        binding.removed_at = Some(10);
        broken.bindings.insert(id(12), Arc::new(binding));
        assert!(broken.with_rule_set_retired(id(10)).is_err());
        let mut exhausted = candidate.clone();
        exhausted.budget.max_bindings_per_read = 0;
        assert!(matches!(
            exhausted.with_rule_set_retired(id(10)),
            Err(CandidateError::BindingBudgetExceeded { .. })
        ));
        let mut exhausted = candidate.clone();
        exhausted.set_rule_set_dependency_generation_for_test(id(10), u64::MAX);
        assert!(exhausted.with_rule_set_retired(id(10)).is_err());
        assert_eq!(
            exhausted.rule_set(id(10)).unwrap().status,
            RuleSetStatus::Active
        );
    }

    // memory—v1: Provide a small explicit test budget.
    #[test]
    // memory—v1: Creation validates relationships, indexes and arithmetic
    // before changing any shared HAMT node.
    fn user_card_create_rejects_invalid_facts_and_preserves_candidates() {
        let original = candidate();
        let valid = UserCardRow {
            user_card_id: id(90),
            user_id: id(1),
            tenant_id: id(5),
            status: UserCardStatus::Active,
        };
        let next = original.with_user_card_create(valid.clone()).unwrap();
        assert_eq!(next.user_card(id(90)), Some(&valid));
        assert_eq!(next.card_dependency_generation(id(90)), Some(0));
        assert!(next.card_candidate(id(90)).unwrap().bindings.is_empty());
        assert!(next.user_cards(id(1)).unwrap().unwrap().contains(&id(90)));
        assert!(next.tenant_cards(id(5)).unwrap().unwrap().contains(&id(90)));
        assert_eq!(
            next.budget_and_row_count().1,
            original.budget_and_row_count().1 + 1
        );
        assert!(original.user_card(id(90)).is_none());
        assert!(!original
            .user_cards(id(1))
            .unwrap()
            .unwrap()
            .contains(&id(90)));
        assert!(!original
            .tenant_cards(id(5))
            .unwrap()
            .unwrap()
            .contains(&id(90)));
        assert_eq!(next.validate_card_indexes(), Ok(()));

        let mut invalid = Vec::new();
        for field in 0..7 {
            let mut row = valid.clone();
            match field {
                0 => row.user_card_id = id(8),
                1 => row.user_card_id = [0; 16],
                2 => row.user_id = [0; 16],
                3 => row.tenant_id = [0; 16],
                4 => row.user_id = id(99),
                5 => row.tenant_id = id(99),
                _ => row.status = UserCardStatus::Disabled,
            }
            invalid.push(row);
        }
        let mut unassociated = valid.clone();
        unassociated.tenant_id = id(7);
        invalid.push(unassociated);
        for row in invalid {
            assert!(original.with_user_card_create(row).is_err());
            assert!(original.user_card(id(90)).is_none());
        }
        for corruption in 0..5 {
            let mut damaged = original.clone();
            match corruption {
                0 => {
                    damaged.identity_by_user.remove(&id(1));
                }
                1 => {
                    damaged.identities.remove(&id(3));
                }
                2 => {
                    let mut wrong = damaged.identities[&id(3)].as_ref().clone();
                    wrong.user_id = id(2);
                    damaged.identities.insert(id(3), Arc::new(wrong));
                }
                3 => {
                    damaged.cards_by_user.remove(&id(1));
                }
                _ => {
                    damaged.card_dependencies.remove(&id(8));
                }
            }
            assert!(damaged.with_user_card_create(valid.clone()).is_err());
            assert!(damaged.user_card(id(90)).is_none());
        }
        for (count, max) in [
            (original.row_count, original.row_count),
            (usize::MAX, usize::MAX),
        ] {
            let mut limited = original.clone();
            limited.row_count = count;
            limited.budget.max_table_rows = max;
            assert!(matches!(
                limited.with_user_card_create(valid.clone()),
                Err(CandidateError::RowBudgetExceeded { .. })
            ));
            assert_eq!(limited.row_count, count);
            assert!(limited.user_card(id(90)).is_none());
        }
    }

    fn budget() -> CandidateBudget {
        CandidateBudget {
            max_table_rows: 100,
            max_bindings_per_read: 10,
        }
    }

    #[test]
    // memory—v1 §4.11: Every current version needs its own active confirmation,
    // including rule sets that have no bindings in the cold snapshot.
    fn serving_rejects_unconfirmed_current_version_without_bindings() {
        let mut input = rows();
        input.rule_sets[0].current_version_bytes = vec![1];
        input.rule_sets[1].current_version_bytes = vec![1];
        input
            .bindings
            .retain(|binding| binding.binding_id == id(12));
        let selections = vec![
            CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![1],
            },
            CurrentSelection {
                rule_set_id: id(11),
                version_bytes: vec![1],
            },
        ];
        let mut confirmation = input.rule_set_change_confirmations[0].clone();
        confirmation.confirmation_id = id(30);
        confirmation.rule_set_id = id(11);
        let expected_error = CandidateError::Rows(ValidationError::MissingVersionReference {
            table: Table::RuleSetChangeConfirmation,
            rule_set_id: id(11),
            version_bytes: vec![1],
        });

        let candidate = HamtCandidate::build(input.clone(), selections.clone(), budget()).unwrap();
        assert_eq!(
            candidate.validate_for_serving(),
            Err(expected_error.clone())
        );

        let mut revoked = confirmation.clone();
        revoked.revoked_at = Some(10);
        revoked.revoked_by = Some(id(1));
        input.rule_set_change_confirmations.push(revoked);
        let candidate = HamtCandidate::build(input.clone(), selections.clone(), budget()).unwrap();
        assert_eq!(candidate.validate_for_serving(), Err(expected_error));

        input
            .rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: id(31),
                ..confirmation
            });
        let candidate = HamtCandidate::build(input, selections, budget()).unwrap();
        assert_eq!(candidate.validate_for_serving(), Ok(()));
    }

    #[test]
    // memory—v1 §4.11–§4.13: a valid current-version change confirmation
    // cannot conceal another malformed active confirmation for that version.
    fn serving_rejects_valid_change_confirmation_hidden_by_bad_current_row() {
        let mut input = rows();
        input.rule_sets.retain(|row| row.rule_set_id == id(10));
        input.rule_sets[0].current_version_bytes = vec![1];
        input
            .rule_set_versions
            .retain(|row| row.rule_set_id == id(10));
        input.bindings.retain(|row| row.binding_id == id(12));
        input
            .binding_confirmations
            .retain(|row| row.binding_id == id(12));
        let selection = vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: vec![1],
        }];
        let valid = input.rule_set_change_confirmations[0].clone();
        let mut malformed = valid.clone();
        malformed.confirmation_id = id(30);
        malformed.affected_scope_bytes.clear();
        let expected = Err(CandidateError::Rows(
            ValidationError::MissingVersionReference {
                table: Table::RuleSetChangeConfirmation,
                rule_set_id: id(10),
                version_bytes: vec![1],
            },
        ));

        for confirmations in [
            vec![valid.clone(), malformed.clone()],
            vec![malformed, valid],
        ] {
            input.rule_set_change_confirmations = confirmations;
            let candidate =
                HamtCandidate::build(input.clone(), selection.clone(), budget()).unwrap();
            assert_eq!(candidate.validate_for_serving(), expected);
        }
    }

    #[test]
    // memory—v1 §4.11/§4.12: Invalid active confirmations cannot hide behind
    // valid or withdrawn rows; valid tombstones remain adoptable and reversible.
    fn serving_classifies_binding_confirmation_sets() {
        let mut input = rows();
        input.rule_sets.retain(|row| row.rule_set_id == id(10));
        input.rule_sets[0].current_version_bytes = vec![1];
        input
            .rule_set_versions
            .retain(|row| row.rule_set_id == id(10));
        input.bindings.retain(|row| row.binding_id == id(12));
        let selection = vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: vec![1],
        }];
        let valid = input.binding_confirmations[0].clone();
        let mut invalid = valid.clone();
        invalid.confirmation_id = id(30);
        invalid.scope_bytes.clear();
        let mut revoked = valid.clone();
        revoked.revoked_at = Some(100);
        revoked.revoked_by = Some(id(1));
        let expected = Err(CandidateError::MissingConfirmation {
            binding_id: id(12),
            rule_set_id: id(10),
            version_bytes: vec![1],
        });

        for good in [&valid, &revoked] {
            for reversed in [false, true] {
                input.binding_confirmations = vec![good.clone(), invalid.clone()];
                if reversed {
                    input.binding_confirmations.reverse();
                }
                let candidate =
                    HamtCandidate::build(input.clone(), selection.clone(), budget()).unwrap();
                assert_eq!(candidate.validate_for_serving(), expected);
            }
        }
        let mut duplicate_active = valid.clone();
        duplicate_active.confirmation_id = id(32);
        for confirmations in [
            vec![valid.clone(), duplicate_active.clone()],
            vec![duplicate_active, valid.clone()],
        ] {
            input.binding_confirmations = confirmations;
            let candidate =
                HamtCandidate::build(input.clone(), selection.clone(), budget()).unwrap();
            assert_eq!(candidate.validate_for_serving(), expected);
        }
        input.binding_confirmations.clear();
        let candidate = HamtCandidate::build(input.clone(), selection.clone(), budget()).unwrap();
        assert_eq!(candidate.validate_for_serving(), expected);

        input.binding_confirmations = vec![revoked.clone()];
        let withdrawn = HamtCandidate::build(input, selection, budget()).unwrap();
        assert_eq!(withdrawn.validate_for_serving(), Ok(()));
        assert_eq!(
            withdrawn.binding_confirmations(id(12)).unwrap(),
            vec![&revoked]
        );

        let mut reactivated = valid;
        reactivated.confirmation_id = id(31);
        let restored = withdrawn
            .with_confirmation_insert(reactivated.clone())
            .unwrap();
        assert_eq!(restored.validate_for_serving(), Ok(()));
        let confirmations = restored.binding_confirmations(id(12)).unwrap();
        assert_eq!(confirmations.len(), 2);
        assert!(confirmations.contains(&&revoked));
        assert!(confirmations.contains(&&reactivated));
        assert_eq!(
            classify_binding_confirmations(confirmations, id(12), id(10)),
            BindingConfirmationState::Active
        );
    }

    #[test]
    // memory—v1: Standalone serving validation cannot ignore a dangling,
    // foreign or mismatched confirmation alongside a valid active row.
    fn serving_rejects_inconsistent_confirmation_references() {
        let mut input = rows();
        input.rule_sets.retain(|row| row.rule_set_id == id(10));
        input.rule_sets[0].current_version_bytes = vec![1];
        input
            .rule_set_versions
            .retain(|row| row.rule_set_id == id(10));
        input.bindings.retain(|row| row.binding_id == id(12));
        let selection = vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: vec![1],
        }];
        let valid = HamtCandidate::build(input, selection, budget()).unwrap();
        assert_eq!(valid.validate_for_serving(), Ok(()));

        let mut dangling = valid.clone();
        add_member(&mut dangling.confirmations_by_binding, id(12), id(99));
        let mut foreign = valid.clone();
        let mut row = (*foreign.confirmations[&id(15)]).clone();
        row.confirmation_id = id(30);
        row.binding_id = id(13);
        foreign.confirmations.insert(id(30), Arc::new(row));
        add_member(&mut foreign.confirmations_by_binding, id(12), id(30));
        let mut mismatched = valid;
        let mut row = (*mismatched.confirmations[&id(15)]).clone();
        row.confirmation_id = id(99);
        mismatched.confirmations.insert(id(15), Arc::new(row));
        for candidate in [dangling, foreign, mismatched] {
            assert_eq!(
                candidate.validate_for_serving(),
                Err(CandidateError::InconsistentBinding)
            );
        }
    }

    #[test]
    // memory—v1 §4.11/§4.12: A binding accepts one active confirmation;
    // a revoke retains the tombstone and permits a new confirmation.
    fn confirmation_insert_refuses_second_active_and_allows_reconfirmation() {
        let candidate = candidate();
        let mut new_confirmation = rows().binding_confirmations[0].clone();
        new_confirmation.confirmation_id = id(30);
        let count = candidate.budget_and_row_count();
        let generation = candidate.card_dependency_generation(id(8));
        assert!(matches!(
            candidate.with_confirmation_insert(new_confirmation.clone()),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(candidate.budget_and_row_count(), count);
        assert_eq!(candidate.card_dependency_generation(id(8)), generation);
        assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);

        let revoked = candidate
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap();
        let restored = revoked
            .with_confirmation_insert(new_confirmation.clone())
            .unwrap();
        let rows = restored.binding_confirmations(id(12)).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|row| row.confirmation_id == id(15) && row.revoked_at == Some(100)));
        assert!(rows.contains(&&new_confirmation));
        assert_eq!(
            classify_binding_confirmations(rows, id(12), id(10)),
            BindingConfirmationState::Active
        );
        assert!(matches!(
            restored.with_confirmation_insert(BindingConfirmationRow {
                confirmation_id: id(31),
                ..new_confirmation
            }),
            Err(CandidateError::InconsistentBinding)
        ));
    }

    #[test]
    // memory—v1: Mixed confirmation conflicts leave all rows and generations unchanged.
    fn confirmation_batch_rejects_active_conflicts_atomically() {
        let candidate = candidate();
        let mut first = rows().binding_confirmations[0].clone();
        first.confirmation_id = id(30);
        first.binding_id = id(13);
        let mut conflicting = first.clone();
        conflicting.confirmation_id = id(31);
        conflicting.binding_id = id(12);
        let count = candidate.budget_and_row_count();
        let generation_a = candidate.card_dependency_generation(id(8));
        let generation_b = candidate.card_dependency_generation(id(9));
        for batch in [
            vec![first.clone(), conflicting.clone()],
            vec![conflicting.clone(), first.clone()],
            vec![
                first.clone(),
                BindingConfirmationRow {
                    confirmation_id: id(32),
                    ..first.clone()
                },
            ],
        ] {
            assert!(matches!(
                candidate.with_confirmations_batch(&batch),
                Err(CandidateError::InconsistentBinding)
            ));
            assert_eq!(candidate.budget_and_row_count(), count);
            assert_eq!(candidate.card_dependency_generation(id(8)), generation_a);
            assert_eq!(candidate.card_dependency_generation(id(9)), generation_b);
            assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);
            assert!(candidate.binding_confirmations(id(13)).unwrap().is_empty());
        }
    }

    #[test]
    // memory—v1: Repeated REMOVE cannot overwrite the first tombstone or advance generations.
    fn binding_tombstone_rejects_repeat_and_preserves_history() {
        let original = candidate();
        let original_row = original.binding(id(12)).unwrap().unwrap().clone();
        let original_generation = original.card_dependency_generation(id(8)).unwrap();
        let removed = original.with_binding_removed(id(12), 100, id(1)).unwrap();
        let first_row = removed.binding(id(12)).unwrap().unwrap().clone();
        assert_eq!(first_row.removed_at, Some(100));
        assert_eq!(first_row.removed_by, Some(id(1)));
        assert_eq!(
            removed.card_dependency_generation(id(8)),
            Some(original_generation + 1)
        );
        assert_eq!(original.binding(id(12)).unwrap().unwrap(), &original_row);
        assert_eq!(
            original.card_dependency_generation(id(8)),
            Some(original_generation)
        );

        let generation = removed.card_dependency_generation(id(8));
        let other_generation = removed.card_dependency_generation(id(9));
        let rule_generation = removed.rule_set_dependency_generation(id(10));
        for (time, actor) in [(100, id(1)), (200, id(2))] {
            assert!(matches!(
                removed.with_binding_removed(id(12), time, actor),
                Err(CandidateError::InconsistentBinding)
            ));
            assert_eq!(removed.binding(id(12)).unwrap().unwrap(), &first_row);
            assert_eq!(removed.card_dependency_generation(id(8)), generation);
            assert_eq!(removed.card_dependency_generation(id(9)), other_generation);
            assert_eq!(
                removed.rule_set_dependency_generation(id(10)),
                rule_generation
            );
        }

        let mut cold_rows = rows();
        cold_rows.bindings[0] = first_row.clone();
        let cold = HamtCandidate::build(cold_rows, vec![], budget()).unwrap();
        let cold_generation = cold.card_dependency_generation(id(8));
        assert!(matches!(
            cold.with_binding_removed(id(12), 200, id(2)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(cold.binding(id(12)).unwrap().unwrap(), &first_row);
        assert_eq!(cold.card_dependency_generation(id(8)), cold_generation);
    }

    #[test]
    // memory—v1: Repeated REVOKE cannot overwrite the first tombstone or advance generations.
    fn confirmation_tombstone_rejects_repeat_and_preserves_history() {
        let original = candidate();
        let original_row = original
            .confirmations
            .get(&id(15))
            .unwrap()
            .as_ref()
            .clone();
        let original_generation = original.card_dependency_generation(id(8)).unwrap();
        let revoked = original
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap();
        let first_row = revoked.confirmations.get(&id(15)).unwrap().as_ref().clone();
        assert_eq!(first_row.revoked_at, Some(100));
        assert_eq!(first_row.revoked_by, Some(id(1)));
        assert_eq!(
            revoked.card_dependency_generation(id(8)),
            Some(original_generation + 1)
        );
        assert_eq!(
            original.confirmations.get(&id(15)).unwrap().as_ref(),
            &original_row
        );
        assert_eq!(
            original.card_dependency_generation(id(8)),
            Some(original_generation)
        );

        let generation = revoked.card_dependency_generation(id(8));
        let other_generation = revoked.card_dependency_generation(id(9));
        let rule_generation = revoked.rule_set_dependency_generation(id(10));
        for (time, actor) in [(100, id(1)), (200, id(2))] {
            assert!(matches!(
                revoked.with_confirmation_revoked(id(15), time, actor),
                Err(CandidateError::InconsistentBinding)
            ));
            assert_eq!(
                revoked.confirmations.get(&id(15)).unwrap().as_ref(),
                &first_row
            );
            assert_eq!(revoked.card_dependency_generation(id(8)), generation);
            assert_eq!(revoked.card_dependency_generation(id(9)), other_generation);
            assert_eq!(
                revoked.rule_set_dependency_generation(id(10)),
                rule_generation
            );
        }

        let mut cold_rows = rows();
        cold_rows.binding_confirmations[0] = first_row.clone();
        let cold = HamtCandidate::build(cold_rows, vec![], budget()).unwrap();
        let cold_generation = cold.card_dependency_generation(id(8));
        assert!(matches!(
            cold.with_confirmation_revoked(id(15), 200, id(2)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            cold.confirmations.get(&id(15)).unwrap().as_ref(),
            &first_row
        );
        assert_eq!(cold.card_dependency_generation(id(8)), cold_generation);
    }

    #[test]
    // memory—v1: A batch cannot replace a revoked confirmation or publish its prefix.
    fn confirmation_batch_tombstone_conflict_is_atomic() {
        let revoked = candidate()
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap();
        let tombstone = revoked.confirmations.get(&id(15)).unwrap().as_ref().clone();
        let generation = revoked.card_dependency_generation(id(8));
        let mut prefix = rows().binding_confirmations.remove(0);
        prefix.confirmation_id = id(30);
        let mut replacement = prefix.clone();
        replacement.confirmation_id = id(15);
        assert!(matches!(
            revoked.with_confirmations_batch(&[prefix, replacement]),
            Err(CandidateError::Rows(ValidationError::DuplicateId {
                table: Table::BindingConfirmation,
                id: duplicate,
            })) if duplicate == id(15)
        ));
        assert!(!revoked.confirmations.contains_key(&id(30)));
        assert_eq!(
            revoked.confirmations.get(&id(15)).unwrap().as_ref(),
            &tombstone
        );
        assert_eq!(revoked.card_dependency_generation(id(8)), generation);
    }

    #[test]
    // memory—v1 §4.12: Card toggles preserve lifecycle history and snapshot isolation.
    fn card_disable_enable_preserves_tombstones_and_snapshot_generations() {
        let original = candidate()
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap()
            .with_binding_removed(id(14), 200, id(2))
            .unwrap();
        let generation = original.card_dependency_generation(id(8)).unwrap();
        let other_generation = original.card_dependency_generation(id(9)).unwrap();
        let removed = original.binding(id(14)).unwrap().unwrap().clone();
        let revoked = original.binding_confirmations(id(12)).unwrap()[0].clone();
        let row_count = original.budget_and_row_count();
        assert_eq!(
            (removed.removed_at, removed.removed_by),
            (Some(200), Some(id(2)))
        );
        assert_eq!(
            (revoked.revoked_at, revoked.revoked_by),
            (Some(100), Some(id(1)))
        );

        let disabled = original
            .with_user_card_status(id(8), UserCardStatus::Disabled)
            .unwrap();
        let enabled = disabled
            .with_user_card_status(id(8), UserCardStatus::Active)
            .unwrap();

        for (snapshot, status, expected_generation) in [
            (&original, UserCardStatus::Active, generation),
            (&disabled, UserCardStatus::Disabled, generation + 1),
            (&enabled, UserCardStatus::Active, generation + 2),
        ] {
            assert_eq!(snapshot.user_card(id(8)).unwrap().status, status);
            assert_eq!(
                snapshot.card_dependency_generation(id(8)),
                Some(expected_generation)
            );
            assert_eq!(
                snapshot.user_card(id(9)).unwrap().status,
                UserCardStatus::Active
            );
            assert_eq!(
                snapshot.card_dependency_generation(id(9)),
                Some(other_generation)
            );
            assert_eq!(snapshot.binding(id(14)).unwrap().unwrap(), &removed);
            assert_eq!(
                snapshot.binding_confirmations(id(12)).unwrap(),
                vec![&revoked]
            );
            assert_eq!(snapshot.budget_and_row_count(), row_count);
        }
    }

    #[test]
    fn dependency_generation_overflow_is_refused_without_changing_the_candidate() {
        let mut candidate = candidate();
        candidate.card_dependencies.insert(id(8), u64::MAX);
        candidate.rule_set_dependencies.insert(id(10), u64::MAX);
        assert!(matches!(
            candidate.with_user_card_status(id(8), UserCardStatus::Disabled),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            candidate.user_card(id(8)).unwrap().status,
            UserCardStatus::Active
        );
        assert!(matches!(
            candidate.with_current_version(id(10), &[1]),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            candidate
                .selected_version(id(10))
                .unwrap()
                .unwrap()
                .version_bytes,
            vec![2]
        );
        assert_eq!(candidate.card_dependency_generation(id(8)), Some(u64::MAX));
        assert_eq!(
            candidate.rule_set_dependency_generation(id(10)),
            Some(u64::MAX)
        );
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
    // memory—v1: A stale witness, same-sized key substitution, or bad change index must not hide corruption.
    fn source_publication_rechecks_every_unproven_index() {
        let before = candidate();
        let mut changed_binding = before.clone();
        changed_binding.confirmations_by_binding.remove(&id(12));
        let mut missing_source = before.clone();
        let row = missing_source.rule_sets.remove(&id(10)).unwrap();
        missing_source.rule_sets.insert(id(99), row);
        let mut changed_source_index = before.clone();
        changed_source_index.changes_by_rule_set.clear();
        for mut broken in [changed_binding, missing_source, changed_source_index] {
            assert_eq!(
                broken.check_publication_indexes(true),
                Err(CandidateError::InconsistentBinding)
            );
        }
        let mut unproven = before.clone();
        unproven.checked_bindings = None;
        unproven.check_publication_indexes(true).unwrap();
        assert!(unproven.checked_bindings.is_some());
        before.validate_binding_indexes().unwrap();
        before.validate_confirmation_indexes().unwrap();
    }

    #[test]
    // memory—v1: Writes obey the same confirmation references and lengths as cold load.
    fn confirmation_writes_enforce_cold_load_constraints() {
        let candidate = candidate();
        let mut binding_confirmation = rows().binding_confirmations.remove(0);
        binding_confirmation.confirmation_id = id(30);
        binding_confirmation.confirmer_user_id = id(99);
        assert!(matches!(
            candidate.with_confirmation_insert(binding_confirmation.clone()),
            Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::BindingConfirmation,
                field: "confirmer_user_id",
                id: missing,
            })) if missing == id(99)
        ));
        assert!(matches!(
            candidate.with_confirmations_batch(&[binding_confirmation.clone()]),
            Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::BindingConfirmation,
                field: "confirmer_user_id",
                id: missing,
            })) if missing == id(99)
        ));
        binding_confirmation.confirmer_user_id = id(1);
        binding_confirmation.operation_id = vec![1; 256];
        for result in [
            candidate.with_confirmation_insert(binding_confirmation.clone()),
            candidate.with_confirmations_batch(&[binding_confirmation.clone()]),
        ] {
            assert!(matches!(
                result,
                Err(CandidateError::Rows(ValidationError::FieldTooLong {
                    table: Table::BindingConfirmation,
                    field: "operation_id",
                    max: 255,
                    actual: 256,
                }))
            ));
        }

        let mut change = rows().rule_set_change_confirmations.remove(0);
        change.confirmation_id = id(31);
        change.confirmer_user_id = id(99);
        assert!(matches!(
            candidate.with_change_confirmation_insert(change.clone()),
            Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::RuleSetChangeConfirmation,
                field: "confirmer_user_id",
                id: missing,
            })) if missing == id(99)
        ));
        change.confirmer_user_id = id(1);
        change.confirmed_at_bytes = vec![1; 256];
        assert!(matches!(
            candidate.with_change_confirmation_insert(change),
            Err(CandidateError::Rows(ValidationError::FieldTooLong {
                table: Table::RuleSetChangeConfirmation,
                field: "confirmed_at_bytes",
                max: 255,
                actual: 256,
            }))
        ));
        assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);
        assert_eq!(candidate.change_confirmations(id(10)).unwrap().len(), 1);
    }

    #[test]
    // memory—v1: Rule-set creation must remain reconstructable from its stored pointer.
    fn rule_set_creation_requires_an_existing_owner_and_exact_current_version() {
        let candidate = candidate();
        let mut rule_set = RuleSetRow {
            rule_set_id: id(30),
            owner_tenant_id: id(5),
            current_version_bytes: vec![1],
            status: RuleSetStatus::Active,
        };
        let version = version(30, 1);
        rule_set.current_version_bytes = vec![2];
        assert!(matches!(
            candidate.with_rule_set_create(rule_set.clone(), version.clone()),
            Err(CandidateError::Rows(
                ValidationError::MissingVersionReference { .. }
            ))
        ));
        rule_set.current_version_bytes = vec![1];
        rule_set.owner_tenant_id = id(99);
        assert!(matches!(
            candidate.with_rule_set_create(rule_set.clone(), version.clone()),
            Err(CandidateError::Rows(ValidationError::MissingReference {
                table: Table::RuleSet,
                field: "owner_tenant_id",
                id: missing,
            })) if missing == id(99)
        ));
        rule_set.owner_tenant_id = id(5);
        let mut oversized = version.clone();
        oversized.timestamp_bytes = vec![1; 256];
        assert!(matches!(
            candidate.with_rule_set_create(rule_set.clone(), oversized),
            Err(CandidateError::Rows(ValidationError::FieldTooLong {
                table: Table::RuleSetVersion,
                field: "timestamp_bytes",
                max: 255,
                actual: 256,
            }))
        ));
        let updated = candidate
            .with_rule_set_create(rule_set.clone(), version)
            .unwrap();
        assert_eq!(
            updated.rule_set(id(30)).unwrap().current_version_bytes,
            rule_set.current_version_bytes
        );
        assert_eq!(
            updated
                .selected_version(id(30))
                .unwrap()
                .unwrap()
                .version_bytes,
            vec![1]
        );
        assert!(candidate.rule_set(id(30)).is_none());
    }

    #[test]
    // memory—v1: A binding confirmation must contain both revocation fields or neither.
    fn confirmation_insert_rejects_incomplete_tombstones() {
        let candidate = candidate();
        let mut row = rows().binding_confirmations.remove(0);
        row.confirmation_id = id(30);
        let before_count = candidate.budget_and_row_count().1;
        let before_generation = candidate.card_dependency_generation(id(8));

        for (revoked_at, revoked_by) in [(Some(10), None), (None, Some(id(1)))] {
            row.revoked_at = revoked_at;
            row.revoked_by = revoked_by;
            assert!(matches!(
                candidate.with_confirmation_insert(row.clone()),
                Err(CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::BindingConfirmation,
                    field,
                    id: error_id,
                })) if error_id == row.confirmation_id
                    && field == if revoked_at.is_some() { "revoked_by" } else { "revoked_at" }
            ));
            assert_eq!(candidate.budget_and_row_count().1, before_count);
            assert_eq!(
                candidate.card_dependency_generation(id(8)),
                before_generation
            );
            assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);
        }

        row.revoked_at = Some(10);
        row.revoked_by = Some(id(1));
        assert!(matches!(
            candidate.with_confirmation_insert(row.clone()),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(candidate.budget_and_row_count().1, before_count);
        assert_eq!(
            candidate.card_dependency_generation(id(8)),
            before_generation
        );
        assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);
    }

    #[test]
    // memory—v1: Revoking one trace does not withdraw another active confirmation.
    fn change_confirmation_revoke_preserves_history_and_restores_with_new_row() {
        let mut input = rows();
        input.rule_set_change_confirmations[0].version_bytes = vec![2];
        let first = input.rule_set_change_confirmations[0].clone();
        let mut second = first.clone();
        second.confirmation_id = id(30);
        input.rule_set_change_confirmations.push(second.clone());
        let original = HamtCandidate::build(
            input,
            vec![CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![2],
            }],
            budget(),
        )
        .unwrap();
        let generation = original.rule_set_dependency_generation(id(10)).unwrap();
        let other_generation = original.rule_set_dependency_generation(id(11));
        let card_generation = original.card_dependency_generation(id(8));
        let counts = original.table_counts();
        let classify = |candidate: &HamtCandidate| {
            classify_change_confirmations(
                candidate.change_confirmations(id(10)).unwrap(),
                id(10),
                &[2],
            )
        };
        assert_eq!(classify(&original), ChangeConfirmationState::Active);

        let once = original
            .with_change_confirmation_revoked(first.confirmation_id, 100, id(1))
            .unwrap();
        assert_eq!(classify(&once), ChangeConfirmationState::Active);
        let mut first_revoked = first.clone();
        first_revoked.revoked_at = Some(100);
        first_revoked.revoked_by = Some(id(1));
        assert_eq!(
            once.change_confirmations[&first.confirmation_id].as_ref(),
            &first_revoked
        );
        assert_eq!(
            once.change_confirmations[&second.confirmation_id].as_ref(),
            &second
        );
        assert_eq!(
            once.rule_set_dependency_generation(id(10)),
            Some(generation + 1)
        );
        assert_eq!(
            once.rule_set_dependency_generation(id(11)),
            other_generation
        );
        assert_eq!(once.card_dependency_generation(id(8)), card_generation);
        assert_eq!(once.table_counts(), counts);

        let twice = once
            .with_change_confirmation_revoked(second.confirmation_id, 200, id(2))
            .unwrap();
        assert_eq!(classify(&twice), ChangeConfirmationState::Withdrawn);
        let mut second_revoked = second.clone();
        second_revoked.revoked_at = Some(200);
        second_revoked.revoked_by = Some(id(2));
        assert_eq!(
            twice.change_confirmations[&first.confirmation_id].as_ref(),
            &first_revoked
        );
        assert_eq!(
            twice.change_confirmations[&second.confirmation_id].as_ref(),
            &second_revoked
        );
        assert_eq!(
            twice.rule_set_dependency_generation(id(10)),
            Some(generation + 2)
        );
        assert_eq!(twice.table_counts(), counts);

        let mut replacement = first.clone();
        replacement.confirmation_id = id(31);
        let restored = twice
            .with_change_confirmation_insert(replacement.clone())
            .unwrap();
        assert_eq!(classify(&restored), ChangeConfirmationState::Active);
        assert_eq!(
            restored.rule_set_dependency_generation(id(10)),
            Some(generation + 3)
        );
        assert_eq!(restored.change_confirmations(id(10)).unwrap().len(), 3);
        assert_eq!(
            restored.change_confirmations[&first.confirmation_id].as_ref(),
            &first_revoked
        );
        assert_eq!(
            restored.change_confirmations[&second.confirmation_id].as_ref(),
            &second_revoked
        );
        assert_eq!(
            restored.change_confirmations[&replacement.confirmation_id].as_ref(),
            &replacement
        );

        assert_eq!(classify(&original), ChangeConfirmationState::Active);
        assert_eq!(
            original.change_confirmations[&first.confirmation_id].as_ref(),
            &first
        );
        assert_eq!(
            original.change_confirmations[&second.confirmation_id].as_ref(),
            &second
        );
        assert_eq!(
            original.rule_set_dependency_generation(id(10)),
            Some(generation)
        );
        assert_eq!(classify(&once), ChangeConfirmationState::Active);
        assert_eq!(
            once.change_confirmations[&second.confirmation_id].as_ref(),
            &second
        );
        assert_eq!(classify(&twice), ChangeConfirmationState::Withdrawn);
        assert_eq!(twice.change_confirmations(id(10)).unwrap().len(), 2);
    }

    #[test]
    // memory—v1: Rejected revocations never rewrite a row or advance a generation.
    fn change_confirmation_revoke_rejects_unknown_tombstones_and_overflow() {
        let original = candidate();
        let first = original.change_confirmations[&id(15)].as_ref().clone();
        let generation = original.rule_set_dependency_generation(id(10));
        assert!(matches!(
            original.with_change_confirmation_revoked(id(99), 100, id(1)),
            Err(CandidateError::UnknownId {
                table: Table::RuleSetChangeConfirmation,
                id: error_id,
            }) if error_id == id(99)
        ));
        assert_eq!(original.change_confirmations[&id(15)].as_ref(), &first);
        assert_eq!(original.rule_set_dependency_generation(id(10)), generation);

        let revoked = original
            .with_change_confirmation_revoked(id(15), 100, id(1))
            .unwrap();
        let tombstone = revoked.change_confirmations[&id(15)].as_ref().clone();
        let revoked_generation = revoked.rule_set_dependency_generation(id(10));
        for (time, actor) in [(100, id(1)), (200, id(2))] {
            assert!(matches!(
                revoked.with_change_confirmation_revoked(id(15), time, actor),
                Err(CandidateError::InconsistentBinding)
            ));
            assert_eq!(revoked.change_confirmations[&id(15)].as_ref(), &tombstone);
            assert_eq!(
                revoked.rule_set_dependency_generation(id(10)),
                revoked_generation
            );
        }

        for (revoked_at, revoked_by) in [(Some(100), None), (None, Some(id(1)))] {
            let mut corrupt = original.clone();
            let mut half = first.clone();
            half.revoked_at = revoked_at;
            half.revoked_by = revoked_by;
            corrupt
                .change_confirmations
                .insert(id(15), Arc::new(half.clone()));
            assert!(matches!(
                corrupt.with_change_confirmation_revoked(id(15), 200, id(2)),
                Err(CandidateError::InconsistentBinding)
            ));
            assert_eq!(corrupt.change_confirmations[&id(15)].as_ref(), &half);
            assert_eq!(corrupt.rule_set_dependency_generation(id(10)), generation);
        }

        let mut exhausted = original.clone();
        exhausted.set_rule_set_dependency_generation_for_test(id(10), u64::MAX);
        assert!(matches!(
            exhausted.with_change_confirmation_revoked(id(15), 100, id(1)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(exhausted.change_confirmations[&id(15)].as_ref(), &first);
        assert_eq!(
            exhausted.rule_set_dependency_generation(id(10)),
            Some(u64::MAX)
        );
        assert_eq!(original.change_confirmations[&id(15)].as_ref(), &first);
        assert_eq!(original.rule_set_dependency_generation(id(10)), generation);
    }

    #[test]
    // memory—v1: Historical rule-set change confirmations preserve complete tombstones.
    fn change_confirmation_insert_rejects_incomplete_tombstones() {
        let candidate = candidate();
        let mut row = rows().rule_set_change_confirmations.remove(0);
        row.confirmation_id = id(30);
        let before_count = candidate.budget_and_row_count().1;
        let before_generation = candidate.rule_set_dependency_generation(id(10));

        for (revoked_at, revoked_by) in [(Some(10), None), (None, Some(id(1)))] {
            row.revoked_at = revoked_at;
            row.revoked_by = revoked_by;
            assert!(matches!(
                candidate.with_change_confirmation_insert(row.clone()),
                Err(CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::RuleSetChangeConfirmation,
                    field,
                    id: error_id,
                })) if error_id == row.confirmation_id
                    && field == if revoked_at.is_some() { "revoked_by" } else { "revoked_at" }
            ));
            assert_eq!(candidate.budget_and_row_count().1, before_count);
            assert_eq!(
                candidate.rule_set_dependency_generation(id(10)),
                before_generation
            );
            assert_eq!(candidate.change_confirmations(id(10)).unwrap().len(), 1);
        }

        row.revoked_at = Some(10);
        row.revoked_by = Some(id(1));
        let updated = candidate
            .with_change_confirmation_insert(row.clone())
            .unwrap();
        assert_eq!(updated.budget_and_row_count().1, before_count + 1);
        assert!(updated
            .change_confirmations(id(10))
            .unwrap()
            .contains(&&row));
        assert_eq!(candidate.change_confirmations(id(10)).unwrap().len(), 1);
    }

    #[test]
    // memory—v1: An invalid tombstone rejects the whole confirmation batch.
    fn confirmation_batch_rejects_incomplete_tombstones_atomically() {
        let candidate = candidate()
            .with_confirmation_revoked(id(15), 5, id(1))
            .unwrap();
        let mut prefix = rows().binding_confirmations.remove(0);
        prefix.confirmation_id = id(30);
        let mut last = prefix.clone();
        last.confirmation_id = id(31);
        last.binding_id = id(13);
        let before_count = candidate.budget_and_row_count().1;
        let before_first_generation = candidate.card_dependency_generation(id(8));
        let before_second_generation = candidate.card_dependency_generation(id(9));

        for (revoked_at, revoked_by) in [(Some(10), None), (None, Some(id(1)))] {
            last.revoked_at = revoked_at;
            last.revoked_by = revoked_by;
            assert!(matches!(
                candidate.with_confirmations_batch(&[prefix.clone(), last.clone()]),
                Err(CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::BindingConfirmation,
                    field,
                    id: error_id,
                })) if error_id == last.confirmation_id
                    && field == if revoked_at.is_some() { "revoked_by" } else { "revoked_at" }
            ));
            assert_eq!(candidate.budget_and_row_count().1, before_count);
            assert_eq!(
                candidate.card_dependency_generation(id(8)),
                before_first_generation
            );
            assert_eq!(
                candidate.card_dependency_generation(id(9)),
                before_second_generation
            );
            assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);
            assert!(candidate.binding_confirmations(id(13)).unwrap().is_empty());
        }

        last.revoked_at = Some(10);
        last.revoked_by = Some(id(1));
        assert!(matches!(
            candidate.with_confirmations_batch(&[prefix.clone(), last.clone()]),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(candidate.budget_and_row_count().1, before_count);
        assert_eq!(
            candidate.card_dependency_generation(id(8)),
            before_first_generation
        );
        assert_eq!(
            candidate.card_dependency_generation(id(9)),
            before_second_generation
        );
        assert_eq!(candidate.binding_confirmations(id(12)).unwrap().len(), 1);
        assert!(candidate.binding_confirmations(id(13)).unwrap().is_empty());
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
    // memory—v1 §4.5/§4.13: Cold-load uniqueness is checked independently of SQL.
    fn candidate_build_rejects_duplicate_binding_and_overlay() {
        let mut input = rows();
        let mut duplicate_pair = input.bindings[0].clone();
        duplicate_pair.binding_id = id(30);
        duplicate_pair.binding_layer = BindingLayer::Overlay;
        input.bindings.push(duplicate_pair);
        let mut other_card_overlay = input.bindings[2].clone();
        other_card_overlay.binding_id = id(31);
        other_card_overlay.user_card_id = id(9);
        other_card_overlay.rule_set_id = id(11);
        input.bindings.push(other_card_overlay);
        for input in [input.clone(), {
            input.bindings.reverse();
            input
        }] {
            assert!(matches!(
                HamtCandidate::build(input, vec![], budget()),
                Err(CandidateError::DoubleBinding {
                    user_card_id,
                    rule_set_id,
                }) if user_card_id == id(8) && rule_set_id == id(10)
            ));
        }

        let mut input = rows();
        let mut second_overlay = input.bindings[2].clone();
        second_overlay.binding_id = id(30);
        second_overlay.rule_set_id = id(10);
        input
            .bindings
            .retain(|binding| binding.binding_id != id(12));
        input
            .binding_confirmations
            .retain(|confirmation| confirmation.binding_id != id(12));
        input.bindings.push(second_overlay);
        assert!(matches!(
            HamtCandidate::build(input, vec![], budget()),
            Err(CandidateError::DoubleOverlay { user_card_id }) if user_card_id == id(8)
        ));
    }

    #[test]
    // memory—v1 §4.12: REMOVE releases the relationship slot without erasing history.
    fn binding_remove_rebind_preserves_rows_indexes_and_generations() {
        for binding_index in [0, 2] {
            let mut input = rows();
            input.rule_sets[1].owner_tenant_id = id(5);
            let old = input.bindings[binding_index].clone();
            let initial = HamtCandidate::build(input, vec![], budget()).unwrap();
            let initial_count = initial.budget_and_row_count().1;
            let generation = initial.card_dependency_generation(id(8)).unwrap();
            let other_generation = initial.card_dependency_generation(id(9));
            let rule_generation = initial.rule_set_dependency_generation(old.rule_set_id);
            let removed = initial
                .with_binding_removed(old.binding_id, 100, id(1))
                .unwrap();
            let mut replacement = old.clone();
            replacement.binding_id = id(30);
            let rebound = removed.with_binding_insert(replacement.clone()).unwrap();

            let mut tombstone = old.clone();
            tombstone.removed_at = Some(100);
            tombstone.removed_by = Some(id(1));
            assert_eq!(initial.binding(old.binding_id).unwrap(), Some(&old));
            assert_eq!(removed.binding(old.binding_id).unwrap(), Some(&tombstone));
            assert_eq!(rebound.binding(old.binding_id).unwrap(), Some(&tombstone));
            assert_eq!(rebound.binding(id(30)).unwrap(), Some(&replacement));
            assert!(removed.binding(id(30)).unwrap().is_none());
            assert_eq!(rebound.budget_and_row_count().1, initial_count + 1);
            assert_eq!(
                removed.card_dependency_generation(id(8)),
                Some(generation + 1)
            );
            assert_eq!(
                rebound.card_dependency_generation(id(8)),
                Some(generation + 2)
            );
            assert_eq!(rebound.card_dependency_generation(id(9)), other_generation);
            assert_eq!(
                rebound.rule_set_dependency_generation(old.rule_set_id),
                rule_generation
            );
            let card = rebound.card_candidate(id(8)).unwrap();
            assert_eq!(card.bindings.len(), 3);
            assert!(card.bindings.contains(&&tombstone));
            assert!(card.bindings.contains(&&replacement));
            let impact = rebound.rule_set_impact(old.rule_set_id).unwrap();
            assert!(impact.binding_ids.contains(&old.binding_id));
            assert!(impact.binding_ids.contains(&replacement.binding_id));
            if old.binding_id == id(12) {
                assert_eq!(rebound.binding_confirmations(id(12)).unwrap().len(), 1);
                assert!(rebound.binding_confirmations(id(30)).unwrap().is_empty());
                let mut confirmation = rows().binding_confirmations[0].clone();
                confirmation.confirmation_id = id(32);
                confirmation.binding_id = id(30);
                let confirmed = rebound
                    .with_confirmation_insert(confirmation.clone())
                    .unwrap();
                assert_eq!(
                    confirmed.binding_confirmations(id(30)).unwrap(),
                    vec![&confirmation]
                );
                assert_eq!(
                    confirmed.card_dependency_generation(id(8)),
                    Some(generation + 3)
                );
                assert_eq!(confirmed.binding(id(12)).unwrap(), Some(&tombstone));
            }
            assert!(matches!(
                rebound.with_binding_insert(BindingRow {
                    binding_id: old.binding_id,
                    ..replacement.clone()
                }),
                Err(CandidateError::Rows(ValidationError::DuplicateId {
                    table: Table::Binding,
                    id: duplicate,
                })) if duplicate == old.binding_id
            ));
            assert!(matches!(
                rebound.with_binding_insert(BindingRow {
                    binding_id: id(31),
                    ..replacement
                }),
                Err(CandidateError::DoubleBinding { user_card_id, rule_set_id })
                    if user_card_id == id(8) && rule_set_id == old.rule_set_id
            ));
            assert_eq!(
                rebound.card_dependency_generation(id(8)),
                Some(generation + 2)
            );
        }
    }

    #[test]
    // memory—v1: The indexed slot check refuses dangling or foreign entries.
    fn binding_insert_refuses_inconsistent_card_index() {
        let mut proposed = rows().bindings[0].clone();
        proposed.binding_id = id(30);
        let vacant = candidate()
            .with_binding_removed(id(12), 100, id(1))
            .unwrap()
            .with_binding_removed(id(14), 100, id(1))
            .unwrap();
        let before = vacant.card_dependency_generation(proposed.user_card_id);

        let mut dangling = vacant.clone();
        add_member(
            &mut dangling.bindings_by_card,
            proposed.user_card_id,
            id(200),
        );
        assert!(matches!(
            dangling.with_binding_insert(proposed.clone()),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            dangling.card_dependency_generation(proposed.user_card_id),
            before
        );

        let mut foreign = vacant;
        add_member(&mut foreign.bindings_by_card, proposed.user_card_id, id(13));
        assert!(matches!(
            foreign.with_binding_insert(proposed.clone()),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            foreign.card_dependency_generation(proposed.user_card_id),
            before
        );
    }

    #[test]
    // memory—v1: Disabled cards and revoked confirmations retain their binding slots.
    fn binding_uniqueness_survives_card_disable_and_confirmation_revoke() {
        let mut input = rows();
        input.rule_sets[1].owner_tenant_id = id(5);
        let candidate = HamtCandidate::build(input, vec![], budget()).unwrap();
        let revoked = candidate
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap();
        let disabled = revoked
            .with_user_card_status(id(8), UserCardStatus::Disabled)
            .unwrap();
        let generation = disabled.card_dependency_generation(id(8));
        let mut duplicate = rows().bindings[0].clone();
        duplicate.binding_id = id(30);
        for snapshot in [&revoked, &disabled] {
            assert!(matches!(
                snapshot.with_binding_insert(duplicate.clone()),
                Err(CandidateError::DoubleBinding { user_card_id, rule_set_id })
                    if user_card_id == id(8) && rule_set_id == id(10)
            ));
        }
        let without_base = disabled.with_binding_removed(id(12), 101, id(1)).unwrap();
        duplicate.binding_layer = BindingLayer::Overlay;
        assert!(matches!(
            without_base.with_binding_insert(duplicate),
            Err(CandidateError::DoubleOverlay { user_card_id }) if user_card_id == id(8)
        ));
        assert_eq!(disabled.card_dependency_generation(id(8)), generation);
        assert_eq!(
            without_base.card_dependency_generation(id(8)),
            generation.map(|n| n + 1)
        );
    }

    #[test]
    // memory—v1: Partial removal markers cannot enter an incremental candidate.
    fn binding_insert_rejects_partial_tombstones_without_mutation() {
        let candidate = candidate();
        let generation = candidate.card_dependency_generation(id(8));
        let row_count = candidate.budget_and_row_count();
        for (removed_at, removed_by, missing_field) in [
            (Some(100), None, "removed_by"),
            (None, Some(id(1)), "removed_at"),
        ] {
            let mut row = rows().bindings[0].clone();
            row.binding_id = id(30);
            row.removed_at = removed_at;
            row.removed_by = removed_by;
            assert!(matches!(
                candidate.with_binding_insert(row),
                Err(CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::Binding, field, id: binding_id,
                })) if field == missing_field && binding_id == id(30)
            ));
            assert!(candidate.binding(id(30)).unwrap().is_none());
            assert_eq!(candidate.card_dependency_generation(id(8)), generation);
            assert_eq!(candidate.budget_and_row_count(), row_count);
        }
    }

    #[test]
    // memory—v1: Cold load keeps multiple historical rows and one current row in either order.
    fn cold_load_accepts_rebound_history_and_preserves_indexes() {
        for binding_index in [0, 2] {
            for reverse in [false, true] {
                let mut input = rows();
                let mut historical = input.bindings[binding_index].clone();
                historical.removed_at = Some(100);
                historical.removed_by = Some(id(1));
                input.bindings[binding_index] = historical.clone();
                let mut older = historical.clone();
                older.binding_id = id(31);
                older.removed_at = Some(50);
                let mut current = historical.clone();
                current.binding_id = id(30);
                current.removed_at = None;
                current.removed_by = None;
                input.bindings.extend([older.clone(), current.clone()]);
                if reverse {
                    input.bindings.reverse();
                }
                let candidate = HamtCandidate::build(input, vec![], budget()).unwrap();
                let card = candidate.card_candidate(id(8)).unwrap();
                assert_eq!(card.bindings.len(), 4);
                assert!(card.bindings.contains(&&historical));
                assert!(card.bindings.contains(&&older));
                assert!(card.bindings.contains(&&current));
                let impact = candidate.rule_set_impact(current.rule_set_id).unwrap();
                for binding_id in [historical.binding_id, older.binding_id, current.binding_id] {
                    assert!(impact.binding_ids.contains(&binding_id));
                }
                assert_eq!(candidate.card_dependency_generation(id(8)), Some(0));
            }
        }
    }

    #[test]
    // memory—v1: Cold-load uniqueness ignores neither card status nor broken tombstones.
    fn cold_load_rejects_conflicts_and_incomplete_tombstones() {
        let mut duplicate = rows();
        duplicate.user_cards[0].status = UserCardStatus::Disabled;
        let mut second = duplicate.bindings[0].clone();
        second.binding_id = id(30);
        duplicate.bindings.push(second);
        assert!(matches!(
            HamtCandidate::build(duplicate, vec![], budget()),
            Err(CandidateError::DoubleBinding { user_card_id, rule_set_id })
                if user_card_id == id(8) && rule_set_id == id(10)
        ));

        let mut overlays = rows();
        overlays.user_cards[0].status = UserCardStatus::Disabled;
        overlays.bindings[0].binding_layer = BindingLayer::Overlay;
        assert!(matches!(
            HamtCandidate::build(overlays, vec![], budget()),
            Err(CandidateError::DoubleOverlay { user_card_id }) if user_card_id == id(8)
        ));

        for (removed_at, removed_by, missing_field) in [
            (Some(100), None, "removed_by"),
            (None, Some(id(1)), "removed_at"),
        ] {
            let mut input = rows();
            input.bindings[0].removed_at = removed_at;
            input.bindings[0].removed_by = removed_by;
            assert!(matches!(
                HamtCandidate::build(input, vec![], budget()),
                Err(CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::Binding, field, id: binding_id,
                })) if field == missing_field && binding_id == id(12)
            ));
        }
        let mut input = rows();
        input.bindings[0].removed_at = Some(100);
        input.bindings[0].removed_by = Some(id(1));
        let mut duplicate_id = input.bindings[0].clone();
        duplicate_id.removed_at = None;
        duplicate_id.removed_by = None;
        input.bindings.push(duplicate_id);
        assert!(matches!(
            HamtCandidate::build(input, vec![], budget()),
            Err(CandidateError::Rows(ValidationError::DuplicateId {
                table: Table::Binding, id: binding_id,
            })) if binding_id == id(12)
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
    // memory—v1: Tombstones never consume the authorization read budget.
    fn unremoved_index_budgets_history_and_snapshot_updates() {
        let mut input = rows();
        input.rule_sets[1].owner_tenant_id = id(5);
        for n in 40..45 {
            let mut old = input.bindings[0].clone();
            old.binding_id = id(n);
            old.removed_at = Some(100);
            old.removed_by = Some(id(1));
            input.bindings.push(old);
        }
        // Only one nonremoved binding on card 8; all history remains readable
        // under the original API's own, unchanged historical budget.
        input.bindings[2].removed_at = Some(100);
        input.bindings[2].removed_by = Some(id(1));
        let mut limits = budget();
        limits.max_bindings_per_read = 1;
        let initial = HamtCandidate::build(input, vec![], limits).unwrap();
        assert!(matches!(
            initial.card_candidate(id(8)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 7 })
        ));
        let (card, history) = initial.unremoved_card_candidate(id(8)).unwrap();
        assert!(history);
        assert_eq!(card.bindings.len(), 1);
        assert_eq!(card.bindings[0].binding_id, id(12));
        assert_eq!(
            initial.card_authorization_dependency_exhausted(id(8)),
            Ok(false)
        );

        let removed = initial.with_binding_removed(id(12), 200, id(1)).unwrap();
        let (card, history) = removed.unremoved_card_candidate(id(8)).unwrap();
        assert!(history && card.bindings.is_empty());
        assert_eq!(
            initial
                .unremoved_card_candidate(id(8))
                .unwrap()
                .0
                .bindings
                .len(),
            1
        );
        let mut replacement = initial.binding(id(12)).unwrap().unwrap().clone();
        replacement.binding_id = id(50);
        let rebound = removed.with_binding_insert(replacement.clone()).unwrap();
        assert_eq!(
            rebound.unremoved_card_candidate(id(8)).unwrap().0.bindings[0].binding_id,
            id(50)
        );
        assert_eq!(
            removed
                .unremoved_card_candidate(id(8))
                .unwrap()
                .0
                .bindings
                .len(),
            0
        );
        assert_eq!(rebound.card_dependency_generation(id(8)), Some(2));
        for candidate in [&initial, &removed, &rebound] {
            assert_eq!(candidate.validate_binding_indexes(), Ok(()));
        }
        let mut second = replacement;
        second.binding_id = id(51);
        second.rule_set_id = id(11);
        let over = rebound.with_binding_insert(second).unwrap();
        assert!(matches!(
            over.unremoved_card_candidate(id(8)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 2 })
        ));
        assert!(matches!(
            over.card_authorization_dependency_exhausted(id(8)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 2 })
        ));
        assert!(matches!(
            rebound.with_binding_insert(BindingRow {
                binding_id: id(52),
                ..rebound.binding(id(50)).unwrap().unwrap().clone()
            }),
            Err(CandidateError::DoubleBinding { .. })
        ));
        assert_eq!(rebound.card_dependency_generation(id(8)), Some(2));
        let mut exhausted = rebound.clone();
        exhausted.set_card_dependency_generation_for_test(id(8), u64::MAX);
        assert!(matches!(
            exhausted.with_binding_removed(id(50), 300, id(1)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            exhausted
                .unremoved_card_candidate(id(8))
                .unwrap()
                .0
                .bindings
                .len(),
            1
        );
        assert_eq!(exhausted.validate_binding_indexes(), Ok(()));
    }

    #[test]
    // memory—v1: Confirmation index coverage rejects omissions, substitutions,
    // foreign memberships, dangling IDs and empty buckets for both row kinds.
    fn confirmation_index_integrity_rejects_corruption() {
        let original = candidate();
        assert_eq!(original.validate_confirmation_indexes(), Ok(()));

        let mut missing_binding = original.clone();
        missing_binding.confirmations_by_binding.remove(&id(12));
        let mut extra_binding = original.clone();
        add_member(&mut extra_binding.confirmations_by_binding, id(12), id(99));
        let mut foreign_binding = original.clone();
        add_member(
            &mut foreign_binding.confirmations_by_binding,
            id(13),
            id(15),
        );
        let mut swapped_binding = original.clone();
        swapped_binding.confirmations_by_binding.remove(&id(12));
        add_member(
            &mut swapped_binding.confirmations_by_binding,
            id(13),
            id(15),
        );
        let mut empty_binding = original.clone();
        empty_binding
            .confirmations_by_binding
            .insert(id(99), Members::default());
        let mut mismatched_binding_row = original.clone();
        let mut row = (*mismatched_binding_row.confirmations[&id(15)]).clone();
        row.confirmation_id = id(99);
        mismatched_binding_row
            .confirmations
            .insert(id(15), Arc::new(row));
        let mut missing_state = original.clone();
        missing_state.binding_confirmation_states.remove(&id(12));
        let mut foreign_state = original.clone();
        foreign_state
            .binding_confirmation_states
            .insert(id(99), BindingConfirmationState::Active);
        let mut wrong_state = original.clone();
        wrong_state
            .binding_confirmation_states
            .insert(id(12), BindingConfirmationState::Withdrawn);
        let mut dangling_binding = original.clone();
        dangling_binding.bindings.remove(&id(12));

        let mut missing_change = original.clone();
        missing_change.changes_by_rule_set.remove(&id(10));
        let mut extra_change = original.clone();
        add_member(&mut extra_change.changes_by_rule_set, id(10), id(99));
        let mut foreign_change = original.clone();
        add_member(&mut foreign_change.changes_by_rule_set, id(11), id(15));
        let mut swapped_change = original.clone();
        swapped_change.changes_by_rule_set.remove(&id(10));
        add_member(&mut swapped_change.changes_by_rule_set, id(11), id(15));
        let mut empty_change = original.clone();
        empty_change
            .changes_by_rule_set
            .insert(id(99), Members::default());
        let mut mismatched_change_row = original.clone();
        let mut row = (*mismatched_change_row.change_confirmations[&id(15)]).clone();
        row.confirmation_id = id(99);
        mismatched_change_row
            .change_confirmations
            .insert(id(15), Arc::new(row));

        assert!(matches!(
            extra_binding.binding_confirmations(id(12)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            swapped_binding.binding_confirmations(id(13)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            mismatched_binding_row.binding_confirmations(id(12)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            mismatched_binding_row.binding_for_confirmation(id(15)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            dangling_binding.binding_for_confirmation(id(15)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(
            missing_state.binding_confirmation_state(original.binding(id(12)).unwrap().unwrap()),
            Err(CandidateError::InconsistentBinding)
        );
        assert!(matches!(
            extra_change.change_confirmations(id(10)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            swapped_change.change_confirmations(id(11)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            mismatched_change_row.change_confirmations(id(10)),
            Err(CandidateError::InconsistentBinding)
        ));

        for bad in [
            missing_binding,
            extra_binding,
            foreign_binding,
            swapped_binding,
            empty_binding,
            mismatched_binding_row,
            missing_state,
            foreign_state,
            wrong_state,
            dangling_binding,
            missing_change,
            extra_change,
            foreign_change,
            swapped_change,
            empty_change,
            mismatched_change_row,
        ] {
            assert_eq!(
                bad.validate_confirmation_indexes(),
                Err(CandidateError::InconsistentBinding)
            );
        }
    }

    #[test]
    // memory—v1: An invalid classification must still examine every index ID;
    // a later dangling row is an index failure, not just an Invalid state.
    fn invalid_confirmation_does_not_hide_dangling_history() {
        let mut corrupted = candidate();
        add_member(&mut corrupted.confirmations_by_binding, id(12), id(99));
        let ids = corrupted.confirmations_by_binding[&id(12)]
            .iter()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        let mut invalid = (*corrupted.confirmations[&id(15)]).clone();
        invalid.confirmation_id = ids[0];
        invalid.scope_bytes.clear();
        corrupted.confirmations.remove(&ids[1]);
        corrupted.confirmations.insert(ids[0], Arc::new(invalid));
        assert_eq!(
            classify_binding_confirmations(
                [corrupted.confirmations[&ids[0]].as_ref()],
                id(12),
                id(10),
            ),
            BindingConfirmationState::Invalid
        );
        assert_eq!(
            corrupted.compute_binding_confirmation_state(id(12)),
            Err(CandidateError::InconsistentBinding)
        );
    }

    #[test]
    // memory—v1: Cold-build states agree with full-history classification for
    // empty, revoked, malformed and duplicate-active rows in either order.
    fn binding_confirmation_derived_state_matches_classifier() {
        let input = rows();
        let valid = input.binding_confirmations[0].clone();
        let mut second = valid.clone();
        second.confirmation_id = id(30);
        let mut revoked = valid.clone();
        revoked.revoked_at = Some(100);
        revoked.revoked_by = Some(id(1));
        let mut invalid = second.clone();
        invalid.scope_bytes.clear();
        let mut invalid_revoked = invalid.clone();
        invalid_revoked.revoked_at = Some(100);
        invalid_revoked.revoked_by = Some(id(1));
        for confirmations in [
            vec![],
            vec![valid.clone()],
            vec![revoked.clone()],
            vec![invalid.clone()],
            vec![invalid_revoked.clone()],
            vec![revoked.clone(), second.clone()],
            vec![second.clone(), revoked.clone()],
            vec![valid.clone(), second.clone()],
            vec![valid.clone(), invalid.clone()],
            vec![revoked.clone(), invalid.clone()],
            vec![revoked.clone(), invalid_revoked.clone()],
        ] {
            let expected = classify_binding_confirmations(confirmations.iter(), id(12), id(10));
            let mut supplied = input.clone();
            supplied.binding_confirmations = confirmations;
            let candidate = HamtCandidate::build(supplied, vec![], budget()).unwrap();
            let binding = candidate.binding(id(12)).unwrap().unwrap();
            assert_eq!(candidate.binding_confirmation_state(binding), Ok(expected));
            assert_eq!(candidate.validate_confirmation_indexes(), Ok(()));
        }

        for (revoked_at, revoked_by) in [(Some(100), None), (None, Some(id(1)))] {
            let mut candidate = candidate();
            let mut incomplete = (*candidate.confirmations[&id(15)]).clone();
            incomplete.revoked_at = revoked_at;
            incomplete.revoked_by = revoked_by;
            candidate.confirmations.insert(id(15), Arc::new(incomplete));
            candidate
                .refresh_binding_confirmation_state(id(12))
                .unwrap();
            let binding = candidate.binding(id(12)).unwrap().unwrap();
            assert_eq!(
                candidate.binding_confirmation_state(binding),
                Ok(BindingConfirmationState::Invalid)
            );
            assert_eq!(candidate.validate_confirmation_indexes(), Ok(()));
        }
    }

    #[test]
    // memory—v1: Reconciliation classifies each binding's complete fact history,
    // including empty histories, and cannot conceal corruption behind Invalid.
    fn confirmation_reconciliation_isolates_histories_and_detects_corruption() {
        let mut candidate = candidate();
        let mut revoked = (*candidate.confirmations[&id(15)]).clone();
        revoked.confirmation_id = id(30);
        revoked.binding_id = id(13);
        revoked.revoked_at = Some(100);
        revoked.revoked_by = Some(id(1));
        let mut active = revoked.clone();
        active.confirmation_id = id(31);
        active.revoked_at = None;
        active.revoked_by = None;
        for row in [revoked, active] {
            add_member(
                &mut candidate.confirmations_by_binding,
                row.binding_id,
                row.confirmation_id,
            );
            candidate
                .confirmations
                .insert(row.confirmation_id, Arc::new(row));
        }
        candidate
            .refresh_binding_confirmation_state(id(13))
            .unwrap();
        assert_eq!(
            candidate.compute_binding_confirmation_state(id(12)),
            Ok(BindingConfirmationState::Active)
        );
        assert_eq!(
            candidate.compute_binding_confirmation_state(id(13)),
            Ok(BindingConfirmationState::Active)
        );
        assert_eq!(
            candidate.compute_binding_confirmation_state(id(14)),
            Ok(BindingConfirmationState::Invalid)
        );
        assert_eq!(candidate.validate_confirmation_indexes(), Ok(()));

        let mut half_tombstone = (*candidate.confirmations[&id(30)]).clone();
        half_tombstone.revoked_by = None;
        candidate
            .confirmations
            .insert(id(30), Arc::new(half_tombstone));
        assert_eq!(
            candidate.compute_binding_confirmation_state(id(13)),
            Ok(BindingConfirmationState::Invalid)
        );
        assert_eq!(
            candidate.validate_confirmation_indexes(),
            Err(CandidateError::InconsistentBinding)
        );
        candidate
            .refresh_binding_confirmation_state(id(13))
            .unwrap();
        assert_eq!(candidate.validate_confirmation_indexes(), Ok(()));

        let mut ids = candidate.confirmations_by_binding[&id(13)].clone();
        ids.remove(&id(31));
        candidate.confirmations_by_binding.insert(id(13), ids);
        add_member(&mut candidate.confirmations_by_binding, id(14), id(31));
        assert_eq!(
            candidate.validate_confirmation_indexes(),
            Err(CandidateError::InconsistentBinding)
        );
    }

    #[test]
    // memory—v1: The derived classification follows each private candidate's
    // complete history and cannot transfer across binding identities.
    fn binding_confirmation_state_tracks_mutations_and_history() {
        let original = candidate();
        let state = |candidate: &HamtCandidate, binding_id| {
            let binding = candidate.binding(binding_id).unwrap().unwrap();
            candidate.binding_confirmation_state(binding).unwrap()
        };
        assert_eq!(state(&original, id(12)), BindingConfirmationState::Active);
        assert_eq!(state(&original, id(13)), BindingConfirmationState::Invalid);

        let revoked = original
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap();
        assert_eq!(state(&original, id(12)), BindingConfirmationState::Active);
        assert_eq!(state(&revoked, id(12)), BindingConfirmationState::Withdrawn);
        assert_eq!(revoked.validate_confirmation_indexes(), Ok(()));

        let mut first = rows().binding_confirmations.remove(0);
        first.confirmation_id = id(30);
        let mut second = first.clone();
        second.confirmation_id = id(31);
        second.binding_id = id(13);
        let restored = revoked.with_confirmations_batch(&[first, second]).unwrap();
        assert_eq!(state(&restored, id(12)), BindingConfirmationState::Active);
        assert_eq!(state(&restored, id(13)), BindingConfirmationState::Active);
        assert_eq!(state(&revoked, id(12)), BindingConfirmationState::Withdrawn);
        assert_eq!(state(&revoked, id(13)), BindingConfirmationState::Invalid);
        assert_eq!(restored.validate_confirmation_indexes(), Ok(()));
        assert_eq!(restored.binding_confirmations(id(12)).unwrap().len(), 2);
    }

    #[test]
    // memory—v1: Publication proof detects every index shape discrepancy.
    fn card_index_integrity_rejects_corruption() {
        let original = candidate();
        assert_eq!(original.validate_binding_indexes(), Ok(()));
        let mut missing = original.clone();
        missing.unremoved_bindings_by_card.remove(&id(8));
        let mut extra = original.clone();
        add_member(&mut extra.unremoved_bindings_by_card, id(8), id(99));
        let mut foreign = original.clone();
        add_member(&mut foreign.unremoved_bindings_by_card, id(9), id(12));
        let mut historical_missing = original.clone();
        historical_missing.bindings_by_card.remove(&id(8));
        let mut historical_rule_set_missing = original.clone();
        historical_rule_set_missing
            .bindings_by_rule_set
            .remove(&id(10));
        let mut historical_rule_set_extra = original.clone();
        add_member(
            &mut historical_rule_set_extra.bindings_by_rule_set,
            id(10),
            id(99),
        );
        let mut historical_rule_set_foreign = original.clone();
        add_member(
            &mut historical_rule_set_foreign.bindings_by_rule_set,
            id(11),
            id(12),
        );
        let mut empty = original.clone();
        empty.bindings_by_card.insert(id(99), Members::default());
        let mut rule_set_missing = original.clone();
        rule_set_missing
            .unremoved_bindings_by_rule_set
            .remove(&id(10));
        let mut rule_set_extra = original.clone();
        add_member(
            &mut rule_set_extra.unremoved_bindings_by_rule_set,
            id(10),
            id(99),
        );
        let mut rule_set_foreign = original.clone();
        add_member(
            &mut rule_set_foreign.unremoved_bindings_by_rule_set,
            id(11),
            id(12),
        );
        // Equal-size substitutions must not hide a missing expected membership.
        let mut swapped_historical = original.clone();
        swapped_historical
            .bindings_by_card
            .get_mut(&id(8))
            .unwrap()
            .remove(&id(12));
        add_member(&mut swapped_historical.bindings_by_card, id(8), id(99));
        let mut swapped_historical_rule_set = original.clone();
        swapped_historical_rule_set
            .bindings_by_rule_set
            .get_mut(&id(10))
            .unwrap()
            .remove(&id(12));
        add_member(
            &mut swapped_historical_rule_set.bindings_by_rule_set,
            id(10),
            id(99),
        );
        let mut swapped_card = original.clone();
        swapped_card
            .unremoved_bindings_by_card
            .get_mut(&id(8))
            .unwrap()
            .remove(&id(12));
        add_member(&mut swapped_card.unremoved_bindings_by_card, id(8), id(99));
        let mut swapped_rule_set = original.clone();
        swapped_rule_set
            .unremoved_bindings_by_rule_set
            .get_mut(&id(10))
            .unwrap()
            .remove(&id(12));
        add_member(
            &mut swapped_rule_set.unremoved_bindings_by_rule_set,
            id(10),
            id(99),
        );
        let mut empty_historical_rule_set = original.clone();
        empty_historical_rule_set
            .bindings_by_rule_set
            .insert(id(99), Members::default());
        let mut empty_card = original.clone();
        empty_card
            .unremoved_bindings_by_card
            .insert(id(99), Members::default());
        let mut empty_rule_set = original.clone();
        empty_rule_set
            .unremoved_bindings_by_rule_set
            .insert(id(99), Members::default());
        let mut half = original.clone();
        let mut row = (*half.bindings[&id(12)]).clone();
        row.removed_by = Some(id(1));
        half.bindings.insert(id(12), Arc::new(row));
        for bad in [
            missing,
            extra.clone(),
            foreign.clone(),
            historical_missing,
            historical_rule_set_missing,
            historical_rule_set_extra,
            historical_rule_set_foreign,
            empty,
            rule_set_missing.clone(),
            rule_set_extra.clone(),
            rule_set_foreign.clone(),
            swapped_historical,
            swapped_historical_rule_set,
            swapped_card,
            swapped_rule_set,
            empty_historical_rule_set,
            empty_card,
            empty_rule_set,
            half,
        ] {
            assert_eq!(
                bad.validate_binding_indexes(),
                Err(CandidateError::InconsistentBinding)
            );
        }
        assert!(matches!(
            extra.unremoved_card_candidate(id(8)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            foreign.unremoved_card_candidate(id(9)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            rule_set_extra.rule_set_change_impact(id(10)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            rule_set_foreign.rule_set_change_impact(id(11)),
            Err(CandidateError::InconsistentBinding)
        ));
        assert!(matches!(
            rule_set_missing.with_binding_removed(id(12), 100, id(1)),
            Err(CandidateError::InconsistentBinding)
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
        assert_eq!(old.version(id(10), &[2]).unwrap(), &version(10, 2));
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
    // memory—v1: Bind a prepared plan to its own version and snapshot, not
    // merely to a rule-set ID or bytes supplied by a caller.
    fn prepared_plan_tracks_exact_selection() {
        let before = candidate();
        let row = before.selected_version(id(10)).unwrap().unwrap();
        let plan = before.prepared_selected_rules(row).unwrap();
        assert!(before.prepared_selected_rules(&row.clone()).is_none());

        let unchanged = before
            .with_selection(id(10), Some(&row.version_bytes))
            .unwrap();
        assert!(std::ptr::eq(
            plan,
            unchanged.prepared_selected_rules(row).unwrap()
        ));
        let changed = before.with_selection(id(10), Some(&[1])).unwrap();
        let replacement = changed.selected_version(id(10)).unwrap().unwrap();
        assert!(changed.prepared_selected_rules(row).is_none());
        assert!(before.prepared_selected_rules(replacement).is_none());
        assert!(changed.prepared_selected_rules(replacement).is_some());
    }

    #[test]
    // memory—v1 §4.11/§4.12: Change impact keeps resumable relationships.
    fn change_impact_is_conservative_and_excludes_only_removed_bindings() {
        let mut impact_rows = rows();
        impact_rows.user_cards[1].tenant_id = id(5);
        let candidate = HamtCandidate::build(
            impact_rows,
            vec![CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![2],
            }],
            budget(),
        )
        .unwrap()
        .with_user_card_status(id(8), UserCardStatus::Disabled)
        .unwrap()
        .with_confirmation_revoked(id(15), 100, id(2))
        .unwrap();
        let impact = candidate.rule_set_change_impact(id(10)).unwrap();
        assert_eq!(impact.binding_ids.len(), 2);
        assert!(impact.user_ids.contains(&id(1)));
        assert!(impact.user_ids.contains(&id(2)));
        assert!(impact.card_ids.contains(&id(8)));
        assert!(impact.card_ids.contains(&id(9)));

        let removed = candidate.with_binding_removed(id(13), 200, id(1)).unwrap();
        let impact = removed.rule_set_change_impact(id(10)).unwrap();
        assert_eq!(impact.binding_ids.len(), 1);
        assert!(impact.binding_ids.contains(&id(12)));
        assert!(!impact.binding_ids.contains(&id(13)));
        assert!(impact.user_ids.contains(&id(1)));
        assert!(!impact.user_ids.contains(&id(2)));
    }

    #[test]
    // memory—v1: Removed history does not consume the current impact budget.
    fn change_impact_ignores_history_without_omitting_resumable_bindings() {
        let mut input = rows();
        input.user_cards[1].tenant_id = id(5);
        input.bindings[1].removed_at = Some(100);
        input.bindings[1].removed_by = Some(id(1));
        for n in 40..45 {
            let mut old = input.bindings[0].clone();
            old.binding_id = id(n);
            old.removed_at = Some(100);
            old.removed_by = Some(id(1));
            input.bindings.push(old);
        }
        let mut limits = budget();
        limits.max_bindings_per_read = 1;
        let initial = HamtCandidate::build(input, vec![], limits)
            .unwrap()
            .with_user_card_status(id(8), UserCardStatus::Disabled)
            .unwrap()
            .with_confirmation_revoked(id(15), 101, id(2))
            .unwrap();
        assert!(matches!(
            initial.rule_set_impact(id(10)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 7 })
        ));
        let impact = initial.rule_set_change_impact(id(10)).unwrap();
        assert_eq!(impact.binding_ids.len(), 1);
        assert!(impact.binding_ids.contains(&id(12)));
        assert!(impact.user_ids.contains(&id(1)));
        assert!(impact.card_ids.contains(&id(8)));
        assert!(impact.tenant_ids.contains(&id(5)));

        let removed = initial.with_binding_removed(id(12), 200, id(2)).unwrap();
        assert!(removed
            .rule_set_change_impact(id(10))
            .unwrap()
            .binding_ids
            .is_empty());
        assert!(initial
            .rule_set_change_impact(id(10))
            .unwrap()
            .binding_ids
            .contains(&id(12)));
        let mut replacement = initial.binding(id(12)).unwrap().unwrap().clone();
        replacement.binding_id = id(50);
        let rebound = removed.with_binding_insert(replacement).unwrap();
        let impact = rebound.rule_set_change_impact(id(10)).unwrap();
        assert_eq!(impact.binding_ids.len(), 1);
        assert!(impact.binding_ids.contains(&id(50)));
        for candidate in [&initial, &removed, &rebound] {
            assert_eq!(candidate.validate_binding_indexes(), Ok(()));
        }
    }

    #[test]
    // memory—v1 §4.11/§4.12: Change impact fails closed on budget and bad tenant data.
    fn change_impact_rejects_budget_and_tenant_inconsistency() {
        let mut limits = budget();
        limits.max_bindings_per_read = 1;
        let candidate = HamtCandidate::build(
            rows(),
            vec![CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![2],
            }],
            limits,
        )
        .unwrap();
        assert!(matches!(
            candidate.rule_set_change_impact(id(10)),
            Err(CandidateError::BindingBudgetExceeded { max: 1, actual: 2 })
        ));

        let mut inconsistent_rows = rows();
        inconsistent_rows.user_cards[0].tenant_id = id(7);
        let inconsistent = HamtCandidate::build(
            inconsistent_rows,
            vec![CurrentSelection {
                rule_set_id: id(10),
                version_bytes: vec![2],
            }],
            budget(),
        )
        .unwrap();
        assert_eq!(
            inconsistent.rule_set_change_impact(id(10)),
            Err(CandidateError::InconsistentBinding)
        );
    }

    #[test]
    // memory—v1 §4.12: New rows cannot revive removed or revoked state.
    fn lifecycle_writes_reject_tombstone_revival_without_mutation() {
        let candidate = candidate();
        let before_count = candidate.budget_and_row_count().1;
        let before_card_generation = candidate.card_dependency_generation(id(8));
        let mut removed_binding = rows().bindings[0].clone();
        removed_binding.binding_id = id(30);
        removed_binding.removed_at = Some(100);
        removed_binding.removed_by = Some(id(1));
        assert!(matches!(
            candidate.with_binding_insert(removed_binding),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(candidate.budget_and_row_count().1, before_count);
        assert_eq!(
            candidate.card_dependency_generation(id(8)),
            before_card_generation
        );

        let removed = candidate.with_binding_removed(id(12), 200, id(2)).unwrap();
        let removed_count = removed.budget_and_row_count().1;
        let removed_generation = removed.card_dependency_generation(id(8));
        let mut confirmation = rows().binding_confirmations[0].clone();
        confirmation.confirmation_id = id(30);
        assert!(matches!(
            removed.with_confirmation_insert(confirmation.clone()),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(removed.budget_and_row_count().1, removed_count);
        assert_eq!(
            removed.card_dependency_generation(id(8)),
            removed_generation
        );
        assert_eq!(removed.binding_confirmations(id(12)).unwrap().len(), 1);

        confirmation.revoked_at = Some(300);
        confirmation.revoked_by = Some(id(2));
        assert!(matches!(
            candidate.with_confirmation_insert(confirmation),
            Err(CandidateError::InconsistentBinding)
        ));
        assert_eq!(candidate.budget_and_row_count().1, before_count);
    }

    #[test]
    // memory—v1 §4.11: A mixed batch validates before any candidate mutation.
    fn mixed_confirmation_batch_rejects_removed_binding_atomically() {
        let candidate = candidate()
            .with_confirmation_revoked(id(15), 100, id(1))
            .unwrap()
            .with_binding_removed(id(13), 200, id(1))
            .unwrap();
        let before_count = candidate.budget_and_row_count().1;
        let before_first_generation = candidate.card_dependency_generation(id(8));
        let before_second_generation = candidate.card_dependency_generation(id(9));
        let before_first = candidate.binding_confirmations(id(12)).unwrap();
        let before_second = candidate.binding_confirmations(id(13)).unwrap();

        let mut valid = rows().binding_confirmations[0].clone();
        valid.confirmation_id = id(30);
        let mut removed = valid.clone();
        removed.confirmation_id = id(31);
        removed.binding_id = id(13);
        let result = candidate.with_confirmations_batch(&[valid, removed]);
        assert!(matches!(result, Err(CandidateError::InconsistentBinding)));
        assert_eq!(candidate.budget_and_row_count().1, before_count);
        assert_eq!(
            candidate.card_dependency_generation(id(8)),
            before_first_generation
        );
        assert_eq!(
            candidate.card_dependency_generation(id(9)),
            before_second_generation
        );
        assert_eq!(
            candidate.binding_confirmations(id(12)).unwrap(),
            before_first
        );
        assert_eq!(
            candidate.binding_confirmations(id(13)).unwrap(),
            before_second
        );
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
