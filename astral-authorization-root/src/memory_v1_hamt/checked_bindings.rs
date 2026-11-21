//! memory—v1: Reuse only the binding checks of an immutable, verified candidate.

use super::{
    Arc, BinaryId, BindingConfirmationRow, BindingConfirmationState, BindingRow, CandidateError,
    HamtCandidate, HashMap, Membership, UserCardRow,
};

#[derive(Debug)]
pub(super) struct CheckedBindings {
    cards: HashMap<BinaryId, Arc<UserCardRow>>,
    bindings: HashMap<BinaryId, Arc<BindingRow>>,
    by_card: Membership,
    by_set: Membership,
    unremoved_by_card: Membership,
    unremoved_by_set: Membership,
    confirmations: HashMap<BinaryId, Arc<BindingConfirmationRow>>,
    by_binding: Membership,
    states: HashMap<BinaryId, BindingConfirmationState>,
}

impl CheckedBindings {
    // memory—v1: The witness is constructed only after the full binding checks succeed.
    fn capture(c: &HamtCandidate) -> Self {
        Self {
            cards: c.cards.clone(),
            bindings: c.bindings.clone(),
            by_card: c.bindings_by_card.clone(),
            by_set: c.bindings_by_rule_set.clone(),
            unremoved_by_card: c.unremoved_bindings_by_card.clone(),
            unremoved_by_set: c.unremoved_bindings_by_rule_set.clone(),
            confirmations: c.confirmations.clone(),
            by_binding: c.confirmations_by_binding.clone(),
            states: c.binding_confirmation_states.clone(),
        }
    }

    // memory—v1: Strong HAMT handles pin the exact immutable rows and indexes, not their sizes or digests.
    fn covers(&self, c: &HamtCandidate) -> bool {
        self.cards.ptr_eq(&c.cards)
            && self.bindings.ptr_eq(&c.bindings)
            && self.by_card.ptr_eq(&c.bindings_by_card)
            && self.by_set.ptr_eq(&c.bindings_by_rule_set)
            && self.unremoved_by_card.ptr_eq(&c.unremoved_bindings_by_card)
            && self
                .unremoved_by_set
                .ptr_eq(&c.unremoved_bindings_by_rule_set)
            && self.confirmations.ptr_eq(&c.confirmations)
            && self.by_binding.ptr_eq(&c.confirmations_by_binding)
            && self.states.ptr_eq(&c.binding_confirmation_states)
    }
}

impl HamtCandidate {
    // memory—v1: Rule-set rows change on publication. When binding memberships are identical,
    // recheck every distinct referenced source, rather than every card referencing that source.
    // Always rebuild and verify the separate change-confirmation index on the successor.
    pub(crate) fn check_publication_indexes(
        &mut self,
        source_publish: bool,
    ) -> Result<(), CandidateError> {
        if source_publish
            && self
                .checked_bindings
                .as_ref()
                .is_some_and(|proof| proof.covers(self))
        {
            if self
                .bindings_by_rule_set
                .keys()
                .any(|id| !self.rule_sets.contains_key(id))
            {
                return Err(CandidateError::InconsistentBinding);
            }
            return self.validate_change_confirmation_indexes();
        }
        self.validate_binding_indexes()?;
        self.validate_confirmation_indexes()?;
        self.checked_bindings = Some(Arc::new(CheckedBindings::capture(self)));
        Ok(())
    }
}
