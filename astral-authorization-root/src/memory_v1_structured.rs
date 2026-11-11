//! memory—v1 experimental structured adapter for the local slot kernel.
//!
//! This adapter is not an authorization reader, a source of coverage proof, or
//! a production mutation capability. Identity, eligibility, confirmation,
//! resource ownership, rule semantics, trusted time and persistence remain
//! unverified. Inputs and returned rows are candidates only.
//!
//! Two fixed slots hold relationship facts and current rule-set tuples. They
//! are captured together and updated in one kernel transaction; lookup indexes
//! are rebuilt from the captured facts, not retained as a separate authority.
//! Each changed partition is serialized in full. This is an experimental
//! bridge, not the target incremental aggregate storage or a database format.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::atomic_state::{Limits, Metadata, StateError};
use crate::memory_v1_facts::{
    Binding, BindingConfirmation, CandidateFacts, IdentityCard, RuleSet, Tenant, User, UserCard,
    ValidationError,
};
use crate::memory_v1_kernel::{
    MemoryRootCapture, MemoryRootChange, MemoryRootHandle, MemoryRootOwner,
};
use crate::memory_v1_rules::{ExperimentalRuleSet, RuleSetIntegrityError};

const FACTS_SLOT: usize = 0;
const RULES_SLOT: usize = 1;

/// A candidate rule-set identity and its current experimental tuple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentRuleSet {
    /// Stable candidate rule-set identity.
    pub rule_set_id: i64,
    /// Opaque experimental version bytes.
    pub version: Vec<u8>,
    /// Complete bytes supplied for this candidate tuple; completeness is not proven.
    pub content: Vec<u8>,
    /// Opaque experimental timestamp bytes.
    pub timestamp: Vec<u8>,
    /// Experimental tuple digest, not an authorization proof.
    pub hash: [u8; 32],
}

/// Candidate partitions supplied by a caller, with no coverage guarantees.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateState {
    /// Candidate identity, tenant, binding and confirmation facts.
    pub facts: CandidateFacts,
    /// The candidate current versions that have been loaded.
    pub current_rule_sets: Vec<CurrentRuleSet>,
}

/// Failure to construct, update or inspect the experimental adapter.
#[derive(Debug)]
pub enum CandidateError {
    /// Underlying bounded kernel rejected the operation.
    Kernel(StateError),
    /// The supplied facts have inconsistent relationships.
    Facts(ValidationError),
    /// A tuple does not match the experimental digest.
    RuleSet(RuleSetIntegrityError),
    /// A tuple references an invalid or unknown rule-set identity.
    UnknownRuleSet(i64),
    /// More than one current tuple was supplied for an identity.
    DuplicateRuleSet(i64),
    /// The card or requested subject relationship is absent or inconsistent.
    CardMismatch,
    /// A bound rule-set tuple has not been loaded into this candidate.
    MissingCurrentRuleSet(i64),
    /// The provided capture no longer names this owner's current state.
    StaleCapture,
    /// A candidate partition could not be encoded or decoded.
    Encoding,
    /// An adapter partition was unexpectedly absent.
    MissingPartition,
}

/// A candidate binding and the referenced current tuple, with traceability rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateBindingContext {
    /// The candidate relationship; its presence does not establish entitlement.
    pub binding: Binding,
    /// The current tuple at the same captured state version.
    pub rule_set: RuleSet,
    /// The current experimental tuple for the referenced identity.
    pub current: Arc<CurrentRuleSet>,
    /// Candidate confirmation records, not evidence of valid confirmation.
    pub confirmations: Vec<BindingConfirmation>,
}

/// A candidate card context from one coherent read of both partitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCardContext {
    /// Candidate user.
    pub user: User,
    /// Candidate tenant-independent identity card.
    pub identity_card: IdentityCard,
    /// Candidate user card.
    pub card: UserCard,
    /// Candidate tenant.
    pub tenant: Tenant,
    /// Direct card bindings, not inherited from other cards or tenants.
    pub bindings: Vec<CandidateBindingContext>,
}

/// Candidate context and state token. It cannot establish permission to allow.
pub struct CandidateRead {
    capture: MemoryRootCapture,
    context: CandidateCardContext,
}

/// An owner-bound observation, independent of any card lookup or authorization.
pub struct CandidateToken {
    capture: MemoryRootCapture,
}

/// Non-cloneable experimental owner, independent of production authorization.
pub struct CandidateOwner {
    kernel: MemoryRootOwner,
}

/// Read-only handle to the same experimental owner.
#[derive(Clone)]
pub struct CandidateHandle {
    kernel: MemoryRootHandle,
}

// memory—v1: Validate candidate relationships and experimental tuple integrity.
fn validate(candidate: &CandidateState) -> Result<(), CandidateError> {
    let index = candidate
        .facts
        .build_index()
        .map_err(CandidateError::Facts)?;
    let mut ids = BTreeSet::new();
    for current in &candidate.current_rule_sets {
        if current.rule_set_id <= 0 || index.rule_set(current.rule_set_id).is_none() {
            return Err(CandidateError::UnknownRuleSet(current.rule_set_id));
        }
        if !ids.insert(current.rule_set_id) {
            return Err(CandidateError::DuplicateRuleSet(current.rule_set_id));
        }
        ExperimentalRuleSet::from_parts(
            current.version.clone(),
            current.content.clone(),
            current.timestamp.clone(),
            current.hash,
        )
        .map_err(CandidateError::RuleSet)?;
    }
    Ok(())
}

// memory—v1: Encode both candidate partitions before an atomic slot transaction.
fn encode(candidate: &CandidateState) -> Result<[Vec<u8>; 2], CandidateError> {
    validate(candidate)?;
    Ok([
        serde_json::to_vec(&candidate.facts).map_err(|_| CandidateError::Encoding)?,
        serde_json::to_vec(&candidate.current_rule_sets).map_err(|_| CandidateError::Encoding)?,
    ])
}

impl CandidateOwner {
    /// memory—v1: Construct an isolated candidate owner with two bounded partitions.
    ///
    /// Callers must bound input allocation and retained reads independently.
    pub fn new(candidate: CandidateState, limits: Limits) -> Result<Self, CandidateError> {
        if limits.max_capture_slots < 2 || limits.max_change_slots < 2 {
            return Err(CandidateError::Kernel(StateError::InvalidLimits));
        }
        let [facts, rules] = encode(&candidate)?;
        let kernel = MemoryRootOwner::new(vec![Some(facts), Some(rules)], limits)
            .map_err(CandidateError::Kernel)?;
        Ok(Self { kernel })
    }

    /// memory—v1: Share a read-only handle to this candidate owner.
    pub fn handle(&self) -> CandidateHandle {
        CandidateHandle {
            kernel: self.kernel.handle(),
        }
    }

    /// memory—v1: Atomically replace both candidate partitions after a fresh read.
    ///
    /// This is not an authorized write: the caller must not use it for production
    /// mutations. It checks the supplied read token has not changed; it cannot
    /// establish that a user or operation was authorized. No automatic retries.
    pub fn replace(
        &mut self,
        expected: &CandidateRead,
        candidate: CandidateState,
    ) -> Result<Metadata, CandidateError> {
        if !self
            .kernel
            .handle()
            .is_current(&expected.capture)
            .map_err(CandidateError::Kernel)?
        {
            return Err(CandidateError::StaleCapture);
        }
        let token = CandidateToken {
            capture: self
                .kernel
                .handle()
                .capture(&[])
                .map_err(CandidateError::Kernel)?,
        };
        self.replace_if_current(&token, candidate)
    }

    /// memory—v1: Replace partitions only when an owner-bound token is current.
    ///
    /// This token is an observation only and carries no authority to mutate.
    pub fn replace_if_current(
        &mut self,
        expected: &CandidateToken,
        candidate: CandidateState,
    ) -> Result<Metadata, CandidateError> {
        let [facts, rules] = encode(&candidate)?;
        if !self
            .kernel
            .handle()
            .is_current(&expected.capture)
            .map_err(CandidateError::Kernel)?
        {
            return Err(CandidateError::StaleCapture);
        }
        self.kernel
            .apply(vec![
                MemoryRootChange {
                    slot: FACTS_SLOT,
                    value: Some(facts),
                },
                MemoryRootChange {
                    slot: RULES_SLOT,
                    value: Some(rules),
                },
            ])
            .map_err(CandidateError::Kernel)
    }
}

impl CandidateHandle {
    /// memory—v1: Capture a state token even if no card can yet be read.
    ///
    /// This token is only a freshness observation, not an authorization grant.
    pub fn token(&self) -> Result<CandidateToken, CandidateError> {
        Ok(CandidateToken {
            capture: self.kernel.capture(&[]).map_err(CandidateError::Kernel)?,
        })
    }

    /// memory—v1: Capture one card and its direct candidate references together.
    ///
    /// Missing current tuples are unknown, not empty rule sets. Even success does
    /// not prove complete data, confirmation, time validity or authorization.
    pub fn read_card(
        &self,
        user_id: i64,
        identity_card_id: i64,
        card_id: i64,
        tenant_id: i64,
    ) -> Result<CandidateRead, CandidateError> {
        let capture = self
            .kernel
            .capture(&[FACTS_SLOT, RULES_SLOT])
            .map_err(CandidateError::Kernel)?;
        let mut entries = capture.entries();
        let facts_bytes = entries
            .next()
            .and_then(|(_, bytes)| bytes)
            .ok_or(CandidateError::MissingPartition)?;
        let rules_bytes = entries
            .next()
            .and_then(|(_, bytes)| bytes)
            .ok_or(CandidateError::MissingPartition)?;
        let facts: CandidateFacts =
            serde_json::from_slice(facts_bytes).map_err(|_| CandidateError::Encoding)?;
        let rules: Vec<CurrentRuleSet> =
            serde_json::from_slice(rules_bytes).map_err(|_| CandidateError::Encoding)?;
        drop(entries);
        let index = facts.build_index().map_err(CandidateError::Facts)?;
        let card = index.card(card_id).ok_or(CandidateError::CardMismatch)?;
        if card.user.user_id != user_id
            || card.identity_card.identity_card_id != identity_card_id
            || card.tenant.tenant_id != tenant_id
        {
            return Err(CandidateError::CardMismatch);
        }
        let by_id: BTreeMap<_, _> = rules
            .into_iter()
            .map(|rule| (rule.rule_set_id, Arc::new(rule)))
            .collect();
        let mut bindings = Vec::with_capacity(card.bindings.len());
        for binding in card.bindings {
            let rule_set = index
                .rule_set(binding.rule_set_id)
                .ok_or(CandidateError::UnknownRuleSet(binding.rule_set_id))?;
            let current = by_id
                .get(&binding.rule_set_id)
                .ok_or(CandidateError::MissingCurrentRuleSet(binding.rule_set_id))?;
            bindings.push(CandidateBindingContext {
                binding: (*binding).clone(),
                rule_set: rule_set.clone(),
                current: current.clone(),
                confirmations: index
                    .binding_confirmations(binding.binding_id)
                    .iter()
                    .map(|confirmation| (*confirmation).clone())
                    .collect(),
            });
        }
        let context = CandidateCardContext {
            user: card.user.clone(),
            identity_card: card.identity_card.clone(),
            card: card.card.clone(),
            tenant: card.tenant.clone(),
            bindings,
        };
        Ok(CandidateRead { capture, context })
    }

    /// memory—v1: Observe whether the same owner, version and digest remain current.
    ///
    /// This observation does not check trusted time or grant authorization.
    pub fn is_current(&self, read: &CandidateRead) -> Result<bool, CandidateError> {
        self.kernel
            .is_current(&read.capture)
            .map_err(CandidateError::Kernel)
    }
}

impl CandidateRead {
    /// memory—v1: Borrow the context without changing the captured result.
    pub fn context(&self) -> &CandidateCardContext {
        &self.context
    }

    /// memory—v1: Return the metadata captured with this candidate context.
    pub fn metadata(&self) -> Metadata {
        self.capture.metadata()
    }
}

#[cfg(test)]
#[path = "memory_v1_structured/tests.rs"]
mod tests;
