//! Non-production, process-local synchronization kernel.
//!
//! A single owner can close the global gate; readers can only obtain scoped
//! copies after committing against the same lock as close. There is deliberately
//! no public installation or reopening API. Local revisions and successful
//! reads do not constitute authorization, source admission, or V7 proof. A
//! dropped owner with an unresolved mutation permanently retains its in-process
//! registration. Process restart is not reconciliation; callers must reconcile
//! durable outcomes independently before attempting any real recovery.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::model::{SingleNodeCardRuleSetRef, SingleNodePermissionRule, SingleNodeRuleSetEntry};

mod state;
use state::{Inner, Phase};

#[cfg(test)]
mod tests;

use crate::OWNER_REGISTERED as OWNER_EXISTS;

// Retain the correlation identity and terminal state when no safe local
// replacement exists. This is process-local diagnostic state, not proof.
static UNRESOLVED_OWNER: OnceLock<Arc<Mutex<Inner>>> = OnceLock::new();

/// Stable correlation identity only; this is not durable admission evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationId(String);

impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || value
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(Error::InvalidOperationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Candidate facts for one tenant and card. They are not evidence of card
/// existence, coverage, publication, eligibility, or an authorization decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedCardFacts {
    pub bindings: Vec<SingleNodeCardRuleSetRef>,
    pub entries: Vec<SingleNodeRuleSetEntry>,
    pub direct_rules: Vec<SingleNodePermissionRule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosedReason {
    Cold,
    Mutation,
    Unknown,
    Expired,
    OwnerDropped,
    Exhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootStatus {
    pub gate: GateStatus,
    /// Process-local install counter; it is not an authority generation.
    pub install_revision: u64,
    pub gate_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateStatus {
    Closed {
        reason: ClosedReason,
        operation_id: Option<OperationId>,
    },
    /// Only possible through the private test installer in this version.
    OpenForExperiment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OwnerAlreadyExists,
    InvalidOperationId,
    InvalidDeadline,
    InvalidScope,
    Closed,
    Busy,
    Unknown,
    Expired,
    StaleRead,
    TooManyFacts,
    Exhausted,
    Poisoned,
}

/// The unique process owner. It is intentionally not `Clone`.
pub struct RootOwner {
    inner: Arc<Mutex<Inner>>,
    process_registration: bool,
}

impl RootOwner {
    /// Create the only live process owner, initially globally closed.
    pub fn new() -> Result<Self, Error> {
        OWNER_EXISTS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::OwnerAlreadyExists)?;
        Ok(Self::with_registration(true))
    }

    fn with_registration(process_registration: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new())),
            process_registration,
        }
    }

    pub fn handle(&self) -> RootHandle {
        RootHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Close globally before beginning a mutation. No database or network work
    /// is performed under the lock. Dropping the guard leaves an UNKNOWN gate.
    pub fn close_for_mutation(
        &self,
        operation_id: OperationId,
        timeout: Duration,
    ) -> Result<MutationGuard, Error> {
        let mut inner = self.inner.lock().map_err(|_| Error::Poisoned)?;
        let now = Instant::now();
        inner.expire(now);
        if matches!(inner.phase, Phase::Pending { .. }) {
            return Err(Error::Busy);
        }
        if matches!(
            inner.phase,
            Phase::Closed {
                reason: ClosedReason::Unknown
                    | ClosedReason::OwnerDropped
                    | ClosedReason::Exhausted,
                ..
            }
        ) {
            return Err(Error::Unknown);
        }
        // Invalid deadlines must also revoke any outstanding readers.
        let Some(deadline) = now.checked_add(timeout).filter(|d| *d > now) else {
            inner.close(ClosedReason::Expired, Some(operation_id))?;
            return Err(Error::InvalidDeadline);
        };
        inner.close(ClosedReason::Mutation, Some(operation_id.clone()))?;
        let epoch = inner.epoch;
        inner.phase = Phase::Pending {
            operation_id: operation_id.clone(),
            epoch,
            deadline,
        };
        Ok(MutationGuard {
            inner: Arc::clone(&self.inner),
            operation_id,
            epoch,
            armed: true,
        })
    }
}

impl Drop for RootOwner {
    fn drop(&mut self) {
        // Even a poisoned lock must not leave an open gate after owner loss.
        let (mut inner, poisoned) = match self.inner.lock() {
            Ok(inner) => (inner, false),
            Err(poison) => (poison.into_inner(), true),
        };
        let unresolved = inner.shutdown();
        drop(inner);
        // A new owner must not erase an unresolved operation or a poisoned
        // state. There is no trusted reconciliation API in this experiment.
        if self.process_registration {
            if unresolved || poisoned {
                let _ = UNRESOLVED_OWNER.set(Arc::clone(&self.inner));
            } else {
                OWNER_EXISTS.store(false, Ordering::Release);
            }
        }
    }
}

/// A clonable read capability sharing the same state, never an installation capability.
#[derive(Clone)]
pub struct RootHandle {
    inner: Arc<Mutex<Inner>>,
}

impl RootHandle {
    pub fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn status(&self) -> Result<RootStatus, Error> {
        let mut inner = self.inner.lock().map_err(|_| Error::Poisoned)?;
        inner.expire(Instant::now());
        Ok(inner.status())
    }

    /// Bind one tenant and card to an immutable candidate root. No raw root is exposed.
    pub fn begin_read(&self, tenant_id: i64, card_id: i64) -> Result<RootRead, Error> {
        if tenant_id <= 0 || card_id <= 0 {
            return Err(Error::InvalidScope);
        }
        let mut inner = self.inner.lock().map_err(|_| Error::Poisoned)?;
        inner.expire(Instant::now());
        if !matches!(inner.phase, Phase::Open) {
            return Err(Error::Closed);
        }
        let snapshot = inner.snapshot.as_ref().ok_or(Error::Closed)?;
        Ok(RootRead {
            inner: Arc::clone(&self.inner),
            epoch: inner.epoch,
            install_revision: inner.revision,
            content_digest: snapshot.root.content_digest().to_owned(),
            tenant_id,
            card_id,
        })
    }
}

/// A request-bound token; committing it is serialized with closing the gate.
/// It does not retain the snapshot after the gate closes.
pub struct RootRead {
    inner: Arc<Mutex<Inner>>,
    epoch: u64,
    install_revision: u64,
    content_digest: String,
    tenant_id: i64,
    card_id: i64,
}

impl RootRead {
    /// Return a local fact only if the same root is still valid at this lock's
    /// linearization point. Absence is not proof of coverage or authorization.
    pub fn commit(self) -> Result<Option<ScopedCardFacts>, Error> {
        let mut inner = self.inner.lock().map_err(|_| Error::Poisoned)?;
        inner.expire(Instant::now());
        if !matches!(inner.phase, Phase::Open)
            || inner.epoch != self.epoch
            || inner.revision != self.install_revision
        {
            return Err(Error::StaleRead);
        }
        let root = &inner.snapshot.as_ref().ok_or(Error::StaleRead)?.root;
        if root.content_digest() != self.content_digest {
            return Err(Error::StaleRead);
        }
        const MAX_FACTS: usize = 1024;
        let mut bindings = Vec::new();
        let mut entries = Vec::new();
        let mut direct_rules = Vec::new();
        // Bound work even when the indexed card belongs to a different tenant.
        for binding in root
            .rule_set_bindings_for_card(self.card_id)
            .take(MAX_FACTS + 1)
        {
            if bindings.len() == MAX_FACTS {
                return Err(Error::TooManyFacts);
            }
            if binding.tenant_id != self.tenant_id || binding.card_id != self.card_id {
                return Ok(None);
            }
            bindings.push(binding.clone());
            for entry in root
                .rule_set_entries(binding.rule_set_id)
                .take(MAX_FACTS + 1)
            {
                if entries.len() == MAX_FACTS {
                    return Err(Error::TooManyFacts);
                }
                entries.push(entry.clone());
            }
        }
        for rule in root
            .permission_rules_for_card(self.card_id)
            .take(MAX_FACTS + 1)
        {
            if direct_rules.len() == MAX_FACTS {
                return Err(Error::TooManyFacts);
            }
            if rule.tenant_id != self.tenant_id || rule.card_id != self.card_id {
                return Ok(None);
            }
            direct_rules.push(rule.clone());
        }
        if bindings.is_empty() && direct_rules.is_empty() {
            return Ok(None);
        }
        Ok(Some(ScopedCardFacts {
            bindings,
            entries,
            direct_rules,
        }))
    }
}

/// An outstanding local mutation. Cancellation or drop never reopens the gate.
pub struct MutationGuard {
    inner: Arc<Mutex<Inner>>,
    operation_id: OperationId,
    epoch: u64,
    armed: bool,
}

impl MutationGuard {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Explicitly record an unknown outcome; identical to cancellation on drop.
    pub fn mark_unknown(self) {}
}

impl Drop for MutationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if matches!(&inner.phase, Phase::Pending { operation_id, epoch, .. } if operation_id == &self.operation_id && *epoch == self.epoch)
        {
            // It is already closed, but advance the epoch for a distinct transition.
            let _ = inner.close(ClosedReason::Unknown, Some(self.operation_id.clone()));
        }
    }
}
