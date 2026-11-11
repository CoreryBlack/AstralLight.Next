//! Restricted process-local lifecycle for a candidate authorization root.
//!
//! This module is exposed for candidate lifecycle experiments, not wired into a
//! production path. A candidate, its digest, and its local lifecycle are not authority evidence.
//! There is no `Serving` state, authorization read API, or local recovery from
//! UNKNOWN. Durable reconciliation and verified V7 proof require a separate,
//! reviewed integration; restarting a process does not establish either.
//!
//! Capacity is limited to one live manager, one outstanding build permit, and
//! one retained candidate in this module. The candidate is discarded before a
//! new build starts, and is never handed to a reader. The model enforces row,
//! JSON-encoding and cooperative build-time budgets. These are not a heap or
//! RSS limit: input may already be allocated before the permit is used, and
//! indexes, allocator overhead, other code, and independent model builds are
//! outside this accounting. Expiry is checked on access, not by a timer.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::model::{
    SingleNodeDatabaseSnapshot, SingleNodeMemoryRoot, SingleNodeMemoryRootError,
    SingleNodeRootBuildBudget,
};

use crate::OWNER_REGISTERED as MANAGER_REGISTERED;

/// Correlation only; it is not a durable receipt or an authority capability.
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
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(Error::InvalidOperationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable bounds for this manager. All durations and limits must be nonzero.
#[derive(Clone, Copy, Debug)]
pub struct ManagerBudget {
    pub build: SingleNodeRootBuildBudget,
    /// Covers time from permit acquisition, including external input collection.
    pub attempt_timeout: Duration,
    pub candidate_ttl: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    Explicit,
    Drift,
    DependencyUnavailable,
    CandidateExpired,
    BuildFailed,
}

/// No variant represents a verified or serving root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Cold,
    Building {
        operation_id: OperationId,
    },
    AwaitingExternalProof {
        operation_id: OperationId,
        content_digest: String,
        /// Local candidate metadata, not a globally proven generation.
        candidate_generation: u64,
    },
    Invalid {
        reason: InvalidReason,
    },
    Unknown {
        operation_id: Option<OperationId>,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub lifecycle: Lifecycle,
    /// Process-local fence only; it is not an authority epoch.
    pub epoch: u64,
    /// A stale or timed-out attempt retains its slot until its permit returns.
    pub build_in_flight: bool,
    pub retained_candidates: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    AlreadyRegistered,
    InvalidOperationId,
    InvalidBudget,
    Busy,
    Unknown,
    Shutdown,
    StaleAttempt,
    BuildFailed,
    Exhausted,
    Poisoned,
}

struct Candidate {
    // Retain the model without exporting an unguarded authorization read.
    _root: SingleNodeMemoryRoot,
    expires_at: Instant,
}

struct Attempt {
    operation_id: OperationId,
    epoch: u64,
    deadline: Instant,
}

struct State {
    lifecycle: Lifecycle,
    epoch: u64,
    candidate: Option<Candidate>,
    attempt: Option<Attempt>,
}

impl State {
    fn new() -> Self {
        Self {
            lifecycle: Lifecycle::Cold,
            epoch: 0,
            candidate: None,
            attempt: None,
        }
    }

    // Counter exhaustion is permanently closed, just like an unknown outcome.
    fn advance(&mut self, operation_id: Option<OperationId>) -> Result<(), Error> {
        match self.epoch.checked_add(1) {
            Some(epoch) => {
                self.epoch = epoch;
                Ok(())
            }
            None => {
                self.lifecycle = Lifecycle::Unknown { operation_id };
                Err(Error::Exhausted)
            }
        }
    }

    /// Take expired data under the lock and release it outside the lock.
    fn expire(&mut self, now: Instant) -> Option<Candidate> {
        if let Some(attempt) = &self.attempt {
            if now >= attempt.deadline
                && !matches!(
                    self.lifecycle,
                    Lifecycle::Unknown { .. } | Lifecycle::Shutdown
                )
            {
                let operation_id = Some(attempt.operation_id.clone());
                let _ = self.advance(operation_id.clone());
                self.lifecycle = Lifecycle::Unknown { operation_id };
            }
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| now >= candidate.expires_at)
        {
            if !matches!(
                self.lifecycle,
                Lifecycle::Unknown { .. } | Lifecycle::Shutdown
            ) && self.advance(None).is_ok()
            {
                self.lifecycle = Lifecycle::Invalid {
                    reason: InvalidReason::CandidateExpired,
                };
            }
            return self.candidate.take();
        }
        None
    }

    fn status(&self) -> Status {
        Status {
            lifecycle: self.lifecycle.clone(),
            epoch: self.epoch,
            build_in_flight: self.attempt.is_some(),
            retained_candidates: usize::from(self.candidate.is_some()),
        }
    }
}

struct Shared {
    state: Mutex<State>,
    budget: ManagerBudget,
}

/// Unique management owner. Readers receive only diagnostic handles.
pub struct RootManager {
    shared: Arc<Shared>,
    registered: bool,
}

impl RootManager {
    pub fn new(budget: ManagerBudget) -> Result<Self, Error> {
        Self::validate_budget(budget)?;
        MANAGER_REGISTERED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AlreadyRegistered)?;
        Ok(Self::create(budget, true))
    }

    fn validate_budget(budget: ManagerBudget) -> Result<(), Error> {
        if budget.build.max_rows == 0
            || budget.build.max_snapshot_bytes == 0
            || budget.build.max_canonical_bytes == 0
            || budget.build.max_build_time.is_zero()
            || budget.attempt_timeout.is_zero()
            || budget.candidate_ttl.is_zero()
            || Instant::now().checked_add(budget.attempt_timeout).is_none()
            || Instant::now().checked_add(budget.candidate_ttl).is_none()
        {
            return Err(Error::InvalidBudget);
        }
        Ok(())
    }

    fn create(budget: ManagerBudget, registered: bool) -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State::new()),
                budget,
            }),
            registered,
        }
    }

    pub fn handle(&self) -> RootHandle {
        RootHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Invalidate globally. An in-flight build keeps its slot but cannot install.
    /// An UNKNOWN outcome is sticky and cannot be cleared by invalidation.
    pub fn invalidate(&self, reason: InvalidReason) -> Result<(), Error> {
        let mut state = self.shared.state.lock().map_err(|_| Error::Poisoned)?;
        let expired = state.expire(Instant::now());
        let result = match state.lifecycle {
            Lifecycle::Unknown { .. } => Err(Error::Unknown),
            Lifecycle::Shutdown => Err(Error::Shutdown),
            _ => {
                let result = state.advance(None);
                if result.is_ok() {
                    state.lifecycle = Lifecycle::Invalid { reason };
                }
                result
            }
        };
        let candidate = state.candidate.take();
        drop(state);
        drop((expired, candidate));
        result
    }

    /// Acquire the sole build slot before collecting external inputs. No lock is
    /// held by the returned permit. Attempts are not queued or retried here.
    pub fn begin_rebuild(&self, operation_id: OperationId) -> Result<BuildPermit, Error> {
        let mut state = self.shared.state.lock().map_err(|_| Error::Poisoned)?;
        let now = Instant::now();
        let expired = state.expire(now);
        let result = if matches!(state.lifecycle, Lifecycle::Unknown { .. }) {
            Err(Error::Unknown)
        } else if matches!(state.lifecycle, Lifecycle::Shutdown) {
            Err(Error::Shutdown)
        } else if state.attempt.is_some() {
            Err(Error::Busy)
        } else if let Some(deadline) = now.checked_add(self.shared.budget.attempt_timeout) {
            match state.advance(Some(operation_id.clone())) {
                Ok(()) => {
                    let epoch = state.epoch;
                    state.attempt = Some(Attempt {
                        operation_id: operation_id.clone(),
                        epoch,
                        deadline,
                    });
                    state.lifecycle = Lifecycle::Building {
                        operation_id: operation_id.clone(),
                    };
                    Ok(BuildPermit {
                        shared: Arc::clone(&self.shared),
                        operation_id,
                        epoch,
                        armed: true,
                    })
                }
                Err(error) => Err(error),
            }
        } else {
            // A deadline that cannot be represented is not permission to run.
            state.lifecycle = Lifecycle::Unknown {
                operation_id: Some(operation_id),
            };
            Err(Error::Exhausted)
        };
        // At most one retained candidate or one candidate being built.
        let candidate = if result.is_ok() || matches!(state.lifecycle, Lifecycle::Unknown { .. }) {
            state.candidate.take()
        } else {
            None
        };
        drop(state);
        drop((expired, candidate));
        result
    }
}

impl Drop for RootManager {
    fn drop(&mut self) {
        let (mut state, poisoned) = match self.shared.state.lock() {
            Ok(state) => (state, false),
            Err(error) => (error.into_inner(), true),
        };
        let expired = state.expire(Instant::now());
        let unresolved = poisoned
            || state.attempt.is_some()
            || matches!(state.lifecycle, Lifecycle::Unknown { .. });
        if unresolved {
            if !matches!(state.lifecycle, Lifecycle::Unknown { .. }) {
                let operation_id = state.attempt.as_ref().map(|a| a.operation_id.clone());
                let _ = state.advance(operation_id.clone());
                state.lifecycle = Lifecycle::Unknown { operation_id };
            }
        } else if state.advance(None).is_ok() {
            state.lifecycle = Lifecycle::Shutdown;
        }
        let candidate = state.candidate.take();
        let exhausted = matches!(state.lifecycle, Lifecycle::Unknown { .. });
        drop(state);
        drop((expired, candidate));
        // A replacement must not erase an unresolved result, poison or exhausted
        // fence. Restart still requires independent durable reconciliation.
        if self.registered && !unresolved && !exhausted {
            MANAGER_REGISTERED.store(false, Ordering::Release);
        }
    }
}

/// Cloneable diagnostics only. It cannot obtain a root or authorize a request.
#[derive(Clone)]
pub struct RootHandle {
    shared: Arc<Shared>,
}

impl RootHandle {
    pub fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    pub fn status(&self) -> Result<Status, Error> {
        let mut state = self.shared.state.lock().map_err(|_| Error::Poisoned)?;
        let expired = state.expire(Instant::now());
        let status = state.status();
        drop(state);
        drop(expired);
        Ok(status)
    }
}

/// A single outstanding attempt. Dropping it without a completed build marks
/// the outcome UNKNOWN, including cancellation while an external loader runs.
pub struct BuildPermit {
    shared: Arc<Shared>,
    operation_id: OperationId,
    epoch: u64,
    armed: bool,
}

impl BuildPermit {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Build the candidate without holding the manager lock. Even success only
    /// reaches `AwaitingExternalProof`; no caller-provided input opens a gate.
    pub fn build(mut self, snapshot: SingleNodeDatabaseSnapshot) -> Result<(), Error> {
        let build_started = Instant::now();
        let root = SingleNodeMemoryRoot::build_with_budget(snapshot, self.shared.budget.build);
        // The model's deadline is cooperative; it can return another error after
        // the limit. Treat either signal as UNKNOWN, never as an ordinary failure.
        let build_timed_out = build_started.elapsed() >= self.shared.budget.build.max_build_time
            || matches!(
                &root,
                Err(SingleNodeMemoryRootError::InvalidValue { entity: "root_budget", detail })
                    if detail == "build time exceeded"
            );
        let mut state = self.shared.state.lock().map_err(|_| Error::Poisoned)?;
        let now = Instant::now();
        let expired = state.expire(now);
        let current = state.attempt.as_ref().is_some_and(|attempt| {
            attempt.epoch == self.epoch && attempt.operation_id == self.operation_id
        });
        let result = if !current {
            Err(Error::StaleAttempt)
        } else if matches!(state.lifecycle, Lifecycle::Unknown { .. }) {
            Err(Error::Unknown)
        } else if build_timed_out {
            let operation_id = Some(self.operation_id.clone());
            let _ = state.advance(operation_id.clone());
            state.lifecycle = Lifecycle::Unknown { operation_id };
            Err(Error::Unknown)
        } else if state.epoch != self.epoch
            || !matches!(&state.lifecycle, Lifecycle::Building { operation_id } if operation_id == &self.operation_id)
        {
            Err(Error::StaleAttempt)
        } else {
            match root {
                Ok(root) => match now.checked_add(self.shared.budget.candidate_ttl) {
                    Some(expires_at) => {
                        state.lifecycle = Lifecycle::AwaitingExternalProof {
                            operation_id: self.operation_id.clone(),
                            content_digest: root.content_digest().to_owned(),
                            candidate_generation: root.version().generation,
                        };
                        state.candidate = Some(Candidate {
                            _root: root,
                            expires_at,
                        });
                        Ok(())
                    }
                    None => {
                        state.lifecycle = Lifecycle::Unknown {
                            operation_id: Some(self.operation_id.clone()),
                        };
                        Err(Error::Exhausted)
                    }
                },
                Err(_) => {
                    state.lifecycle = Lifecycle::Invalid {
                        reason: InvalidReason::BuildFailed,
                    };
                    Err(Error::BuildFailed)
                }
            }
        };
        if current {
            state.attempt = None;
        }
        self.armed = false;
        drop(state);
        drop(expired);
        result
    }
}

impl Drop for BuildPermit {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.attempt.as_ref().is_some_and(|attempt| {
            attempt.epoch == self.epoch && attempt.operation_id == self.operation_id
        }) {
            state.attempt = None;
            if !matches!(state.lifecycle, Lifecycle::Unknown { .. }) {
                let operation_id = Some(self.operation_id.clone());
                let _ = state.advance(operation_id.clone());
                state.lifecycle = Lifecycle::Unknown { operation_id };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SingleNodeRootVersion;
    use std::sync::{mpsc, Barrier};
    use std::thread;

    fn budget() -> ManagerBudget {
        ManagerBudget {
            build: SingleNodeRootBuildBudget {
                max_rows: 100,
                max_snapshot_bytes: 100_000,
                max_canonical_bytes: 100_000,
                max_build_time: Duration::from_secs(5),
            },
            attempt_timeout: Duration::from_secs(10),
            candidate_ttl: Duration::from_secs(10),
        }
    }

    fn manager() -> RootManager {
        RootManager::create(budget(), false)
    }

    fn id(value: &str) -> OperationId {
        OperationId::new(value).unwrap()
    }

    fn snapshot() -> SingleNodeDatabaseSnapshot {
        SingleNodeDatabaseSnapshot {
            version: SingleNodeRootVersion {
                source_snapshot_id: "local-unverified".into(),
                generation: 1,
                dependency_frontier_digest: "ab".repeat(32),
                revoke_watermark: 0,
            },
            users: vec![],
            identity_cards: vec![],
            user_cards: vec![],
            tenants: vec![],
            domains: vec![],
            tenant_domains: vec![],
            org_memberships: vec![],
            rule_sets: vec![],
            rule_set_entries: vec![],
            card_rule_set_refs: vec![],
            permission_rules: vec![],
            published_pointers: vec![],
            global_admins: vec![],
            sod_policies: vec![],
        }
    }

    #[test]
    fn candidate_is_never_authority_proof_and_rebuild_discards_it() {
        let owner = manager();
        let handle = owner.handle();
        assert!(handle.same_instance(&owner.handle()));
        owner
            .begin_rebuild(id("first"))
            .unwrap()
            .build(snapshot())
            .unwrap();
        let status = handle.status().unwrap();
        assert!(matches!(
            status.lifecycle,
            Lifecycle::AwaitingExternalProof {
                candidate_generation: 1,
                ..
            }
        ));
        assert_eq!(status.retained_candidates, 1);
        let permit = owner.begin_rebuild(id("second")).unwrap();
        let status = handle.status().unwrap();
        assert!(matches!(status.lifecycle, Lifecycle::Building { .. }));
        assert_eq!(status.retained_candidates, 0);
        assert_eq!(owner.begin_rebuild(id("third")).err(), Some(Error::Busy));
        permit.build(snapshot()).unwrap();
        assert!(matches!(
            handle.status().unwrap().lifecycle,
            Lifecycle::AwaitingExternalProof { .. }
        ));
    }

    #[test]
    fn invalidation_fences_late_completion_and_keeps_build_slot() {
        let owner = manager();
        let handle = owner.handle();
        let permit = owner.begin_rebuild(id("stale")).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            sender.send(()).unwrap();
            worker_barrier.wait();
            permit.build(snapshot())
        });
        receiver.recv().unwrap();
        owner.invalidate(InvalidReason::Drift).unwrap();
        assert_eq!(
            owner.begin_rebuild(id("concurrent")).err(),
            Some(Error::Busy)
        );
        assert!(handle.status().unwrap().build_in_flight);
        barrier.wait();
        assert_eq!(worker.join().unwrap(), Err(Error::StaleAttempt));
        assert_eq!(
            handle.status().unwrap().lifecycle,
            Lifecycle::Invalid {
                reason: InvalidReason::Drift
            }
        );
        owner
            .begin_rebuild(id("fresh"))
            .unwrap()
            .build(snapshot())
            .unwrap();
    }

    #[test]
    fn timeout_and_cancellation_are_sticky_unknown() {
        let owner = manager();
        let handle = owner.handle();
        let permit = owner.begin_rebuild(id("timeout")).unwrap();
        owner
            .shared
            .state
            .lock()
            .unwrap()
            .attempt
            .as_mut()
            .unwrap()
            .deadline = Instant::now();
        assert!(matches!(
            handle.status().unwrap().lifecycle,
            Lifecycle::Unknown { .. }
        ));
        assert_eq!(permit.build(snapshot()), Err(Error::Unknown));
        assert_eq!(
            owner.invalidate(InvalidReason::Explicit),
            Err(Error::Unknown)
        );
        assert_eq!(owner.begin_rebuild(id("retry")).err(), Some(Error::Unknown));

        let other = manager();
        let permit = other.begin_rebuild(id("cancelled")).unwrap();
        other
            .invalidate(InvalidReason::DependencyUnavailable)
            .unwrap();
        drop(permit);
        assert_eq!(
            other.handle().status().unwrap().lifecycle,
            Lifecycle::Unknown {
                operation_id: Some(id("cancelled"))
            }
        );
        assert_eq!(other.begin_rebuild(id("retry")).err(), Some(Error::Unknown));
    }

    #[test]
    fn failed_build_and_candidate_expiry_allow_controlled_rebuild() {
        let owner = manager();
        let mut bad = snapshot();
        bad.version.generation = 0;
        assert_eq!(
            owner.begin_rebuild(id("bad")).unwrap().build(bad),
            Err(Error::BuildFailed)
        );
        assert_eq!(owner.handle().status().unwrap().retained_candidates, 0);
        owner
            .begin_rebuild(id("good"))
            .unwrap()
            .build(snapshot())
            .unwrap();
        owner
            .shared
            .state
            .lock()
            .unwrap()
            .candidate
            .as_mut()
            .unwrap()
            .expires_at = Instant::now();
        let status = owner.handle().status().unwrap();
        assert_eq!(
            status.lifecycle,
            Lifecycle::Invalid {
                reason: InvalidReason::CandidateExpired
            }
        );
        assert_eq!(status.retained_candidates, 0);
        owner
            .begin_rebuild(id("rebuild"))
            .unwrap()
            .build(snapshot())
            .unwrap();
    }

    #[test]
    fn limits_and_registration_are_enforced() {
        let mut invalid = budget();
        invalid.build.max_rows = 0;
        assert_eq!(RootManager::new(invalid).err(), Some(Error::InvalidBudget));
        let owner = RootManager::create(budget(), false);
        let handle = owner.handle();
        drop(owner);
        assert_eq!(handle.status().unwrap().lifecycle, Lifecycle::Shutdown);

        let mut limited = budget();
        limited.build.max_snapshot_bytes = 1;
        let owner = RootManager::create(limited, false);
        assert_eq!(
            owner.begin_rebuild(id("limit")).unwrap().build(snapshot()),
            Err(Error::BuildFailed)
        );
        assert_eq!(owner.handle().status().unwrap().retained_candidates, 0);
    }

    #[test]
    fn cooperative_build_deadline_is_sticky_unknown() {
        let mut limits = budget();
        limits.build.max_build_time = Duration::from_nanos(1);
        let owner = RootManager::create(limits, false);
        assert_eq!(
            owner
                .begin_rebuild(id("model-timeout"))
                .unwrap()
                .build(snapshot()),
            Err(Error::Unknown)
        );
        assert_eq!(
            owner.handle().status().unwrap().lifecycle,
            Lifecycle::Unknown {
                operation_id: Some(id("model-timeout"))
            }
        );
        assert_eq!(owner.begin_rebuild(id("retry")).err(), Some(Error::Unknown));
    }

    #[test]
    fn owner_drop_and_epoch_exhaustion_stay_closed() {
        let owner = manager();
        let handle = owner.handle();
        let permit = owner.begin_rebuild(id("lost-owner")).unwrap();
        drop(owner);
        assert!(matches!(
            handle.status().unwrap().lifecycle,
            Lifecycle::Unknown { .. }
        ));
        assert_eq!(permit.build(snapshot()), Err(Error::Unknown));

        let owner = manager();
        owner.shared.state.lock().unwrap().epoch = u64::MAX;
        assert_eq!(
            owner.begin_rebuild(id("exhausted")).err(),
            Some(Error::Exhausted)
        );
        assert!(matches!(
            owner.handle().status().unwrap().lifecycle,
            Lifecycle::Unknown { .. }
        ));
    }
}
