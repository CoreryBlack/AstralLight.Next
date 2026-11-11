use std::sync::Arc;
use std::time::Instant;

use crate::model::SingleNodeMemoryRoot;

use super::{ClosedReason, Error, GateStatus, OperationId, RootStatus};

pub(super) struct Snapshot {
    pub(super) root: SingleNodeMemoryRoot,
    pub(super) expires_at: Instant,
}

pub(super) enum Phase {
    Closed {
        reason: ClosedReason,
        operation_id: Option<OperationId>,
    },
    Pending {
        operation_id: OperationId,
        epoch: u64,
        deadline: Instant,
    },
    // Only the private experimental test installer can enter this state.
    #[cfg_attr(not(test), allow(dead_code))]
    Open,
}

pub(super) struct Inner {
    pub(super) snapshot: Option<Arc<Snapshot>>,
    pub(super) phase: Phase,
    pub(super) epoch: u64,
    pub(super) revision: u64,
}

impl Inner {
    pub(super) fn new() -> Self {
        Self {
            snapshot: None,
            phase: Phase::Closed {
                reason: ClosedReason::Cold,
                operation_id: None,
            },
            epoch: 0,
            revision: 0,
        }
    }

    pub(super) fn close(
        &mut self,
        reason: ClosedReason,
        operation_id: Option<OperationId>,
    ) -> Result<(), Error> {
        let Some(next) = self.epoch.checked_add(1) else {
            self.phase = Phase::Closed {
                reason: ClosedReason::Exhausted,
                operation_id,
            };
            self.snapshot = None;
            return Err(Error::Exhausted);
        };
        self.epoch = next;
        self.phase = Phase::Closed {
            reason,
            operation_id,
        };
        self.snapshot = None;
        Ok(())
    }

    pub(super) fn expire(&mut self, now: Instant) {
        let reason = match &self.phase {
            Phase::Pending {
                operation_id,
                deadline,
                ..
            } if now >= *deadline => Some((ClosedReason::Unknown, Some(operation_id.clone()))),
            Phase::Open
                if self
                    .snapshot
                    .as_ref()
                    .is_none_or(|snapshot| now >= snapshot.expires_at) =>
            {
                Some((ClosedReason::Expired, None))
            }
            _ => None,
        };
        if let Some((reason, operation_id)) = reason {
            let _ = self.close(reason, operation_id);
        }
    }

    /// Close the old instance and report whether replacing it would discard an
    /// unresolved mutation or a terminal counter failure. Neither a guard drop
    /// nor a local deadline proves the external outcome.
    pub(super) fn shutdown(&mut self) -> bool {
        let (unresolved, operation_id) = match &self.phase {
            Phase::Pending { operation_id, .. } => (true, Some(operation_id.clone())),
            Phase::Closed {
                reason: ClosedReason::Unknown | ClosedReason::Exhausted,
                operation_id,
            } => (true, operation_id.clone()),
            _ => (false, None),
        };
        // Preserve terminal closure even when the epoch counter is exhausted.
        let exhausted = self
            .close(ClosedReason::OwnerDropped, operation_id)
            .is_err();
        unresolved || exhausted
    }

    pub(super) fn status(&self) -> RootStatus {
        let gate = match &self.phase {
            Phase::Closed {
                reason,
                operation_id,
            } => GateStatus::Closed {
                reason: *reason,
                operation_id: operation_id.clone(),
            },
            Phase::Pending { operation_id, .. } => GateStatus::Closed {
                reason: ClosedReason::Mutation,
                operation_id: Some(operation_id.clone()),
            },
            Phase::Open => GateStatus::OpenForExperiment,
        };
        RootStatus {
            gate,
            install_revision: self.revision,
            gate_epoch: self.epoch,
        }
    }
}

// This intentionally is not compiled into non-test builds. A future production
// installer requires opaque verified evidence and reconciliation, not a bool.
#[cfg(test)]
impl super::MutationGuard {
    pub(super) fn install_for_test(
        mut self,
        root: SingleNodeMemoryRoot,
        expires_at: Instant,
    ) -> Result<(), Error> {
        if expires_at <= Instant::now() {
            return Err(Error::InvalidDeadline);
        }
        let snapshot = Arc::new(Snapshot { root, expires_at });
        let mut inner = self.inner.lock().map_err(|_| Error::Poisoned)?;
        let now = Instant::now();
        inner.expire(now);
        if !matches!(&inner.phase, Phase::Pending { operation_id, epoch, deadline } if operation_id == &self.operation_id && *epoch == self.epoch && now < *deadline)
            || now >= snapshot.expires_at
        {
            return Err(Error::Unknown);
        }
        let Some(revision) = inner.revision.checked_add(1) else {
            let _ = inner.close(ClosedReason::Exhausted, Some(self.operation_id.clone()));
            return Err(Error::Exhausted);
        };
        let Some(epoch) = inner.epoch.checked_add(1) else {
            let _ = inner.close(ClosedReason::Exhausted, Some(self.operation_id.clone()));
            return Err(Error::Exhausted);
        };
        inner.revision = revision;
        inner.epoch = epoch;
        inner.snapshot = Some(snapshot);
        inner.phase = Phase::Open;
        self.armed = false;
        Ok(())
    }
}
