//! Shared candidate-root protocol for process-local consumers.
//!
//! This combines one registered candidate owner, immutable snapshot handles
//! and scoped candidate reads. It does not authenticate the caller, prove
//! coverage or publication, enforce expiry, or produce an authorization
//! decision. It must not be used as production evidence or admission.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::candidate_scope::{CandidateCardRead, CandidateCardScope, CandidateCardView};
use crate::model::SingleNodeMemoryRoot;
use crate::shared_snapshot::{
    ContentHash, InstallError, Snapshot, SnapshotHandle, SnapshotMetadata, SnapshotOwner,
};

/// Unique owner of this candidate protocol. It is not a production root owner.
pub struct CandidateRootOwner {
    slot: Option<SnapshotOwner<SingleNodeMemoryRoot>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateRootError {
    OwnerAlreadyRegistered,
    InvalidDigest,
    RevisionExhausted,
}

impl CandidateRootOwner {
    /// Share the process registration with the other experimental owners.
    pub fn new() -> Result<Self, CandidateRootError> {
        crate::OWNER_REGISTERED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CandidateRootError::OwnerAlreadyRegistered)?;
        Ok(Self {
            slot: Some(SnapshotOwner::new()),
        })
    }

    pub fn handle(&self) -> CandidateRootHandle {
        CandidateRootHandle {
            slot: self.slot.as_ref().expect("owner slot exists").handle(),
        }
    }

    /// Publish a candidate using its model-computed digest. A digest does not
    /// establish trusted origin, complete coverage or current authorization.
    pub fn install(
        &mut self,
        root: SingleNodeMemoryRoot,
    ) -> Result<SnapshotMetadata, CandidateRootError> {
        let digest = ContentHash::new(root.content_digest())
            .map_err(|_| CandidateRootError::InvalidDigest)?;
        self.slot
            .as_mut()
            .expect("owner slot exists")
            .install(Arc::new(root), digest)
            .map_err(|error| match error {
                InstallError::RevisionExhausted => CandidateRootError::RevisionExhausted,
            })
    }

    pub fn invalidate(&mut self) {
        self.slot.as_mut().expect("owner slot exists").invalidate();
    }
}

impl Drop for CandidateRootOwner {
    fn drop(&mut self) {
        // Clear the old slot before making registration available to a new owner.
        drop(self.slot.take());
        crate::OWNER_REGISTERED.store(false, Ordering::Release);
    }
}

/// Clonable read-only handle; it does not expose installation or the raw root.
#[derive(Clone)]
pub struct CandidateRootHandle {
    slot: SnapshotHandle<SingleNodeMemoryRoot>,
}

impl CandidateRootHandle {
    /// Capture one immutable candidate and bind a caller-claimed card scope.
    pub fn begin_read(&self, scope: CandidateCardScope) -> Option<CandidateRootRead> {
        self.slot.snapshot().map(|snapshot| CandidateRootRead {
            slot: self.slot.clone(),
            snapshot,
            scope,
        })
    }
}

/// One request's candidate snapshot. Scope values are caller claims only.
pub struct CandidateRootRead {
    slot: SnapshotHandle<SingleNodeMemoryRoot>,
    snapshot: Snapshot<SingleNodeMemoryRoot>,
    scope: CandidateCardScope,
}

impl CandidateRootRead {
    pub fn metadata(&self) -> &SnapshotMetadata {
        self.snapshot.metadata()
    }

    pub fn card_facts(&self) -> CandidateCardRead {
        CandidateCardView::new(self.snapshot.data(), self.scope).read()
    }

    /// Observe whether this publication remains current, without reading or
    /// hashing the candidate. This is not a production authorization fence.
    pub fn is_current(&self) -> bool {
        self.slot.is_current(&self.snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_scope::tests::{scope, snapshot};

    #[test]
    fn shared_handles_bind_one_candidate_and_reject_stale_reads() {
        let _lock = crate::TEST_OWNER_LOCK.lock().unwrap();
        let mut owner = CandidateRootOwner::new().unwrap();
        assert!(matches!(
            CandidateRootOwner::new(),
            Err(CandidateRootError::OwnerAlreadyRegistered)
        ));
        let first_handle = owner.handle();
        let second_handle = first_handle.clone();
        assert!(first_handle.begin_read(scope()).is_none());

        owner
            .install(SingleNodeMemoryRoot::build(snapshot()).unwrap())
            .unwrap();
        let first = first_handle.begin_read(scope()).unwrap();
        let second = second_handle.begin_read(scope()).unwrap();
        assert_eq!(first.metadata(), second.metadata());
        assert!(matches!(
            first.card_facts(),
            CandidateCardRead::Candidate(_)
        ));
        let cross_tenant = CandidateCardScope {
            tenant_id: 11,
            ..scope()
        };
        let other = second_handle.begin_read(cross_tenant).unwrap();
        assert_eq!(other.card_facts(), CandidateCardRead::Uncovered);
        assert!(first.is_current());

        owner
            .install(SingleNodeMemoryRoot::build(snapshot()).unwrap())
            .unwrap();
        let updated = second_handle.begin_read(scope()).unwrap();
        assert_eq!(
            first.metadata().content_hash(),
            updated.metadata().content_hash()
        );
        assert!(updated.metadata().install_revision() > first.metadata().install_revision());
        assert!(!first.is_current());
        assert!(!second.is_current());
        assert!(updated.is_current());
        drop(owner);
        assert!(!updated.is_current());
        assert!(first_handle.begin_read(scope()).is_none());
        let replacement = CandidateRootOwner::new().unwrap();
        assert!(replacement.handle().begin_read(scope()).is_none());
    }

    #[test]
    fn existing_registered_manager_cannot_coexist() {
        let _lock = crate::TEST_OWNER_LOCK.lock().unwrap();
        let owner = CandidateRootOwner::new().unwrap();
        assert!(matches!(
            crate::experimental::RootOwner::new(),
            Err(crate::experimental::Error::OwnerAlreadyExists)
        ));
        drop(owner);
    }
}
