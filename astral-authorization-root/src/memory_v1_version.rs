//! memory—v1 process-local candidate root identity.
//!
//! These values do not establish unique ownership, complete coverage, digest
//! integrity, source provenance, persistence, or permission to authorize.
//! The owner must generate a fresh instance identifier on each process start and
//! publish metadata atomically with the corresponding root state.

use std::num::NonZeroU64;

/// Identifies a single process-local authority instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InstanceId([u8; 16]);

/// Failure to construct or advance candidate root metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataError {
    /// An all-zero instance identifier cannot identify an authority.
    InvalidInstanceId,
    /// The owner must invalidate the root when the version is exhausted.
    VersionExhausted,
}

impl InstanceId {
    /// memory—v1: Validate an externally generated process instance identifier.
    ///
    /// A nonzero value alone does not prove uniqueness.
    pub fn new(bytes: [u8; 16]) -> Result<Self, MetadataError> {
        if bytes == [0; 16] {
            return Err(MetadataError::InvalidInstanceId);
        }
        Ok(Self(bytes))
    }

    /// memory—v1: Return the identifier for correlation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Candidate identity of one state, not an authorization or persistence proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootMetadata {
    instance: InstanceId,
    version: NonZeroU64,
    content_digest: [u8; 32],
}

impl RootMetadata {
    /// memory—v1: Identify an initial state using an opaque caller-provided digest.
    pub fn initial(instance: InstanceId, content_digest: [u8; 32]) -> Self {
        Self {
            instance,
            version: NonZeroU64::MIN,
            content_digest,
        }
    }

    /// memory—v1: Advance the local version without reusing a sequence number.
    ///
    /// The caller must verify the digest and commit it together with the facts;
    /// producing this value alone does not commit or invalidate any state.
    pub fn next(self, content_digest: [u8; 32]) -> Result<Self, MetadataError> {
        let version = self
            .version
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(MetadataError::VersionExhausted)?;
        Ok(Self {
            instance: self.instance,
            version,
            content_digest,
        })
    }

    /// memory—v1: Return the instance identity.
    pub fn instance(&self) -> InstanceId {
        self.instance
    }

    /// memory—v1: Return the instance-local state version.
    pub fn version(&self) -> NonZeroU64 {
        self.version
    }

    /// memory—v1: Return the opaque caller-supplied content digest.
    pub fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // memory—v1
    fn instance_must_not_be_zero() {
        assert_eq!(
            InstanceId::new([0; 16]),
            Err(MetadataError::InvalidInstanceId)
        );
        assert_eq!(InstanceId::new([1; 16]).unwrap().as_bytes(), &[1; 16]);
    }

    #[test]
    // memory—v1
    fn sequence_changes_even_when_content_returns_to_prior_value() {
        let instance = InstanceId::new([1; 16]).unwrap();
        let initial = RootMetadata::initial(instance, [7; 32]);
        let changed = initial.next([8; 32]).unwrap();
        let restored = changed.next([7; 32]).unwrap();
        assert_eq!(initial.version().get(), 1);
        assert_eq!(restored.version().get(), 3);
        assert_eq!(restored.content_digest(), initial.content_digest());
        assert_eq!(restored.instance(), initial.instance());
        assert_ne!(restored, initial);
    }

    #[test]
    // memory—v1
    fn different_instances_do_not_share_identity() {
        let first = RootMetadata::initial(InstanceId::new([1; 16]).unwrap(), [0; 32]);
        let second = RootMetadata::initial(InstanceId::new([2; 16]).unwrap(), [0; 32]);
        assert_ne!(first, second);
    }

    #[test]
    // memory—v1
    fn exhausted_version_cannot_wrap() {
        let max = RootMetadata {
            instance: InstanceId::new([1; 16]).unwrap(),
            version: NonZeroU64::new(u64::MAX).unwrap(),
            content_digest: [1; 32],
        };
        assert_eq!(max.next([2; 32]), Err(MetadataError::VersionExhausted));
    }
}
