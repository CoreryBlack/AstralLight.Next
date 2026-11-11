//! Generic, process-local candidate snapshot infrastructure.
//!
//! Each independently constructed owner has one publication slot. It is a
//! demonstration object, not a process-wide singleton, and does not interact
//! with the crate's `OWNER_REGISTERED` registration. This module does not prove
//! authorization, readiness, provenance, content integrity, or coverage, and
//! must not be used on its own to admit an operation or produce ALLOW.
//!
//! The trusted caller supplies both the data and its claimed hash. The hash is
//! only syntax-checked; it is neither calculated nor verified here. `Arc<T>`
//! does not prevent interior mutation or mutation through other shared handles:
//! callers must ensure the candidate's logical immutability themselves. Only
//! data in the caller-supplied `T` is exposed; this module supplies no scope or
//! tenant isolation.
//!
//! An F0 snapshot retains its candidate after replacement, invalidation, or
//! owner drop. F1 checks the current slot at one instant, without reading `T` or
//! recalculating its hash. A successful F1 does not prevent an immediately
//! subsequent invalidation and is not a read/write gate or a commit fence.
//! The slot retains at most one candidate, but readers can retain arbitrarily
//! many old candidates; this module imposes no TTL, reader count, data-size, or
//! process-memory limit. Callers must supply any required resource bounds.

use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwapOption;

/// A caller-supplied, 64-character lowercase hexadecimal content hash.
///
/// Validation checks representation only, not the algorithm, contents, source,
/// integrity, authenticity, or completeness of the candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentHash(String);

impl ContentHash {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidContentHash> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InvalidContentHash);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidContentHash;

/// Metadata captured together with the candidate in one publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotMetadata {
    install_revision: u64,
    content_hash: ContentHash,
    installed_at: Instant,
}

impl SnapshotMetadata {
    /// A nonzero counter local to this owner, advanced for each installation.
    /// It is not a durable, global, source, or authority version. Invalidating
    /// the slot does not reset it; a new independent owner starts over.
    pub fn install_revision(&self) -> u64 {
        self.install_revision
    }

    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    /// Monotonic process-local time sampled immediately before publication.
    /// This is not a wall-clock time, a source capture or commit time, a proof
    /// of validity, or the exact atomic publication instant.
    pub fn installed_at(&self) -> Instant {
        self.installed_at
    }
}

struct Published<T> {
    data: Arc<T>,
    metadata: SnapshotMetadata,
}

struct Shared<T> {
    current: ArcSwapOption<Published<T>>,
}

/// The sole writer for one independent slot. This type is deliberately not
/// `Clone`; installation and invalidation require an exclusive owner borrow.
pub struct SnapshotOwner<T> {
    shared: Arc<Shared<T>>,
    last_revision: u64,
    exhausted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// The local counter cannot advance. The slot is cleared permanently.
    RevisionExhausted,
}

impl<T> SnapshotOwner<T> {
    /// Create an independent empty slot, with no process-global registration.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                current: ArcSwapOption::empty(),
            }),
            last_revision: 0,
            exhausted: false,
        }
    }

    pub fn handle(&self) -> SnapshotHandle<T> {
        SnapshotHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Atomically replace the slot with the supplied data and metadata.
    ///
    /// Even identical hashes receive distinct revisions. On counter exhaustion,
    /// the slot is cleared and this owner can never install another candidate.
    pub fn install(
        &mut self,
        data: Arc<T>,
        content_hash: ContentHash,
    ) -> Result<SnapshotMetadata, InstallError> {
        let Some(revision) = self
            .last_revision
            .checked_add(1)
            .filter(|_| !self.exhausted)
        else {
            self.exhausted = true;
            self.shared.current.store(None);
            return Err(InstallError::RevisionExhausted);
        };
        let metadata = SnapshotMetadata {
            install_revision: revision,
            content_hash,
            installed_at: Instant::now(),
        };
        self.last_revision = revision;
        self.shared.current.store(Some(Arc::new(Published {
            data,
            metadata: metadata.clone(),
        })));
        Ok(metadata)
    }

    /// Clear the current slot. Existing F0 snapshots retain their data but fail
    /// subsequent F1 checks unless they raced before this atomic clear.
    pub fn invalidate(&mut self) {
        self.shared.current.store(None);
    }
}

impl<T> Default for SnapshotOwner<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for SnapshotOwner<T> {
    fn drop(&mut self) {
        self.shared.current.store(None);
    }
}

/// Clonable read capability for one slot. It cannot install or invalidate.
pub struct SnapshotHandle<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for SnapshotHandle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> SnapshotHandle<T> {
    /// F0: capture one coherent publication, or `None` if the slot is empty.
    pub fn snapshot(&self) -> Option<Snapshot<T>> {
        self.shared
            .current
            .load_full()
            .map(|published| Snapshot { published })
    }

    /// F1: check whether this exact F0 publication is still in this slot.
    ///
    /// The atomic load observes the current valid/empty state and its metadata
    /// together. Object identity also prevents a snapshot from a different
    /// independent owner with coincidentally equal metadata from matching. No
    /// candidate data is accessed and no hash is computed. This is a point-in-
    /// time observation, not a guarantee that the slot stays unchanged.
    pub fn is_current(&self, snapshot: &Snapshot<T>) -> bool {
        self.shared.current.load_full().is_some_and(|current| {
            Arc::ptr_eq(&current, &snapshot.published)
                && current.metadata == snapshot.published.metadata
        })
    }
}

/// An F0 publication, retaining the candidate and its coherent metadata.
pub struct Snapshot<T> {
    published: Arc<Published<T>>,
}

impl<T> Clone for Snapshot<T> {
    fn clone(&self) -> Self {
        Self {
            published: Arc::clone(&self.published),
        }
    }
}

impl<T> Snapshot<T> {
    pub fn data(&self) -> &Arc<T> {
        &self.published.data
    }

    pub fn metadata(&self) -> &SnapshotMetadata {
        &self.published.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;

    fn hash(byte: char) -> ContentHash {
        ContentHash::new(byte.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn hash_requires_exactly_lowercase_ascii_hex() {
        assert_eq!(hash('a').as_str(), "a".repeat(64));
        for invalid in [
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            &"g".repeat(64),
            &"é".repeat(32),
        ] {
            assert_eq!(ContentHash::new(invalid), Err(InvalidContentHash));
        }
    }

    #[test]
    fn replacement_binds_data_and_metadata_even_for_same_hash() {
        let mut owner = SnapshotOwner::new();
        let first_handle = owner.handle();
        let second_handle = first_handle.clone();
        assert!(first_handle.snapshot().is_none());
        let before = Instant::now();
        let first_metadata = owner.install(Arc::new(10), hash('a')).unwrap();
        let after = Instant::now();
        let first = first_handle.snapshot().unwrap();
        assert_eq!(**first.data(), 10);
        assert_eq!(first.metadata(), &first_metadata);
        assert!(before <= first_metadata.installed_at() && first_metadata.installed_at() <= after);
        assert_eq!(first_metadata.install_revision(), 1);
        assert!(second_handle.is_current(&first));

        let second_metadata = owner.install(Arc::new(20), hash('a')).unwrap();
        let second = second_handle.snapshot().unwrap();
        assert_eq!(**first.data(), 10);
        assert_eq!(**second.data(), 20);
        assert_eq!(second.metadata(), &second_metadata);
        assert_eq!(second_metadata.install_revision(), 2);
        assert_eq!(
            first_metadata.content_hash(),
            second_metadata.content_hash()
        );
        assert!(!first_handle.is_current(&first));
        assert!(first_handle.is_current(&second));
    }

    #[test]
    fn independent_owners_cannot_accept_each_others_snapshots() {
        let mut first = SnapshotOwner::new();
        let mut second = SnapshotOwner::new();
        first.install(Arc::new(1), hash('a')).unwrap();
        second.install(Arc::new(1), hash('a')).unwrap();
        let captured = first.handle().snapshot().unwrap();
        assert!(!second.handle().is_current(&captured));
    }

    #[test]
    fn invalidation_drop_and_exhaustion_fail_closed() {
        let mut owner = SnapshotOwner::new();
        let handle = owner.handle();
        owner.install(Arc::new(1), hash('a')).unwrap();
        let old = handle.snapshot().unwrap();
        owner.invalidate();
        assert!(handle.snapshot().is_none());
        assert!(!handle.is_current(&old));
        assert_eq!(
            owner
                .install(Arc::new(2), hash('b'))
                .unwrap()
                .install_revision(),
            2
        );
        let latest = handle.snapshot().unwrap();
        owner.last_revision = u64::MAX;
        assert_eq!(
            owner.install(Arc::new(3), hash('c')),
            Err(InstallError::RevisionExhausted)
        );
        assert!(handle.snapshot().is_none());
        assert!(!handle.is_current(&latest));
        owner.last_revision = 0;
        assert_eq!(
            owner.install(Arc::new(4), hash('d')),
            Err(InstallError::RevisionExhausted)
        );

        let mut another = SnapshotOwner::new();
        let retained_handle = another.handle();
        another.install(Arc::new(5), hash('e')).unwrap();
        let retained_snapshot = retained_handle.snapshot().unwrap();
        drop(another);
        assert!(retained_handle.snapshot().is_none());
        assert!(!retained_handle.is_current(&retained_snapshot));
        assert_eq!(**retained_snapshot.data(), 5);
    }

    #[test]
    fn f1_never_hashes_or_accesses_candidate() {
        // The candidate has no Hash implementation and deliberately offers no
        // accessors. F1 must work solely through the publication metadata.
        struct Opaque;
        let mut owner = SnapshotOwner::new();
        let handle = owner.handle();
        owner.install(Arc::new(Opaque), hash('f')).unwrap();
        let captured = handle.snapshot().unwrap();
        assert!(handle.is_current(&captured));
        owner.invalidate();
        assert!(!handle.is_current(&captured));
    }

    #[test]
    fn concurrent_readers_always_observe_coherent_publications() {
        const INSTALLS: usize = 2_000;
        let mut owner = SnapshotOwner::new();
        let handle = owner.handle();
        let finished = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let handle = handle.clone();
            let finished = Arc::clone(&finished);
            readers.push(thread::spawn(move || {
                while !finished.load(Ordering::Acquire) {
                    if let Some(snapshot) = handle.snapshot() {
                        let revision = snapshot.metadata().install_revision();
                        assert_eq!(**snapshot.data(), revision);
                        let expected = if revision % 2 == 0 {
                            hash('a')
                        } else {
                            hash('b')
                        };
                        assert_eq!(snapshot.metadata().content_hash(), &expected);
                    }
                }
            }));
        }
        for revision in 1..=INSTALLS as u64 {
            let claimed = if revision % 2 == 0 {
                hash('a')
            } else {
                hash('b')
            };
            owner.install(Arc::new(revision), claimed).unwrap();
        }
        finished.store(true, Ordering::Release);
        for reader in readers {
            reader.join().unwrap();
        }
        let last = handle.snapshot().unwrap();
        assert_eq!(**last.data(), INSTALLS as u64);
        assert_eq!(last.metadata().install_revision(), INSTALLS as u64);
    }

    #[test]
    fn slot_retains_one_candidate_and_readers_control_old_lifetimes() {
        struct Counted(Arc<AtomicUsize>);
        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = SnapshotOwner::new();
        let handle = owner.handle();
        owner
            .install(Arc::new(Counted(Arc::clone(&drops))), hash('a'))
            .unwrap();
        let old = handle.snapshot().unwrap();
        let old_clone = old.clone();
        owner
            .install(Arc::new(Counted(Arc::clone(&drops))), hash('b'))
            .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(old);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(old_clone);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        owner.invalidate();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }
}
