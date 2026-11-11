//! Independent, process-local candidate state with bounded batch transactions.
//!
//! This is not connected to the authorization path. It proves no source,
//! coverage, authorization, digest integrity, durability, or production
//! readiness. A digest is opaque caller-supplied metadata; it is never checked
//! against the facts. Versions are local to one owner and restart with a new
//! owner. A current check is a point-in-time observation, not a commit fence.
//!
//! The state has a fixed number of slots. One logical change can replace or
//! clear a bounded set of distinct slots atomically. Bytes are owned and
//! immutable while retained. This deliberately avoids promising rollback for
//! arbitrary generic values with interior mutability, user-defined cloning, or
//! destructors. The owner is non-cloneable; its read handles fail closed after
//! owner drop. Already captured values remain readable, but are no longer current.
//! The same state allocation remains in place throughout its lifetime.
//!
//! Capture and commit hold a local lock only for copying references or swapping
//! bounded slots and their metadata. The preparation closure and allocation,
//! including disposal of replaced bytes, occur outside that lock. Captured values
//! can be retained indefinitely, and callers must bound total retained memory and
//! preparation time; limits here are not a process-wide memory budget.

use std::sync::{Arc, Mutex};

/// Bounds on individual values, the slot count, capture, and batch size.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_slots: usize,
    pub max_value_bytes: usize,
    pub max_capture_slots: usize,
    pub max_change_slots: usize,
}

/// Opaque metadata supplied by the caller, with no verification by this module.
pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// Monotonically increasing within this owner, starting at zero.
    pub version: u64,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidLimits,
    TooManySlots,
    TooManyCaptureSlots,
    TooManyChangeSlots,
    EmptyChange,
    DuplicateSlot,
    InvalidSlot,
    ValueTooLarge,
    VersionExhausted,
    OwnerDropped,
    Poisoned,
}

/// An error from either the candidate kernel or the caller's preparation.
#[derive(Debug, PartialEq, Eq)]
pub enum TransactionError<E> {
    State(StateError),
    Prepare(E),
}

/// One logical batch, validated by the caller in its preparation closure.
///
/// The kernel validates bounds and distinct slot indices, not business semantics
/// or the relationship between the values and digest.
pub struct Change {
    pub slots: Vec<SlotChange>,
    pub digest: Digest,
}

pub struct SlotChange {
    pub slot: usize,
    pub value: Option<Vec<u8>>,
}

struct State {
    slots: Vec<Option<Arc<[u8]>>>,
    metadata: Metadata,
    owner_alive: bool,
}

struct Shared {
    state: Mutex<State>,
    identity: Arc<()>,
    limits: Limits,
    slot_count: usize,
}

/// The only mutation capability for an independent state. It is not `Clone`.
pub struct AtomicStateOwner {
    shared: Arc<Shared>,
}

/// A shared read-only capability. It cannot prepare or commit a change.
#[derive(Clone)]
pub struct AtomicStateHandle {
    shared: Arc<Shared>,
}

/// Request-local values and metadata captured under the same lock.
pub struct Capture {
    identity: Arc<()>,
    metadata: Metadata,
    entries: Vec<(usize, Option<Arc<[u8]>>)>,
}

impl Capture {
    pub fn metadata(&self) -> Metadata {
        self.metadata
    }

    /// Iterates in request order, including duplicate slot indices.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (usize, Option<&[u8]>)> {
        self.entries
            .iter()
            .map(|(index, value)| (*index, value.as_deref()))
    }
}

impl AtomicStateOwner {
    /// Construct a new independent owner and its initial candidate facts.
    pub fn new(
        initial: Vec<Option<Vec<u8>>>,
        digest: Digest,
        limits: Limits,
    ) -> Result<Self, StateError> {
        if limits.max_slots == 0
            || limits.max_value_bytes == 0
            || limits.max_capture_slots == 0
            || limits.max_change_slots == 0
        {
            return Err(StateError::InvalidLimits);
        }
        if initial.len() > limits.max_slots {
            return Err(StateError::TooManySlots);
        }
        if initial
            .iter()
            .flatten()
            .any(|value| value.len() > limits.max_value_bytes)
        {
            return Err(StateError::ValueTooLarge);
        }
        let slot_count = initial.len();
        let slots = initial
            .into_iter()
            .map(|value| value.map(Arc::from))
            .collect();
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    slots,
                    metadata: Metadata { version: 0, digest },
                    owner_alive: true,
                }),
                identity: Arc::new(()),
                limits,
                slot_count,
            }),
        })
    }

    pub fn handle(&self) -> AtomicStateHandle {
        AtomicStateHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Capture `read_slots`, prepare one batch without a lock, and commit it.
    ///
    /// Exclusive access to this non-cloneable owner prevents another commit
    /// between capture and commit. Preparation may read through a handle. A
    /// preparation error or unwind, invalid change, or poisoned lock leaves the
    /// facts and metadata untouched. Version exhaustion also invalidates the
    /// owner. Unwinds propagate. The
    /// closure must perform all business validation itself. External effects of
    /// the closure cannot be rolled back by this in-memory kernel.
    pub fn transact<E>(
        &mut self,
        read_slots: &[usize],
        prepare: impl FnOnce(&Capture) -> Result<Change, E>,
    ) -> Result<Metadata, TransactionError<E>> {
        let capture = self
            .handle()
            .capture(read_slots)
            .map_err(TransactionError::State)?;
        let mut change = prepare(&capture).map_err(TransactionError::Prepare)?;
        if change.slots.is_empty() {
            return Err(TransactionError::State(StateError::EmptyChange));
        }
        if change.slots.len() > self.shared.limits.max_change_slots {
            return Err(TransactionError::State(StateError::TooManyChangeSlots));
        }
        change.slots.sort_unstable_by_key(|entry| entry.slot);
        for (index, entry) in change.slots.iter().enumerate() {
            if entry.slot >= self.shared.slot_count {
                return Err(TransactionError::State(StateError::InvalidSlot));
            }
            if index > 0 && change.slots[index - 1].slot == entry.slot {
                return Err(TransactionError::State(StateError::DuplicateSlot));
            }
            if entry
                .value
                .as_ref()
                .is_some_and(|value| value.len() > self.shared.limits.max_value_bytes)
            {
                return Err(TransactionError::State(StateError::ValueTooLarge));
            }
        }
        // Prepare every allocation before the commit lock. Reuse this vector to
        // carry old values out of the lock, avoiding allocation or destruction
        // while any slot and metadata are being changed.
        let mut replacements: Vec<_> = change
            .slots
            .into_iter()
            .map(|entry| (entry.slot, entry.value.map(Arc::<[u8]>::from)))
            .collect();
        let metadata = {
            let mut state = self
                .shared
                .state
                .lock()
                .map_err(|_| TransactionError::State(StateError::Poisoned))?;
            if !state.owner_alive {
                return Err(TransactionError::State(StateError::OwnerDropped));
            }
            let Some(version) = state.metadata.version.checked_add(1) else {
                state.owner_alive = false;
                return Err(TransactionError::State(StateError::VersionExhausted));
            };
            let metadata = Metadata {
                version,
                digest: change.digest,
            };
            for (slot, replacement) in &mut replacements {
                std::mem::swap(&mut state.slots[*slot], replacement);
            }
            state.metadata = metadata;
            metadata
        };
        drop(replacements);
        Ok(metadata)
    }
}

impl Drop for AtomicStateOwner {
    fn drop(&mut self) {
        // Poisoned locks already fail closed for every handle; marking the
        // recovered state also preserves closure if poisoning is ever cleared.
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.owner_alive = false;
    }
}

impl AtomicStateHandle {
    /// Capture only requested slots with their common version and digest.
    pub fn capture(&self, slots: &[usize]) -> Result<Capture, StateError> {
        if slots.len() > self.shared.limits.max_capture_slots {
            return Err(StateError::TooManyCaptureSlots);
        }
        if slots.iter().any(|&slot| slot >= self.shared.slot_count) {
            return Err(StateError::InvalidSlot);
        }
        let mut entries = Vec::with_capacity(slots.len());
        let metadata = {
            let state = self.shared.state.lock().map_err(|_| StateError::Poisoned)?;
            if !state.owner_alive {
                return Err(StateError::OwnerDropped);
            }
            for &slot in slots {
                entries.push((slot, state.slots[slot].clone()));
            }
            state.metadata
        };
        Ok(Capture {
            identity: Arc::clone(&self.shared.identity),
            metadata,
            entries,
        })
    }

    /// Compare owner identity and version at one instant; no data is rehashed.
    pub fn is_current(&self, capture: &Capture) -> Result<bool, StateError> {
        let state = self.shared.state.lock().map_err(|_| StateError::Poisoned)?;
        if !state.owner_alive {
            return Err(StateError::OwnerDropped);
        }
        Ok(Arc::ptr_eq(&self.shared.identity, &capture.identity)
            && state.metadata.version == capture.metadata.version)
    }
}

#[cfg(test)]
mod tests;
