//! memory—v1 experimental bounded state kernel with internally computed digests.
//!
//! This module is not an authorization reader or a production root. Slot bytes
//! have no defined business schema or coverage proof, and a digest proves neither
//! provenance nor authorization. Callers must not use it to grant permissions.
//! It deliberately has no database, network, rule evaluation or persistence.
//!
//! A non-cloneable owner serializes preparation and commits. Handles capture
//! selected slots and their metadata together; the owner updates the same state
//! allocation. A versioned, domain-separated binary hash tree covers slot count,
//! slot position, presence and exact bytes. This is an experimental encoding, not
//! the as-yet-undecided RuleSet hash contract. Captures retain immutable slot
//! bytes; aggregate retained memory and process-wide uniqueness are not enforced.
//! A mutation copies the hash tree (O(number of slots)) before updating affected
//! hash paths; this is not yet a bounded process-wide memory or performance design.

use sha2::{Digest as _, Sha256};

use crate::atomic_state::{
    AtomicStateHandle, AtomicStateOwner, Capture, Change, Digest, Limits, Metadata, SlotChange,
    StateError, TransactionError,
};

/// An independent candidate owner. It does not enforce process-wide uniqueness.
pub struct MemoryRootOwner {
    state: AtomicStateOwner,
    hashes: HashTree,
    limits: Limits,
}

/// A cloneable read-only handle to the owner's state.
#[derive(Clone)]
pub struct MemoryRootHandle {
    state: AtomicStateHandle,
}

/// One coherent selection of candidate bytes and associated metadata.
pub struct MemoryRootCapture {
    capture: Capture,
}

/// A bounded replacement or removal of a slot.
pub struct MemoryRootChange {
    /// The fixed slot index.
    pub slot: usize,
    /// Exact new bytes, or absence when `None`.
    pub value: Option<Vec<u8>>,
}

struct HashTree {
    slots: usize,
    base: usize,
    nodes: Vec<Digest>,
}

impl HashTree {
    // memory—v1: Build an experimental digest from every bounded initial slot.
    fn new(initial: &[Option<Vec<u8>>]) -> Result<Self, StateError> {
        let base = initial
            .len()
            .max(1)
            .checked_next_power_of_two()
            .ok_or(StateError::TooManySlots)?;
        let count = base.checked_mul(2).ok_or(StateError::TooManySlots)?;
        let mut tree = Self {
            slots: initial.len(),
            base,
            nodes: vec![[0; 32]; count],
        };
        for index in 0..base {
            tree.nodes[base + index] =
                Self::leaf(index, initial.get(index).and_then(Option::as_deref));
        }
        for index in (1..base).rev() {
            tree.nodes[index] = Self::branch(&tree.nodes[index * 2], &tree.nodes[index * 2 + 1]);
        }
        Ok(tree)
    }

    // memory—v1: Bind each slot position, presence and exact bytes to its leaf.
    fn leaf(index: usize, value: Option<&[u8]>) -> Digest {
        let mut hash = Sha256::new();
        hash.update(b"astrallight/memory-v1/slot-leaf/1\0");
        hash.update((index as u64).to_be_bytes());
        match value {
            None => hash.update([0]),
            Some(bytes) => {
                hash.update([1]);
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            }
        }
        hash.finalize().into()
    }

    // memory—v1: Separate internal nodes from leaves and root metadata.
    fn branch(left: &Digest, right: &Digest) -> Digest {
        let mut hash = Sha256::new();
        hash.update(b"astrallight/memory-v1/slot-node/1\0");
        hash.update(left);
        hash.update(right);
        hash.finalize().into()
    }

    // memory—v1: Bind the logical slot count to the experimental tree root.
    fn digest(&self) -> Digest {
        let mut hash = Sha256::new();
        hash.update(b"astrallight/memory-v1/slot-root/1\0");
        hash.update((self.slots as u64).to_be_bytes());
        hash.update(self.nodes[1]);
        hash.finalize().into()
    }

    // memory—v1: Update affected paths in a private prepared tree.
    fn update(&mut self, changes: &[MemoryRootChange]) {
        for change in changes {
            let mut index = self.base + change.slot;
            self.nodes[index] = Self::leaf(change.slot, change.value.as_deref());
            while index > 1 {
                index /= 2;
                self.nodes[index] =
                    Self::branch(&self.nodes[index * 2], &self.nodes[index * 2 + 1]);
            }
        }
    }
}

impl MemoryRootOwner {
    /// memory—v1: Create an isolated owner after checking kernel bounds.
    ///
    /// Construction does not prove that input is complete or trusted. Callers
    /// must independently bound input allocation and retained captures.
    pub fn new(initial: Vec<Option<Vec<u8>>>, limits: Limits) -> Result<Self, StateError> {
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
        let hashes = HashTree::new(&initial)?;
        let state = AtomicStateOwner::new(initial, hashes.digest(), limits)?;
        Ok(Self {
            state,
            hashes,
            limits,
        })
    }

    /// memory—v1: Obtain another read-only handle to this same owner.
    pub fn handle(&self) -> MemoryRootHandle {
        MemoryRootHandle {
            state: self.state.handle(),
        }
    }

    /// memory—v1: Atomically replace a bounded group of slots and metadata.
    ///
    /// This API performs no authorization, relationship or schema validation.
    /// A future authorized writer must validate its request and affected facts;
    /// this operation must not be exposed as a production mutation capability.
    pub fn apply(&mut self, changes: Vec<MemoryRootChange>) -> Result<Metadata, StateError> {
        if changes.is_empty() {
            return Err(StateError::EmptyChange);
        }
        if changes.len() > self.limits.max_change_slots {
            return Err(StateError::TooManyChangeSlots);
        }
        let mut indices: Vec<_> = changes.iter().map(|change| change.slot).collect();
        indices.sort_unstable();
        if indices.iter().any(|&index| index >= self.hashes.slots) {
            return Err(StateError::InvalidSlot);
        }
        if indices.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StateError::DuplicateSlot);
        }
        if changes.iter().any(|change| {
            change
                .value
                .as_ref()
                .is_some_and(|value| value.len() > self.limits.max_value_bytes)
        }) {
            return Err(StateError::ValueTooLarge);
        }
        // The hash tree contains hashes only, not another root or fact snapshot.
        // Preparing it outside the state lock keeps readers off the hashing path.
        let mut prepared = HashTree {
            slots: self.hashes.slots,
            base: self.hashes.base,
            nodes: self.hashes.nodes.clone(),
        };
        prepared.update(&changes);
        let digest = prepared.digest();
        let slots = changes
            .into_iter()
            .map(|change| SlotChange {
                slot: change.slot,
                value: change.value,
            })
            .collect();
        let metadata = self
            .state
            .transact::<std::convert::Infallible>(&[], |_| Ok(Change { slots, digest }))
            .map_err(|error| match error {
                TransactionError::State(error) => error,
                TransactionError::Prepare(never) => match never {},
            })?;
        self.hashes = prepared;
        Ok(metadata)
    }
}

impl MemoryRootHandle {
    /// memory—v1: Capture selected slots with a single consistent metadata value.
    pub fn capture(&self, slots: &[usize]) -> Result<MemoryRootCapture, StateError> {
        Ok(MemoryRootCapture {
            capture: self.state.capture(slots)?,
        })
    }

    /// memory—v1: Check owner identity, version and stored digest at one instant.
    ///
    /// This does not validate trusted time, completeness or an authorization
    /// decision; a successful observation is not a business commit fence.
    pub fn is_current(&self, capture: &MemoryRootCapture) -> Result<bool, StateError> {
        let current = self.state.capture(&[])?;
        Ok(current.metadata() == capture.capture.metadata()
            && self.state.is_current(&capture.capture)?)
    }
}

impl MemoryRootCapture {
    /// memory—v1: Return the metadata captured alongside these bytes.
    pub fn metadata(&self) -> Metadata {
        self.capture.metadata()
    }

    /// memory—v1: Iterate over requested slot indices and their captured bytes.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (usize, Option<&[u8]>)> {
        self.capture.entries()
    }
}

#[cfg(test)]
#[path = "memory_v1_kernel/tests.rs"]
mod tests;
