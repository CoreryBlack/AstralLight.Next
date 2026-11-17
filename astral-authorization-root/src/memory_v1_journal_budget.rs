#![forbid(unsafe_code)]

//! B-memory-budget: a bounded, process-local ownership reservation primitive.
//!
//! This module is intentionally independent and is not wired into the crate
//! root yet. A future caller can use it to account for memory owned by pending
//! journal frames or encoded copies while those owners are alive. The pool
//! limits are accounting limits, not an allocator or operating-system claim:
//!
//! * `total_bytes` counts only the byte extent explicitly declared for a
//!   caller-owned allocation and represented by a live [`Reservation`]. It
//!   excludes allocator metadata, alignment slack, the caller's borrowed/raw
//!   input, HAMT nodes, thread stacks, and all other process memory.
//! * `total_slots` counts live reservation handles. An explicit
//!   [`Reservation::try_clone`] consumes another slot, while all handles for
//!   one allocation keep that allocation's byte charge until the last handle
//!   is dropped.
//! * [`ReservationPool::try_reserve`] and
//!   [`ReservationPool::try_reserve_encoded`] do not allocate the caller's
//!   bytes and do not retain raw input. They only issue a bounded token after
//!   the declared charge fits. The caller must own the allocation separately
//!   and keep the token beside it.
//! * A reservation is not queue length, persistence, an authorization proof,
//!   an RSS measurement, or evidence that an allocation was actually made.
//!
//! Capacity failure is immediate. The pool uses an internal private `Arc` and
//! a mutex whose `try_lock` path is used by reservation and clone operations;
//! contention is reported as [`ReservationError::PoolBusy`] instead of making
//! those operations wait. RAII release uses the same private state and never
//! decrements below zero. No public arbitrary-release operation or `Clone` impl
//! exists for [`Reservation`].
//!
//! Aggregation is deliberately a fixed-size structural grouping operation. A
//! [`ReservationGroup`] accepts only reservations from one pool whose charge
//! owners are unique, sums their distinct charges with checked arithmetic, and
//! preserves the existing byte and slot charges. Splitting the group returns
//! the same handles. It never compresses several slots into one or deduplicates
//! a shared clone, so it cannot silently change ownership accounting.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

/// Fixed limits owned by one reservation pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolLimits {
    /// Maximum total declared allocated bytes held by live reservations.
    pub total_bytes: usize,
    /// Maximum number of live reservation handles.
    pub total_slots: usize,
}

/// A rejected pool configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolConfigError {
    /// The pool cannot issue a positive allocation charge.
    ZeroTotalBytes,
    /// The pool cannot issue even one reservation handle.
    ZeroTotalSlots,
}

impl fmt::Display for PoolConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTotalBytes => formatter.write_str("total byte capacity must be nonzero"),
            Self::ZeroTotalSlots => formatter.write_str("total slot capacity must be nonzero"),
        }
    }
}

impl std::error::Error for PoolConfigError {}

/// A snapshot of the pool's live accounting counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolUsage {
    /// Bytes currently charged by distinct live allocation owners.
    pub used_bytes: usize,
    /// Live reservation handles currently occupying slots.
    pub used_slots: usize,
}

/// Failure while reading the pool's counters without waiting for its lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolAccessError {
    /// Another operation currently owns the accounting lock.
    Busy,
    /// A panic poisoned the accounting lock; the pool is not trusted for a
    /// positive capacity decision.
    Poisoned,
}

impl fmt::Display for PoolAccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("reservation pool accounting is busy"),
            Self::Poisoned => formatter.write_str("reservation pool accounting is poisoned"),
        }
    }
}

impl std::error::Error for PoolAccessError {}

/// Failure to issue or explicitly clone a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationError {
    /// A reservation must account for a positive owned allocation extent.
    ZeroAllocatedBytes,
    /// Adding the requested bytes would overflow `usize`.
    ByteCountOverflow,
    /// Adding one live handle would overflow `usize`.
    SlotCountOverflow,
    /// The byte limit would be exceeded.
    BytesExhausted {
        /// The requested owned allocation extent.
        requested: usize,
        /// Bytes still available at the time of the check.
        remaining: usize,
    },
    /// The slot limit would be exceeded.
    SlotsExhausted {
        /// The configured slot limit.
        limit: usize,
    },
    /// The accounting lock was contended; no capacity decision was made.
    PoolBusy,
    /// The accounting lock was poisoned; no capacity decision was made.
    PoolPoisoned,
}

impl fmt::Display for ReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroAllocatedBytes => formatter.write_str("allocated byte extent must be nonzero"),
            Self::ByteCountOverflow => formatter.write_str("allocated byte counter overflow"),
            Self::SlotCountOverflow => formatter.write_str("reservation slot counter overflow"),
            Self::BytesExhausted {
                requested,
                remaining,
            } => write!(
                formatter,
                "allocated byte capacity exhausted: requested {requested}, remaining {remaining}"
            ),
            Self::SlotsExhausted { limit } => {
                write!(formatter, "reservation slot capacity exhausted at {limit}")
            }
            Self::PoolBusy => formatter.write_str("reservation pool accounting is busy"),
            Self::PoolPoisoned => formatter.write_str("reservation pool accounting is poisoned"),
        }
    }
}

impl std::error::Error for ReservationError {}

/// Failure to form a bounded aggregate of reservation owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateError {
    /// An aggregate must contain at least two reservations.
    TooFewReservations,
    /// Every reservation must belong to the exact same pool instance.
    PoolMismatch,
    /// A charge has another live owner, so summing it would double-count or
    /// make the aggregate's ownership ambiguous.
    SharedCharge,
    /// The aggregate byte sum is not representable by `usize`.
    ByteCountOverflow,
}

impl fmt::Display for AggregateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewReservations => {
                formatter.write_str("an aggregate needs at least two reservations")
            }
            Self::PoolMismatch => formatter.write_str("reservations belong to different pools"),
            Self::SharedCharge => {
                formatter.write_str("an aggregate input has a shared or duplicate charge")
            }
            Self::ByteCountOverflow => formatter.write_str("aggregate byte sum overflow"),
        }
    }
}

impl std::error::Error for AggregateError {}

/// One private pool state shared by the pool and every token it issues.
struct PoolState {
    limits: PoolLimits,
    usage: Mutex<Usage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Usage {
    bytes: usize,
    slots: usize,
}

/// A process-local bounded reservation pool.
///
/// The `Arc<PoolState>` is private. Cloning this pool handle is intentionally
/// not exposed; callers that need to move access across threads can put the
/// pool handle in their own explicitly bounded `Arc`. Reservation handles
/// themselves carry the pool state so RAII release remains tied to the exact
/// pool that issued the charge.
pub struct ReservationPool {
    state: Arc<PoolState>,
}

impl ReservationPool {
    /// Construct a pool with positive byte and slot limits.
    ///
    /// Construction creates only the small accounting state. It does not
    /// reserve `total_bytes` from the allocator and does not preallocate a
    /// queue or frame store.
    pub fn new(total_bytes: usize, total_slots: usize) -> Result<Self, PoolConfigError> {
        if total_bytes == 0 {
            return Err(PoolConfigError::ZeroTotalBytes);
        }
        if total_slots == 0 {
            return Err(PoolConfigError::ZeroTotalSlots);
        }
        Ok(Self {
            state: Arc::new(PoolState {
                limits: PoolLimits {
                    total_bytes,
                    total_slots,
                },
                usage: Mutex::new(Usage { bytes: 0, slots: 0 }),
            }),
        })
    }

    /// Return this pool's immutable configured limits.
    pub fn limits(&self) -> PoolLimits {
        self.state.limits
    }

    /// Read usage without waiting for the accounting lock.
    pub fn try_usage(&self) -> Result<PoolUsage, PoolAccessError> {
        match self.state.usage.try_lock() {
            Ok(usage) => Ok(PoolUsage {
                used_bytes: usage.bytes,
                used_slots: usage.slots,
            }),
            Err(TryLockError::WouldBlock) => Err(PoolAccessError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(PoolAccessError::Poisoned),
        }
    }

    /// Issue one reservation for a caller-owned allocation extent.
    ///
    /// `allocated_bytes` is the exact byte extent selected by the caller for
    /// the owned allocation. This method does not allocate or retain those
    /// bytes. It uses a nonblocking accounting lock: capacity failure and lock
    /// contention return immediately.
    pub fn try_reserve(&self, allocated_bytes: usize) -> Result<Reservation, ReservationError> {
        if allocated_bytes == 0 {
            return Err(ReservationError::ZeroAllocatedBytes);
        }

        let mut usage = self.try_lock_usage()?;
        let next_bytes = usage
            .bytes
            .checked_add(allocated_bytes)
            .ok_or(ReservationError::ByteCountOverflow)?;
        let next_slots = usage
            .slots
            .checked_add(1)
            .ok_or(ReservationError::SlotCountOverflow)?;
        if next_bytes > self.state.limits.total_bytes {
            return Err(ReservationError::BytesExhausted {
                requested: allocated_bytes,
                remaining: self
                    .state
                    .limits
                    .total_bytes
                    .saturating_sub(usage.bytes),
            });
        }
        if next_slots > self.state.limits.total_slots {
            return Err(ReservationError::SlotsExhausted {
                limit: self.state.limits.total_slots,
            });
        }

        usage.bytes = next_bytes;
        usage.slots = next_slots;
        Ok(Reservation {
            charge: Arc::new(Charge {
                pool: Arc::clone(&self.state),
                bytes: allocated_bytes,
            }),
        })
    }

    /// Issue a reservation while making the raw encoded input boundary
    /// explicit.
    ///
    /// `raw_encoded_input` is borrowed caller input. Its length is deliberately
    /// ignored and it is not retained or charged. Only `allocated_bytes`
    /// contributes to the returned token. A caller that creates an owned
    /// encoded copy must pass that copy's selected owned allocation extent as
    /// `allocated_bytes` and hold the returned token with the copy.
    pub fn try_reserve_encoded(
        &self,
        raw_encoded_input: &[u8],
        allocated_bytes: usize,
    ) -> Result<Reservation, ReservationError> {
        let _raw_input_length = raw_encoded_input.len();
        self.try_reserve(allocated_bytes)
    }

    fn try_clone_slot(&self) -> Result<(), ReservationError> {
        let mut usage = self.try_lock_usage()?;
        let next_slots = usage
            .slots
            .checked_add(1)
            .ok_or(ReservationError::SlotCountOverflow)?;
        if next_slots > self.state.limits.total_slots {
            return Err(ReservationError::SlotsExhausted {
                limit: self.state.limits.total_slots,
            });
        }
        usage.slots = next_slots;
        Ok(())
    }

    fn try_lock_usage(&self) -> Result<MutexGuard<'_, Usage>, ReservationError> {
        match self.state.usage.try_lock() {
            Ok(usage) => Ok(usage),
            Err(TryLockError::WouldBlock) => Err(ReservationError::PoolBusy),
            Err(TryLockError::Poisoned(_)) => Err(ReservationError::PoolPoisoned),
        }
    }

    fn release_slot(&self) {
        let Ok(mut usage) = self.state.usage.lock() else {
            return;
        };
        if let Some(next_slots) = usage.slots.checked_sub(1) {
            usage.slots = next_slots;
        }
    }

    fn release_bytes(&self, bytes: usize) {
        let Ok(mut usage) = self.state.usage.lock() else {
            return;
        };
        if let Some(next_bytes) = usage.bytes.checked_sub(bytes) {
            usage.bytes = next_bytes;
        }
    }
}

/// One live ownership token issued by a [`ReservationPool`].
///
/// This type intentionally has no `Clone` implementation and no public
/// release method. [`Self::try_clone`] is explicit and consumes another bounded
/// slot. Every clone shares the same private byte charge, which is released
/// only when its last owner is dropped.
pub struct Reservation {
    charge: Arc<Charge>,
}

impl Reservation {
    /// Return the caller-declared owned allocation extent held by this token.
    ///
    /// This value excludes allocator metadata and all memory outside the
    /// caller's declared allocation extent.
    pub fn allocated_bytes(&self) -> usize {
        self.charge.bytes
    }

    /// Explicitly create one more owner of this reservation.
    ///
    /// The new owner consumes one slot immediately. The shared byte charge is
    /// retained until the final owner drops, so cloning cannot make the byte
    /// counter fall early. The operation is bounded by the pool's slot limit
    /// and never waits for capacity or the accounting lock.
    pub fn try_clone(&self) -> Result<Self, ReservationError> {
        self.charge.pool.try_clone_slot()?;
        Ok(Self {
            charge: Arc::clone(&self.charge),
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.charge.pool.release_slot();
    }
}

/// The private byte charge shared by explicit reservation owners.
struct Charge {
    pool: Arc<PoolState>,
    bytes: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        // `Charge` is held by an Arc, so this runs exactly once for the last
        // owner. The subtraction is checked in `release_bytes`.
        let pool = ReservationPool {
            state: Arc::clone(&self.pool),
        };
        pool.release_bytes(self.bytes);
    }
}

/// A fixed-size aggregate of distinct reservations from one pool.
///
/// The const-generic array keeps aggregation bounded without introducing an
/// unbounded collection or another queue. The aggregate is a structural owner
/// of the original handles: it retains the same byte and slot charges, and its
/// `split` operation returns them unchanged.
pub struct ReservationGroup<const COUNT: usize> {
    reservations: [Reservation; COUNT],
    pool: Arc<PoolState>,
    bytes: usize,
}

/// The common two-reservation aggregate shape.
pub type ReservationPair = ReservationGroup<2>;

impl<const COUNT: usize> ReservationGroup<COUNT> {
    /// Aggregate distinct, uniquely owned reservations from one exact pool.
    ///
    /// The input array is consumed. If validation fails, its reservations are
    /// dropped by normal RAII cleanup, which returns their charges; no partial
    /// aggregate is produced. A shared charge is rejected because counting it
    /// twice would misstate owned bytes.
    pub fn try_aggregate(
        reservations: [Reservation; COUNT],
    ) -> Result<Self, AggregateError> {
        if COUNT < 2 {
            return Err(AggregateError::TooFewReservations);
        }
        let Some(first) = reservations.first() else {
            return Err(AggregateError::TooFewReservations);
        };

        let pool = Arc::clone(&first.charge.pool);
        let mut bytes = 0usize;
        for (index, reservation) in reservations.iter().enumerate() {
            if !Arc::ptr_eq(&pool, &reservation.charge.pool) {
                return Err(AggregateError::PoolMismatch);
            }
            if Arc::strong_count(&reservation.charge) != 1
                || reservations[..index]
                    .iter()
                    .any(|previous| Arc::ptr_eq(&previous.charge, &reservation.charge))
            {
                return Err(AggregateError::SharedCharge);
            }
            bytes = bytes
                .checked_add(reservation.charge.bytes)
                .ok_or(AggregateError::ByteCountOverflow)?;
        }

        Ok(Self {
            reservations,
            pool,
            bytes,
        })
    }

    /// Return the sum of the distinct owned allocation extents in the group.
    pub fn allocated_bytes(&self) -> usize {
        self.bytes
    }

    /// Return the fixed number of reservation handles in this group.
    pub const fn len(&self) -> usize {
        COUNT
    }

    /// Return whether this group has no handles.
    pub const fn is_empty(&self) -> bool {
        COUNT == 0
    }

    /// Return the original reservation handles without changing accounting.
    pub fn split(self) -> [Reservation; COUNT] {
        let Self {
            reservations,
            pool: _pool,
            bytes: _bytes,
        } = self;
        reservations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn usage(pool: &ReservationPool) -> PoolUsage {
        pool.try_usage().expect("test pool must be readable")
    }

    #[test]
    fn rejects_zero_limits_and_zero_allocations() {
        assert_eq!(
            ReservationPool::new(0, 1),
            Err(PoolConfigError::ZeroTotalBytes)
        );
        assert_eq!(
            ReservationPool::new(1, 0),
            Err(PoolConfigError::ZeroTotalSlots)
        );

        let pool = ReservationPool::new(4, 1).unwrap();
        assert_eq!(
            pool.try_reserve(0),
            Err(ReservationError::ZeroAllocatedBytes)
        );
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn raw_input_is_borrowed_and_only_allocated_bytes_are_charged() {
        let pool = ReservationPool::new(8, 2).unwrap();
        let raw_encoded_input = [0xabu8; 1024];
        let reservation = pool
            .try_reserve_encoded(&raw_encoded_input, 3)
            .unwrap();

        assert_eq!(reservation.allocated_bytes(), 3);
        assert_eq!(
            usage(&pool),
            PoolUsage {
                used_bytes: 3,
                used_slots: 1
            }
        );
        drop(reservation);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn capacity_failure_is_immediate_and_does_not_partially_charge() {
        let byte_limited = ReservationPool::new(8, 2).unwrap();
        let held = byte_limited.try_reserve(8).unwrap();
        assert_eq!(
            byte_limited.try_reserve(1),
            Err(ReservationError::BytesExhausted {
                requested: 1,
                remaining: 0
            })
        );
        assert_eq!(usage(&byte_limited).used_bytes, 8);
        drop(held);
        assert_eq!(usage(&byte_limited), PoolUsage { used_bytes: 0, used_slots: 0 });

        let slot_limited = ReservationPool::new(16, 1).unwrap();
        let held = slot_limited.try_reserve(1).unwrap();
        assert_eq!(
            slot_limited.try_reserve(1),
            Err(ReservationError::SlotsExhausted { limit: 1 })
        );
        assert_eq!(usage(&slot_limited).used_slots, 1);
        drop(held);
    }

    #[test]
    fn clone_is_explicit_slot_bounded_and_keeps_bytes_until_last_drop() {
        let pool = ReservationPool::new(16, 2).unwrap();
        let original = pool.try_reserve(7).unwrap();
        let clone = original.try_clone().unwrap();
        assert_eq!(
            usage(&pool),
            PoolUsage {
                used_bytes: 7,
                used_slots: 2
            }
        );
        assert_eq!(
            original.try_clone(),
            Err(ReservationError::SlotsExhausted { limit: 2 })
        );

        drop(clone);
        assert_eq!(
            usage(&pool),
            PoolUsage {
                used_bytes: 7,
                used_slots: 1
            }
        );
        drop(original);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn cross_thread_clone_and_drop_preserve_the_charge() {
        let pool = Arc::new(ReservationPool::new(32, 2).unwrap());
        let original = pool.try_reserve(11).unwrap();
        let clone = original.try_clone().unwrap();
        let worker = thread::spawn(move || {
            assert_eq!(clone.allocated_bytes(), 11);
            drop(clone);
        });
        worker.join().unwrap();

        assert_eq!(
            usage(&pool),
            PoolUsage {
                used_bytes: 11,
                used_slots: 1
            }
        );
        drop(original);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn aggregate_requires_distinct_unique_same_pool_charges_and_splits_safely() {
        let pool = ReservationPool::new(32, 4).unwrap();
        let first = pool.try_reserve(3).unwrap();
        let second = pool.try_reserve(5).unwrap();
        let group = ReservationPair::try_aggregate([first, second]).unwrap();
        assert_eq!(group.len(), 2);
        assert!(!group.is_empty());
        assert_eq!(group.allocated_bytes(), 8);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 8, used_slots: 2 });

        let [first, second] = group.split();
        drop(first);
        drop(second);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn aggregate_rejects_shared_and_foreign_charges() {
        let pool = ReservationPool::new(32, 4).unwrap();
        let first = pool.try_reserve(4).unwrap();
        let clone = first.try_clone().unwrap();
        assert_eq!(
            ReservationPair::try_aggregate([first, clone]),
            Err(AggregateError::SharedCharge)
        );
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });

        let left_pool = ReservationPool::new(8, 1).unwrap();
        let right_pool = ReservationPool::new(8, 1).unwrap();
        let left = left_pool.try_reserve(2).unwrap();
        let right = right_pool.try_reserve(2).unwrap();
        assert_eq!(
            ReservationPair::try_aggregate([left, right]),
            Err(AggregateError::PoolMismatch)
        );
        assert_eq!(usage(&left_pool), PoolUsage { used_bytes: 0, used_slots: 0 });
        assert_eq!(usage(&right_pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn full_capacity_recovers_after_raii_release() {
        let pool = ReservationPool::new(12, 2).unwrap();
        let first = pool.try_reserve(6).unwrap();
        let second = pool.try_reserve(6).unwrap();
        assert_eq!(
            pool.try_reserve(1),
            Err(ReservationError::BytesExhausted {
                requested: 1,
                remaining: 0
            })
        );
        drop(first);
        let replacement = pool.try_reserve(6).unwrap();
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 12, used_slots: 2 });
        drop(second);
        drop(replacement);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn counter_overflow_is_rejected_without_wrapping() {
        let pool = ReservationPool::new(usize::MAX, 2).unwrap();
        let held = pool.try_reserve(usize::MAX).unwrap();
        assert_eq!(
            pool.try_reserve(1),
            Err(ReservationError::ByteCountOverflow)
        );
        assert_eq!(usage(&pool).used_bytes, usize::MAX);
        drop(held);

        let state = Arc::new(PoolState {
            limits: PoolLimits {
                total_bytes: usize::MAX,
                total_slots: usize::MAX,
            },
            usage: Mutex::new(Usage {
                bytes: 0,
                slots: usize::MAX,
            }),
        });
        let slot_overflow_pool = ReservationPool { state };
        assert_eq!(
            slot_overflow_pool.try_reserve(1),
            Err(ReservationError::SlotCountOverflow)
        );
    }

    #[test]
    fn pools_are_isolated() {
        let first_pool = ReservationPool::new(4, 1).unwrap();
        let second_pool = ReservationPool::new(4, 1).unwrap();
        let first = first_pool.try_reserve(4).unwrap();
        assert_eq!(
            first_pool.try_reserve(1),
            Err(ReservationError::BytesExhausted {
                requested: 1,
                remaining: 0
            })
        );
        let second = second_pool.try_reserve(4).unwrap();
        assert_eq!(usage(&first_pool).used_bytes, 4);
        assert_eq!(usage(&second_pool).used_bytes, 4);
        drop(first);
        drop(second);
        assert_eq!(usage(&first_pool), PoolUsage { used_bytes: 0, used_slots: 0 });
        assert_eq!(usage(&second_pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }

    #[test]
    fn concurrent_competition_never_exceeds_fixed_capacity() {
        const THREADS: usize = 16;
        const SLOT_LIMIT: usize = 3;
        const CHARGE: usize = 4;
        const ATTEMPTS: usize = 100_000;

        let pool = Arc::new(ReservationPool::new(CHARGE * SLOT_LIMIT, SLOT_LIMIT).unwrap());
        let start = Arc::new(Barrier::new(THREADS));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum_active = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(THREADS);

        for _ in 0..THREADS {
            let pool = Arc::clone(&pool);
            let start = Arc::clone(&start);
            let active = Arc::clone(&active);
            let maximum_active = Arc::clone(&maximum_active);
            workers.push(thread::spawn(move || {
                start.wait();
                for _ in 0..ATTEMPTS {
                    match pool.try_reserve(CHARGE) {
                        Ok(reservation) => {
                            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                            maximum_active.fetch_max(current, Ordering::SeqCst);
                            assert!(current <= SLOT_LIMIT);
                            if let Ok(observed) = pool.try_usage() {
                                assert!(observed.used_bytes <= CHARGE * SLOT_LIMIT);
                                assert!(observed.used_slots <= SLOT_LIMIT);
                            }
                            thread::yield_now();
                            active.fetch_sub(1, Ordering::SeqCst);
                            drop(reservation);
                            return;
                        }
                        Err(
                            ReservationError::PoolBusy
                            | ReservationError::BytesExhausted { .. }
                            | ReservationError::SlotsExhausted { .. },
                        ) => thread::yield_now(),
                        Err(error) => panic!("unexpected reservation failure: {error:?}"),
                    }
                }
                panic!("bounded contention test exhausted its fixed retry budget");
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(maximum_active.load(Ordering::SeqCst) <= SLOT_LIMIT);
        assert_eq!(usage(&pool), PoolUsage { used_bytes: 0, used_slots: 0 });
    }
}
