//! memory—v1: test-support-only lock-timing probes for the LOCAL ABC benchmark.
//!
//! Compiled only under the crate feature `test-support` (the `mod
//! abc_lock_timing` declaration in `memory_v1_root.rs` is cfg-gated); ordinary
//! builds without `test-support` emit no code from this file at all. The
//! probes are purely observational: they record `(wait_ns, held_ns)` pairs
//! into per-thread storage and grant no authority and no ability to mutate
//! the root. There is no shared statistics mutex; each thread records only
//! its own last sample.
//!
//! Instrumented endpoints (exact; no other lock acquisition is probed):
//! 1. `astral-authorization-root/src/memory_v1_root.rs`
//!    `RequestRootReader::try_with_rechecked_dependencies_and_target` — the
//!    ordinary C final dependency path — native acquisition
//!    `runtime.mutation_lock.try_read()`; the guard is wrapped on success
//!    only, so a failed `try_read` (normal run contention) records no sample.
//! 2. `astral-authorization-root/src/memory_v1_root.rs`
//!    `RootOwner::execute_on` — the isolated single mutation — native
//!    acquisition `runtime.mutation_lock.write()` taken after the
//!    serving-writer reservation; the `ContextLoad` branch returns before
//!    this lock and records nothing, as do rejections before the lock or a
//!    poisoned lock.
//!
//! Public entry point, re-exported for the benchmark caller:
//! `astral_authorization_root::memory_v1_root::measure_abc_lock_for_test`.

use std::cell::Cell;
use std::time::Instant;

thread_local! {
    // memory—v1: armed only while `measure_abc_lock_for_test` runs on this
    // thread. Checked before any `Instant::now` is taken at the probe sites,
    // so an unarmed thread never measures time.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    // memory—v1: latest completed `(wait_ns, held_ns)` sample on this thread.
    static LAST: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

/// memory—v1: Capture the native wait start only when this thread is armed.
///
/// The probe call sites in `memory_v1_root.rs` invoke this immediately before
/// the native `try_read`/`write` acquisition. Returns `None` when the thread
/// is not armed; no `Instant::now` is taken in that case.
pub(super) fn wait_probe_start() -> Option<Instant> {
    ARMED.with(Cell::get).then(Instant::now)
}

// memory—v1: saturating nanosecond conversion; monotonic instants only.
fn nanos_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// memory—v1: measurement pending for one wrapped guard, recorded at drop.
struct PendingSample {
    wait_ns: u64,
    acquired: Instant,
}

/// memory—v1: RAII timed wrapper around an original native guard.
///
/// `wait_ns` is computed once at wrap time (the native acquisition has already
/// completed by then). `held_ns` is computed in the drop hook, which runs at
/// the wrapped guard's actual drop point — explicit early `drop(guard)`, early
/// `return` scope exit, and normal scope exit are all covered without
/// refactoring any surrounding logic. The wrapped native guard drops from this
/// struct exactly as the original binding would.
pub(super) struct TimedGuard<G> {
    _inner: G,
    pending: Option<PendingSample>,
}

impl<G> TimedGuard<G> {
    /// memory—v1: wrap the original guard; `started` is `None` when unarmed.
    pub(super) fn wrap(inner: G, started: Option<Instant>) -> Self {
        let pending = started.map(|wait_started| PendingSample {
            wait_ns: nanos_since(wait_started),
            acquired: Instant::now(),
        });
        TimedGuard {
            _inner: inner,
            pending,
        }
    }
}

impl<G> Drop for TimedGuard<G> {
    fn drop(&mut self) {
        // memory—v1: record only while this thread is still armed; guards that
        // escape the closure drop after disarm and are not recorded. The
        // elapsed read happens first, then the wrapped native guard drops
        // with this struct, so `held_ns` may undercount the true hold by the
        // nanoseconds spent inside this hook itself.
        if ARMED.with(Cell::get) {
            if let Some(sample) = self.pending.as_ref() {
                LAST.with(|last| last.set(Some((sample.wait_ns, nanos_since(sample.acquired)))));
            }
        }
    }
}

/// memory—v1: restores the previous per-thread arming state on scope exit,
/// including during unwind, so a panicking closure cannot leave the thread
/// armed and cannot corrupt an outer arming frame.
struct ArmingRestore {
    previous_armed: bool,
    previous_last: Option<(u64, u64)>,
}

impl Drop for ArmingRestore {
    fn drop(&mut self) {
        ARMED.with(|armed| armed.set(self.previous_armed));
        LAST.with(|last| last.set(self.previous_last.take()));
    }
}

/// memory—v1: Measure native lock timing of the LOCAL ABC final-check paths.
///
/// Runs `f` once with per-thread probe instrumentation armed and returns
/// `(T, Option<(wait_ns, held_ns)>)` for the LAST acquisition completed by
/// the instrumented paths on the calling thread while the closure ran.
///
/// - `wait_ns`: elapsed monotonic time from immediately before the native
///   acquisition call until the guard was acquired. On the mutation path
///   (`RootOwner::execute_on`, `runtime.mutation_lock.write()`) this is the
///   true blocking wait for the write guard. On the read path
///   (`RequestRootReader::try_with_rechecked_dependencies_and_target`,
///   `runtime.mutation_lock.try_read()`) this is only the duration of the
///   non-blocking attempt, i.e. effectively an immediate acquire; a failed
///   attempt records no sample.
/// - `held_ns`: elapsed monotonic time from acquisition until the actual
///   guard drop, measured by the probe's RAII drop hook. Early returns and
///   the explicit early `drop(guard)` on the exhausted-snapshot branch are
///   covered automatically.
///
/// Semantics and limits:
/// - Per-thread: only acquisitions on the calling thread are recorded.
///   Multi-thread benchmarks must call this on each thread; there is no
///   shared statistics mutex.
/// - `None` is returned when no instrumented acquisition completed while
///   armed — a normal run where the root `try_read` fails, or a mutation
///   that rejects before reaching the native write lock.
/// - The sample is recorded when a guard drop completes, so the returned
///   sample is the most recent hold that finished during the closure. Guards
///   that escape the closure (returned or stashed) are dropped after the
///   probes disarm and are not recorded.
/// - Not reentrant: nesting calls on the same thread keeps arming state
///   consistent (save/restore) but makes the "last acquisition" mapping
///   ambiguous; do not nest.
/// - A panicking closure restores the previous arming state during unwind;
///   any partially recorded sample is discarded.
///
/// Overhead (opt-in at both compile time and run time):
/// - Feature `test-support` off: this file is not compiled and the probe call
///   sites in `memory_v1_root.rs` compile to exactly the original code.
/// - Feature on, thread never armed: each instrumented acquisition performs
///   two thread-local `bool` reads (one before acquisition, one at guard
///   drop) and takes no `Instant::now`.
/// - Feature on and armed: adds one `Instant::now` before the native
///   acquisition, one at acquisition, and one inside the drop hook — roughly
///   tens of nanoseconds each with `std::time::Instant` — plus one
///   thread-local write per completed hold.
pub fn measure_abc_lock_for_test<T>(f: impl FnOnce() -> T) -> (T, Option<(u64, u64)>) {
    let _restore = ArmingRestore {
        previous_armed: ARMED.with(|armed| armed.replace(true)),
        previous_last: LAST.with(Cell::take),
    };
    let out = f();
    let sample = LAST.with(Cell::take);
    (out, sample)
    // `_restore` drops here (and during unwind): re-arms the previous state
    // and restores the previous thread-local sample.
}
