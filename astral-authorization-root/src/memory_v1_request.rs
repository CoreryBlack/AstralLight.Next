//! memory—v1: Request-local injection for the non-authorizing root candidate.
//!
//! A trusted in-process coordinator owns one [`RequestRootScope`] per request
//! and inserts its [`RequestRootExtension`] in the request's extensions. The
//! extension contains no identity and must never be built from client headers.
//! It cannot be serialized or used to authorize a request. This module does not
//! install middleware, validate identity, enforce budgets, or enable a listener.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, TryLockError, Weak,
    },
    task::{Context, Poll, Waker},
};

use thiserror::Error;
use uuid::Uuid;

use crate::memory_v1_root::{RequestRootContext, RequestRootReader, RootError, RootHandle};

/// The non-cloneable owner of a single request's lazily captured read phase.
///
/// Keep this value in the request coordinator's future through the intended
/// request lifetime; dropping that future on cancellation drops this owner.
/// Extensions do not own it. An already executing synchronous callback retains
/// its reader only until it returns; detached work must be bounded and stopped
/// by the coordinator. Streaming responses require an explicitly chosen owner
/// lifetime. Neither the scope nor the supplied correlation ID proves identity.
pub struct RequestRootScope {
    shared: Arc<RequestRootShared>,
}

pub(crate) struct RequestRootShared {
    // Scope drop revokes new calls without waiting for an initializer holding the lock.
    active: AtomicBool,
    state: Mutex<RequestRootState>,
    // Released only when the scope and every callback lease have dropped this state.
    _permit: Option<RequestRootPermit>,
}

/// Process-local admission budget for concurrently live request scopes.
///
/// Every admitted scope pins at most one immutable root phase for its request,
/// so this bounds the number of request-held phases. Admission never waits or
/// queues: an exhausted budget fails immediately and the caller must reject the
/// request as overloaded. A slot returns only after the scope and every
/// in-flight callback lease have released the request state. Clones share one
/// counter. A zero budget rejects every request.
#[derive(Clone)]
pub struct RequestRootBudget {
    state: Arc<RequestRootBudgetState>,
}

struct RequestRootBudgetState {
    active: AtomicUsize,
    max_active: usize,
}

// One admitted slot; dropping it returns the slot to the shared budget.
struct RequestRootPermit {
    state: Arc<RequestRootBudgetState>,
}

struct RequestRootState {
    context: Option<RequestRootContext>,
    callbacks: usize,
    waiter: Option<Arc<DrainWaiter>>,
}

struct DrainWaiter {
    cancelled: AtomicBool,
    waker: Waker,
}

struct CallbackLease {
    shared: Arc<RequestRootShared>,
    reader: Option<Arc<RequestRootReader>>,
}

/// An exclusive, cancellable wait for admitted synchronous callbacks to exit.
///
/// Creating this future has already closed the request scope. Dropping it, or
/// timing it out, never reopens the scope. It borrows the non-cloneable scope so
/// only the coordinator can wait and only one wait exists at a time.
/// Completion proves only that the synchronous callback leases have exited and
/// released their readers; it does not invalidate owned callback outputs, stop
/// spawned work, or authorize a phase transition.
#[must_use = "the scope is already closed; await the drain to observe completion"]
pub struct RequestRootDrain<'a> {
    scope: &'a mut RequestRootScope,
    waiter: Option<Arc<DrainWaiter>>,
}

/// Cloneable, process-local capability for an Axum request's extensions.
///
/// Clones refer to the same scope and phase; they cannot keep the scope alive.
/// Each successful call borrows the same reader. The callback is synchronous,
/// cannot return a reference to the reader, and runs without the context lock.
/// Its owned output must still be treated as request-scoped candidate data, not
/// as an authorization decision or a substitute for identity validation.
#[derive(Clone)]
pub struct RequestRootExtension {
    shared: Weak<RequestRootShared>,
}

/// Failure to access the candidate request scope or its root.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestRootAccessError {
    /// The request coordinator has closed or dropped its scope.
    #[error("memory-v1 request root scope has ended")]
    ScopeEnded,
    /// A panic interrupted initialization; the scope cannot safely continue.
    #[error("memory-v1 request root scope is poisoned")]
    Poisoned,
    /// The request state is in use; closure remains in effect but drain is unproven.
    #[error("memory-v1 request root scope is busy")]
    Busy,
    /// The request-scope budget is exhausted; the request must be rejected, not queued.
    #[error("memory-v1 request root budget is exhausted")]
    Overloaded,
    /// The candidate root could not be read.
    #[error(transparent)]
    Root(#[from] RootError),
}

impl RequestRootScope {
    /// memory—v1: Create a request owner without capturing a root snapshot.
    ///
    /// Only trusted composition code should create and inject a scope. Exactly
    /// one scope must be shared throughout each request; this API cannot enforce
    /// that separate coordinators do not create competing scopes. Request paths
    /// that admit external traffic should use [`RequestRootBudget::try_begin`].
    pub fn new(handle: RootHandle, request_id: Uuid) -> Self {
        Self::with_permit(handle, request_id, None)
    }

    // memory—v1: Build the shared request state around an optional budget slot.
    fn with_permit(
        handle: RootHandle,
        request_id: Uuid,
        permit: Option<RequestRootPermit>,
    ) -> Self {
        Self {
            shared: Arc::new(RequestRootShared {
                active: AtomicBool::new(true),
                state: Mutex::new(RequestRootState {
                    context: Some(RequestRootContext::new(handle, request_id)),
                    callbacks: 0,
                    waiter: None,
                }),
                _permit: permit,
            }),
        }
    }

    /// memory—v1: Create a weak extension for trusted in-process participants.
    pub fn extension(&self) -> RequestRootExtension {
        RequestRootExtension {
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// memory—v1: Check that an extension belongs to this exact scope owner.
    ///
    /// This is only a local capability consistency check; it is not identity or
    /// authorization evidence.
    pub fn owns_extension(&self, extension: &RequestRootExtension) -> bool {
        extension
            .shared
            .upgrade()
            .is_some_and(|shared| Arc::ptr_eq(&self.shared, &shared))
    }

    /// memory—v1: Permanently close admission and wait for admitted callbacks.
    ///
    /// Admission closes synchronously, even if the returned future is never
    /// polled. The coordinator must not block inside an admitted callback waiting
    /// for its own lease. Polling returns `Busy` if the request state is locked;
    /// this is not proof that callbacks exited. A coordinator may retry under a
    /// finite budget or fail closed. Cancellation leaves the scope closed.
    /// An unpolled, busy or cancelled drain may retain the context, and a
    /// cancelled waiter may remain until the final callback, another drain or
    /// scope destruction. A notification may race cancellation. Waker code,
    /// context destruction and callback cleanup are not time-bounded here.
    /// This does not stop detached work or invalidate owned outputs and is not
    /// sufficient to switch phases.
    pub fn close_and_drain(&mut self) -> RequestRootDrain<'_> {
        self.shared.active.store(false, Ordering::Release);
        RequestRootDrain {
            scope: self,
            waiter: None,
        }
    }
}

impl Future for RequestRootDrain<'_> {
    type Output = Result<(), RequestRootAccessError>;

    // memory—v1: Contention returns failure without claiming that readers exited.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let waiter = Arc::new(DrainWaiter {
            cancelled: AtomicBool::new(false),
            waker: cx.waker().clone(),
        });
        let (result, previous, context) = {
            let mut state = match self.scope.shared.state.try_lock() {
                Ok(state) => state,
                Err(TryLockError::WouldBlock) => {
                    return Poll::Ready(Err(RequestRootAccessError::Busy))
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Poll::Ready(Err(RequestRootAccessError::Poisoned))
                }
            };
            let context = state.context.take();
            let (result, previous) = if state.callbacks == 0 {
                (Poll::Ready(Ok(())), state.waiter.take())
            } else {
                (Poll::Pending, state.waiter.replace(Arc::clone(&waiter)))
            };
            (result, previous, context)
        };
        if let Some(old) = self.waiter.replace(waiter) {
            old.cancelled.store(true, Ordering::Release);
        }
        drop(previous);
        drop(context);
        result
    }
}

impl Drop for RequestRootDrain<'_> {
    // memory—v1: Cancellation releases the registered waker but never reopens admission.
    fn drop(&mut self) {
        if let Some(waiter) = self.waiter.take() {
            waiter.cancelled.store(true, Ordering::Release);
            let removed = match self.scope.shared.state.try_lock() {
                Ok(mut state) => {
                    if state
                        .waiter
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &waiter))
                    {
                        state.waiter.take()
                    } else {
                        None
                    }
                }
                Err(_) => None,
            };
            drop(removed);
        }
    }
}

impl Drop for CallbackLease {
    // memory—v1: Release the reader before announcing that this callback exited.
    fn drop(&mut self) {
        drop(self.reader.take());
        let waiter = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.callbacks -= 1;
            if state.callbacks == 0 {
                state.waiter.take()
            } else {
                None
            }
        };
        if let Some(waiter) = waiter {
            // Include the final waiter drop in the unwind boundary: an executor
            // supplied waker may panic while this lease is already unwinding.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                if !waiter.cancelled.load(Ordering::Acquire) {
                    waiter.waker.wake_by_ref();
                }
                drop(waiter);
            }));
        }
    }
}

impl Drop for RequestRootScope {
    // memory—v1: Revoke extensions without waiting for an initializer.
    fn drop(&mut self) {
        self.shared.active.store(false, Ordering::Release);
    }
}

impl Drop for RequestRootPermit {
    // memory—v1: Return the slot once the request state has been fully released.
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl RequestRootBudget {
    /// memory—v1: Create a budget that admits at most `max_active` live scopes.
    pub fn new(max_active: usize) -> Self {
        Self {
            state: Arc::new(RequestRootBudgetState {
                active: AtomicUsize::new(0),
                max_active,
            }),
        }
    }

    /// memory—v1: Return the configured maximum number of live request scopes.
    pub fn max_active(&self) -> usize {
        self.state.max_active
    }

    /// memory—v1: Return the number of admitted scopes whose state is still live.
    ///
    /// This is a diagnostic observation; it is not an authorization input.
    pub fn active(&self) -> usize {
        self.state.active.load(Ordering::Acquire)
    }

    /// memory—v1: Admit one request scope without capturing a root snapshot.
    ///
    /// Fails immediately with [`RequestRootAccessError::Overloaded`] when the
    /// budget is exhausted; it never blocks or queues the caller.
    pub fn try_begin(
        &self,
        handle: RootHandle,
        request_id: Uuid,
    ) -> Result<RequestRootScope, RequestRootAccessError> {
        let mut current = self.state.active.load(Ordering::Acquire);
        loop {
            if current >= self.state.max_active {
                return Err(RequestRootAccessError::Overloaded);
            }
            match self.state.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let permit = RequestRootPermit {
            state: Arc::clone(&self.state),
        };
        Ok(RequestRootScope::with_permit(
            handle,
            request_id,
            Some(permit),
        ))
    }
}

impl RequestRootExtension {
    pub(crate) fn active_shared(&self) -> Result<Arc<RequestRootShared>, RequestRootAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(RequestRootAccessError::ScopeEnded)?;
        if !shared.active.load(Ordering::Acquire) {
            return Err(RequestRootAccessError::ScopeEnded);
        }
        Ok(shared)
    }

    pub(crate) fn shares_scope_with(&self, shared: &Weak<RequestRootShared>) -> bool {
        std::ptr::eq(self.shared.as_ptr(), shared.as_ptr())
    }

    /// memory—v1: Borrow this request's one lazy reader for a synchronous action.
    ///
    /// Initialization is serialized only within this request. The lock is
    /// released before invoking `f`, so callbacks may reenter this method and no
    /// lock or reader borrow can be carried over an await. No phase is refreshed
    /// on root publication. Root access errors must fail closed at the caller.
    /// An action admitted before the scope ends may finish; calls that have not
    /// passed the active check before scope drop fail, even if another call is
    /// still initializing. The coordinator must stop or await in-flight work.
    pub fn with_reader<T>(
        &self,
        f: impl for<'a> FnOnce(&'a RequestRootReader) -> T,
    ) -> Result<T, RequestRootAccessError> {
        let shared = self
            .shared
            .upgrade()
            .ok_or(RequestRootAccessError::ScopeEnded)?;
        let lease = {
            let mut state = shared
                .state
                .lock()
                .map_err(|_| RequestRootAccessError::Poisoned)?;
            if !shared.active.load(Ordering::Acquire) {
                return Err(RequestRootAccessError::ScopeEnded);
            }
            let next = state
                .callbacks
                .checked_add(1)
                .ok_or(RequestRootAccessError::Poisoned)?;
            let reader = state
                .context
                .as_mut()
                .ok_or(RequestRootAccessError::ScopeEnded)?
                .reader_lease()?;
            state.callbacks = next;
            CallbackLease {
                shared: Arc::clone(&shared),
                reader: Some(reader),
            }
        };
        drop(shared);
        Ok(f(lease.reader.as_deref().expect("lease owns its reader")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::CandidateRows;
    use crate::memory_v1_hamt::CandidateBudget;
    use crate::memory_v1_root::{install_process_root, RootOwner};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, OnceLock,
    };
    use std::task::Wake;
    use std::thread;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(5);
    static OWNER: OnceLock<RootOwner> = OnceLock::new();

    // memory—v1: Share the one process root installed by this test binary.
    fn owner() -> &'static RootOwner {
        OWNER.get_or_init(|| {
            install_process_root(
                CandidateRows::default(),
                vec![],
                CandidateBudget {
                    max_table_rows: 1,
                    max_bindings_per_read: 1,
                },
            )
            .unwrap()
        })
    }

    // memory—v1: Share the process root while isolating each test's request scope.
    fn scope() -> RequestRootScope {
        RequestRootScope::new(owner().handle(), Uuid::new_v4())
    }

    // memory—v1: The budget bounds live scopes, never queues, and frees a slot
    // only after both the scope and every admitted callback lease are gone.
    #[test]
    fn request_budget_bounds_live_scopes_and_releases_after_leases() {
        let budget = RequestRootBudget::new(2);
        assert_eq!(budget.max_active(), 2);
        let first = budget.try_begin(owner().handle(), Uuid::new_v4()).unwrap();
        let second = budget.try_begin(owner().handle(), Uuid::new_v4()).unwrap();
        assert_eq!(budget.active(), 2);
        assert!(matches!(
            budget.try_begin(owner().handle(), Uuid::new_v4()),
            Err(RequestRootAccessError::Overloaded)
        ));

        // A callback admitted before the scope ends keeps its slot until it exits.
        let extension = first.extension();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let worker = thread::spawn(move || {
            extension
                .with_reader(|reader| {
                    entered_tx.send(reader.request_id()).unwrap();
                    release_rx.recv_timeout(WAIT).unwrap();
                })
                .unwrap();
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        drop(first);
        assert_eq!(budget.active(), 2, "an in-flight lease still pins the slot");
        assert!(matches!(
            budget.try_begin(owner().handle(), Uuid::new_v4()),
            Err(RequestRootAccessError::Overloaded)
        ));
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(budget.active(), 1);

        let third = budget.try_begin(owner().handle(), Uuid::new_v4()).unwrap();
        assert_eq!(budget.active(), 2);
        drop(second);
        drop(third);
        assert_eq!(budget.active(), 0);

        // Clones share one counter; a zero budget rejects every request.
        let clone = budget.clone();
        let held = clone.try_begin(owner().handle(), Uuid::new_v4()).unwrap();
        assert_eq!(budget.active(), 1);
        drop(held);
        assert_eq!(budget.active(), 0);
        let closed = RequestRootBudget::new(0);
        assert!(matches!(
            closed.try_begin(owner().handle(), Uuid::new_v4()),
            Err(RequestRootAccessError::Overloaded)
        ));
        assert_eq!(closed.active(), 0);
    }

    #[derive(Default)]
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        // memory—v1: Count notifications from the last callback's lease.
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // memory—v1: Poll a drain without introducing an async runtime dependency.
    fn poll_drain(
        drain: &mut RequestRootDrain<'_>,
        waker: &Waker,
    ) -> Poll<Result<(), RequestRootAccessError>> {
        Pin::new(drain).poll(&mut Context::from_waker(waker))
    }

    #[test]
    // memory—v1: Contended initialization cannot block close, poll or cancellation.
    fn contended_close_fails_closed_and_can_be_retried() {
        let mut scope = scope();
        let extension = scope.extension();
        let shared = Arc::clone(&scope.shared);
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut state = shared.state.lock().unwrap();
            let reader = state.context.as_mut().unwrap().reader_lease().unwrap();
            state.callbacks += 1;
            let lease = CallbackLease {
                shared: Arc::clone(&shared),
                reader: Some(reader),
            };
            locked_tx.send(()).unwrap();
            release_rx.recv_timeout(WAIT).unwrap();
            drop(state);
            lease
        });
        locked_rx.recv_timeout(WAIT).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let coordinator = thread::spawn(move || {
            let waker = Waker::from(Arc::new(CountWake::default()));
            let mut drain = scope.close_and_drain();
            assert_eq!(
                poll_drain(&mut drain, &waker),
                Poll::Ready(Err(RequestRootAccessError::Busy))
            );
            drop(drain);
            done_tx.send(scope).unwrap();
        });
        let mut scope = done_rx.recv_timeout(WAIT).unwrap();
        coordinator.join().unwrap();
        release_tx.send(()).unwrap();
        let lease = worker.join().unwrap();
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut drain = scope.close_and_drain();
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        drop(lease);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Ready(Ok(())));
    }

    #[test]
    // memory—v1: Closure and callback admission serialize across concurrent readers.
    fn drain_waits_for_every_admitted_callback_and_wakes_once() {
        let mut scope = scope();
        let extension = scope.extension();
        let (entered_tx, entered_rx) = mpsc::channel();
        let mut workers = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let extension = extension.clone();
            let entered_tx = entered_tx.clone();
            let (release_tx, release_rx) = mpsc::channel();
            releases.push(release_tx);
            workers.push(thread::spawn(move || {
                extension.with_reader(|_| {
                    // Nested reads remain supported before closure.
                    extension.with_reader(|_| ()).unwrap();
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(WAIT).unwrap();
                    assert_eq!(
                        extension.with_reader(|_| ()),
                        Err(RequestRootAccessError::ScopeEnded)
                    );
                })
            }));
        }
        for _ in 0..2 {
            entered_rx.recv_timeout(WAIT).unwrap();
        }
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut drain = scope.close_and_drain();
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        releases.remove(0).send(()).unwrap();
        workers.remove(0).join().unwrap().unwrap();
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        releases.remove(0).send(()).unwrap();
        workers.remove(0).join().unwrap().unwrap();
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Ready(Ok(())));
        drop(drain);
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        assert_eq!(
            poll_drain(&mut scope.close_and_drain(), &waker),
            Poll::Ready(Ok(()))
        );
    }

    #[test]
    // memory—v1: Cancellation under contention does not erase a later waiter's notification.
    fn cancelled_waiter_is_replaced_after_contended_drop() {
        let mut scope = scope();
        let extension = scope.extension();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            extension.with_reader(|_| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(WAIT).unwrap();
            })
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        let first = Arc::new(CountWake::default());
        let first_waker = Waker::from(Arc::clone(&first));
        let mut drain = scope.close_and_drain();
        assert_eq!(poll_drain(&mut drain, &first_waker), Poll::Pending);
        let shared = Arc::clone(&drain.scope.shared);
        let (locked_tx, locked_rx) = mpsc::channel();
        let (unlock_tx, unlock_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let _guard = shared.state.lock().unwrap();
            locked_tx.send(()).unwrap();
            unlock_rx.recv_timeout(WAIT).unwrap();
        });
        locked_rx.recv_timeout(WAIT).unwrap();
        drop(drain);
        unlock_tx.send(()).unwrap();
        holder.join().unwrap();
        let second = Arc::new(CountWake::default());
        let second_waker = Waker::from(Arc::clone(&second));
        let mut next = scope.close_and_drain();
        assert_eq!(poll_drain(&mut next, &second_waker), Poll::Pending);
        release_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll_drain(&mut next, &second_waker), Poll::Ready(Ok(())));
    }

    #[test]
    // memory—v1: Unpolled and cancelled waits cannot reopen admission.
    fn dropping_drain_or_scope_keeps_admission_closed() {
        let mut scope = scope();
        let extension = scope.extension();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_extension = extension.clone();
        let worker = thread::spawn(move || {
            worker_extension.with_reader(|_| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(WAIT).unwrap();
            })
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        drop(scope.close_and_drain());
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut drain = scope.close_and_drain();
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        drop(drain);
        drop(scope);
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        release_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
    }

    struct ReentrantDrop {
        extension: RequestRootExtension,
        finished: mpsc::Sender<()>,
    }

    impl Wake for ReentrantDrop {
        // memory—v1: The test removes this waker before any callback exits.
        fn wake(self: Arc<Self>) {
            panic!("unexpected wake");
        }
    }

    impl Drop for ReentrantDrop {
        // memory—v1: Reenter the closed scope when the final waker is destroyed.
        fn drop(&mut self) {
            assert_eq!(
                self.extension.with_reader(|_| ()),
                Err(RequestRootAccessError::ScopeEnded)
            );
            self.finished.send(()).unwrap();
        }
    }

    struct PanicWake;

    impl Wake for PanicWake {
        // memory—v1: Model a faulty executor notification during unwinding.
        fn wake(self: Arc<Self>) {
            panic!("waker panic");
        }
    }

    #[test]
    // memory—v1: Replacing or cancelling a waiter destroys its waker outside the lock.
    fn drain_waker_drop_can_reenter_scope() {
        for replace in [false, true] {
            let (finished_tx, finished_rx) = mpsc::channel();
            thread::spawn(move || {
                let mut scope = scope();
                let extension = scope.extension();
                let (entered_tx, entered_rx) = mpsc::channel();
                let (release_tx, release_rx) = mpsc::channel();
                let worker_extension = extension.clone();
                let worker = thread::spawn(move || {
                    worker_extension.with_reader(|_| {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(WAIT).unwrap();
                    })
                });
                entered_rx.recv_timeout(WAIT).unwrap();
                let mut drain = scope.close_and_drain();
                let waker = Waker::from(Arc::new(ReentrantDrop {
                    extension,
                    finished: finished_tx,
                }));
                assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
                drop(waker);
                if replace {
                    let next = Waker::from(Arc::new(CountWake::default()));
                    assert_eq!(poll_drain(&mut drain, &next), Poll::Pending);
                }
                drop(drain);
                release_tx.send(()).unwrap();
                worker.join().unwrap().unwrap();
            });
            finished_rx.recv_timeout(WAIT).unwrap();
        }
    }

    #[test]
    // memory—v1: A faulty wake during callback unwinding cannot cause a double panic.
    fn callback_panic_with_panicking_waker_does_not_abort() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_PANIC_WAKER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_request::tests::callback_panic_with_panicking_waker_does_not_abort",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "child status: {}", output.status);
            return;
        }

        let mut scope = scope();
        let extension = scope.extension();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            catch_unwind(AssertUnwindSafe(|| {
                extension.with_reader(|_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(WAIT).unwrap();
                    panic!("callback panic");
                })
            }))
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        let waker = Waker::from(Arc::new(PanicWake));
        let mut drain = scope.close_and_drain();
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        release_tx.send(()).unwrap();
        assert!(worker.join().unwrap().is_err());
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Ready(Ok(())));
    }

    #[test]
    // memory—v1: An external deadline may abandon the wait without reopening the scope.
    fn deadline_and_callback_panic_leave_scope_closed_and_wake_drain() {
        let mut scope = scope();
        let extension = scope.extension();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker_extension = extension.clone();
        let worker = thread::spawn(move || {
            catch_unwind(AssertUnwindSafe(|| {
                worker_extension.with_reader(|_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(WAIT).unwrap();
                    panic!("callback panic");
                })
            }))
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&wake));
        let mut drain = scope.close_and_drain();
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        // Simulate an external timeout cancelling the still-pending wait.
        drop(drain);
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        let mut drain = scope.close_and_drain();
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Pending);
        release_tx.send(()).unwrap();
        assert!(worker.join().unwrap().is_err());
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll_drain(&mut drain, &waker), Poll::Ready(Ok(())));
        drop(drain);
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
    }
}
