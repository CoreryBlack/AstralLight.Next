//! Per-upstream circuit breaker with cancellation-safe half-open probe ownership.
//!
//! A probe permit reopens the circuit on cancellation. Ordinary request permits
//! do not change the circuit when dropped without a recorded result.

use std::sync::Mutex;
use std::time::{Duration, Instant};

const CB_FAILURE_THRESHOLD: u32 = 5;
const CB_RECOVERY: Duration = Duration::from_secs(30);

/// State transitions and permit ownership are serialized by one short lock.
/// No lock is held while a request is in flight or across an await.
pub(super) struct CircuitBreaker {
    state: Mutex<State>,
}

struct State {
    // A generation is never reused: old requests cannot affect a later cycle.
    generation: u64,
    phase: Phase,
}

enum Phase {
    Closed { failures: u32 },
    Open { since: Instant },
    HalfOpen,
    // Generation exhaustion is practically unreachable, but must fail closed.
    Exhausted,
}

#[derive(Clone, Copy)]
enum PermitKind {
    Request,
    Probe,
}

/// A request-scoped, non-cloneable ownership token. A half-open probe is
/// reopened on cancellation, timeout, early return, or unwind.
#[must_use = "hold the permit until the upstream request completes"]
pub(super) struct RequestPermit<'a> {
    breaker: &'a CircuitBreaker,
    generation: u64,
    kind: PermitKind,
    completed: bool,
}

impl State {
    // memory—v1: Fence all permits issued before a change of circuit phase.
    fn advance(&mut self) -> bool {
        match self.generation.checked_add(1) {
            Some(next) => {
                self.generation = next;
                true
            }
            None => {
                self.phase = Phase::Exhausted;
                false
            }
        }
    }
}

impl CircuitBreaker {
    // memory—v1: Each upstream owns an independent, initially closed breaker.
    pub(super) const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                generation: 0,
                phase: Phase::Closed { failures: 0 },
            }),
        }
    }

    /// memory—v1: Admit a request, or deny it while open or another probe runs.
    /// The returned permit must live across the entire upstream operation.
    pub(super) fn acquire(&self) -> Option<RequestPermit<'_>> {
        // A poisoned state has unknown integrity; never use it to admit traffic.
        let mut state = self.state.lock().ok()?;
        let kind = match state.phase {
            Phase::Closed { .. } => PermitKind::Request,
            Phase::Open { since } if since.elapsed() >= CB_RECOVERY => {
                if !state.advance() {
                    return None;
                }
                state.phase = Phase::HalfOpen;
                PermitKind::Probe
            }
            Phase::Open { .. } | Phase::HalfOpen | Phase::Exhausted => return None,
        };
        Some(RequestPermit {
            breaker: self,
            generation: state.generation,
            kind,
            completed: false,
        })
    }

    // memory—v1: Apply only a result belonging to the current circuit phase.
    fn complete(&self, generation: u64, kind: PermitKind, success: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.generation != generation {
            return;
        }
        if matches!((kind, &state.phase), (PermitKind::Probe, Phase::HalfOpen)) {
            if state.advance() {
                state.phase = if success {
                    Phase::Closed { failures: 0 }
                } else {
                    Phase::Open {
                        since: Instant::now(),
                    }
                };
            }
            return;
        }
        if let (PermitKind::Request, Phase::Closed { failures }) = (kind, &mut state.phase) {
            if success {
                *failures = 0;
            } else {
                *failures += 1;
                if *failures >= CB_FAILURE_THRESHOLD && state.advance() {
                    state.phase = Phase::Open {
                        since: Instant::now(),
                    };
                }
            }
        }
    }
}

impl RequestPermit<'_> {
    /// memory—v1: Record a response classified as an upstream success.
    pub(super) fn record_success(mut self) {
        self.completed = true;
        self.breaker.complete(self.generation, self.kind, true);
    }

    /// memory—v1: Record a response classified as an upstream failure.
    pub(super) fn record_failure(mut self) {
        self.completed = true;
        self.breaker.complete(self.generation, self.kind, false);
    }
}

impl Drop for RequestPermit<'_> {
    // memory—v1: Cancellation of the current probe starts a fresh cooldown.
    fn drop(&mut self) {
        if !self.completed && matches!(self.kind, PermitKind::Probe) {
            self.breaker.complete(self.generation, self.kind, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // memory—v1: Reach the normal open state using actual request permits.
    fn open(breaker: &CircuitBreaker) {
        for _ in 0..CB_FAILURE_THRESHOLD {
            breaker.acquire().unwrap().record_failure();
        }
        assert!(breaker.acquire().is_none());
    }

    // memory—v1: Advance only the test's recovery deadline without sleeping.
    fn expire_cooldown(breaker: &CircuitBreaker) {
        let mut state = breaker.state.lock().unwrap();
        match &mut state.phase {
            Phase::Open { since } => {
                *since = Instant::now().checked_sub(CB_RECOVERY).unwrap();
            }
            _ => panic!("expected an open breaker"),
        }
    }

    // memory—v1: Preserve threshold and consecutive-failure reset behavior.
    #[test]
    fn threshold_and_success_reset() {
        let breaker = CircuitBreaker::new();
        for _ in 0..CB_FAILURE_THRESHOLD - 1 {
            breaker.acquire().unwrap().record_failure();
        }
        breaker.acquire().unwrap().record_success();
        for _ in 0..CB_FAILURE_THRESHOLD - 1 {
            breaker.acquire().unwrap().record_failure();
        }
        assert!(breaker.acquire().is_some());
        breaker.acquire().unwrap().record_failure();
        assert!(breaker.acquire().is_none());
    }

    // memory—v1: Probe failure and cancellation both restart the recovery window.
    #[test]
    fn probe_cancellation_and_failure_reopen_then_success_closes() {
        let breaker = CircuitBreaker::new();
        open(&breaker);
        expire_cooldown(&breaker);
        let probe = breaker.acquire().unwrap();
        assert!(breaker.acquire().is_none());
        drop(probe);
        assert!(breaker.acquire().is_none());
        expire_cooldown(&breaker);
        breaker.acquire().unwrap().record_failure();
        assert!(breaker.acquire().is_none());
        expire_cooldown(&breaker);
        breaker.acquire().unwrap().record_success();
        assert!(breaker.acquire().is_some());
    }

    // memory—v1: Dropping a suspended forwarding future releases its probe.
    #[test]
    fn cancelling_a_suspended_future_reopens_the_circuit() {
        use std::future::{pending, Future};
        use std::task::{Context, Poll, Waker};

        let breaker = CircuitBreaker::new();
        open(&breaker);
        expire_cooldown(&breaker);
        let mut request = Box::pin(async {
            let permit = breaker.acquire().unwrap();
            pending::<()>().await;
            permit.record_success();
        });
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(request.as_mut().poll(&mut context), Poll::Pending));
        assert!(breaker.acquire().is_none());
        drop(request);
        assert!(breaker.acquire().is_none());
        expire_cooldown(&breaker);
        breaker.acquire().unwrap().record_success();
        assert!(breaker.acquire().is_some());
    }

    // memory—v1: Results from pre-open requests cannot release or close a probe.
    #[test]
    fn old_request_results_cannot_change_probe_or_later_cycle() {
        let breaker = CircuitBreaker::new();
        let old_success = breaker.acquire().unwrap();
        let old_failure = breaker.acquire().unwrap();
        let older_success = breaker.acquire().unwrap();
        open(&breaker);
        expire_cooldown(&breaker);
        let probe = breaker.acquire().unwrap();
        old_success.record_success();
        old_failure.record_failure();
        assert!(breaker.acquire().is_none());
        drop(probe);
        expire_cooldown(&breaker);
        let next_probe = breaker.acquire().unwrap();
        older_success.record_success();
        assert!(breaker.acquire().is_none());
        next_probe.record_success();
        assert!(breaker.acquire().is_some());
    }

    // memory—v1: A stale ordinary success cannot reset a new generation's failures.
    #[test]
    fn old_success_cannot_reset_new_closed_generation() {
        let breaker = CircuitBreaker::new();
        let stale = breaker.acquire().unwrap();
        open(&breaker);
        expire_cooldown(&breaker);
        breaker.acquire().unwrap().record_success();
        for _ in 0..CB_FAILURE_THRESHOLD - 1 {
            breaker.acquire().unwrap().record_failure();
        }
        stale.record_success();
        breaker.acquire().unwrap().record_failure();
        assert!(breaker.acquire().is_none());
    }

    // memory—v1: Ordinary request cancellation neither increments nor resets failures.
    #[test]
    fn ordinary_cancellation_has_no_effect() {
        let breaker = CircuitBreaker::new();
        for _ in 0..CB_FAILURE_THRESHOLD - 1 {
            breaker.acquire().unwrap().record_failure();
        }
        drop(breaker.acquire().unwrap());
        breaker.acquire().unwrap().record_failure();
        assert!(breaker.acquire().is_none());
    }

    // memory—v1: Concurrent contenders hold their permits until all have tried.
    #[test]
    fn only_one_concurrent_probe_is_admitted() {
        const THREADS: usize = 16;
        let breaker = Arc::new(CircuitBreaker::new());
        open(&breaker);
        expire_cooldown(&breaker);
        let start = Arc::new(Barrier::new(THREADS));
        let acquired = Arc::new(Barrier::new(THREADS));
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let breaker = Arc::clone(&breaker);
                let start = Arc::clone(&start);
                let acquired = Arc::clone(&acquired);
                thread::spawn(move || {
                    start.wait();
                    let permit = breaker.acquire();
                    acquired.wait();
                    permit.is_some()
                })
            })
            .collect();
        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 1);
        assert!(breaker.acquire().is_none());
    }

    // memory—v1: Exhausted generations cannot wrap and revive an old permit.
    #[test]
    fn generation_exhaustion_fails_closed() {
        let breaker = CircuitBreaker::new();
        breaker.state.lock().unwrap().generation = u64::MAX;
        for _ in 0..CB_FAILURE_THRESHOLD {
            breaker.acquire().unwrap().record_failure();
        }
        assert!(breaker.acquire().is_none());
        assert!(matches!(
            breaker.state.lock().unwrap().phase,
            Phase::Exhausted
        ));
    }

    // memory—v1: State integrity failure cannot accidentally admit requests.
    #[test]
    fn poisoned_state_fails_closed() {
        let breaker = CircuitBreaker::new();
        let _ = std::panic::catch_unwind(|| {
            let _guard = breaker.state.lock().unwrap();
            panic!("poison state for test");
        });
        assert!(breaker.acquire().is_none());
    }
}
