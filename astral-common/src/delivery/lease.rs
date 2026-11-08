//! Attempt leasing decisions (pure logic; the durable store enforces them
//! with CAS under concurrency).
//!
//! Rules:
//! - `IN_DOUBT` always demands explicit reconciliation — never an auto retry.
//! - `ACCEPTED` is provider-side responsibility: re-dispatching would
//!   duplicate the message, so no further attempts are allowed here.
//! - Attempts are bounded; a still-queued intent whose budget is exhausted
//!   expires and must be re-minted with a fresh `message_id`.

use crate::delivery::state::DeliveryState;
use time::{Duration, PrimitiveDateTime};

/// What may happen next to an intent row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextAction {
    /// A dispatch attempt may be leased and executed.
    Dispatch,
    /// Outcome unknown; explicit reconciliation is required first.
    ReconciliationRequired,
    /// A settled truth already exists; no further attempt.
    Terminal,
    /// Attempt budget exhausted without acceptance; the intent expires.
    BudgetExhausted,
}

/// Decide the next action from durable state. Pure; unit-testable.
pub fn next_action(state: DeliveryState, attempts: u32, max_attempts: u32) -> NextAction {
    match state {
        DeliveryState::InDoubt => NextAction::ReconciliationRequired,
        DeliveryState::Accepted => NextAction::Terminal,
        DeliveryState::Delivered | DeliveryState::Failed | DeliveryState::Expired => {
            NextAction::Terminal
        }
        DeliveryState::NotAttempted | DeliveryState::Queued => {
            if max_attempts == 0 || attempts >= max_attempts {
                NextAction::BudgetExhausted
            } else {
                NextAction::Dispatch
            }
        }
    }
}

/// Identity of the dispatching worker/process for lease ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerIdentity {
    pub id: String,
}

impl WorkerIdentity {
    /// Fresh per-process identity (uuid v7; stable for this instance's lifetime
    /// when the caller caches it).
    pub fn generate() -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
        }
    }
}

/// A granted attempt lease. `generation` is the post-increment optimistic
/// version guarding exactly this attempt; settlement CASes on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptLease {
    pub message_id: String,
    pub generation: i64,
    pub lease_owner: String,
    pub lease_expires_at: PrimitiveDateTime,
    pub attempt_no: u32,
}

impl AttemptLease {
    pub fn lease_is_live(&self, now: PrimitiveDateTime) -> bool {
        self.lease_expires_at > now
    }
}

/// Compute a lease expiry from `now`.
pub fn lease_expiry(now: PrimitiveDateTime, ttl: Duration) -> PrimitiveDateTime {
    now + ttl
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn in_doubt_never_auto_retries() {
        for attempts in [0u32, 1, 2, 5] {
            assert_eq!(
                next_action(DeliveryState::InDoubt, attempts, 3),
                NextAction::ReconciliationRequired,
                "IN_DOUBT must block every automatic retry"
            );
        }
    }

    #[test]
    fn accepted_is_terminal_to_avoid_duplicate_dispatch() {
        assert_eq!(
            next_action(DeliveryState::Accepted, 0, 3),
            NextAction::Terminal
        );
    }

    #[test]
    fn queued_dispatches_within_budget_only() {
        assert_eq!(
            next_action(DeliveryState::Queued, 0, 3),
            NextAction::Dispatch
        );
        assert_eq!(
            next_action(DeliveryState::Queued, 2, 3),
            NextAction::Dispatch
        );
        assert_eq!(
            next_action(DeliveryState::Queued, 3, 3),
            NextAction::BudgetExhausted
        );
        assert_eq!(
            next_action(DeliveryState::NotAttempted, 0, 0),
            NextAction::BudgetExhausted
        );
    }

    #[test]
    fn terminal_states_never_dispatch() {
        for state in [
            DeliveryState::Delivered,
            DeliveryState::Failed,
            DeliveryState::Expired,
        ] {
            assert_eq!(next_action(state, 0, 3), NextAction::Terminal);
        }
    }

    #[test]
    fn lease_expiry_is_bounded_by_ttl() {
        let now = datetime!(2026-11-07 0:00);
        let lease = AttemptLease {
            message_id: "m".into(),
            generation: 1,
            lease_owner: "w".into(),
            lease_expires_at: lease_expiry(now, Duration::seconds(60)),
            attempt_no: 1,
        };
        assert!(lease.lease_is_live(now));
        assert!(lease.lease_is_live(datetime!(2026-11-07 0:00:59.999_999_999)));
        assert!(!lease.lease_is_live(datetime!(2026-11-07 0:01)));
    }
}
