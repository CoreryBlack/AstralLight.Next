//! memory—v1: One start observation per evaluation; the final guarded sample
//! is taken independently. A negative decision has no reusable time envelope.

use std::cell::Cell;

use astral_authorization_root::memory_v1_policy_time::PolicyTime;
use astral_authorization_root::memory_v1_session::RequestSessionExtension;

#[derive(Default)]
pub(super) struct ReadClock {
    sample: Cell<Option<PolicyTime>>,
}

impl ReadClock {
    // memory—v1: Plan at the lower bound so a denial beginning anywhere in
    // the uncertainty interval is registered as a future activation.
    pub(super) fn start(&self, session: &RequestSessionExtension) -> Option<i64> {
        let sample = session.policy_time()?;
        self.sample.set(Some(sample));
        Some(sample.earliest())
    }

    // memory—v1: A read-phase denial at one tick does not prove that denial
    // at every tick. Do not emit a durable DENY observation on uncertainty.
    pub(super) fn supports_deny(&self) -> bool {
        self.sample.get().is_some_and(PolicyTime::is_single_tick)
    }

    // memory—v1: Only consecutive ticks permit an exhaustive two-point check.
    pub(super) fn second_tick(&self) -> Option<i64> {
        let sample = self.sample.get()?;
        (sample.earliest().checked_add(1)? == sample.latest()).then_some(sample.latest())
    }
}
