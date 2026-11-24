//! memory—v1: Authority-scoped observations of the synchronized host clock.

use std::sync::atomic::{AtomicU64, Ordering};

const LATCHED: u64 = u64::MAX;
const SECOND: i128 = 1_000_000_000;

/// memory—v1: Inclusive possible UTC policy ticks, conditional on the host's
/// synchronization source and kernel maximum-error report being trustworthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTime {
    first: i64,
    observed: i64,
    last: i64,
    earliest_later: i64,
}

impl PolicyTime {
    /// memory—v1: One process-wide time history for signed startup and every
    /// production admission. Constructing a new session authority cannot reset
    /// a detected backstep. A new process needs a fresh synchronized reading.
    pub fn sample_host() -> Option<Self> {
        static CLOCK: std::sync::LazyLock<AdmissionClock> =
            std::sync::LazyLock::new(AdmissionClock::default);
        CLOCK.sample_with(astral_clock_source::sample)
    }

    /// memory—v1: Plan from the earliest possible tick; boundaries after this
    /// tick, including a denial not yet active, must survive final validation.
    pub fn earliest(self) -> i64 {
        self.first
    }

    /// memory—v1: A point-in-time denial can be recorded without a negative
    /// validity envelope only when all possible times share one policy tick.
    pub fn is_single_tick(self) -> bool {
        self.first == self.last
    }

    /// memory—v1: The tick reported by the kernel, not an exact UTC proof.
    pub fn observed(self) -> i64 {
        self.observed
    }

    /// memory—v1: Last policy tick compatible with the same observation.
    pub fn latest(self) -> i64 {
        self.last
    }

    /// memory—v1: Lower bound for the earliest tick of any later accepted
    /// sample, even if its reported error grows. Not a substitute for sampling.
    pub fn earliest_later(self) -> i64 {
        self.earliest_later
    }

    // memory—v1: Preserve the precise sample contract for injected test clocks.
    #[cfg(feature = "test-support")]
    pub(super) fn point(tick: i64) -> Self {
        Self {
            first: tick,
            observed: tick,
            last: tick,
            earliest_later: tick.saturating_sub(1),
        }
    }
}

#[cfg(feature = "test-support")]
pub(super) type FixtureClock = fn() -> Option<(i128, i128)>;

#[derive(Debug, Default)]
pub(super) struct AdmissionClock {
    // Unix nanoseconds plus one. Zero is unused; MAX is terminal for this owner.
    high_water: AtomicU64,
    #[cfg(feature = "test-support")]
    fixture: Option<FixtureClock>,
}

impl AdmissionClock {
    // memory—v1: No network, allocation, blocking lock, or wall-clock fallback.
    pub(super) fn sample(&self) -> Option<PolicyTime> {
        #[cfg(feature = "test-support")]
        if let Some(source) = self.fixture {
            return self.sample_with(|| {
                source().map(
                    |(unix_nanos, max_error_nanos)| astral_clock_source::Sample {
                        unix_nanos,
                        max_error_nanos,
                    },
                )
            });
        }
        PolicyTime::sample_host()
    }

    // memory—v1: Only a new isolated fixture authority can choose a source.
    #[cfg(feature = "test-support")]
    pub(super) fn for_test(source: FixtureClock) -> Self {
        Self {
            fixture: Some(source),
            ..Self::default()
        }
    }

    // memory—v1: Read the watermark *before* observing the kernel. Only an
    // unambiguously later sample can poison the owner on a backstep. A racing
    // older observation cannot lower the watermark or cause a false latch.
    fn sample_with(
        &self,
        source: impl FnOnce() -> Option<astral_clock_source::Sample>,
    ) -> Option<PolicyTime> {
        let before = self.high_water.load(Ordering::Acquire);
        if before == LATCHED {
            return None;
        }
        let raw = source()?;
        let stamp = u64::try_from(raw.unix_nanos).ok()?.checked_add(1)?;
        let error_bound = astral_clock_source::MAX_ERROR_NANOS_EXCLUSIVE;
        if stamp == LATCHED || !(0..error_bound).contains(&raw.max_error_nanos) {
            return None;
        }
        if stamp < before {
            self.high_water.store(LATCHED, Ordering::Release);
            return None;
        }
        let first = raw.unix_nanos.checked_sub(raw.max_error_nanos)?;
        if first < 0 {
            return None;
        }
        let last = raw.unix_nanos.checked_add(raw.max_error_nanos)?;
        let time = PolicyTime {
            first: i64::try_from(first / SECOND).ok()?,
            observed: i64::try_from(raw.unix_nanos / SECOND).ok()?,
            last: i64::try_from(last / SECOND).ok()?,
            earliest_later: i64::try_from((raw.unix_nanos - error_bound).div_euclid(SECOND))
                .ok()?,
        };
        // fetch_max preserves both a newer concurrent sample and a terminal
        // latch. Overlapping successful samples can be ordered at their reads.
        (self.high_water.fetch_max(stamp, Ordering::AcqRel) != LATCHED).then_some(time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(nanos: i128, error: i128) -> Option<astral_clock_source::Sample> {
        Some(astral_clock_source::Sample {
            unix_nanos: nanos,
            max_error_nanos: error,
        })
    }

    #[test]
    fn rollback_latches_across_calls_even_after_catchup() {
        let clock = AdmissionClock::default();
        assert!(clock.sample_with(|| at(10 * SECOND + 2, 0)).is_some());
        assert!(clock.sample_with(|| at(10 * SECOND + 1, 0)).is_none());
        assert!(clock.sample_with(|| at(11 * SECOND, 0)).is_none());
        let fresh_owner = AdmissionClock::default();
        assert!(fresh_owner.sample_with(|| None).is_none());
        assert!(fresh_owner.sample_with(|| at(11 * SECOND, 0)).is_some());
    }

    #[test]
    fn overlapping_samples_do_not_latch_or_lower_the_watermark() {
        let clock = AdmissionClock::default();
        let earlier = clock.sample_with(|| {
            assert!(clock.sample_with(|| at(11 * SECOND, 10)).is_some());
            at(10 * SECOND, 10)
        });
        assert!(earlier.is_some());
        assert!(clock.sample_with(|| at(12 * SECOND, 10)).is_some());
        assert!(clock.sample_with(|| at(11 * SECOND, 10)).is_none());
    }

    #[test]
    fn inclusive_error_bound_is_rounded_out_to_policy_ticks() {
        let clock = AdmissionClock::default();
        let time = clock.sample_with(|| at(10 * SECOND - 1, 1)).unwrap();
        assert_eq!(
            (time.earliest(), time.observed(), time.latest()),
            (9, 9, 10)
        );
        assert!(!time.is_single_tick());
        assert!(clock
            .sample_with(|| at(10 * SECOND + 3, 2))
            .unwrap()
            .is_single_tick());
        assert!(clock.sample_with(|| None).is_none());
        assert!(clock.sample_with(|| at(11 * SECOND, -1)).is_none());
        assert!(clock.sample_with(|| at(11 * SECOND, i128::MAX)).is_none());
    }
}
