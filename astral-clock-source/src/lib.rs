//! memory—v1: Read-only kernel time discipline. This is a host report, not an
//! independent UTC certificate. The provisioner must secure the host and its
//! synchronization source; neither wall time alone nor estimated jitter suffices.

const MAX_ERROR_MICROS_EXCLUSIVE: i64 = 500_000;

/// Upper bound on any accepted sample's error, including quantization.
pub const MAX_ERROR_NANOS_EXCLUSIVE: i128 = MAX_ERROR_MICROS_EXCLUSIVE as i128 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    pub unix_nanos: i128,
    pub max_error_nanos: i128,
}

#[cfg(any(
    test,
    target_os = "macos",
    all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_env = "gnu", target_env = "musl")
    )
))]
fn decode(
    state: i32,
    seconds: i64,
    fraction: i64,
    nanos: bool,
    max_error_us: i64,
) -> Option<Sample> {
    // TIME_OK excludes unsynchronized and leap-transition states. Do not use
    // a saturated error budget, even if the status still reports synchronized.
    if state != 0 || seconds < 0 || !(0..MAX_ERROR_MICROS_EXCLUSIVE).contains(&max_error_us) {
        return None;
    }
    let quantum = if nanos { 1 } else { 1_000 };
    if !(0..1_000_000_000 / quantum).contains(&fraction) {
        return None;
    }
    Some(Sample {
        unix_nanos: i128::from(seconds) * 1_000_000_000 + i128::from(fraction * quantum),
        max_error_nanos: i128::from(max_error_us * 1_000 + quantum - 1),
    })
}

/// memory—v1: Read the time, synchronization status and maximum error from
/// one kernel observation. No syscall on this path requests an adjustment.
#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_env = "gnu", target_env = "musl")
))]
pub fn sample() -> Option<Sample> {
    // SAFETY: timex is a C numeric record; zero initializes its modes to a
    // read-only query. The exclusive output pointer lives through this call.
    let mut info: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::adjtimex(&mut info) };
    if info.status & (libc::STA_UNSYNC | libc::STA_CLOCKERR | libc::STA_INS | libc::STA_DEL) != 0 {
        return None;
    }
    decode(
        state,
        info.time.tv_sec,
        info.time.tv_usec,
        info.status & libc::STA_NANO != 0,
        info.maxerror,
    )
}

/// memory—v1: Darwin reports a timespec and a maximum error in microseconds.
#[cfg(target_os = "macos")]
pub fn sample() -> Option<Sample> {
    // SAFETY: ntptimeval has only integer fields; ntp_gettime writes to a
    // properly aligned, valid buffer and cannot change the system clock.
    let mut info: libc::ntptimeval = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::ntp_gettime(&mut info) };
    if state != 0 {
        return None;
    }
    decode(
        info.time_state,
        info.time.tv_sec,
        info.time.tv_nsec,
        true,
        info.maxerror,
    )
}

/// memory—v1: Unsupported platforms have no trusted kernel observation.
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_env = "gnu", target_env = "musl")
    )
)))]
pub fn sample() -> Option<Sample> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsynchronized_leap_saturated_and_malformed_readings() {
        for state in [-1, 1, 2, 3, 4, 5] {
            assert!(decode(state, 10, 1, true, 1).is_none());
        }
        for error in [-1, 500_000, i64::MAX] {
            assert!(decode(0, 10, 0, false, error).is_none());
        }
        assert!(decode(0, -1, 0, true, 0).is_none());
        for (nanos, invalid) in [(true, 1_000_000_000), (false, 1_000_000)] {
            for fraction in [-1, invalid] {
                assert!(decode(0, 1, fraction, nanos, 0).is_none());
            }
        }
    }

    #[test]
    fn maximum_error_and_sample_units_are_not_interchangeable() {
        assert_eq!(
            decode(0, 1, 999_999, false, 7),
            Some(Sample {
                unix_nanos: 1_999_999_000,
                max_error_nanos: 7_999
            })
        );
        assert_eq!(
            decode(0, 1, 999_999_999, true, 7),
            Some(Sample {
                unix_nanos: 1_999_999_999,
                max_error_nanos: 7_000
            })
        );
    }
}
