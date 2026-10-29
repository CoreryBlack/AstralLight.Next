//! Process-local epoch fencing for the native evidence L1.
//!
//! The epoch is only an in-process cache-generation marker. It is not durable
//! proof and does not provide cross-instance invalidation; authorization cache
//! hits remain fenced by the authoritative published-evidence pointer reads.
//! The bounded TTL rotates abandoned entries, while explicit reset rotates the
//! current process epoch after an in-process restore/rebuild event.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Process-local epoch lifetime. Evidence entries have a shorter TTL, so normal
/// expiry also bounds how long an entry can remain resident across rotations.
pub(crate) const IN_PROCESS_EPOCH_TTL: Duration = Duration::from_secs(60);

/// Monotonic process-local epoch counter.
static IN_PROCESS_EPOCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Current epoch and the instant it was installed.
static IN_PROCESS_EPOCH: RwLock<Option<(u64, Instant)>> = RwLock::new(None);

fn in_process_counter_epoch_value(counter: u64) -> String {
    format!("inproc-{counter}")
}

fn in_process_epoch_is_fresh(cached_at: Instant, now: Instant) -> bool {
    now.duration_since(cached_at) < IN_PROCESS_EPOCH_TTL
}

fn advance_in_process_epoch() -> String {
    let next = IN_PROCESS_EPOCH_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    if let Ok(mut guard) = IN_PROCESS_EPOCH.write() {
        *guard = Some((next, Instant::now()));
    }
    in_process_counter_epoch_value(next)
}

/// Return this process's stable epoch, advancing it when absent or expired.
fn current_in_process_epoch() -> String {
    if let Ok(guard) = IN_PROCESS_EPOCH.read() {
        if let Some((counter, cached_at)) = *guard {
            if in_process_epoch_is_fresh(cached_at, Instant::now()) {
                return in_process_counter_epoch_value(counter);
            }
        }
    }
    advance_in_process_epoch()
}

/// Current process-local cache epoch. There is no shared-cache or network path.
pub async fn current_cache_epoch() -> Option<String> {
    Some(current_in_process_epoch())
}

/// Rotate the current process epoch, invalidating entries created under the
/// previous epoch on their next strict-current check.
pub fn reset_cache_epoch() -> String {
    advance_in_process_epoch()
}

/// Strict currentness: unknown epochs and mismatches are always cache misses.
pub(crate) fn cache_epoch_is_current(current: Option<&str>, entry: Option<&str>) -> bool {
    matches!((current, entry), (Some(current), Some(entry)) if current == entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_freshness_honors_the_ttl_boundary() {
        let at = Instant::now();
        assert!(in_process_epoch_is_fresh(at, at));
        assert!(in_process_epoch_is_fresh(
            at,
            at + IN_PROCESS_EPOCH_TTL - Duration::from_secs(1)
        ));
        assert!(!in_process_epoch_is_fresh(at, at + IN_PROCESS_EPOCH_TTL));
        assert!(!in_process_epoch_is_fresh(
            at,
            at + IN_PROCESS_EPOCH_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn epoch_value_is_namespaced_and_deterministic() {
        assert_eq!(in_process_counter_epoch_value(7), "inproc-7");
        assert_eq!(
            in_process_counter_epoch_value(u64::MAX),
            "inproc-18446744073709551615"
        );
    }

    #[test]
    fn reset_rotates_the_process_epoch() {
        let first = current_in_process_epoch();
        assert_eq!(current_in_process_epoch(), first);
        let rotated = reset_cache_epoch();
        assert_ne!(rotated, first, "rotation must advance the in-memory epoch");
        assert_eq!(current_in_process_epoch(), rotated);
        assert!(rotated.starts_with("inproc-"));
    }

    #[test]
    fn strict_epoch_check_rejects_unknown_and_stale_values() {
        assert!(cache_epoch_is_current(Some("e1"), Some("e1")));
        assert!(!cache_epoch_is_current(Some("e1"), Some("e2")));
        assert!(!cache_epoch_is_current(None, Some("e1")));
        assert!(!cache_epoch_is_current(Some("e1"), None));
        assert!(!cache_epoch_is_current(None, None));
    }
}
