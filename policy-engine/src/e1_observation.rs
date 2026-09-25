//! Feature-gated event correlation for the authorization decision-path race.
//!
//! The clock values are observations, not authorization inputs. `event_sequence`
//! is process-local and monotonic within ONE process epoch; a restart starts a
//! new epoch, so sequences are never comparable across epochs. Every stamp
//! therefore carries `process_observation_id`: a random identifier that is
//! stable for the lifetime of this process (same semantics as the E3
//! `astral-common` process clock, mirrored locally because `policy-engine`
//! must not depend on `astral-common`). Wall-clock nanoseconds are recorded
//! only for cross-process reconciliation and must be interpreted with the E4
//! clock-offset evidence.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROCESS_OBSERVATION_ID: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E1ObservationStamp {
    pub request_id: Option<String>,
    pub process_observation_id: String,
    pub event_sequence: u64,
    pub wall_unix_ns: u128,
}

#[cfg(feature = "e1-observability")]
tokio::task_local! {
    static E1_REQUEST_ID: Option<String>;
}

/// Random identifier, stable for the lifetime of this process (one epoch).
///
/// With `e1-observability` this is a UUIDv4, mirroring the E3 process clock in
/// `astral-common`. Without the feature this module is compiled only for unit
/// tests (production `authz_e1` emission is feature-gated), so a synthetic
/// per-process value keeps the stamp shape exercised without the uuid dep.
pub fn process_observation_id() -> String {
    #[cfg(feature = "e1-observability")]
    {
        PROCESS_OBSERVATION_ID
            .get_or_init(|| uuid::Uuid::new_v4().to_string())
            .clone()
    }
    #[cfg(not(feature = "e1-observability"))]
    {
        PROCESS_OBSERVATION_ID
            .get_or_init(|| {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_nanos());
                format!("e1-obs-{nanos:032x}")
            })
            .clone()
    }
}

pub fn stamp() -> E1ObservationStamp {
    let request_id = current_request_id();
    let event_sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let wall_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    E1ObservationStamp {
        request_id,
        process_observation_id: process_observation_id(),
        event_sequence,
        wall_unix_ns,
    }
}

pub fn current_request_id() -> Option<String> {
    #[cfg(feature = "e1-observability")]
    {
        E1_REQUEST_ID.try_with(Clone::clone).ok().flatten()
    }
    #[cfg(not(feature = "e1-observability"))]
    {
        None
    }
}

pub async fn scope_request<T>(request_id: Option<String>, future: impl Future<Output = T>) -> T {
    #[cfg(feature = "e1-observability")]
    {
        E1_REQUEST_ID.scope(request_id, future).await
    }
    #[cfg(not(feature = "e1-observability"))]
    {
        let _ = request_id;
        future.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sequence_is_strictly_monotonic() {
        let first = stamp();
        let second = stamp();
        assert!(second.event_sequence > first.event_sequence);
        assert!(first.wall_unix_ns > 0);
        assert!(second.wall_unix_ns > 0);
    }

    #[test]
    fn process_observation_id_is_stable_within_one_process() {
        let direct_first = process_observation_id();
        let direct_second = process_observation_id();
        assert!(!direct_first.is_empty());
        assert_eq!(direct_first, direct_second);
        let first = stamp();
        let second = stamp();
        assert_eq!(
            first.process_observation_id, second.process_observation_id,
            "stamps from the same process must share one epoch id"
        );
        assert_eq!(first.process_observation_id, direct_first);
    }

    #[cfg(feature = "e1-observability")]
    #[tokio::test]
    async fn request_scope_is_visible_to_nested_calls() {
        scope_request(Some("request-42".to_owned()), async {
            assert_eq!(current_request_id().as_deref(), Some("request-42"));
            assert_eq!(stamp().request_id.as_deref(), Some("request-42"));
        })
        .await;
        assert_eq!(current_request_id(), None);
    }
}
