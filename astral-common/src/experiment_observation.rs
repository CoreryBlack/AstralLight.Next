//! Feature-gated, process-local clock for E3 experiment observations.
//!
//! Sequence and wall-clock values are evidence metadata only. They never enter
//! authorization, retry, lease, or publication decisions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROCESS_OBSERVATION_ID: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExperimentObservationStamp {
    pub process_observation_id: String,
    pub event_sequence: u64,
    pub wall_unix_ns: u128,
}

pub fn stamp() -> ExperimentObservationStamp {
    ExperimentObservationStamp {
        process_observation_id: PROCESS_OBSERVATION_ID
            .get_or_init(|| uuid::Uuid::new_v4().to_string())
            .clone(),
        event_sequence: EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1,
        wall_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos()),
    }
}

#[cfg(test)]
mod tests {
    use super::stamp;

    #[test]
    fn stamps_are_process_local_and_strictly_monotonic() {
        let first = stamp();
        let second = stamp();
        assert_eq!(first.process_observation_id, second.process_observation_id);
        assert!(second.event_sequence > first.event_sequence);
        assert!(first.wall_unix_ns > 0);
        assert!(second.wall_unix_ns > 0);
    }
}
