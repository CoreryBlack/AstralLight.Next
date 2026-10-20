use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use astral_db::{DeltaLeaseIdentity, OwnedDeltaLease};

use super::{RepositoryRejection, RuntimeAccessError};

const CAPABILITY_LIMIT: usize = 1024;
const CAPABILITY_TTL: Duration = Duration::from_secs(600);
const GC_BATCH: usize = 16;

type Entry = (OwnedDeltaLease, Instant);

struct CapabilityState {
    entries: HashMap<i64, Entry>,
    reservations: usize,
    capacity: usize,
}

#[derive(Default)]
pub(super) struct OwnedCapabilities {
    state: Arc<Mutex<CapabilityState>>,
}

pub(super) struct OwnedCapabilityReservation {
    state: Arc<Mutex<CapabilityState>>,
    active: bool,
}

fn unavailable() -> RuntimeAccessError {
    RuntimeAccessError::Repository(RepositoryRejection::Other(
        "code=auth_projector.owned_capability_unavailable".to_owned(),
    ))
}

impl OwnedCapabilities {
    #[cfg(test)]
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(CapabilityState {
                entries: HashMap::new(),
                reservations: 0,
                capacity,
            })),
        }
    }

    /// Reserve one local capability slot before any durable claim begins. The
    /// mutex is held only for this bounded bookkeeping operation; the returned
    /// RAII permit crosses the database await without holding the mutex.
    pub(super) fn reserve(&self) -> Result<OwnedCapabilityReservation, RuntimeAccessError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        if state.entries.len() + state.reservations >= state.capacity {
            return Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
                "code=auth_projector.owned_capability_capacity".to_owned(),
            )));
        }
        state.reservations += 1;
        Ok(OwnedCapabilityReservation {
            state: Arc::clone(&self.state),
            active: true,
        })
    }

    pub(super) fn get(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> Result<OwnedDeltaLease, RuntimeAccessError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .entries
            .get(&identity.delta_event_id)
            .filter(|(lease, _)| lease.identity() == identity)
            .map(|(lease, _)| lease.clone())
            .ok_or_else(unavailable)
    }

    /// Consume a reservation and install the capability while holding the same
    /// bookkeeping lock. A registration failure leaves the reservation active,
    /// so Drop releases it; the caller must treat the durable claim as UNKNOWN.
    pub(super) fn insert_reserved(
        &self,
        reservation: OwnedCapabilityReservation,
        lease: OwnedDeltaLease,
    ) -> Result<(), RuntimeAccessError> {
        reservation.commit(Arc::clone(&self.state), lease)
    }

    pub(super) fn remove(&self, identity: &DeltaLeaseIdentity) {
        if let Ok(mut state) = self.state.lock() {
            if state
                .entries
                .get(&identity.delta_event_id)
                .is_some_and(|(lease, _)| lease.identity() == identity)
            {
                state.entries.remove(&identity.delta_event_id);
            }
        }
    }

    pub(super) async fn reconcile_expired(&self, pool: &sqlx::MySqlPool) {
        let expired: Vec<_> = self
            .state
            .lock()
            .map(|state| {
                state
                    .entries
                    .values()
                    .filter(|(_, touched)| touched.elapsed() >= CAPABILITY_TTL)
                    .take(GC_BATCH)
                    .map(|(lease, _)| lease.clone())
                    .collect()
            })
            .unwrap_or_default();
        for lease in expired {
            // TTL alone never revokes a capability or permits replay of UNKNOWN.
            if matches!(
                astral_db::owned_delta_lease_is_retired(pool, &lease).await,
                Ok(true)
            ) {
                self.remove(lease.identity());
            }
        }
    }
}

impl OwnedCapabilityReservation {
    fn commit(
        mut self,
        expected_state: Arc<Mutex<CapabilityState>>,
        lease: OwnedDeltaLease,
    ) -> Result<(), RuntimeAccessError> {
        if !Arc::ptr_eq(&self.state, &expected_state) {
            return Err(RuntimeAccessError::PublicationUnknown(
                "code=auth_projector.capability_reservation_mismatch".to_owned(),
            ));
        }
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| {
                RuntimeAccessError::PublicationUnknown(
                    "code=auth_projector.claim_committed_capability_unavailable".to_owned(),
                )
            })?;
            if state.reservations == 0 {
                return Err(RuntimeAccessError::PublicationUnknown(
                    "code=auth_projector.capability_reservation_missing".to_owned(),
                ));
            }
            let id = lease.identity().delta_event_id;
            if state.entries.len() >= state.capacity && !state.entries.contains_key(&id) {
                return Err(RuntimeAccessError::PublicationUnknown(
                    "code=auth_projector.claim_committed_capability_capacity".to_owned(),
                ));
            }
            state.reservations -= 1;
            state.entries.insert(id, (lease, Instant::now()));
            Ok(())
        })();
        if result.is_ok() {
            self.active = false;
        }
        result
    }
}

impl Drop for OwnedCapabilityReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut state) = self.state.lock() {
            state.reservations = state.reservations.saturating_sub(1);
        }
    }
}

impl Default for CapabilityState {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            reservations: 0,
            capacity: CAPABILITY_LIMIT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_make_capacity_atomic_and_release_on_drop() {
        let capabilities = OwnedCapabilities::with_capacity(1);
        let first = capabilities.reserve().expect("first permit");
        assert!(capabilities.reserve().is_err());
        drop(first);
        assert!(capabilities.reserve().is_ok());
    }

    #[test]
    fn concurrent_capacity_one_reservation_has_exactly_one_winner() {
        use std::sync::Barrier;

        let capabilities = Arc::new(OwnedCapabilities::with_capacity(1));
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let capabilities = Arc::clone(&capabilities);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let reservation = capabilities.reserve().ok();
                barrier.wait();
                reservation.is_some()
            }));
        }
        barrier.wait();
        barrier.wait();
        let winners = threads
            .into_iter()
            .map(|thread| thread.join().expect("reservation thread"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }
}
