//! memory—v1: Plan expired and revoked session removal under the authority writer.

use super::{MemoryV1SessionAuthorityError, SessionState};

/// A conservative bound on the earliest retained expiry and a dirty bit set
/// when a record is revoked. Neither participates in authorization.
#[derive(Default)]
pub(super) struct CleanupHint {
    earliest_expiry: Option<i64>,
    has_revoked: bool,
}

impl CleanupHint {
    // memory—v1: Every insertion updates the hint before the writer releases.
    pub(super) fn note_expiry(&mut self, expiry: i64) {
        self.earliest_expiry = Some(self.earliest_expiry.map_or(expiry, |old| old.min(expiry)));
    }

    // memory—v1: Mark revocation even when its generation cannot advance.
    pub(super) fn note_revocation(&mut self) {
        self.has_revoked = true;
    }
}

pub(super) struct CleanupPlan {
    remove: Vec<[u8; 32]>,
    remaining: CleanupHint,
}

impl CleanupPlan {
    // memory—v1: The caller holds the authority writer from planning to apply.
    // A normal login with no eligible rows does not scan or allocate a list.
    pub(super) fn prepare(
        state: &SessionState,
        cutoff: i64,
    ) -> Result<Option<Self>, MemoryV1SessionAuthorityError> {
        if !state.cleanup.has_revoked
            && state
                .cleanup
                .earliest_expiry
                .is_none_or(|earliest| earliest > cutoff)
        {
            return Ok(None);
        }
        let mut plan = Self {
            remove: Vec::new(),
            remaining: CleanupHint::default(),
        };
        for (digest, record) in &state.records {
            let expiry = record.facts.expires_at_unix_seconds();
            if record.revoked || expiry <= cutoff {
                plan.remove
                    .try_reserve(1)
                    .map_err(|_| MemoryV1SessionAuthorityError::CapacityExhausted)?;
                plan.remove.push(*digest);
            } else {
                plan.remaining.note_expiry(expiry);
            }
        }
        Ok(Some(plan))
    }

    pub(super) fn len(&self) -> usize {
        self.remove.len()
    }

    // memory—v1: Apply only after the caller has proved issuance. Account for
    // a newly inserted record when rebuilding the hint from the retained set.
    pub(super) fn apply(self, state: &mut SessionState, inserted_expiry: Option<i64>) {
        for digest in self.remove {
            state.records.remove(&digest);
        }
        state.cleanup = self.remaining;
        if let Some(expiry) = inserted_expiry {
            state.cleanup.note_expiry(expiry);
        }
    }
}
