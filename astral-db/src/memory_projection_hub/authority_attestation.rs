//! Atomic installation of a bounded, explicitly certified serving partition.

use super::{AuthorityFrontier, HubMaps, MemoryProjectionHub, RefillScope, MAX_MIRROR_STATES};
use astral_types::{
    AuthorizationAuthorityState, CertifiedAuthorizationState, PublishedCardEvidenceScope,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// A reconciliation stamp; it carries no authorization capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedPartitionToken {
    epoch: u64,
    mutation_revision: u64,
    health_revision: u64,
}

pub(super) struct CertifiedPartitionCoverage {
    epoch: u64,
    mutation_revision: u64,
    scopes: HashSet<RefillScope>,
    expires_at: i64,
    observed: Instant,
    lifetime: Duration,
}

impl HubMaps {
    pub(super) fn certified_partition_ready(&self) -> bool {
        let Some(coverage) = &self.certified_partition else {
            return false;
        };
        coverage.epoch == self.durable_reconcile_epoch
            && coverage.mutation_revision == self.mutation_revision
            && !coverage.scopes.is_empty()
            && coverage.scopes.len() == self.certified_states.len()
            && coverage
                .scopes
                .iter()
                .all(|scope| self.certified_states.contains_key(scope))
            && OffsetDateTime::now_utc().unix_timestamp() < coverage.expires_at
            && coverage.observed.elapsed() < coverage.lifetime
    }

    pub(super) fn certified_partition_contains(&self, scope: &RefillScope) -> bool {
        self.certified_partition_ready()
            && self
                .certified_partition
                .as_ref()
                .is_some_and(|coverage| coverage.scopes.contains(scope))
    }
}

#[cfg(test)]
pub(super) fn seal_partition_for_test(hub: &MemoryProjectionHub, expires_at: i64) {
    let mut maps = hub.maps.write().unwrap();
    maps.certified_partition = Some(CertifiedPartitionCoverage {
        epoch: maps.durable_reconcile_epoch,
        mutation_revision: maps.mutation_revision,
        scopes: maps.certified_states.keys().cloned().collect(),
        expires_at,
        observed: Instant::now(),
        lifetime: Duration::from_secs(600),
    });
}

impl MemoryProjectionHub {
    /// Compare an independently verified linearizable authority observation.
    /// Success cannot extend a certificate/proof lifetime or clear recovery gates.
    pub(crate) fn verify_serving_authority_observation(
        &self,
        response: &astral_types::AuthorityFenceReadResponse,
    ) -> Result<(), String> {
        let maps = self
            .maps
            .read()
            .map_err(|_| "memory projection hub lock poisoned")?;
        let frontier = &response.global_frontier;
        let observed = AuthorityFrontier {
            authority_id: frontier.authority_id.clone(),
            authority_term: frontier.authority_term,
            global_fence_sequence: frontier.global_fence_sequence,
            key_id: frontier.key_id.clone(),
            key_epoch: frontier.key_epoch,
        };
        if maps.authority_state != AuthorizationAuthorityState::Serving
            || !maps.certified_partition_ready()
            || maps.authority_frontier.as_ref() != Some(&observed)
        {
            return Err("serving partition differs from the current authority frontier".into());
        }
        response
            .read_gate
            .validate()
            .map_err(|error| error.to_string())?;
        for certified in maps.certified_states.values() {
            let scope = astral_types::AuthorityProtocolScope::Card(certified.proof().scope.clone());
            if response
                .read_gate
                .blocks(&scope)
                .map_err(|error| error.to_string())?
            {
                return Err("authority reservation blocks the serving partition".into());
            }
        }
        Ok(())
    }

    /// Capture only after durable reconciliation. Any local writer, invalidation
    /// or health transition during remote attestation invalidates this stamp.
    pub fn capture_certified_partition_token(&self) -> Result<CertifiedPartitionToken, String> {
        let maps = self
            .maps
            .read()
            .map_err(|_| "memory projection hub lock poisoned")?;
        if maps.authority_state != AuthorizationAuthorityState::FenceSyncing
            || maps.durable_reconcile_mutation_revision != Some(maps.mutation_revision)
            || maps.active_source_writers != 0
            || maps.uncertain_source
            || maps.warming_up
            || maps.authority_fence_unavailable()
        {
            return Err("certified partition requires an unraced durable reconciliation".into());
        }
        Ok(CertifiedPartitionToken {
            epoch: maps.durable_reconcile_epoch,
            mutation_revision: maps.mutation_revision,
            health_revision: maps.health_revision,
        })
    }

    /// Install exactly the scope set attested by the runtime owner, at one
    /// frontier. Missing scopes remain unavailable; raw mirror rows are hints.
    pub fn install_certified_partition(
        &self,
        token: CertifiedPartitionToken,
        entries: Vec<(PublishedCardEvidenceScope, CertifiedAuthorizationState)>,
    ) -> Result<usize, String> {
        if entries.is_empty() || entries.len() > MAX_MIRROR_STATES {
            return Err("certified partition is empty or exceeds capacity".into());
        }
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut roots = HashMap::with_capacity(entries.len());
        let mut frontier = None;
        let mut expires_at = i64::MAX;
        for (scope, certified) in entries {
            scope.validate().map_err(|error| error.to_string())?;
            certified
                .validate_at(now, &scope)
                .map_err(|error| error.to_string())?;
            if certified.certificate().is_none() {
                return Err(
                    "startup partition requires an attached publication certificate".into(),
                );
            }
            let proof = certified.proof();
            let candidate = AuthorityFrontier::from_proof(&proof);
            if frontier
                .as_ref()
                .is_some_and(|previous| previous != &candidate)
            {
                return Err("certified partition spans different global frontiers".into());
            }
            frontier = Some(candidate);
            expires_at = expires_at.min(proof.expires_at);
            if let Some(certificate_expiry) = certified
                .certificate()
                .and_then(|certificate| certificate.expires_at)
            {
                expires_at = expires_at.min(certificate_expiry);
            }
            if roots
                .insert(RefillScope::from(&scope), Arc::new(certified))
                .is_some()
            {
                return Err("certified partition contains duplicate scopes".into());
            }
        }
        let mut maps = self
            .maps
            .write()
            .map_err(|_| "memory projection hub lock poisoned")?;
        if maps.authority_state != AuthorizationAuthorityState::FenceSyncing
            || token.epoch != maps.durable_reconcile_epoch
            || token.mutation_revision != maps.mutation_revision
            || token.health_revision != maps.health_revision
            || maps.durable_reconcile_mutation_revision != Some(token.mutation_revision)
            || maps.active_source_writers != 0
            || maps.uncertain_source
            || maps.warming_up
            || maps.authority_fence_unavailable()
        {
            return Err("local state changed during certified partition attestation".into());
        }
        let frontier = frontier.ok_or("certified partition has no authority frontier")?;
        if let Some(previous) = &maps.authority_frontier {
            previous.validate_successor(&frontier)?;
        }
        for (scope, next) in &roots {
            if let Some(previous) = maps.certified_states.get(scope) {
                next.validate_successor_of(previous)
                    .map_err(|error| error.to_string())?;
            }
        }
        let count = roots.len();
        let observed = Instant::now();
        let lifetime = u64::try_from(expires_at.saturating_sub(now))
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or("certified partition expired before installation")?;
        maps.certified_partition = Some(CertifiedPartitionCoverage {
            epoch: token.epoch,
            mutation_revision: token.mutation_revision,
            scopes: roots.keys().cloned().collect(),
            expires_at,
            observed,
            lifetime: Duration::from_secs(lifetime),
        });
        maps.certified_installed_at = roots
            .keys()
            .cloned()
            .map(|scope| (scope, observed))
            .collect();
        maps.certified_states = roots;
        maps.authority_frontier = Some(frontier);
        Ok(count)
    }
}
