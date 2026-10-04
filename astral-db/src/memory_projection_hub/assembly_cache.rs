//! Bounded memoization of complete evidence assembled from immutable published states.

use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use astral_types::{CanonicalGrant, PublishedCardAuthorization, PublishedCardEvidenceScope};

use super::{AuthorizationPublishedState, ReadToken, RefillScope};
use crate::authorization_projection_repository::AuthorizationCurrentPointerRecord;
use crate::grant_repository::Sha256Digest;

const MAX_ENTRIES: usize = 1_024;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;
const TTL: Duration = Duration::from_secs(1);

#[derive(Clone, PartialEq, Eq)]
struct PublicationStamp {
    pointer: AuthorizationCurrentPointerRecord,
    manifest_id: i64,
    generation: u64,
    source_generation: u64,
    projected_generation: u64,
    revoke_fence: u64,
    manifest_digest: Sha256Digest,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AssemblyStamp {
    token: ReadToken,
    read_unix_seconds: i64,
    publications: Vec<PublicationStamp>,
}

impl AssemblyStamp {
    pub(super) fn new(
        token: ReadToken,
        read_unix_seconds: i64,
        states: &[Arc<AuthorizationPublishedState>],
    ) -> Self {
        let mut publications: Vec<_> = states
            .iter()
            .map(|state| PublicationStamp {
                pointer: state.pointer.clone(),
                manifest_id: state.manifest_id,
                generation: state.generation,
                source_generation: state.source_generation,
                projected_generation: state.projected_generation,
                revoke_fence: state.revoke_fence,
                manifest_digest: state.manifest_digest,
            })
            .collect();
        publications.sort_unstable_by(|a, b| {
            let a = &a.pointer.identity;
            let b = &b.pointer.identity;
            (a.tenant_id, &a.aggregate_type, a.aggregate_id).cmp(&(
                b.tenant_id,
                &b.aggregate_type,
                b.aggregate_id,
            ))
        });
        Self {
            token,
            read_unix_seconds,
            publications,
        }
    }

    fn retained_bytes(&self) -> usize {
        self.publications.iter().fold(
            self.publications.capacity() * size_of::<PublicationStamp>(),
            |bytes, stamp| {
                bytes.saturating_add(
                    stamp.pointer.identity.aggregate_type.capacity()
                        + stamp.pointer.event_id.capacity()
                        + stamp.pointer.operation_id.capacity()
                        + stamp.pointer.compiler_version.capacity(),
                )
            },
        )
    }
}

struct Entry {
    stamp: AssemblyStamp,
    evidence: Arc<PublishedCardAuthorization>,
    installed_at: Instant,
    last_used: u64,
    bytes: usize,
}

#[derive(Default)]
struct Entries {
    values: HashMap<RefillScope, Entry>,
    order: BTreeMap<u64, RefillScope>,
    last_gc: Option<Instant>,
    bytes: usize,
    clock: u64,
    #[cfg(test)]
    hits: usize,
}

impl Entries {
    fn remove(&mut self, scope: &RefillScope) {
        if let Some(entry) = self.values.remove(scope) {
            self.order.remove(&entry.last_used);
            self.bytes = self.bytes.saturating_sub(entry.bytes);
        }
    }

    fn tick(&mut self) -> u64 {
        if self.clock == u64::MAX {
            self.values.clear();
            self.order.clear();
            self.bytes = 0;
            self.clock = 0;
        }
        self.clock += 1;
        self.clock
    }
}

#[derive(Default)]
pub(super) struct AssemblyCache {
    entries: Mutex<Entries>,
}

impl AssemblyCache {
    pub(super) fn get(
        &self,
        scope: &PublishedCardEvidenceScope,
        stamp: &AssemblyStamp,
        now: Instant,
    ) -> Option<Arc<PublishedCardAuthorization>> {
        let mut entries = self.entries.lock().ok()?;
        let key = RefillScope::from(scope);
        let current = entries.values.get(&key).is_some_and(|entry| {
            entry.stamp == *stamp
                && now
                    .checked_duration_since(entry.installed_at)
                    .is_some_and(|age| age < TTL)
        });
        if !current {
            entries.remove(&key);
            return None;
        }
        let last_used = entries.tick();
        let entry = entries.values.get_mut(&key)?;
        let previous = entry.last_used;
        entry.last_used = last_used;
        let evidence = Arc::clone(&entry.evidence);
        entries.order.remove(&previous);
        entries.order.insert(last_used, key);
        #[cfg(test)]
        {
            entries.hits += 1;
        }
        Some(evidence)
    }

    pub(super) fn can_store(stamp: &AssemblyStamp, evidence: &PublishedCardAuthorization) -> bool {
        Self::entry_bytes(stamp, evidence) <= MAX_ENTRY_BYTES
    }

    fn entry_bytes(stamp: &AssemblyStamp, evidence: &PublishedCardAuthorization) -> usize {
        evidence_retained_bytes(evidence)
            .saturating_add(stamp.retained_bytes())
            .saturating_add(size_of::<Entry>() + size_of::<RefillScope>() + 256)
    }

    pub(super) fn insert(
        &self,
        scope: &PublishedCardEvidenceScope,
        stamp: AssemblyStamp,
        evidence: Arc<PublishedCardAuthorization>,
        now: Instant,
    ) {
        let bytes = Self::entry_bytes(&stamp, &evidence);
        if bytes > MAX_ENTRY_BYTES {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.last_gc.is_none_or(|last| {
            now.checked_duration_since(last)
                .is_none_or(|age| age >= TTL)
        }) {
            let expired: Vec<_> = entries
                .values
                .iter()
                .filter(|(_, entry)| {
                    !now.checked_duration_since(entry.installed_at)
                        .is_some_and(|age| age < TTL)
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                entries.remove(&key);
            }
            entries.last_gc = Some(now);
        }
        let key = RefillScope::from(scope);
        entries.remove(&key);
        while entries.values.len() >= MAX_ENTRIES || entries.bytes.saturating_add(bytes) > MAX_BYTES
        {
            let Some(oldest) = entries.order.first_key_value().map(|(_, key)| key.clone()) else {
                return;
            };
            entries.remove(&oldest);
        }
        let last_used = entries.tick();
        entries.bytes = entries.bytes.saturating_add(bytes);
        entries.order.insert(last_used, key.clone());
        entries.values.insert(
            key,
            Entry {
                stamp,
                evidence,
                installed_at: now,
                last_used,
                bytes,
            },
        );
    }

    #[cfg(test)]
    pub(super) fn hits(&self) -> usize {
        self.entries.lock().unwrap().hits
    }
}

fn grant_heap_bytes(grant: &CanonicalGrant) -> usize {
    let provenance = &grant.provenance;
    grant.resource.capacity()
        + grant.action.capacity()
        + provenance.source_id.capacity()
        + provenance.source_entry.as_ref().map_or(0, String::capacity)
        + provenance.binding_id.as_ref().map_or(0, String::capacity)
        + provenance
            .delegation_id
            .as_ref()
            .map_or(0, String::capacity)
        + provenance.operation_id.capacity()
        + provenance.event_id.as_ref().map_or(0, String::capacity)
}

fn evidence_retained_bytes(evidence: &PublishedCardAuthorization) -> usize {
    let mut bytes = size_of::<PublishedCardAuthorization>()
        + evidence.manifests.capacity()
            * size_of::<astral_types::PublishedAggregateManifestSummary>()
        + evidence.records.capacity() * size_of::<astral_types::VerifiedPublishedGrantRecord>()
        + evidence.effective_grants.capacity() * size_of::<CanonicalGrant>();
    for manifest in &evidence.manifests {
        bytes = bytes.saturating_add(
            manifest.aggregate_type.capacity()
                + manifest.semantic_hash_hex.capacity()
                + manifest.dependency_hash_hex.capacity()
                + manifest.manifest_digest_hex.capacity()
                + manifest.compiler_version.capacity()
                + manifest.event_id.capacity()
                + manifest.operation_id.capacity(),
        );
    }
    for record in &evidence.records {
        bytes = bytes.saturating_add(
            record.aggregate_type.capacity()
                + record.event_id.capacity()
                + record.operation_id.capacity()
                + record.semantic_hash_hex.capacity()
                + record.dependency_hash_hex.capacity()
                + record.compiler_version.capacity()
                + grant_heap_bytes(&record.grant),
        );
    }
    for grant in &evidence.effective_grants {
        bytes = bytes.saturating_add(grant_heap_bytes(grant));
    }
    bytes
}

#[cfg(test)]
mod tests;
