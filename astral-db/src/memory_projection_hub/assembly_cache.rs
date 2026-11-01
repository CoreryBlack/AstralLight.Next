//! Bounded memoization of complete evidence assembled from immutable published states.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use astral_types::{
    CanonicalGrant, PublicationStamp, PublishedCardAuthorization, PublishedCardEvidenceScope,
};

use super::{AuthorizationPublishedState, ReadToken, RefillScope};
use crate::authorization_projection_repository::AuthorizationCurrentPointerRecord;
#[cfg(test)]
use crate::grant_repository::Sha256Digest;

const MAX_ENTRIES: usize = 1_024;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;
const TTL: Duration = Duration::from_secs(1);
const STRIPE_COUNT: usize = 8;
const STRIPE_MAX_ENTRIES: usize = MAX_ENTRIES / STRIPE_COUNT;

#[derive(Clone, PartialEq, Eq)]
struct AssemblyPublicationIdentity {
    pointer: AuthorizationCurrentPointerRecord,
    stamp: PublicationStamp,
    manifest_id: i64,
    source_generation: u64,
    projected_generation: u64,
    revoke_fence: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AssemblyStamp {
    token: ReadToken,
    read_unix_seconds: i64,
    publications: Vec<AssemblyPublicationIdentity>,
}

impl AssemblyStamp {
    pub(super) fn new(
        token: ReadToken,
        read_unix_seconds: i64,
        states: &[Arc<AuthorizationPublishedState>],
    ) -> Result<Self, String> {
        let mut publications: Vec<_> = states
            .iter()
            .map(|state| {
                Ok(AssemblyPublicationIdentity {
                    pointer: state.pointer.clone(),
                    stamp: state
                        .publication_stamp()
                        .map_err(|error| error.to_string())?,
                    manifest_id: state.manifest_id,
                    source_generation: state.source_generation,
                    projected_generation: state.projected_generation,
                    revoke_fence: state.revoke_fence,
                })
            })
            .collect::<Result<_, String>>()?;
        publications.sort_unstable_by(|a, b| {
            let a = &a.pointer.identity;
            let b = &b.pointer.identity;
            (a.tenant_id, &a.aggregate_type, a.aggregate_id).cmp(&(
                b.tenant_id,
                &b.aggregate_type,
                b.aggregate_id,
            ))
        });
        Ok(Self {
            token,
            read_unix_seconds,
            publications,
        })
    }

    fn retained_bytes(&self) -> usize {
        self.publications.iter().fold(
            self.publications.capacity() * size_of::<AssemblyPublicationIdentity>(),
            |bytes, stamp| {
                bytes.saturating_add(
                    stamp.pointer.identity.aggregate_type.capacity()
                        + stamp.pointer.event_id.capacity()
                        + stamp.pointer.operation_id.capacity()
                        + stamp.pointer.compiler_version.capacity()
                        + stamp.stamp.manifest_digest_hex.capacity(),
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
    #[cfg(any(test, feature = "performance-attribution"))]
    hits: usize,
    #[cfg(any(test, feature = "performance-attribution"))]
    misses: usize,
    #[cfg(any(test, feature = "performance-attribution"))]
    arc_clones: usize,
    #[cfg(any(test, feature = "performance-attribution"))]
    get_lock_wait_ns: u64,
    #[cfg(any(test, feature = "performance-attribution"))]
    insert_lock_wait_ns: u64,
    #[cfg(any(test, feature = "performance-attribution"))]
    get_lock_hold_ns: u64,
    #[cfg(any(test, feature = "performance-attribution"))]
    insert_lock_hold_ns: u64,
    #[cfg(any(test, feature = "performance-attribution"))]
    gc_removed: usize,
    #[cfg(any(test, feature = "performance-attribution"))]
    evictions: usize,
}

impl Entries {
    fn remove(&mut self, scope: &RefillScope) -> Option<Entry> {
        let entry = self.values.remove(scope)?;
        self.order.remove(&entry.last_used);
        self.bytes = self.bytes.saturating_sub(entry.bytes);
        Some(entry)
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

#[cfg(any(test, feature = "performance-attribution"))]
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct CacheAttribution {
    pub hits: usize,
    pub misses: usize,
    pub arc_clones: usize,
    pub get_lock_wait_ns: u64,
    pub insert_lock_wait_ns: u64,
    pub get_lock_hold_ns: u64,
    pub insert_lock_hold_ns: u64,
    pub gc_removed: usize,
    pub evictions: usize,
}

#[derive(Default)]
struct Budget {
    entries: usize,
    bytes: usize,
}

impl Budget {
    fn remove(&mut self, entry: &Entry) {
        self.entries = self.entries.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(entry.bytes);
    }
}

#[cfg(any(test, feature = "performance-attribution"))]
fn record_get_lock_hold(entries: &mut Entries, started: Instant) {
    entries.get_lock_hold_ns = entries
        .get_lock_hold_ns
        .saturating_add(started.elapsed().as_nanos() as u64);
}

#[cfg(any(test, feature = "performance-attribution"))]
fn record_insert_lock_hold(entries: &mut Entries, started: Instant) {
    entries.insert_lock_hold_ns = entries
        .insert_lock_hold_ns
        .saturating_add(started.elapsed().as_nanos() as u64);
}

#[cfg(any(test, feature = "performance-attribution"))]
fn record_get_lock_wait(entries: &mut Entries, started: Instant) {
    entries.get_lock_wait_ns = entries
        .get_lock_wait_ns
        .saturating_add(started.elapsed().as_nanos() as u64);
}

#[cfg(any(test, feature = "performance-attribution"))]
fn record_insert_lock_wait(entries: &mut Entries, started: Instant) {
    entries.insert_lock_wait_ns = entries
        .insert_lock_wait_ns
        .saturating_add(started.elapsed().as_nanos() as u64);
}

#[cfg(any(test, feature = "performance-attribution"))]
fn record_gc_removed(entries: &mut Entries) {
    entries.gc_removed = entries.gc_removed.saturating_add(1);
}

#[cfg(any(test, feature = "performance-attribution"))]
fn record_eviction(entries: &mut Entries) {
    entries.evictions = entries.evictions.saturating_add(1);
}

#[cfg(any(test, feature = "performance-attribution"))]
#[inline]
fn record_hit(entries: &mut Entries) {
    entries.hits = entries.hits.saturating_add(1);
}

#[cfg(any(test, feature = "performance-attribution"))]
#[inline]
fn record_miss(entries: &mut Entries) {
    entries.misses = entries.misses.saturating_add(1);
}

pub(super) struct AssemblyCache {
    stripes: Box<[Mutex<Entries>; STRIPE_COUNT]>,
    budget: Mutex<Budget>,
}

impl Default for AssemblyCache {
    fn default() -> Self {
        Self {
            stripes: std::array::from_fn(|_| Mutex::new(Entries::default())).into(),
            budget: Mutex::new(Budget::default()),
        }
    }
}

impl AssemblyCache {
    fn stripe_index(scope: &PublishedCardEvidenceScope) -> usize {
        let key = RefillScope::from(scope);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % STRIPE_COUNT
    }

    fn stripe(&self, scope: &PublishedCardEvidenceScope) -> &Mutex<Entries> {
        &self.stripes[Self::stripe_index(scope)]
    }
    pub(super) fn get(
        &self,
        scope: &PublishedCardEvidenceScope,
        stamp: &AssemblyStamp,
        now: Instant,
    ) -> Option<Arc<PublishedCardAuthorization>> {
        #[cfg(any(test, feature = "performance-attribution"))]
        let lock_started = Instant::now();
        let mut entries = self.stripe(scope).lock().ok()?;
        #[cfg(any(test, feature = "performance-attribution"))]
        let hold_started = Instant::now();
        #[cfg(any(test, feature = "performance-attribution"))]
        record_get_lock_wait(&mut entries, lock_started);

        let key = RefillScope::from(scope);
        let current = entries.values.get(&key).is_some_and(|entry| {
            entry.stamp == *stamp
                && now
                    .checked_duration_since(entry.installed_at)
                    .is_some_and(|age| age < TTL)
        });
        if !current {
            #[cfg(any(test, feature = "performance-attribution"))]
            {
                record_miss(&mut entries);
                record_get_lock_hold(&mut entries, hold_started);
            }
            drop(entries);

            let Ok(mut budget) = self.budget.lock() else {
                return None;
            };
            #[cfg(any(test, feature = "performance-attribution"))]
            let retry_lock_started = Instant::now();
            let Ok(mut entries) = self.stripe(scope).lock() else {
                return None;
            };
            #[cfg(any(test, feature = "performance-attribution"))]
            let retry_hold_started = Instant::now();
            #[cfg(any(test, feature = "performance-attribution"))]
            record_get_lock_wait(&mut entries, retry_lock_started);

            let still_current = entries.values.get(&key).is_some_and(|entry| {
                entry.stamp == *stamp
                    && now
                        .checked_duration_since(entry.installed_at)
                        .is_some_and(|age| age < TTL)
            });
            if still_current {
                #[cfg(any(test, feature = "performance-attribution"))]
                record_get_lock_hold(&mut entries, retry_hold_started);
                drop(entries);
                drop(budget);
                return self.get(scope, stamp, now);
            }
            let removed = entries.remove(&key);
            if let Some(entry) = removed.as_ref() {
                budget.remove(entry);
            }
            #[cfg(any(test, feature = "performance-attribution"))]
            record_get_lock_hold(&mut entries, retry_hold_started);
            drop(entries);
            drop(budget);
            drop(removed);
            return None;
        }

        let last_used = entries.tick();
        let Some(entry) = entries.values.get_mut(&key) else {
            #[cfg(any(test, feature = "performance-attribution"))]
            record_get_lock_hold(&mut entries, hold_started);
            return None;
        };
        let previous = entry.last_used;
        entry.last_used = last_used;
        let evidence = Arc::clone(&entry.evidence);
        entries.order.remove(&previous);
        entries.order.insert(last_used, key);
        #[cfg(any(test, feature = "performance-attribution"))]
        {
            record_hit(&mut entries);
            entries.arc_clones = entries.arc_clones.saturating_add(1);
            record_get_lock_hold(&mut entries, hold_started);
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
        #[cfg(any(test, feature = "performance-attribution"))]
        let lock_started = Instant::now();
        let Ok(mut budget) = self.budget.lock() else {
            return;
        };
        let Ok(mut entries) = self.stripe(scope).lock() else {
            return;
        };
        #[cfg(any(test, feature = "performance-attribution"))]
        let hold_started = Instant::now();
        #[cfg(any(test, feature = "performance-attribution"))]
        record_insert_lock_wait(&mut entries, lock_started);

        let mut dropped = Vec::new();
        if entries.last_gc.is_none_or(|last| {
            now.checked_duration_since(last)
                .is_none_or(|age| age >= TTL)
        }) {
            let expired: Vec<_> = entries
                .values
                .iter()
                .filter(|(_, entry)| {
                    now.checked_duration_since(entry.installed_at)
                        .is_none_or(|age| age >= TTL)
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                if let Some(entry) = entries.remove(&key) {
                    budget.remove(&entry);
                    #[cfg(any(test, feature = "performance-attribution"))]
                    record_gc_removed(&mut entries);
                    dropped.push(entry);
                }
            }
            entries.last_gc = Some(now);
        }
        let key = RefillScope::from(scope);
        if let Some(entry) = entries.remove(&key) {
            budget.remove(&entry);
            dropped.push(entry);
        }
        while entries.values.len() >= STRIPE_MAX_ENTRIES
            || budget.entries >= MAX_ENTRIES
            || budget.bytes.saturating_add(bytes) > MAX_BYTES
        {
            let Some(oldest) = entries.order.first_key_value().map(|(_, key)| key.clone()) else {
                #[cfg(any(test, feature = "performance-attribution"))]
                record_insert_lock_hold(&mut entries, hold_started);
                drop(entries);
                drop(budget);
                drop(dropped);
                return;
            };
            if let Some(entry) = entries.remove(&oldest) {
                budget.remove(&entry);
                #[cfg(any(test, feature = "performance-attribution"))]
                record_eviction(&mut entries);
                dropped.push(entry);
            }
        }
        let last_used = entries.tick();
        entries.bytes = entries.bytes.saturating_add(bytes);
        budget.entries = budget.entries.saturating_add(1);
        budget.bytes = budget.bytes.saturating_add(bytes);
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
        #[cfg(any(test, feature = "performance-attribution"))]
        record_insert_lock_hold(&mut entries, hold_started);
        drop(entries);
        drop(budget);
        drop(dropped);
    }

    #[cfg(test)]
    pub(super) fn hits(&self) -> usize {
        self.stripes
            .iter()
            .filter_map(|stripe| stripe.lock().ok().map(|entries| entries.hits))
            .sum()
    }

    #[cfg(any(test, feature = "performance-attribution"))]
    pub(super) fn detailed_attribution(&self) -> CacheAttribution {
        self.stripes
            .iter()
            .fold(CacheAttribution::default(), |mut total, stripe| {
                let Ok(entries) = stripe.lock() else {
                    return total;
                };
                total.hits = total.hits.saturating_add(entries.hits);
                total.misses = total.misses.saturating_add(entries.misses);
                total.arc_clones = total.arc_clones.saturating_add(entries.arc_clones);
                total.get_lock_wait_ns = total
                    .get_lock_wait_ns
                    .saturating_add(entries.get_lock_wait_ns);
                total.insert_lock_wait_ns = total
                    .insert_lock_wait_ns
                    .saturating_add(entries.insert_lock_wait_ns);
                total.get_lock_hold_ns = total
                    .get_lock_hold_ns
                    .saturating_add(entries.get_lock_hold_ns);
                total.insert_lock_hold_ns = total
                    .insert_lock_hold_ns
                    .saturating_add(entries.insert_lock_hold_ns);
                total.gc_removed = total.gc_removed.saturating_add(entries.gc_removed);
                total.evictions = total.evictions.saturating_add(entries.evictions);
                total
            })
    }

    #[cfg(any(test, feature = "performance-attribution"))]
    #[allow(dead_code)]
    pub(super) fn attribution(&self) -> (usize, usize, usize, u64, u64) {
        self.stripes.iter().fold((0, 0, 0, 0, 0), |total, stripe| {
            let Ok(entries) = stripe.lock() else {
                return total;
            };
            (
                total.0.saturating_add(entries.hits),
                total.1.saturating_add(entries.misses),
                total.2.saturating_add(entries.arc_clones),
                total.3.saturating_add(entries.get_lock_wait_ns),
                total.4.saturating_add(entries.insert_lock_wait_ns),
            )
        })
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
