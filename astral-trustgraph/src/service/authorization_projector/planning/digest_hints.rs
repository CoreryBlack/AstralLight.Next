use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use policy_engine::ProjectionKey;

use crate::observability::{record_segment_digest_hint_cache, SegmentDigestHintCacheOutcome};

pub(crate) const DIGEST_HINT_CACHE_CAPACITY: usize = 20_000;
pub(crate) const DIGEST_HINT_CACHE_TTL: Duration = Duration::from_secs(600);

static SEGMENT_DIGEST_HINTS: LazyLock<Mutex<DigestHintCache>> = LazyLock::new(|| {
    Mutex::new(DigestHintCache::new(
        DIGEST_HINT_CACHE_CAPACITY,
        DIGEST_HINT_CACHE_TTL,
    ))
});

pub(crate) static SEGMENT_DIGEST_HINT_STATS: (
    std::sync::atomic::AtomicU64,
    std::sync::atomic::AtomicU64,
) = (
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct DigestHintEntry {
    content_hash: String,
    digest_hex: String,
    expires_at: Instant,
    sequence: u128,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DigestHintMaintenance {
    pub(crate) evicted: usize,
    pub(crate) expired: usize,
}

/// Process-local, bounded FIFO cache for exact payload digest hints.
///
/// Queue generations make updates O(1); stale queue records are compacted before
/// they can grow beyond twice the configured entry capacity.
pub(crate) struct DigestHintCache {
    entries: HashMap<ProjectionKey, DigestHintEntry>,
    order: VecDeque<(ProjectionKey, u128)>,
    capacity: usize,
    ttl: Duration,
    next_sequence: u128,
}

impl DigestHintCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            ttl,
            next_sequence: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(capacity: usize, ttl: Duration) -> Self {
        Self::new(capacity, ttl)
    }

    fn get_at(
        &mut self,
        key: &ProjectionKey,
        content_hash: &str,
        now: Instant,
    ) -> (Option<String>, DigestHintMaintenance) {
        let mut maintenance = DigestHintMaintenance::default();
        self.collect_expired(now, &mut maintenance);
        let expired = self
            .entries
            .get(key)
            .is_some_and(|entry| entry.expires_at <= now);
        if expired {
            self.entries.remove(key);
            self.order.retain(|(queued_key, _)| queued_key != key);
            maintenance.expired += 1;
        }
        let digest = self
            .entries
            .get(key)
            .filter(|entry| entry.content_hash == content_hash)
            .map(|entry| entry.digest_hex.clone());
        (digest, maintenance)
    }

    #[cfg(test)]
    pub(crate) fn cached_at_for_test(
        &mut self,
        key: &ProjectionKey,
        content_hash: &str,
        now: Instant,
    ) -> (Option<String>, DigestHintMaintenance) {
        self.get_at(key, content_hash, now)
    }

    fn remember_at(
        &mut self,
        key: ProjectionKey,
        content_hash: String,
        digest_hex: String,
        now: Instant,
    ) -> DigestHintMaintenance {
        let mut maintenance = DigestHintMaintenance::default();
        self.collect_expired(now, &mut maintenance);
        if self.capacity == 0 {
            return maintenance;
        }

        let existing = self.entries.contains_key(&key);
        if !existing {
            while self.entries.len() >= self.capacity {
                if !self.evict_oldest() {
                    self.compact_order();
                    if !self.evict_oldest() {
                        break;
                    }
                }
                maintenance.evicted += 1;
            }
        }

        let sequence = match self.next_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.resequence_order();
                self.next_sequence + 1
            }
        };
        self.next_sequence = sequence;
        let expires_at = now.checked_add(self.ttl).unwrap_or(now);
        self.entries.insert(
            key.clone(),
            DigestHintEntry {
                content_hash,
                digest_hex,
                expires_at,
                sequence,
            },
        );
        self.order.push_back((key, sequence));
        self.compact_if_needed();
        maintenance
    }

    #[cfg(test)]
    pub(crate) fn remember_at_for_test(
        &mut self,
        key: ProjectionKey,
        content_hash: String,
        digest_hex: String,
        now: Instant,
    ) -> DigestHintMaintenance {
        self.remember_at(key, content_hash, digest_hex, now)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn queue_len(&self) -> usize {
        self.order.len()
    }

    fn collect_expired(&mut self, now: Instant, maintenance: &mut DigestHintMaintenance) {
        while let Some((key, sequence)) = self.order.front() {
            let current = self
                .entries
                .get(key)
                .filter(|entry| entry.sequence == *sequence);
            match current {
                None => {
                    self.order.pop_front();
                }
                Some(entry) if entry.expires_at <= now => {
                    let key = key.clone();
                    self.order.pop_front();
                    self.entries.remove(&key);
                    maintenance.expired += 1;
                }
                Some(_) => break,
            }
        }
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((key, sequence)) = self.order.pop_front() {
            let is_current = self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.sequence == sequence);
            if is_current {
                self.entries.remove(&key);
                return true;
            }
        }
        false
    }

    fn compact_if_needed(&mut self) {
        if self.order.len() > self.capacity.saturating_mul(2) {
            self.compact_order();
        }
    }

    fn compact_order(&mut self) {
        let mut current: Vec<_> = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.sequence, key.clone()))
            .collect();
        current.sort_unstable_by_key(|(sequence, _)| *sequence);
        self.order = current
            .into_iter()
            .map(|(sequence, key)| (key, sequence))
            .collect();
    }

    fn resequence_order(&mut self) {
        self.compact_order();
        for (index, (key, queued_sequence)) in self.order.iter_mut().enumerate() {
            let sequence = index as u128 + 1;
            if let Some(entry) = self.entries.get_mut(key) {
                entry.sequence = sequence;
            }
            *queued_sequence = sequence;
        }
        self.next_sequence = self.entries.len() as u128;
    }
}

pub(crate) trait DigestHintStore {
    fn cached_digest(&mut self, key: &ProjectionKey, content_hash: &str) -> Option<String>;

    fn remember_digest(&mut self, key: ProjectionKey, content_hash: String, digest_hex: String);
}

impl DigestHintStore for DigestHintCache {
    fn cached_digest(&mut self, key: &ProjectionKey, content_hash: &str) -> Option<String> {
        self.get_at(key, content_hash, Instant::now()).0
    }

    fn remember_digest(&mut self, key: ProjectionKey, content_hash: String, digest_hex: String) {
        self.remember_at(key, content_hash, digest_hex, Instant::now());
    }
}

#[cfg(test)]
pub(crate) struct DisabledDigestHintStore;

#[cfg(test)]
impl DigestHintStore for DisabledDigestHintStore {
    fn cached_digest(&mut self, _key: &ProjectionKey, _content_hash: &str) -> Option<String> {
        None
    }

    fn remember_digest(&mut self, _key: ProjectionKey, _content_hash: String, _digest_hex: String) {
    }
}

pub(crate) struct ProcessDigestHintStore;

impl DigestHintStore for ProcessDigestHintStore {
    fn cached_digest(&mut self, key: &ProjectionKey, content_hash: &str) -> Option<String> {
        let mut cache = SEGMENT_DIGEST_HINTS.lock().ok()?;
        let (digest, maintenance) = cache.get_at(key, content_hash, Instant::now());
        drop(cache);
        record_maintenance(maintenance);
        digest
    }

    fn remember_digest(&mut self, key: ProjectionKey, content_hash: String, digest_hex: String) {
        if let Ok(mut cache) = SEGMENT_DIGEST_HINTS.lock() {
            let maintenance = cache.remember_at(key, content_hash, digest_hex, Instant::now());
            drop(cache);
            record_maintenance(maintenance);
        }
    }
}

fn record_maintenance(maintenance: DigestHintMaintenance) {
    if maintenance.evicted > 0 {
        record_segment_digest_hint_cache(
            SegmentDigestHintCacheOutcome::Evicted,
            maintenance.evicted as u64,
        );
    }
    if maintenance.expired > 0 {
        record_segment_digest_hint_cache(
            SegmentDigestHintCacheOutcome::Expired,
            maintenance.expired as u64,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: i64) -> ProjectionKey {
        ProjectionKey::new(id, 42, format!("resource_{id}"), "read").unwrap()
    }

    fn value(
        cache: &mut DigestHintCache,
        key: &ProjectionKey,
        content_hash: &str,
        now: Instant,
    ) -> Option<String> {
        cache.cached_at_for_test(key, content_hash, now).0
    }

    #[test]
    fn cache_requires_key_and_content_hash_and_preserves_updated_entries() {
        let now = Instant::now();
        let a = key(1);
        let mut cache = DigestHintCache::new_for_test(2, Duration::from_secs(30));
        cache.remember_at_for_test(a.clone(), "hash-a".into(), "digest-a".into(), now);

        assert_eq!(
            value(&mut cache, &a, "hash-a", now),
            Some("digest-a".into())
        );
        assert_eq!(value(&mut cache, &a, "changed-hash", now), None);

        cache.remember_at_for_test(
            a.clone(),
            "changed-hash".into(),
            "digest-updated".into(),
            now + Duration::from_secs(1),
        );
        assert_eq!(value(&mut cache, &a, "hash-a", now), None);
        assert_eq!(
            value(&mut cache, &a, "changed-hash", now + Duration::from_secs(1)),
            Some("digest-updated".into())
        );
    }

    #[test]
    fn cache_expires_lazily_without_removing_a_refreshed_key() {
        let now = Instant::now();
        let a = key(1);
        let b = key(2);
        let mut cache = DigestHintCache::new_for_test(3, Duration::from_secs(5));
        cache.remember_at_for_test(a.clone(), "a1".into(), "d1".into(), now);
        cache.remember_at_for_test(
            b.clone(),
            "b1".into(),
            "db".into(),
            now + Duration::from_secs(1),
        );
        cache.remember_at_for_test(
            a.clone(),
            "a2".into(),
            "d2".into(),
            now + Duration::from_secs(3),
        );

        let (digest, maintenance) = cache.get_at(&a, "a2", now + Duration::from_secs(6));
        assert_eq!(digest.as_deref(), Some("d2"));
        assert_eq!(maintenance.expired, 1);
        assert_eq!(cache.len(), 1);

        let (digest, maintenance) = cache.get_at(&a, "a2", now + Duration::from_secs(8));
        assert_eq!(digest, None);
        assert_eq!(maintenance.expired, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_evicts_oldest_live_entry_and_compacts_stale_fifo_records() {
        let now = Instant::now();
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let mut cache = DigestHintCache::new_for_test(2, Duration::from_secs(30));
        cache.remember_at_for_test(a.clone(), "a1".into(), "da1".into(), now);
        cache.remember_at_for_test(b.clone(), "b1".into(), "db".into(), now);
        cache.remember_at_for_test(
            a.clone(),
            "a2".into(),
            "da2".into(),
            now + Duration::from_secs(1),
        );
        let maintenance = cache.remember_at_for_test(
            c.clone(),
            "c1".into(),
            "dc".into(),
            now + Duration::from_secs(2),
        );

        assert_eq!(maintenance.evicted, 1);
        assert_eq!(cache.len(), 2);
        assert_eq!(value(&mut cache, &a, "a2", now), Some("da2".into()));
        assert_eq!(value(&mut cache, &b, "b1", now), None);
        assert_eq!(value(&mut cache, &c, "c1", now), Some("dc".into()));

        for revision in 0..16 {
            cache.remember_at_for_test(
                a.clone(),
                format!("a{revision}"),
                format!("d{revision}"),
                now + Duration::from_secs(3 + revision),
            );
            assert!(cache.queue_len() <= cache.capacity.saturating_mul(2));
        }
    }

    #[test]
    fn zero_capacity_never_retains_hints() {
        let now = Instant::now();
        let mut cache = DigestHintCache::new_for_test(0, Duration::from_secs(30));
        let a = key(1);
        cache.remember_at_for_test(a.clone(), "a".into(), "digest".into(), now);
        assert_eq!(cache.len(), 0);
        assert_eq!(value(&mut cache, &a, "a", now), None);
    }
}
