use super::*;
use astral_types::{
    DomainScopeRequirement, PublishedCardAuthorizationGate, PublishedEvidenceGateStatus,
};

fn scope(card_id: i64) -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        tenant_id: 7,
        card_id,
        user_filter: Some(42),
        domain: DomainScopeRequirement::Unconstrained,
    }
}

fn stamp() -> AssemblyStamp {
    AssemblyStamp::new(
        ReadToken {
            health: 1,
            source: 2,
            tenant: 3,
            card: 4,
        },
        100,
        &[],
    )
}

fn evidence() -> Arc<PublishedCardAuthorization> {
    Arc::new(PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 17,
        read_unix_seconds: 100,
        gate: PublishedCardAuthorizationGate {
            status: PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 0,
            verified_record_count: 0,
            effective_grant_count: 0,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: Vec::new(),
        records: Vec::new(),
        effective_grants: Vec::new(),
    })
}

#[test]
fn cache_reuses_only_the_same_scope_stamp_and_time_bucket() {
    let cache = AssemblyCache::default();
    let now = Instant::now();
    let original = evidence();
    cache.insert(&scope(17), stamp(), Arc::clone(&original), now);
    assert!(Arc::ptr_eq(
        &cache.get(&scope(17), &stamp(), now).unwrap(),
        &original
    ));
    let mut other = scope(17);
    other.user_filter = None;
    assert!(cache.get(&other, &stamp(), now).is_none());
    assert!(cache.get(&scope(18), &stamp(), now).is_none());
    let mut changed = stamp();
    changed.read_unix_seconds += 1;
    assert!(cache.get(&scope(17), &changed, now).is_none());
    assert!(cache.entries.lock().unwrap().values.is_empty());
}

#[test]
fn cache_expiry_and_hard_entry_capacity_are_enforced() {
    let cache = AssemblyCache::default();
    let now = Instant::now();
    for card in 1..=(MAX_ENTRIES + 1) as i64 {
        cache.insert(&scope(card), stamp(), evidence(), now);
    }
    assert_eq!(cache.entries.lock().unwrap().values.len(), MAX_ENTRIES);
    assert!(cache.get(&scope(1), &stamp(), now).is_none());
    assert!(cache.get(&scope(2), &stamp(), now + TTL).is_none());
    cache.insert(&scope(1), stamp(), evidence(), now + TTL);
    let entries = cache.entries.lock().unwrap();
    assert_eq!(entries.values.len(), 1);
    assert!(entries.bytes <= MAX_BYTES);
}

#[test]
fn cache_byte_budget_and_oversize_bypass_are_enforced() {
    let cache = AssemblyCache::default();
    let now = Instant::now();
    let mut large = (*evidence()).clone();
    large.records = Vec::with_capacity(
        MAX_ENTRY_BYTES / size_of::<astral_types::VerifiedPublishedGrantRecord>() + 1,
    );
    assert!(!AssemblyCache::can_store(&stamp(), &large));
    cache.insert(&scope(17), stamp(), Arc::new(large), now);
    assert!(cache.entries.lock().unwrap().values.is_empty());
    for card in 1..=32 {
        let mut large = (*evidence()).clone();
        large.records = Vec::with_capacity(
            2 * 1024 * 1024 / size_of::<astral_types::VerifiedPublishedGrantRecord>(),
        );
        cache.insert(&scope(card), stamp(), Arc::new(large), now);
    }
    let entries = cache.entries.lock().unwrap();
    assert!(entries.values.len() < 32);
    assert!(entries.bytes <= MAX_BYTES);
}

#[test]
fn cache_hit_promotion_preserves_order_and_accounting_on_eviction() {
    let cache = AssemblyCache::default();
    let now = Instant::now();
    for card in 1..=MAX_ENTRIES as i64 {
        cache.insert(&scope(card), stamp(), evidence(), now);
    }
    assert!(cache.get(&scope(1), &stamp(), now).is_some());
    cache.insert(&scope(MAX_ENTRIES as i64 + 1), stamp(), evidence(), now);
    assert!(cache.get(&scope(1), &stamp(), now).is_some());
    assert!(cache.get(&scope(2), &stamp(), now).is_none());
    let entries = cache.entries.lock().unwrap();
    assert_eq!(entries.values.len(), entries.order.len());
    assert_eq!(
        entries.bytes,
        entries
            .values
            .values()
            .map(|entry| entry.bytes)
            .sum::<usize>()
    );
    for (order, key) in &entries.order {
        assert_eq!(*order, entries.values[key].last_used);
    }
}

#[test]
fn cache_rejects_each_changed_read_token_dimension() {
    let cache = AssemblyCache::default();
    let now = Instant::now();
    for component in 0..4 {
        cache.insert(&scope(17), stamp(), evidence(), now);
        let mut changed = stamp();
        match component {
            0 => changed.token.health += 1,
            1 => changed.token.source += 1,
            2 => changed.token.tenant += 1,
            3 => changed.token.card += 1,
            _ => unreachable!(),
        }
        assert!(cache.get(&scope(17), &changed, now).is_none());
    }
    assert_eq!(cache.hits(), 0);
}

#[test]
fn cache_rejects_changed_publication_identity_and_frontiers() {
    use crate::authorization_projection_repository::ProjectionAggregateIdentity;

    let mut original = stamp();
    original.publications.push(PublicationStamp {
        pointer: AuthorizationCurrentPointerRecord {
            pointer_id: 1,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            card_id: Some(17),
            current_generation: 1,
            manifest_id: 1,
            event_id: "event-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            semantic_hash: Sha256Digest::from_raw_bytes([1; 32]),
            dependency_hash: Sha256Digest::from_raw_bytes([2; 32]),
            compiler_version: "compiler-1".to_owned(),
            revoke_fence: 1,
            revoke_fence_proven: true,
            cas_version: 1,
        },
        manifest_id: 1,
        generation: 1,
        source_generation: 1,
        projected_generation: 1,
        revoke_fence: 1,
        manifest_digest: Sha256Digest::from_raw_bytes([3; 32]),
    });
    let cache = AssemblyCache::default();
    let now = Instant::now();
    for component in 0..9 {
        cache.insert(&scope(17), original.clone(), evidence(), now);
        let mut changed = original.clone();
        let publication = &mut changed.publications[0];
        match component {
            0 => publication.pointer.identity.aggregate_id += 1,
            1 => publication.manifest_id += 1,
            2 => publication.generation += 1,
            3 => publication.source_generation += 1,
            4 => publication.projected_generation += 1,
            5 => publication.revoke_fence += 1,
            6 => publication.manifest_digest = Sha256Digest::from_raw_bytes([4; 32]),
            7 => publication.pointer.cas_version += 1,
            8 => publication.pointer.revoke_fence_proven = false,
            _ => unreachable!(),
        }
        assert!(cache.get(&scope(17), &changed, now).is_none());
    }
    assert_eq!(cache.hits(), 0);
}

#[test]
fn concurrent_cache_reads_and_fills_preserve_internal_bounds() {
    let cache = Arc::new(AssemblyCache::default());
    let now = Instant::now();
    std::thread::scope(|threads| {
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            threads.spawn(move || {
                for read in 0..1_000 {
                    let scope = scope(read % 64 + 1);
                    cache.insert(&scope, stamp(), evidence(), now);
                    if let Some(evidence) = cache.get(&scope, &stamp(), now) {
                        evidence.validate().unwrap();
                    }
                }
            });
        }
    });
    let entries = cache.entries.lock().unwrap();
    assert_eq!(entries.values.len(), entries.order.len());
    assert!(entries.values.len() <= MAX_ENTRIES);
    assert!(entries.bytes <= MAX_BYTES);
    assert_eq!(
        entries.bytes,
        entries
            .values
            .values()
            .map(|entry| entry.bytes)
            .sum::<usize>()
    );
}

#[test]
fn poisoned_cache_is_only_a_miss() {
    let cache = AssemblyCache::default();
    let _ = std::panic::catch_unwind(|| {
        let _guard = cache.entries.lock().unwrap();
        panic!("poison cache lock");
    });
    assert!(cache.get(&scope(17), &stamp(), Instant::now()).is_none());
    cache.insert(&scope(17), stamp(), evidence(), Instant::now());
}
