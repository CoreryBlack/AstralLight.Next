use super::*;

fn at(
    hub: &MemoryProjectionHub,
    scope: &PublishedCardEvidenceScope,
    now: i64,
) -> PublishedCardAuthorization {
    serve(hub.try_memory_evidence_with_clock(scope, || now, || {}))
}

fn installed() -> (MemoryProjectionHub, AuthorizationPublishedState) {
    let hub = MemoryProjectionHub::default();
    let mut bounded = grant(1);
    bounded.validity = ValidityWindow {
        not_before: Some(100),
        expires_at: Some(101),
    };
    let hot = policy_engine::HotState::from_grants(tenant(), 1, vec![bounded], dependency_vector())
        .unwrap();
    let state = seal_state(&card_identity(), 17, 1, hot, None, 0);
    hub.install_published_state(state.clone());
    (hub, state)
}

#[test]
fn assembly_cache_same_second_matches_cold_evidence_and_cross_second_expires_grant() {
    let (hub, state) = installed();
    let cold = assemble_published_card_evidence(&scope(), 100, &[state]).unwrap();
    assert_eq!(at(&hub, &scope(), 100), cold);
    assert_eq!(at(&hub.clone(), &scope(), 100), cold);
    assert_eq!(hub.assemblies.hits(), 1);
    let expired = at(&hub, &scope(), 101);
    assert!(expired.effective_grants.is_empty());
    assert_eq!(expired.records.len(), 1);
    assert_eq!(hub.assemblies.hits(), 1);
    expired.validate().unwrap();
}

#[test]
fn assembly_cache_separates_user_domain_tenant_and_card() {
    let (hub, _) = installed();
    at(&hub, &scope(), 100);
    let mut other = scope();
    other.user_filter = Some(43);
    assert!(at(&hub, &other, 100).effective_grants.is_empty());
    other = scope();
    other.domain = DomainScopeRequirement::ExactlySome(12);
    assert!(at(&hub, &other, 100).effective_grants.is_empty());
    other = scope();
    other.tenant_id = 8;
    defer(hub.try_memory_evidence_with_clock(&other, || 100, || {}));
    other = scope();
    other.card_id = 18;
    defer(hub.try_memory_evidence_with_clock(&other, || 100, || {}));
    assert_eq!(hub.assemblies.hits(), 0);
}

#[test]
fn assembly_cache_does_not_bypass_admission_gates() {
    for gate in 0..7 {
        let (hub, _) = installed();
        at(&hub, &scope(), 100);
        if gate == 6 {
            hub.record_pending_delta(&pending_request(
                Some(17),
                DeltaEventType::Remove,
                2,
                0,
                true,
            ));
        } else {
            let mut maps = hub.maps.write().unwrap();
            match gate {
                0 => maps.warming_up = true,
                1 => maps.active_source_writers = 1,
                2 => maps.uncertain_source = true,
                3 => maps.runtime_owner_failed = true,
                4 => maps.suspect("test transport failure"),
                5 => {
                    maps.installed_at.insert(
                        card_identity(),
                        Instant::now() - MIRROR_TTL - Duration::from_secs(1),
                    );
                }
                _ => unreachable!(),
            }
        }
        defer(hub.try_memory_evidence_with_clock(&scope(), || 100, || {}));
        assert_eq!(hub.assemblies.hits(), 0, "gate {gate}");
    }
}

#[test]
fn assembly_cache_invalidates_publication_and_fence_in_the_same_second() {
    let (hub, _) = installed();
    at(&hub, &scope(), 100);
    let hot =
        policy_engine::HotState::from_grants(tenant(), 2, vec![grant(2)], dependency_vector())
            .unwrap();
    hub.install_published_state(seal_state(&card_identity(), 17, 2, hot, Some(1), 2));
    let next = at(&hub, &scope(), 100);
    assert_eq!(next.manifests[0].generation, 2);
    assert_eq!(next.manifests[0].revoke_fence, 2);
    assert_eq!(next.effective_grants[0].grant_id, grant(2).grant_id);
    assert_eq!(hub.assemblies.hits(), 0);
}

#[test]
fn assembly_cache_final_token_check_rejects_publication_racing_a_hit() {
    let (hub, _) = installed();
    at(&hub, &scope(), 100);
    defer(hub.try_memory_evidence_with_clock(
        &scope(),
        || 100,
        || {
            let hot = policy_engine::HotState::from_grants(
                tenant(),
                2,
                vec![grant(2)],
                dependency_vector(),
            )
            .unwrap();
            hub.install_published_state(seal_state(&card_identity(), 17, 2, hot, Some(1), 0));
        },
    ));
    assert_eq!(hub.assemblies.hits(), 1);
    assert_eq!(at(&hub, &scope(), 100).manifests[0].generation, 2);
}

#[test]
fn assembly_cache_failed_assembly_is_never_memoized() {
    let (hub, mut state) = installed();
    state.total_grant_count += 1;
    let broken = MemoryProjectionHub::default();
    broken.install_published_state(state);
    defer(broken.try_memory_evidence_with_clock(&scope(), || 100, || {}));
    defer(broken.try_memory_evidence_with_clock(&scope(), || 100, || {}));
    assert_eq!(broken.assemblies.hits(), 0);
    assert!(Arc::strong_count(&hub.assemblies) == 1);
}

#[test]
#[ignore = "local CPU-only evidence assembly performance probe"]
fn assembly_cache_performance_probe() {
    use std::hint::black_box;

    for size in [8_u16, 128, 512, 2_048] {
        let hub = MemoryProjectionHub::default();
        let grants: Vec<_> = (0..size).map(grant).collect();
        let hot =
            policy_engine::HotState::from_grants(tenant(), 1, grants, dependency_vector()).unwrap();
        let state = seal_state(&card_identity(), 17, 1, hot, None, 0);
        hub.install_published_state(state.clone());
        at(&hub, &scope(), 100);
        let start = Instant::now();
        for _ in 0..40 {
            let evidence =
                assemble_published_card_evidence(&scope(), 100, std::slice::from_ref(&state))
                    .unwrap();
            evidence.validate().unwrap();
            black_box(evidence);
        }
        let cold_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        for _ in 0..40 {
            let evidence = at(&hub, &scope(), 100);
            evidence.validate().unwrap();
            black_box(evidence);
        }
        let cached_ns = start.elapsed().as_nanos();
        eprintln!("evidence_assembly size={size} reads=40 cold_ns={cold_ns} cached_ns={cached_ns} hits={}", hub.assemblies.hits());
    }
}
