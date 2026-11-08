use super::*;

fn root(
    scope: PublishedCardEvidenceScope,
    fence: u64,
    proof_id: &str,
) -> CertifiedAuthorizationState {
    let state = seal_state(
        &card_identity(),
        17,
        1,
        policy_engine::HotState::from_grants(tenant(), 1, vec![grant(0x91)], dependency_vector())
            .unwrap(),
        None,
        0,
    );
    certified_state_for(
        state,
        scope,
        "authority-a",
        1,
        fence,
        "key-1",
        1,
        None,
        proof_id,
        proof_id,
    )
}

fn reconciled_hub() -> MemoryProjectionHub {
    let hub = MemoryProjectionHub::default();
    hub.transition_authority_state_for_tests(AuthorizationAuthorityState::Warming)
        .unwrap();
    hub.begin_authority_fence_sync().unwrap();
    {
        let mut maps = hub.maps.write().unwrap();
        maps.durable_reconcile_epoch = 1;
        maps.durable_reconcile_mutation_revision = Some(maps.mutation_revision);
    }
    hub.record_channel_heartbeat();
    hub
}

pub(super) fn seal_existing_partition(hub: &MemoryProjectionHub) {
    crate::memory_projection_hub::authority_attestation::seal_partition_for_test(
        hub,
        OffsetDateTime::now_utc().unix_timestamp() + 600,
    );
}

#[test]
fn nonempty_root_cannot_replace_explicit_partition_coverage() {
    let hub = reconciled_hub();
    hub.install_certified_authorization_state(&scope(), root(scope(), 1, "unsealed"))
        .unwrap();
    assert!(hub.mark_authority_reconcile_ready().is_err());
    assert!(hub.complete_authority_fence_sync().is_err());
    assert!(!hub.positive_authorization_ready());
}

#[test]
fn partition_is_atomic_exact_and_expires_without_a_request() {
    let hub = reconciled_hub();
    let token = hub.capture_certified_partition_token().unwrap();
    let entries = vec![
        (scope(), root(scope(), 2, "scope-one")),
        (alternate_scope(), root(alternate_scope(), 2, "scope-two")),
    ];
    assert_eq!(hub.install_certified_partition(token, entries).unwrap(), 2);
    hub.mark_authority_reconcile_ready().unwrap();
    hub.complete_authority_fence_sync().unwrap();
    assert!(hub.positive_authorization_ready());
    assert!(matches!(
        hub.try_certified_memory_evidence(&scope()),
        MemoryEvidenceOutcome::Serve(_)
    ));
    let missing = PublishedCardEvidenceScope {
        user_filter: Some(99),
        ..scope()
    };
    defer(hub.try_certified_memory_evidence(&missing));
    crate::memory_projection_hub::authority_attestation::seal_partition_for_test(&hub, 1);
    assert!(!hub.positive_authorization_ready());
    defer(hub.try_certified_memory_evidence(&scope()));
}

#[test]
fn partition_rejects_duplicate_mixed_frontier_and_local_race() {
    let hub = reconciled_hub();
    let token = hub.capture_certified_partition_token().unwrap();
    assert!(hub.install_certified_partition(token, vec![]).is_err());
    assert!(hub
        .install_certified_partition(
            token,
            vec![
                (scope(), root(scope(), 2, "duplicate-one")),
                (scope(), root(scope(), 2, "duplicate-two")),
            ]
        )
        .is_err());
    assert!(hub
        .install_certified_partition(
            token,
            vec![
                (scope(), root(scope(), 2, "frontier-one")),
                (
                    alternate_scope(),
                    root(alternate_scope(), 3, "frontier-two")
                ),
            ]
        )
        .is_err());
    assert!(hub.maps.read().unwrap().certified_states.is_empty());
    hub.mark_channel_suspect("local change during attestation");
    assert!(hub
        .install_certified_partition(token, vec![(scope(), root(scope(), 2, "raced"))])
        .is_err());
    assert!(!hub.positive_authorization_ready());
}

#[test]
fn request_installed_scope_invalidates_the_previous_partition_seal() {
    let hub = reconciled_hub();
    let token = hub.capture_certified_partition_token().unwrap();
    hub.install_certified_partition(token, vec![(scope(), root(scope(), 2, "initial"))])
        .unwrap();
    hub.mark_authority_reconcile_ready().unwrap();
    hub.complete_authority_fence_sync().unwrap();
    hub.install_certified_authorization_state(
        &alternate_scope(),
        root(alternate_scope(), 2, "new-scope"),
    )
    .unwrap();
    assert!(!hub.positive_authorization_ready());
    defer(hub.try_certified_memory_evidence(&scope()));
}

#[test]
fn serving_observation_checks_frontier_and_gate_without_extending_coverage() {
    use astral_types::{AuthorityFenceReadResponse, AuthorityReadGate, GlobalAuthorityFrontier};
    let hub = reconciled_hub();
    let token = hub.capture_certified_partition_token().unwrap();
    hub.install_certified_partition(token, vec![(scope(), root(scope(), 2, "observed"))])
        .unwrap();
    hub.mark_authority_reconcile_ready().unwrap();
    hub.complete_authority_fence_sync().unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut response = AuthorityFenceReadResponse {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: astral_types::AUTHORIZATION_EDITION,
        global_frontier: GlobalAuthorityFrontier {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-a".into(),
            root_id: "root".into(),
            authority_term: 1,
            global_fence_sequence: 2,
            key_id: "key-1".into(),
            key_epoch: 1,
            trust_root_digest: "bb".repeat(32),
            global_chain_digest: "aa".repeat(32),
            updated_at: now,
        },
        read_gate: AuthorityReadGate::evaluate(vec![]).unwrap(),
        scope_certificate: None,
        scope_certificate_hash: None,
        proof: None,
        observed_at: now,
    };
    assert!(hub.verify_serving_authority_observation(&response).is_ok());
    response.global_frontier.global_fence_sequence += 1;
    assert!(hub.verify_serving_authority_observation(&response).is_err());
    response.global_frontier.global_fence_sequence -= 1;
    response.read_gate = AuthorityReadGate::blocked();
    assert!(hub.verify_serving_authority_observation(&response).is_err());
    response.read_gate = AuthorityReadGate::evaluate(vec![]).unwrap();
    crate::memory_projection_hub::authority_attestation::seal_partition_for_test(&hub, 1);
    assert!(hub.verify_serving_authority_observation(&response).is_err());
}
