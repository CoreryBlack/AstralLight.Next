//! Redis-free hub freshness proof from a real committed MySQL publication.
//! Run with the migrated isolated DATABASE_URL and --ignored.

use astral_db::{
    memory_projection_hub::{EvidenceInvalidationRequest, MemoryProjectionHub},
    MemoryEvidenceOutcome,
};
use astral_types::PublishedEvidenceAggregate;
use testsuite::{
    allow_rule_set_grant, cleanup_suite_rows, connect_suite, publish_card_manifest,
    seed_all_tenants, SuiteFixture, TenantRole,
};

#[tokio::test]
#[ignore = "requires migrated isolated MySQL (commit-proven hub freshness)"]
async fn hub_invalidation_notification_is_the_load_bearing_freshness_fence() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let fixture = SuiteFixture::new("hub-premise", &[TenantRole::AllowActive]);
    seed_all_tenants(&pool, &fixture).await.unwrap();
    let tenant = &fixture.tenants[0];
    let grant = allow_rule_set_grant(
        fixture.salt,
        tenant.tenant_id,
        tenant.domain_id,
        tenant.card_id,
        tenant.user_id,
        "learn_subject:*",
        tenant.entry_id,
        tenant.card_rule_set_ref_id,
        1,
    );
    let published = publish_card_manifest(
        &pool,
        tenant.tenant_id,
        tenant.card_id,
        vec![grant],
        "hub-g1",
        fixture.salt,
        1,
        None,
    )
    .await;
    let hub = MemoryProjectionHub::default();
    hub.install_published_state((*published.published_state).clone());
    let scope = tenant.card_scope();
    let MemoryEvidenceOutcome::Serve(evidence) = hub.try_memory_evidence(&scope) else {
        panic!("committed gen1 must serve from the warm mirror");
    };
    assert_eq!(evidence.gate.effective_grant_count, 1);
    assert_eq!(
        evidence.effective_grants[0].tenant.tenant_id,
        tenant.tenant_id
    );

    // No notification means the mirror still knows only gen1.
    assert!(matches!(
        hub.try_memory_evidence(&scope),
        MemoryEvidenceOutcome::Serve(_)
    ));
    hub.apply_evidence_invalidation(EvidenceInvalidationRequest {
        tenant_id: tenant.tenant_id,
        card_id: Some(tenant.card_id),
        aggregate_type: PublishedEvidenceAggregate::UserCard,
        aggregate_id: tenant.card_id,
        event_id: format!("hub-event-{:032x}", fixture.salt),
        operation_id: format!("hub-operation-{:032x}", fixture.salt),
        source_generation: 2,
        published_generation: 1,
        revoke_fence: 0,
    })
    .unwrap();
    assert!(matches!(
        hub.try_memory_evidence(&scope),
        MemoryEvidenceOutcome::DeferToDurable
    ));
    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
