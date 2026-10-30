//! Redis-free hub freshness proof from a real committed MySQL publication.
//! Run with the migrated isolated DATABASE_URL and --ignored.

use astral_db::{
    memory_projection_hub::{EvidenceInvalidationRequest, MemoryProjectionHub},
    MemoryEvidenceOutcome,
};
#[path = "../MT-E1/support/source_identity.rs"]
mod source_identity;
use astral_trustgraph::service::rule_set_write_service::AddEntryRequest;
use astral_types::PublishedEvidenceAggregate;
use testsuite::{
    cleanup_suite_rows, connect_suite, publish_card_manifest, seed_all_tenants, SuiteFixture,
    TenantRole,
};

fn allow_entry(priority: i32) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some("read".to_owned()),
        condition_json: None,
        priority,
    }
}

#[tokio::test]
#[ignore = "requires migrated isolated MySQL (commit-proven hub freshness)"]
async fn hub_invalidation_notification_is_the_load_bearing_freshness_fence() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let fixture = SuiteFixture::new("hub-premise", &[TenantRole::AllowActive]);
    seed_all_tenants(&pool, &fixture).await.unwrap();
    let tenant = &fixture.tenants[0];
    let published = publish_card_manifest(
        &pool,
        tenant.tenant_id,
        tenant.card_id,
        tenant.rule_set_id,
        tenant.user_id,
        vec![allow_entry(2)],
        ("hub-g1", fixture.salt),
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
    source_identity::assert_ruleset_source_binding(
        &pool,
        &evidence.effective_grants[0],
        tenant.tenant_id,
        tenant.card_id,
        tenant.rule_set_id,
    )
    .await;

    // No notification means the mirror still knows only gen1.
    assert!(matches!(
        hub.try_memory_evidence(&scope),
        MemoryEvidenceOutcome::Serve(_)
    ));
    let event_id = format!("hub-event-{:032x}", fixture.salt);
    let operation_id = format!("hub-operation-{:032x}", fixture.salt);
    hub.apply_evidence_invalidation(EvidenceInvalidationRequest {
        tenant_id: tenant.tenant_id,
        card_id: Some(tenant.card_id),
        aggregate_type: PublishedEvidenceAggregate::RuleSet,
        aggregate_id: tenant.rule_set_id,
        event_id,
        operation_id,
        source_generation: published.pointer.current_generation + 1,
        published_generation: published.pointer.current_generation,
        stamp: published.published_state.publication_stamp().unwrap(),
        revoke_fence: published.pointer.revoke_fence,
    })
    .unwrap();
    assert!(matches!(
        hub.try_memory_evidence(&scope),
        MemoryEvidenceOutcome::DeferToDurable
    ));
    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
