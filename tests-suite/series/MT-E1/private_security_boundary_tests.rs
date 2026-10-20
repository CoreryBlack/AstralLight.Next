//! P0 security-boundary migration from the private Java baseline.
//!
//! The Java `SecurityBoundaryTest` asserts that client-supplied roles and
//! cross-tenant data cannot replace the authoritative authorization facts.
//! These tests exercise the same purpose through the Rust strict published
//! evidence path; they do not claim to reproduce Java service wiring.

#[allow(dead_code)]
#[path = "support/published.rs"]
mod published;

use astral_types::PolicyContext;
use policy_engine::PolicyEngine;
use published::{assert_deny, canonical_grant, ready_evidence, strict_context, PublishedRepo};

fn context_with_client_roles(
    user_id: i64,
    card_id: i64,
    tenant_id: i64,
    domain_id: Option<i64>,
    resource: &str,
    action: &str,
) -> PolicyContext {
    let mut ctx = strict_context(user_id, card_id, tenant_id, domain_id, resource, action);
    ctx.request = Some(serde_json::json!({
        "roles": ["SUPER_ADMIN", "GLOBAL_ADMIN"],
        "isSuperAdmin": true,
    }));
    ctx
}

#[tokio::test]
async fn client_supplied_roles_do_not_authorize_without_published_grant() {
    let repo = PublishedRepo::from_evidence(vec![ready_evidence(100, 1000, vec![])]);
    let ctx = context_with_client_roles(7, 1000, 100, Some(10), "learn_subject:42", "read");

    let decision = PolicyEngine::new().evaluate(&ctx, &repo).await;

    assert_deny(&decision, "DEFAULT_DENY");
    assert!(
        repo.published_reads() >= 1,
        "strict evaluation must read published evidence"
    );
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn foreign_tenant_or_other_action_grant_does_not_authorize() {
    let cross_tenant = PublishedRepo::from_evidence(vec![
        ready_evidence(100, 1000, vec![]),
        ready_evidence(
            200,
            2000,
            vec![canonical_grant(
                1,
                200,
                Some(20),
                2000,
                7,
                "learn_subject:42",
                "read",
            )],
        ),
    ]);
    let cross_tenant_ctx = strict_context(7, 1000, 100, Some(10), "learn_subject:42", "read");
    let cross_tenant_decision = PolicyEngine::new()
        .evaluate(&cross_tenant_ctx, &cross_tenant)
        .await;
    assert_deny(&cross_tenant_decision, "DEFAULT_DENY");

    let other_action = PublishedRepo::from_evidence(vec![ready_evidence(
        100,
        1000,
        vec![canonical_grant(
            2,
            100,
            Some(10),
            1000,
            7,
            "learn_subject:42",
            "read",
        )],
    )]);
    let other_action_ctx = strict_context(7, 1000, 100, Some(10), "learn_subject:42", "delete");
    let other_action_decision = PolicyEngine::new()
        .evaluate(&other_action_ctx, &other_action)
        .await;
    assert_deny(&other_action_decision, "DEFAULT_DENY");

    cross_tenant.assert_no_legacy_reads();
    other_action.assert_no_legacy_reads();
}
