//! memory—v1: Fail-closed checks while the shared-root evaluator is unavailable.
//! These cases do not establish tenant isolation or a working positive authorization path.

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

// memory—v1: Client-supplied roles cannot bypass the unavailable evaluator.
#[tokio::test]
async fn client_supplied_roles_do_not_authorize_without_published_grant() {
    let repo = PublishedRepo::from_evidence(vec![ready_evidence(100, 1000, vec![])]);
    let ctx = context_with_client_roles(7, 1000, 100, Some(10), "learn_subject:42", "read");

    let decision = PolicyEngine::new().evaluate(&ctx, &repo).await;

    assert_deny(&decision, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 0);
}

// memory—v1: Legacy grants cannot bypass the unavailable evaluator.
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
    assert_deny(&cross_tenant_decision, "AUTHORIZATION_PENDING");
    assert_eq!(cross_tenant.published_reads(), 0);

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
    assert_deny(&other_action_decision, "AUTHORIZATION_PENDING");
    assert_eq!(other_action.published_reads(), 0);
}
