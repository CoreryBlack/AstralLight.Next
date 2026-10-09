//! PolicyEngine tenant-isolation tests for the strict published-evidence path.

#[path = "support/published.rs"]
mod published;

use std::sync::Arc;

use astral_types::PolicyContext;
use policy_engine::{DataScopeFilter, DataScopeFilterResolver, PolicyEngine};
use published::{
    assert_allow, assert_deny, canonical_grant, ready_evidence, strict_context, strict_scope,
    PublishedRepo,
};

#[tokio::test]
async fn test_multi_tenant_same_resource_allow_and_deny() {
    let engine = PolicyEngine::new();
    let repo = PublishedRepo::from_evidence(vec![
        ready_evidence(
            100,
            1000,
            vec![canonical_grant(
                1,
                100,
                Some(10),
                1000,
                2000,
                "learn_subject:42",
                "read",
            )],
        ),
        ready_evidence(200, 2000, vec![]),
    ]);

    let allow = engine
        .evaluate(
            &strict_context(2000, 1000, 100, Some(10), "learn_subject:42", "read"),
            &repo,
        )
        .await;
    assert_allow(&allow);

    let deny = engine
        .evaluate(
            &strict_context(3000, 2000, 200, Some(20), "learn_subject:42", "read"),
            &repo,
        )
        .await;
    assert_deny(&deny, "DEFAULT_DENY");
    assert_eq!(
        repo.published_reads(),
        3,
        "ALLOW reads initial/final; DENY reads initial"
    );
    let scopes = repo.scopes();
    assert_eq!(scopes.len(), 3);
    assert_eq!(scopes[0], strict_scope(100, 1000, 2000, Some(10)));
    assert_eq!(scopes[1], strict_scope(100, 1000, 2000, Some(10)));
    assert_eq!(scopes[2], strict_scope(200, 2000, 3000, Some(20)));
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_tenant_id_in_context_preserved() {
    let engine = PolicyEngine::new();
    let repo = PublishedRepo::from_grants(vec![canonical_grant(
        2,
        42,
        Some(10),
        42,
        1,
        "test",
        "read",
    )]);
    let ctx = strict_context(1, 42, 42, Some(10), "test", "read");

    let decision = engine.evaluate(&ctx, &repo).await;
    assert_allow(&decision);
    assert_eq!(ctx.tenant_id, Some(42));
    assert_eq!(ctx.domain_id, Some(10));
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(
        repo.scopes(),
        vec![
            strict_scope(42, 42, 1, Some(10)),
            strict_scope(42, 42, 1, Some(10)),
        ]
    );
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_cross_tenant_rule_no_cross_talk() {
    let engine = PolicyEngine::new();
    let repo = PublishedRepo::from_evidence(vec![
        ready_evidence(
            100,
            1000,
            vec![canonical_grant(
                3,
                100,
                Some(10),
                1000,
                1,
                "sensitive_data",
                "read",
            )],
        ),
        ready_evidence(200, 2000, vec![]),
    ]);

    let tenant_a = engine
        .evaluate(
            &strict_context(1, 1000, 100, Some(10), "sensitive_data", "read"),
            &repo,
        )
        .await;
    assert_allow(&tenant_a);

    let tenant_b = engine
        .evaluate(
            &strict_context(2, 2000, 200, Some(20), "sensitive_data", "read"),
            &repo,
        )
        .await;
    assert_deny(&tenant_b, "DEFAULT_DENY");
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_same_card_wrong_tenant_is_pending_without_leakage() {
    let engine = PolicyEngine::new();
    let repo = PublishedRepo::from_grants(vec![canonical_grant(
        4,
        100,
        Some(10),
        1000,
        1,
        "sensitive_data",
        "read",
    )]);

    let decision = engine
        .evaluate(
            &strict_context(1, 1000, 200, Some(10), "sensitive_data", "read"),
            &repo,
        )
        .await;
    assert_deny(&decision, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 1);
    assert_eq!(repo.scopes(), vec![strict_scope(200, 1000, 1, Some(10))]);
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_same_card_wrong_user_or_domain_fails_closed() {
    let engine = PolicyEngine::new();
    let repo = PublishedRepo::from_grants(vec![canonical_grant(
        5,
        100,
        Some(10),
        1000,
        1,
        "sensitive_data",
        "read",
    )]);

    let wrong_user = engine
        .evaluate(
            &strict_context(2, 1000, 100, Some(10), "sensitive_data", "read"),
            &repo,
        )
        .await;
    assert_deny(&wrong_user, "DEFAULT_DENY");

    let wrong_domain = engine
        .evaluate(
            &strict_context(1, 1000, 100, Some(20), "sensitive_data", "read"),
            &repo,
        )
        .await;
    assert_deny(&wrong_domain, "DEFAULT_DENY");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(
        repo.scopes(),
        vec![
            strict_scope(100, 1000, 2, Some(10)),
            strict_scope(100, 1000, 1, Some(20)),
        ]
    );
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_missing_or_unpublished_evidence_is_pending() {
    let engine = PolicyEngine::new();
    let ctx = strict_context(1, 1000, 100, Some(10), "sensitive_data", "read");

    let missing = PublishedRepo::missing();
    let missing_decision = engine.evaluate(&ctx, &missing).await;
    assert_deny(&missing_decision, "AUTHORIZATION_PENDING");
    assert_eq!(missing.published_reads(), 1);
    assert_eq!(missing.scopes(), vec![strict_scope(100, 1000, 1, Some(10))]);
    missing.assert_no_legacy_reads();

    let unpublished = PublishedRepo::unpublished(100, 1000);
    let unpublished_decision = engine.evaluate(&ctx, &unpublished).await;
    assert_deny(&unpublished_decision, "AUTHORIZATION_PENDING");
    assert_eq!(unpublished.published_reads(), 1);
    assert_eq!(
        unpublished.scopes(),
        vec![strict_scope(100, 1000, 1, Some(10))]
    );
    unpublished.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_concurrent_multi_tenant_evaluations_use_positive_ids() {
    let engine = Arc::new(PolicyEngine::new());
    let mut grants = Vec::new();
    for index in 0..10u64 {
        let tenant_id = 100 + index as i64;
        let card_id = 1000 + index as i64;
        let user_id = 2000 + index as i64;
        grants.push(canonical_grant(
            100 + index,
            tenant_id,
            Some(3000 + index as i64),
            card_id,
            user_id,
            &format!("resource_{index}"),
            "read",
        ));
    }
    let repo = Arc::new(PublishedRepo::from_grants(grants));

    let mut handles = Vec::new();
    for index in 0..10i64 {
        let engine = Arc::clone(&engine);
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            let tenant_id = 100 + index;
            let card_id = 1000 + index;
            let user_id = 2000 + index;
            let domain_id = 3000 + index;
            let ctx = strict_context(
                user_id,
                card_id,
                tenant_id,
                Some(domain_id),
                &format!("resource_{index}"),
                "read",
            );
            let decision = engine.evaluate(&ctx, repo.as_ref()).await;
            assert_allow(&decision);
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(repo.published_reads(), 20);
    let scopes = repo.scopes();
    assert_eq!(scopes.len(), 20);
    for index in 0..10i64 {
        let expected = strict_scope(100 + index, 1000 + index, 2000 + index, Some(3000 + index));
        assert_eq!(scopes.iter().filter(|scope| **scope == expected).count(), 2);
    }
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_inactive_card_rejected_multi_tenant() {
    let engine = PolicyEngine::new();
    let repo = PublishedRepo::inactive_with_evidence(vec![canonical_grant(
        6,
        100,
        Some(10),
        1000,
        1,
        "test",
        "read",
    )]);

    for tenant_id in [100i64, 200, 300] {
        let ctx = strict_context(1, 1000, tenant_id, Some(10), "test", "read");
        let decision = engine.evaluate(&ctx, &repo).await;
        assert_deny(&decision, "CARD_DISABLED");
    }
    assert_eq!(repo.published_reads(), 0);
    repo.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_benchmark_fixture_disables_scope_samples_without_bypassing_strict_reads() {
    let ctx = strict_context(1, 1000, 100, Some(10), "test", "read");
    let grant = canonical_grant(7, 100, Some(10), 1000, 1, "test", "read");
    for repo in [
        PublishedRepo::from_grants_without_scope_recording(vec![grant.clone()]),
        PublishedRepo::from_evidence_without_scope_recording(vec![ready_evidence(
            100,
            1000,
            vec![grant.clone()],
        )]),
    ] {
        assert_allow(&PolicyEngine::new().evaluate(&ctx, &repo).await);
        assert_eq!(repo.published_reads(), 2);
        assert!(repo.scopes().is_empty());
        repo.assert_no_legacy_reads();
        repo.reset_counters();
        assert_eq!(repo.published_reads(), 0);
        assert!(repo.scopes().is_empty());
    }
    let empty = PublishedRepo::ready_empty_without_scope_recording(100, 1000);
    assert_deny(
        &PolicyEngine::new().evaluate(&ctx, &empty).await,
        "DEFAULT_DENY",
    );
    assert!(empty.scopes().is_empty());
    empty.assert_no_legacy_reads();
    let missing = PublishedRepo::unavailable_without_scope_recording();
    assert_deny(
        &PolicyEngine::new().evaluate(&ctx, &missing).await,
        "AUTHORIZATION_PENDING",
    );
    assert!(missing.scopes().is_empty());
    missing.assert_no_legacy_reads();
}

#[tokio::test]
async fn test_data_scope_tenant_isolation() {
    let resolver = DataScopeFilterResolver::new();
    let ctx_a = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(100))
        .domain_id(Some(10))
        .build();
    let ctx_b = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(200))
        .domain_id(Some(20))
        .build();

    let filter_a = resolver.resolve(&ctx_a).await;
    let filter_b = resolver.resolve(&ctx_b).await;
    assert_eq!(filter_a.tenant_id, Some(100));
    assert_eq!(filter_a.domain_id, Some(10));
    assert_eq!(filter_b.tenant_id, Some(200));
    assert_eq!(filter_b.domain_id, Some(20));
    assert_ne!(filter_a.tenant_id, filter_b.tenant_id);
}

#[tokio::test]
async fn test_data_scope_no_tenant_no_filter() {
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder().action("read".into()).build();
    let filter: DataScopeFilter = resolver.resolve(&ctx).await;
    assert!(filter.is_empty());
    assert!(filter.tenant_id.is_none());
}

#[tokio::test]
async fn test_data_scope_personal_scope_user_isolation() {
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder()
        .action("personal:read".into())
        .tenant_id(Some(1))
        .user_id(Some(999))
        .build();
    let filter = resolver.resolve(&ctx).await;
    assert_eq!(filter.tenant_id, Some(1));
    assert_eq!(filter.user_id, Some(999));
}

#[tokio::test]
async fn test_data_scope_non_personal_no_user_filter() {
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(1))
        .user_id(Some(999))
        .build();
    let filter = resolver.resolve(&ctx).await;
    assert_eq!(filter.tenant_id, Some(1));
    assert!(filter.user_id.is_none());
}

#[tokio::test]
async fn test_data_scope_custom_filters() {
    let resolver = DataScopeFilterResolver::new();
    let ctx = PolicyContext::builder()
        .action("read".into())
        .tenant_id(Some(1))
        .request(Some(serde_json::json!({
            "org_id": 77,
            "filters": {
                "department_id": 3,
                "project_id": 99
            }
        })))
        .build();
    let filter = resolver.resolve(&ctx).await;
    assert_eq!(filter.org_id, Some(77));
    assert!(filter.custom.iter().any(|(key, _)| key == "department_id"));
    assert!(filter.custom.iter().any(|(key, _)| key == "project_id"));
}

#[test]
fn test_data_scope_filter_merge() {
    let mut base = DataScopeFilter {
        tenant_id: Some(1),
        domain_id: Some(10),
        ..Default::default()
    };
    let overlay = DataScopeFilter {
        tenant_id: Some(2),
        user_id: Some(100),
        ..Default::default()
    };
    base.merge(&overlay);
    assert_eq!(base.tenant_id, Some(2));
    assert_eq!(base.domain_id, Some(10));
    assert_eq!(base.user_id, Some(100));
}

#[test]
fn test_data_scope_filter_is_empty() {
    assert!(DataScopeFilter::default().is_empty());
    assert!(!DataScopeFilter {
        tenant_id: Some(1),
        ..Default::default()
    }
    .is_empty());
}
