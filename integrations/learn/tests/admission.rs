use astral_learn_sdk_sample::{actor, manifest, Course, CourseScope, LearnStore};
use astral_sdk::{AccessToken, ClientConfig, SdkClient};
use astral_sdk_contracts::{
    AuthorizationDecision, AuthorizationRequest, DecisionOutcome, ResourceFacts,
    SignedAuthorizationDecision, SignedAuthorizationRequest, VerifiedAuthorizationDecision,
};
use astral_sdk_test_support::{Fault, TestApplication, TestDecisionServer};
use ed25519_dalek::SigningKey;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn store() -> LearnStore {
    let mut store = LearnStore::default();
    for (id, tenant) in [(1, "school-a"), (2, "school-b")] {
        store
            .insert_scope(CourseScope {
                id,
                tenant: tenant.into(),
                domain: "courses".into(),
                revision: 1,
            })
            .unwrap();
        store
            .insert(Course {
                id,
                scope_id: id,
                owner: actor("teacher-a"),
                revision: 1,
                published: false,
            })
            .unwrap();
    }
    store
}
fn request(facts: ResourceFacts) -> AuthorizationRequest {
    let collection = facts.operation == astral_sdk_contracts::ResourceOperation::ScopedCollection;
    let path = if collection {
        format!("/course-scopes/{}/courses", facts.target_id)
    } else {
        format!("/courses/{}/publish", facts.target_id)
    };
    AuthorizationRequest {
        app_id: "astral-learn".into(),
        key_id: "test-app".into(),
        manifest_digest: manifest().digest().unwrap(),
        revision: "1".into(),
        request_id: "request-1".into(),
        nonce: "abcdefghijkl123456789012".into(),
        timestamp: now(),
        session_token_id: "test-session".into(),
        subject: actor("teacher-a"),
        method: if collection { "GET" } else { "POST" }.into(),
        path,
        action: if collection { "read" } else { "update" }.into(),
        operation_id: "publish-1".into(),
        facts,
    }
}
fn proof(
    request: &AuthorizationRequest,
    outcome: DecisionOutcome,
) -> VerifiedAuthorizationDecision {
    let key = SigningKey::from_bytes(&[7; 32]);
    SignedAuthorizationDecision::sign(
        "test-decision",
        &key,
        AuthorizationDecision::bound_to(request, "1", outcome, None, now()).unwrap(),
    )
    .unwrap()
    .verify(&key.verifying_key(), "test-decision", request, now())
    .unwrap()
}
#[test]
fn in_flight_fact_change_and_pending_do_not_publish() {
    let mut store = store();
    let req = request(store.facts(1).unwrap());
    let allow = proof(&req, DecisionOutcome::Allow);
    store.move_course(1, 2).unwrap();
    assert_eq!(store.publish(&req, allow), Err("FACTS_CHANGED"));
    let req = request(store.facts(1).unwrap());
    assert_eq!(
        store.publish(&req, proof(&req, DecisionOutcome::Pending)),
        Err("DENIED")
    );
    assert!(!store.course(1).unwrap().published);
}
#[test]
fn fresh_authorization_retry_uses_stable_business_digest() {
    let mut store = store();
    let first = request(store.facts(1).unwrap());
    store
        .publish(&first, proof(&first, DecisionOutcome::Allow))
        .unwrap();
    let revision = store.course(1).unwrap().revision;
    let mut retry = request(store.facts(1).unwrap());
    retry.request_id = "request-2".into();
    retry.nonce = "differentnonce1234567890".into();
    store
        .publish(&retry, proof(&retry, DecisionOutcome::Allow))
        .unwrap();
    assert_eq!(store.course(1).unwrap().revision, revision);
    let receipt = store
        .receipt(&first.subject.subject, &first.operation_id)
        .unwrap();
    assert_eq!(receipt.request_digest, first.digest().unwrap());
    assert_eq!(receipt.facts_digest, first.facts_digest().unwrap());
    let conflicting = request(store.facts(2).unwrap());
    assert_eq!(
        store.publish(&conflicting, proof(&conflicting, DecisionOutcome::Allow)),
        Err("OPERATION_CONFLICT")
    );
}
#[test]
fn collection_is_exact_scope_and_version_not_object_grant() {
    let mut store = store();
    let req = request(store.collection_facts(1).unwrap());
    let allow = proof(&req, DecisionOutcome::Allow);
    assert_eq!(
        store
            .list_scope(&req, allow)
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect::<Vec<_>>(),
        [1]
    );
    let stale = proof(&req, DecisionOutcome::Allow);
    store.move_course(1, 2).unwrap();
    assert_eq!(store.list_scope(&req, stale), Err("FACTS_CHANGED"));
    let object = request(store.facts(1).unwrap());
    assert_eq!(
        store.list_scope(&object, proof(&object, DecisionOutcome::Allow)),
        Err("FACTS_CHANGED")
    );
}
#[tokio::test]
async fn public_sdk_loopback_round_trip_precedes_local_commit() {
    let server = TestDecisionServer::start(
        TestApplication {
            manifest: manifest(),
            subject: actor("teacher-a"),
            tenant: "school-a".into(),
            domain: "courses".into(),
        },
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[12; 32]),
    )
    .await;
    let client = SdkClient::new(
        ClientConfig::new(
            server.address.parse().unwrap(),
            Duration::from_secs(2),
            65536,
            &server.decision_key_id,
            server.decision_key.verifying_key(),
        )
        .with_insecure_loopback_http(true),
    )
    .unwrap();
    let mut store = store();
    let request = request(store.facts(1).unwrap());
    let signed = SignedAuthorizationRequest::sign(&server.app_key, request).unwrap();
    let decision = client
        .authorize(&signed, &AccessToken::new("test-bearer").unwrap())
        .await
        .unwrap();
    store.publish(&signed.request, decision).unwrap();
    assert!(store.course(1).unwrap().published);
    server.stop().await;
}

#[tokio::test]
async fn malformed_stale_and_unavailable_remote_results_never_publish() {
    let server = TestDecisionServer::start(
        TestApplication {
            manifest: manifest(),
            subject: actor("teacher-a"),
            tenant: "school-a".into(),
            domain: "courses".into(),
        },
        SigningKey::from_bytes(&[31; 32]),
        SigningKey::from_bytes(&[32; 32]),
    )
    .await;
    let client = SdkClient::new(
        ClientConfig::new(
            server.address.parse().unwrap(),
            Duration::from_millis(100),
            4096,
            &server.decision_key_id,
            server.decision_key.verifying_key(),
        )
        .with_insecure_loopback_http(true),
    )
    .unwrap();
    let mut store = store();
    for (index, fault) in [
        Fault::Pending,
        Fault::Deny,
        Fault::MissingMapping,
        Fault::DisabledMapping,
        Fault::StaleSession,
        Fault::BadSignature,
        Fault::BadScope,
        Fault::Expired,
        Fault::WrongTrace,
        Fault::BadEnvelope,
        Fault::Oversized,
        Fault::Timeout,
        Fault::Redirect,
    ]
    .into_iter()
    .enumerate()
    {
        server.set_fault(fault);
        let mut req = request(store.facts(1).unwrap());
        req.nonce = format!("abcdefghijkl12345678{index:04}");
        let signed = SignedAuthorizationRequest::sign(&server.app_key, req).unwrap();
        let result = client
            .authorize(&signed, &AccessToken::new("test-bearer").unwrap())
            .await;
        if let Ok(proof) = result {
            assert!(store.publish(&signed.request, proof).is_err());
        }
        assert!(!store.course(1).unwrap().published);
    }
    assert_eq!(
        server.request_count(),
        13,
        "redirects and transport failures must not retry"
    );
    server.stop().await;
}

#[tokio::test]
async fn replay_and_unapproved_scope_are_refused_over_transport() {
    let server = TestDecisionServer::start(
        TestApplication {
            manifest: manifest(),
            subject: actor("teacher-a"),
            tenant: "school-a".into(),
            domain: "courses".into(),
        },
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
    )
    .await;
    let client = SdkClient::new(
        ClientConfig::new(
            server.address.parse().unwrap(),
            Duration::from_secs(1),
            4096,
            &server.decision_key_id,
            server.decision_key.verifying_key(),
        )
        .with_insecure_loopback_http(true),
    )
    .unwrap();
    let token = AccessToken::new("test-bearer").unwrap();
    let store = store();
    let signed =
        SignedAuthorizationRequest::sign(&server.app_key, request(store.facts(1).unwrap()))
            .unwrap();
    client.authorize(&signed, &token).await.unwrap();
    assert!(client.authorize(&signed, &token).await.is_err());
    for index in 0..5 {
        let mut req = request(store.facts(1).unwrap());
        req.nonce = format!("abcdefghijkl12345{index:05}");
        match index {
            0 => req.facts.external_tenant_id = "foreign".into(),
            1 => req.subject = actor("other-actor"),
            2 => req.manifest_digest = "a".repeat(64),
            3 => req.path = "/courses/2/publish".into(),
            _ => req.session_token_id = "foreign-session".into(),
        }
        let signed = SignedAuthorizationRequest::sign(&server.app_key, req).unwrap();
        assert!(client.authorize(&signed, &token).await.is_err());
    }
    server.stop().await;
}
