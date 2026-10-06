use astral_chat_sdk_sample::{actor, manifest, ChatStore, Conversation};
use astral_sdk::{AccessToken, ClientConfig, SdkClient};
use astral_sdk_contracts::{
    AuthorizationDecision, AuthorizationRequest, DecisionOutcome, ResourceFacts,
    SignedAuthorizationDecision, SignedAuthorizationRequest, VerifiedAuthorizationDecision,
};
use astral_sdk_test_support::{TestApplication, TestDecisionServer};
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn store() -> ChatStore {
    let mut store = ChatStore::default();
    for id in 1..=2 {
        store
            .insert(Conversation {
                id,
                tenant: "tenant-a".into(),
                domain: "chat".into(),
                revision: 1,
                members: BTreeSet::from(["member-a".into()]),
            })
            .unwrap();
    }
    store
}
fn request(facts: ResourceFacts, action: &str) -> AuthorizationRequest {
    let socket = facts.resource_type == "chat_conversation";
    AuthorizationRequest {
        app_id: "astral-chat".into(),
        key_id: "test-app".into(),
        manifest_digest: manifest().digest().unwrap(),
        revision: "1".into(),
        request_id: "request-1".into(),
        nonce: "abcdefghijkl123456789012".into(),
        timestamp: now(),
        session_token_id: "test-session".into(),
        subject: actor("member-a"),
        method: if action == "create" { "POST" } else { "GET" }.into(),
        path: format!(
            "/conversations/{}/{}",
            facts.target_id,
            if socket { "socket" } else { "messages" }
        ),
        action: action.into(),
        operation_id: "message-1".into(),
        facts,
    }
}
fn proof(
    request: &AuthorizationRequest,
    outcome: DecisionOutcome,
) -> VerifiedAuthorizationDecision {
    let key = SigningKey::from_bytes(&[8; 32]);
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
fn handshake_does_not_authorize_frame_and_revocation_is_rechecked() {
    let mut store = store();
    let handshake = request(store.handshake_facts(1).unwrap(), "read");
    store
        .handshake(&handshake, proof(&handshake, DecisionOutcome::Allow))
        .unwrap();
    assert_eq!(
        store.send(
            &handshake,
            proof(&handshake, DecisionOutcome::Allow),
            "hello"
        ),
        Err("MEMBERSHIP_CHANGED")
    );
    let frame = request(store.facts(1).unwrap(), "create");
    let allow = proof(&frame, DecisionOutcome::Allow);
    store.revoke_member(1, "member-a").unwrap();
    assert_eq!(
        store.send(&frame, allow, "hello"),
        Err("MEMBERSHIP_CHANGED")
    );
    assert_eq!(store.message_count(), 0);
}
#[test]
fn idempotency_outbound_scope_and_sender_are_checked() {
    let mut store = store();
    let req = request(store.facts(1).unwrap(), "create");
    store
        .send(&req, proof(&req, DecisionOutcome::Allow), "hello")
        .unwrap();
    store
        .send(&req, proof(&req, DecisionOutcome::Allow), "hello")
        .unwrap();
    assert_eq!(
        store.send(&req, proof(&req, DecisionOutcome::Allow), "different"),
        Err("MESSAGE_CONFLICT")
    );
    let receipt = store
        .receipt(&req.subject.subject, &req.operation_id)
        .unwrap();
    assert_eq!(receipt.request_digest, req.digest().unwrap());
    assert_eq!(receipt.facts_digest, req.facts_digest().unwrap());
    let read = request(store.facts(2).unwrap(), "read");
    assert!(store
        .receive(&read, proof(&read, DecisionOutcome::Allow))
        .unwrap()
        .is_empty());
    let read = request(store.facts(1).unwrap(), "read");
    assert_eq!(
        store
            .receive(&read, proof(&read, DecisionOutcome::Allow))
            .unwrap(),
        ["hello"]
    );
    store.revoke_member(1, "member-a").unwrap();
    let read = request(store.facts(1).unwrap(), "read");
    assert_eq!(
        store.receive(&read, proof(&read, DecisionOutcome::Allow)),
        Err("MEMBERSHIP_CHANGED")
    );
}
#[test]
fn pending_and_backpressure_have_no_extra_side_effects() {
    let mut store = store();
    let req = request(store.facts(1).unwrap(), "create");
    assert_eq!(
        store.send(&req, proof(&req, DecisionOutcome::Pending), "hello"),
        Err("DENIED")
    );
    for i in 0..64 {
        let mut frame = req.clone();
        frame.operation_id = format!("message-{i}");
        store
            .send(&frame, proof(&frame, DecisionOutcome::Allow), "hello")
            .unwrap();
    }
    let mut overflow = req;
    overflow.operation_id = "message-65".into();
    assert_eq!(
        store.send(&overflow, proof(&overflow, DecisionOutcome::Allow), "hello"),
        Err("BACKPRESSURE")
    );
    assert_eq!(store.message_count(), 64);
    store.acknowledge_delivery();
    store
        .send(&overflow, proof(&overflow, DecisionOutcome::Allow), "hello")
        .unwrap();
    assert_eq!(store.message_count(), 65);
}
#[tokio::test]
async fn sdk_round_trip_is_per_target_frame_not_handshake_capability() {
    let server = TestDecisionServer::start(
        TestApplication {
            manifest: manifest(),
            subject: actor("member-a"),
            tenant: "tenant-a".into(),
            domain: "chat".into(),
        },
        SigningKey::from_bytes(&[21; 32]),
        SigningKey::from_bytes(&[22; 32]),
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
    for target in [1, 2] {
        let mut req = request(store.facts(target).unwrap(), "create");
        req.operation_id = format!("message-{target}");
        req.nonce = format!("abcdefghijkl1234567890{target}00");
        let signed = SignedAuthorizationRequest::sign(&server.app_key, req).unwrap();
        let decision = client
            .authorize(&signed, &AccessToken::new("test-bearer").unwrap())
            .await
            .unwrap();
        store.send(&signed.request, decision, "hello").unwrap();
    }
    assert_eq!(store.message_count(), 2);
    server.stop().await;
}
