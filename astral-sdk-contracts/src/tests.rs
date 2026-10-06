use ed25519_dalek::SigningKey;

use crate::{
    identifier, opaque_identifier, sign_decision, verify_request, ApplicationManifest,
    AuthorizationDecision, AuthorizationRequest, ContractError, DecisionOutcome, ExternalSubject,
    ManifestRoute, ResourceFacts, ResourceOperation, ResourceResolver, SignedAuthorizationRequest,
    AUTHORIZATION_PATH, MAX_DECISION_TTL_MS,
};

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn request() -> AuthorizationRequest {
    AuthorizationRequest {
        app_id: "chat_app".into(),
        key_id: "client_key_1".into(),
        manifest_digest: "a".repeat(64),
        revision: "mapping-17".into(),
        request_id: "req_01".into(),
        nonce: "0123456789abcdefghijkl".into(),
        timestamp: 1_800_000_000_000,
        session_token_id: "gateway-token-42".into(),
        subject: ExternalSubject {
            issuer: "https://issuer.example/".into(),
            subject: "subject-9".into(),
        },
        method: "POST".into(),
        path: "/chat/messages/7".into(),
        action: "create".into(),
        operation_id: "operation-20261005-01".into(),
        facts: ResourceFacts {
            resource_type: "chat_message".into(),
            target_id: "7".into(),
            external_tenant_id: "tenant-a".into(),
            external_domain_id: "domain-a".into(),
            owner: Some(ExternalSubject {
                issuer: "https://issuer.example/".into(),
                subject: "subject-9".into(),
            }),
            revision: "etag-4".into(),
            operation: ResourceOperation::Object,
        },
    }
}

fn manifest() -> ApplicationManifest {
    ApplicationManifest {
        app_id: "chat_app".into(),
        revision: "manifest-2".into(),
        routes: vec![ManifestRoute {
            method: "POST".into(),
            path: "/chat/messages/{id}".into(),
            resource_type: "chat_message".into(),
            action: "create".into(),
            operation: ResourceOperation::Object,
            resolver: ResourceResolver::Object {
                target_id_path: "/{id}".into(),
            },
        }],
    }
}

#[test]
fn identifiers_and_manifest_mapping_are_strict() {
    assert!(identifier("chat_message").is_ok());
    assert!(identifier("Bad:resource").is_err());
    assert!(identifier("resource.*").is_err());
    assert!(identifier("_resource").is_err());
    assert!(opaque_identifier("https://issuer.example/tenant-a").is_ok());
    assert!(opaque_identifier("subject with spaces").is_err());

    let mut invalid = manifest();
    invalid.app_id = "chat app".into();
    assert!(invalid.validate().is_err());
    let mut invalid_target = request();
    invalid_target.facts.target_id = "9223372036854775808".into();
    assert!(invalid_target.validate().is_err());
    invalid_target.facts.target_id = "0".into();
    assert!(invalid_target.validate().is_err());
    invalid_target.facts.target_id = "0007".into();
    assert!(invalid_target.validate().is_err());
}

#[test]
fn serde_rejects_unknown_actor_and_platform_identity_fields() {
    let subject = r#"{"issuer":"https://issuer.example/","subject":"s1","user_id":7}"#;
    assert!(serde_json::from_str::<ExternalSubject>(subject).is_err());

    let mut value = serde_json::to_value(request()).unwrap();
    value["role"] = serde_json::json!("admin");
    assert!(serde_json::from_value::<AuthorizationRequest>(value).is_err());
}

#[test]
fn request_signature_binds_body_endpoint_session_and_nonce() {
    let signing_key = keypair(7);
    let signed = SignedAuthorizationRequest::sign(&signing_key, request()).unwrap();
    assert_eq!(
        AUTHORIZATION_PATH,
        "/main/api/v1/integrations/authorization-decisions"
    );
    assert!(signed.verify(&signing_key.verifying_key()).is_ok());

    let mut tampered = signed.request.clone();
    tampered.facts.target_id = "8".into();
    assert_eq!(
        verify_request(&signing_key.verifying_key(), &tampered, &signed.signature),
        Err(ContractError::InvalidSignature)
    );
    let mut tampered_session = signed.request.clone();
    tampered_session.session_token_id = "another-gateway-token".into();
    assert_eq!(
        verify_request(
            &signing_key.verifying_key(),
            &tampered_session,
            &signed.signature
        ),
        Err(ContractError::InvalidSignature)
    );
}

#[test]
fn decision_signature_is_bound_and_pending_or_deny_never_allow() {
    let signing_key = keypair(8);
    let req = request();
    let now = 1_800_000_000_100;
    let allow = AuthorizationDecision::bound_to(
        &req,
        "mapping-17",
        DecisionOutcome::Allow,
        Some("matched".into()),
        now,
    )
    .unwrap();
    assert!(allow.expires_at_ms - allow.issued_at_ms <= MAX_DECISION_TTL_MS);
    let signed = sign_decision("decision_key_1", &signing_key, allow).unwrap();
    let verified = signed
        .verify(
            &signing_key.verifying_key(),
            "decision_key_1",
            &req,
            now + 1,
        )
        .unwrap();
    assert!(verified.is_allow());
    assert!(verified.matches_request(&req));

    let mut tampered = signed;
    tampered.decision.mapping_revision = "mapping-18".into();
    assert!(matches!(
        tampered.verify(
            &signing_key.verifying_key(),
            "decision_key_1",
            &req,
            now + 1,
        ),
        Err(ContractError::InvalidSignature)
    ));

    for outcome in [DecisionOutcome::Deny, DecisionOutcome::Pending] {
        let decision =
            AuthorizationDecision::bound_to(&req, "mapping-17", outcome, None, now).unwrap();
        let signed = sign_decision("decision_key_1", &signing_key, decision).unwrap();
        let verified = signed
            .verify(
                &signing_key.verifying_key(),
                "decision_key_1",
                &req,
                now + 1,
            )
            .unwrap();
        assert!(!verified.is_allow());
    }
}

#[test]
fn manifest_rejects_duplicates_and_undeclared_or_mismatched_routes() {
    let declared = manifest();
    declared.validate().unwrap();
    assert!(declared.permits(
        "chat_message",
        "create",
        "POST",
        "/chat/messages/7",
        ResourceOperation::Object
    ));
    assert!(!declared.permits(
        "user_card",
        "create",
        "POST",
        "/chat/messages/7",
        ResourceOperation::Object
    ));
    assert!(!declared.permits(
        "chat_message",
        "delete",
        "POST",
        "/chat/messages/7",
        ResourceOperation::Object
    ));
    assert!(!declared.permits(
        "chat_message",
        "create",
        "GET",
        "/chat/messages/7",
        ResourceOperation::Object
    ));
    assert!(!declared.permits(
        "chat_message",
        "create",
        "POST",
        "/chat/other",
        ResourceOperation::Object
    ));
    let mut mismatched_target = request();
    mismatched_target.facts.target_id = "9".into();
    assert!(!declared.permits_request(&mismatched_target));
    let mut matching_request = request();
    matching_request.facts.resource_type = "chat_message".into();
    matching_request.action = "create".into();
    matching_request.method = "POST".into();
    matching_request.path = "/chat/messages/7".into();
    matching_request.facts.target_id = "7".into();
    assert!(declared.permits_request(&matching_request));

    let mut duplicate = manifest();
    duplicate.routes.push(duplicate.routes[0].clone());
    assert!(duplicate.validate().is_err());

    let mut ambiguous = manifest();
    ambiguous.routes[0].resolver = ResourceResolver::ScopedCollection {
        target_id_path: "/{id}".into(),
    };
    assert!(ambiguous.validate().is_err());
}

#[test]
fn request_timestamp_uses_fixed_clock_skew_window() {
    assert!(request().validate_at(1_800_000_000_001).is_ok());
    assert!(request().validate_at(1_800_000_100_000).is_err());
}

#[test]
fn overlapping_manifest_routes_and_expiry_boundary_are_refused() {
    let mut manifest = manifest();
    let mut other = manifest.routes[0].clone();
    other.path = "/chat/messages/{other}".into();
    other.resolver = ResourceResolver::Object {
        target_id_path: "/{other}".into(),
    };
    manifest.routes.push(other);
    assert!(manifest.validate().is_err());
    let key = keypair(10);
    let req = request();
    let decision =
        AuthorizationDecision::bound_to(&req, "1", DecisionOutcome::Allow, None, req.timestamp)
            .unwrap();
    let expiry = decision.expires_at_ms;
    let signed = sign_decision("decision-key", &key, decision).unwrap();
    assert!(matches!(
        signed.verify(&key.verifying_key(), "decision-key", &req, expiry),
        Err(ContractError::DecisionExpired)
    ));
    assert!(matches!(
        signed.verify(
            &key.verifying_key(),
            "decision-key",
            &req,
            req.timestamp - 1
        ),
        Err(ContractError::DecisionExpired)
    ));
}

#[test]
fn oversized_manifest_is_rejected_independently_of_field_bounds() {
    let mut value = manifest();
    value.routes = (0..128)
        .map(|index| {
            let mut route = value.routes[0].clone();
            route.path = format!("/long-route-{}-{index}/{{id}}", "x".repeat(300));
            route
        })
        .collect();
    assert!(matches!(
        value.validate(),
        Err(ContractError::PayloadTooLarge)
    ));
}
