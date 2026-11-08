use super::*;
use astral_types::*;

fn summary(generation: u64, aggregate_id: i64) -> PublishedAggregateManifestSummary {
    PublishedAggregateManifestSummary {
        seal: PublicationSeal::from_unix_seconds(100).unwrap(),
        tenant_id: 7,
        card_id: 17,
        aggregate_type: "USER_CARD".into(),
        aggregate_id,
        manifest_id: generation as i64 + 10,
        generation,
        source_generation: generation,
        projected_generation: generation,
        revoke_fence: 0,
        cas_version: generation as i64,
        semantic_hash_hex: "11".repeat(32),
        dependency_hash_hex: "22".repeat(32),
        manifest_digest_hex: format!("{generation:064x}"),
        compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
        event_id: format!("event-{generation}"),
        operation_id: format!("operation-{generation}"),
        parent_manifest_id: (generation > 1).then_some(generation as i64 + 9),
        segment_count: 0,
        declared_grant_row_count: 0,
    }
}

fn scope() -> AuthorityProtocolScope {
    AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 17,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    })
}

fn evidence(manifests: Vec<PublishedAggregateManifestSummary>) -> PublishedCardAuthorization {
    PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 17,
        read_unix_seconds: 100,
        gate: PublishedCardAuthorizationGate {
            status: PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: manifests.len(),
            verified_record_count: 0,
            effective_grant_count: 0,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests,
        records: vec![],
        effective_grants: vec![],
    }
}

fn baseline(manifests: Vec<AuthorityManifestIdentity>) -> AuthorityScopePublicationCertificate {
    AuthorityScopePublicationCertificate {
        protocol_version: AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority".into(),
        authority_term: 1,
        global_fence_sequence: 1,
        certificate_id: "baseline".into(),
        intent_digest: "11".repeat(32),
        reservation_id: "prior".into(),
        operation_id: "prior".into(),
        event_id: "prior".into(),
        scope: scope(),
        approved_request_digest: "22".repeat(32),
        before_image_digest: Some("33".repeat(32)),
        after_image_digest: "44".repeat(32),
        source_commit_digest: "55".repeat(32),
        completion_digest: "66".repeat(32),
        snapshot_hash: "77".repeat(32),
        source_outcome_digest: "88".repeat(32),
        parent_certificate_hash: None,
        manifests,
        key_id: "signer".into(),
        key_epoch: 1,
        issued_at: 100,
        not_before: 100,
        expires_at: None,
        certificate_nonce: "nonce".into(),
        signature: "00".repeat(64),
    }
}

fn receipt(manifest: &PublishedAggregateManifestSummary) -> DeltaEventAppendRequest {
    let grant = CanonicalGrant {
        grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(7, None).unwrap(),
        card_id: 17,
        user_id: 23,
        resource: "learn_subject".into(),
        action: "read".into(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "source".into(),
            source_entry: Some("entry".into()),
            binding_id: Some("binding".into()),
            delegation_id: None,
            operation_id: manifest.operation_id.clone(),
            event_id: Some(manifest.event_id.clone()),
            actor_user_id: Some(23),
        },
    };
    DeltaEventAppendRequest {
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: manifest.aggregate_type.clone(),
        aggregate_id: manifest.aggregate_id,
        grant_id: grant.grant_id,
        event_id: manifest.event_id.clone(),
        operation_id: manifest.operation_id.clone(),
        event_type: crate::DeltaEventType::Add,
        base_version: 0,
        target_version: 1,
        source_generation: manifest.source_generation,
        revoke_fence: 0,
        invalidates_published_evidence: false,
        before_image_json: None,
        before_digest_hex: None,
        delta_json: serde_json::to_string(&GrantDelta::add(grant)).unwrap(),
        semantic_hash_hex: manifest.semantic_hash_hex.clone(),
        dependency_hash_hex: manifest.dependency_hash_hex.clone(),
        compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
        next_attempt_at: None,
    }
}

#[test]
fn a_later_unrelated_publication_cannot_be_signed_for_an_earlier_source_batch() {
    let prior = baseline(vec![manifest_identity(&summary(1, 17))]);
    let approved = summary(2, 17);
    let request = receipt(&approved);
    let proof = OwnedDeltaCompletionProof::from_test_receipt(
        &request,
        approved.manifest_id,
        2,
        &approved.manifest_digest_hex,
    );
    // The exact approved event is retained, but current includes another
    // reservation's generation. Historical closure cannot approve that content.
    assert!(validate_transition(
        &scope(),
        &evidence(vec![summary(3, 17)]),
        Some(&prior),
        &[(&request, proof)],
    )
    .is_err());
}

#[test]
fn continuous_generation_still_requires_exact_parent_content_and_revoke_fence() {
    let approved = summary(2, 17);
    let request = receipt(&approved);
    let proof = OwnedDeltaCompletionProof::from_test_receipt(
        &request,
        approved.manifest_id,
        2,
        &approved.manifest_digest_hex,
    );
    let complete = vec![(&request, proof)];
    let mut wrong_parent = summary(1, 17);
    wrong_parent.manifest_digest_hex = "fe".repeat(32);
    assert!(validate_transition(
        &scope(),
        &evidence(vec![approved.clone()]),
        Some(&baseline(vec![manifest_identity(&wrong_parent)])),
        &complete,
    )
    .is_err());
    let mut revoked = summary(1, 17);
    revoked.revoke_fence = 1;
    assert!(validate_transition(
        &scope(),
        &evidence(vec![approved]),
        Some(&baseline(vec![manifest_identity(&revoked)])),
        &complete,
    )
    .is_err());
}

#[test]
fn only_contiguous_approved_changes_can_extend_a_certified_bundle() {
    let prior = baseline(vec![manifest_identity(&summary(1, 17))]);
    let current = summary(2, 17);
    let request = receipt(&current);
    let proof = OwnedDeltaCompletionProof::from_test_receipt(
        &request,
        current.manifest_id,
        2,
        &current.manifest_digest_hex,
    );
    let complete = vec![(&request, proof)];
    assert!(validate_transition(
        &scope(),
        &evidence(vec![current.clone()]),
        Some(&prior),
        &complete
    )
    .is_ok());
    assert!(
        validate_transition(&scope(), &evidence(vec![current.clone()]), None, &complete).is_err()
    );
    assert!(validate_transition(
        &scope(),
        &evidence(vec![current.clone()]),
        Some(&prior),
        &[]
    )
    .is_err());
    let mut forged = current.clone();
    forged.manifest_digest_hex = "ff".repeat(32);
    assert!(
        validate_transition(&scope(), &evidence(vec![forged]), Some(&prior), &complete).is_err()
    );
    let skipped = summary(3, 17);
    let skipped_request = receipt(&skipped);
    let skipped_proof = OwnedDeltaCompletionProof::from_test_receipt(
        &skipped_request,
        skipped.manifest_id,
        3,
        &skipped.manifest_digest_hex,
    );
    assert!(validate_transition(
        &scope(),
        &evidence(vec![skipped]),
        Some(&prior),
        &[(&skipped_request, skipped_proof)]
    )
    .is_err());
    let unknown = summary(1, 99);
    assert!(validate_transition(
        &scope(),
        &evidence(vec![current.clone(), unknown.clone()]),
        Some(&prior),
        &complete
    )
    .is_err());
    let with_unchanged = baseline(vec![
        manifest_identity(&summary(1, 17)),
        manifest_identity(&unknown),
    ]);
    assert!(validate_transition(
        &scope(),
        &evidence(vec![current.clone(), unknown]),
        Some(&with_unchanged),
        &complete
    )
    .is_ok());
    assert!(validate_transition(
        &scope(),
        &evidence(vec![current]),
        Some(&with_unchanged),
        &complete
    )
    .is_err());
}
