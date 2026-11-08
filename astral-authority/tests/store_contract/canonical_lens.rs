//! Canonical card publication lookup and exact-lens read proofs.
//!
//! Card publications live at the canonical `(tenant_id, card_id)` identity
//! (`user_id: None`, `domain: Any`): every user/domain lens of one card reads
//! the SAME immutable certificate, while each minted proof keeps its exact
//! requested actor lens and its own per-lens one-use nonce. Certifying a
//! lens-bearing card scope is refused: lens-specific certificates never
//! exist. Same-card blocking is identity-closed; other cards and ORG scopes
//! are never conflated (ORG stays exact, never normalized into card terms).
//! These regressions run the real `AuthorityService` against
//! `MemoryAuthorityStore` — an in-process CAS mirror, NOT real etcd/quorum.

use super::*;

use astral_types::AuthorityFenceReadResponse;

fn card_scope_for(tenant_id: i64, card_id: i64) -> AuthorityProtocolScope {
    AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
        tenant_id,
        card_id,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    })
}

fn lens_scope(user_id: i64, domain_value: i64) -> AuthorityProtocolScope {
    AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
        tenant_id: 7,
        card_id: 17,
        user_id: Some(user_id),
        domain: AuthorizationDomainScope::Exact(domain_value),
    })
}

fn org_scope(tenant_id: i64, user_id: i64, card_id: i64) -> AuthorityProtocolScope {
    AuthorityProtocolScope::Org(astral_types::AuthorityOrgScope {
        tenant_id,
        root_tenant_id: None,
        member: astral_types::AuthorityOrgMemberSubject {
            user_id,
            identity_card_id: user_id + 1,
            card_id,
        },
    })
}

fn lens_read_proof(lens: &AuthorityProtocolScope, nonce: &str) -> AuthorityReadProofRequest {
    AuthorityReadProofRequest {
        actor_scope: lens.clone(),
        source_scope: None,
        request_nonce: nonce.to_owned(),
        mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
        operation_id: OPERATION_ID.to_owned(),
        event_id: "event-1".to_owned(),
        request_binding_digest: "11".repeat(32),
        expected_frontier: None,
        proof_ttl_seconds: None,
    }
}

async fn mint_lens_proof(
    service: &AuthorityService,
    lens: &AuthorityProtocolScope,
    nonce: &str,
) -> AuthorizationFenceProof {
    attempt_mint(service, lens, nonce)
        .await
        .expect("card-scope lens mint issues a proof")
        .proof
        .expect("the minted read proof is present")
}

async fn attempt_mint(
    service: &AuthorityService,
    lens: &AuthorityProtocolScope,
    nonce: &str,
) -> Result<AuthorityFenceReadResponse, AuthorityServiceError> {
    service
        .read_fence(&AuthorityFenceReadRequest {
            caller: caller(),
            scope: None,
            expected_certificate_hash: None,
            read_proof: Some(lens_read_proof(lens, nonce)),
        })
        .await
}

#[tokio::test]
async fn card_lenses_share_the_canonical_publication_and_keep_exact_proofs() {
    // EXACT single-scope lifecycle: certification auto-closes the barrier, so
    // the post-publication lens reads and mints below are not blocked.
    let (service, store, keys, signer_key) = test_service_with_exact_coverage(true).await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;

    let one = op_one();
    let prepare = service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &one,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();
    service
        .record_source_commit(&op_commit_request(
            &one,
            &prepare.reservation,
            Some(astral_types::AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
        ))
        .await
        .unwrap();

    let lens_a = lens_scope(23, 31);
    let lens_b = lens_scope(24, 32);
    assert_ne!(
        lens_a.store_key_text().unwrap(),
        lens_b.store_key_text().unwrap()
    );
    assert_ne!(
        lens_a.store_key_text().unwrap(),
        card_scope().store_key_text().unwrap()
    );

    // Certifying a lens-bearing card scope is refused: certificates exist
    // only at the canonical publication identity, so lens-specific
    // certificates can never be created.
    let lens_certify = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            lens_a.clone(),
        ))
        .await;
    assert!(
        matches!(
            lens_certify,
            Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch
            ))
        ),
        "a lens-bearing card scope must never certify, got {lens_certify:?}"
    );

    let certify = service
        .certify_publication(&op_certify_request(
            &one,
            &prepare.reservation,
            None,
            card_scope(),
        ))
        .await
        .unwrap();
    assert_certify_binds_post_publication_frontier(&certify, &signer_key.verifying_key());
    assert_eq!(
        certify.reservation.state,
        astral_types::AuthorityReservationState::Certified,
        "single-scope EXACT coverage auto-closes"
    );
    let canonical_hash = certify.certificate.record_digest().unwrap();
    let canonical_key = card_scope().store_key_text().unwrap();

    // Both lenses resolve to the SAME immutable certificate under the
    // canonical pointer, and the pinned-hash check runs against it.
    for lens in [&lens_a, &lens_b] {
        let fence = service
            .read_fence(&AuthorityFenceReadRequest {
                caller: caller(),
                scope: Some(lens.clone()),
                expected_certificate_hash: Some(canonical_hash.clone()),
                read_proof: None,
            })
            .await
            .unwrap();
        assert_eq!(
            fence.scope_certificate.as_ref().unwrap(),
            &certify.certificate,
            "a card lens must read the canonical certificate"
        );
        assert_eq!(
            fence.scope_certificate_hash.as_deref(),
            Some(canonical_hash.as_str())
        );
    }
    // A lens pinning a foreign hash is refused.
    assert!(matches!(
        service
            .read_fence(&AuthorityFenceReadRequest {
                caller: caller(),
                scope: Some(lens_a.clone()),
                expected_certificate_hash: Some("ff".repeat(32)),
                read_proof: None,
            })
            .await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::FrontierDiverged
        ))
    ));

    // Each lens mints its own exact proof over the shared certificate.
    let proof_a = mint_lens_proof(&service, &lens_a, "lens-a-nonce").await;
    let proof_b = mint_lens_proof(&service, &lens_b, "lens-b-nonce").await;
    assert_ne!(proof_a.proof_id, proof_b.proof_id);
    proof_a
        .verify_at(&signer_key.verifying_key(), now_unix_seconds())
        .unwrap();
    proof_b
        .verify_at(&signer_key.verifying_key(), now_unix_seconds())
        .unwrap();
    assert_eq!(
        proof_a.scope,
        astral_types::AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: Some(23),
            domain: AuthorizationDomainScope::Exact(31),
        },
        "the proof keeps the exact requested actor lens"
    );
    assert_eq!(proof_b.scope.user_id, Some(24));
    assert_eq!(
        proof_a.scope_certificate_hash, proof_b.scope_certificate_hash,
        "both lens proofs bind the same immutable certificate"
    );
    assert_eq!(
        proof_a.scope_certificate_hash.as_deref(),
        Some(canonical_hash.as_str())
    );
    assert_eq!(proof_a.snapshot_hash, certify.certificate.snapshot_hash);

    // Receipts: exact actor lens, canonical source binding.
    let receipt: StoredProofReceipt = serde_json::from_slice(
        &store
            .get(&keys.proof_binding(&proof_a.proof_id))
            .await
            .unwrap()
            .unwrap()
            .value,
    )
    .unwrap();
    assert_eq!(
        receipt.actor_scope_key,
        lens_a.store_key_text().unwrap(),
        "the receipt keeps the exact request lens"
    );
    assert_eq!(
        receipt.source_scope_key, canonical_key,
        "the source binding names the actual canonical certificate"
    );
    assert_eq!(receipt.request_nonce, "lens-a-nonce");

    // Per-lens one-use nonce indexes, never conflated across lenses.
    assert!(store
        .get(&keys.proof_nonce(&lens_a.store_key_text().unwrap(), "lens-a-nonce"))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get(&keys.proof_nonce(&lens_b.store_key_text().unwrap(), "lens-b-nonce"))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get(&keys.proof_nonce(&canonical_key, "lens-a-nonce"))
        .await
        .unwrap()
        .is_none());

    // The publication pointer and the certification index exist only at the
    // canonical identity: the CAS ran against the actual publication pointer
    // for both lens mints, and no lens certificate/index was created.
    assert!(store
        .get(&keys.scope_current(&canonical_key))
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get(&keys.scope_current(&lens_a.store_key_text().unwrap()))
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get(&keys.reservation_certificate(
            &prepare.reservation.reservation_id,
            &lens_a.store_key_text().unwrap()
        ))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn same_card_blocking_is_identity_closed_and_other_scopes_stay_exact() {
    // An active EXACT reservation on the canonical card identity blocks every
    // lens of that card — and only that card.
    let (service, store, keys, signer_key) = test_service_with_exact_coverage(true).await;
    seed_admission_proof(
        &service,
        &store,
        &keys,
        &signer_key,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;
    let one = op_one();
    service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &one,
                AuthorityReservationCoverage::Exact(vec![card_scope()]),
            ),
        })
        .await
        .unwrap();

    // Same card, different user/domain lens: blocked by identity.
    assert!(matches!(
        attempt_mint(&service, &lens_scope(23, 31), "blocked-lens-a").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ReadsBlocked { .. }
        ))
    ));
    // The canonical lens itself: blocked.
    assert!(matches!(
        attempt_mint(&service, &card_scope(), "blocked-canonical").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::ReadsBlocked { .. }
        ))
    ));
    // A different card: NOT blocked — the request passes blocking and fails
    // at the publication lookup instead (no publication for that card).
    assert!(matches!(
        attempt_mint(&service, &card_scope_for(9, 42), "cross-card").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "scope_publication"
            }
        ))
    ));
    // Different tenant, same card id: not blocked either.
    assert!(matches!(
        attempt_mint(&service, &card_scope_for(8, 17), "cross-tenant").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "scope_publication"
            }
        ))
    ));

    // ORG exactness: an active ORG reservation never blocks a card (ORG is
    // never normalized into card terms, and a card never leaks into ORG).
    let (org_service, org_store, org_keys, org_signer) =
        test_service_with_exact_coverage(true).await;
    seed_admission_proof(
        &org_service,
        &org_store,
        &org_keys,
        &org_signer,
        "prf-seed",
        REQUEST_DIGEST,
    )
    .await;
    org_service
        .prepare_source_mutation(&AuthorityPrepareRequest {
            caller: caller(),
            intent: op_intent(
                &one,
                AuthorityReservationCoverage::Exact(vec![org_scope(9, 1, 3)]),
            ),
        })
        .await
        .unwrap();
    // The card request passes blocking and fails only at the missing
    // publication: the ORG reservation did not block the card identity.
    assert!(matches!(
        attempt_mint(&org_service, &card_scope_for(7, 17), "org-not-normalized").await,
        Err(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "scope_publication"
            }
        ))
    ));
}
