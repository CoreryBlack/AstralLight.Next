//! Binding of administrative publication and membership facts to a fence proof.

use sha2::{Digest, Sha256};

use crate::org_scope::OrgAdmissionEvidence;
use crate::{
    authorization_request_digest, AuthorityOrgScope, AuthorityProtocolScope,
    AuthorityScopePublicationCertificate, AuthorizationAuthorityError, AuthorizationDomainScope,
    AuthorizationFenceProof, DomainScopeRequirement, PolicyContext, PublishedCardEvidenceScope,
};

pub fn org_authority_evidence_scope(
    context: &PolicyContext,
) -> Result<PublishedCardEvidenceScope, AuthorizationAuthorityError> {
    let scope = PublishedCardEvidenceScope {
        tenant_id: context
            .tenant_id
            .ok_or(AuthorizationAuthorityError::ScopeMismatch)?,
        card_id: context
            .card_id
            .ok_or(AuthorizationAuthorityError::ScopeMismatch)?,
        user_filter: context.user_id,
        domain: match context.domain_id {
            Some(domain_id) => DomainScopeRequirement::ExactlySome(domain_id),
            None => DomainScopeRequirement::ExactlyNone,
        },
    };
    scope
        .validate()
        .map_err(|_| AuthorizationAuthorityError::ScopeMismatch)?;
    Ok(scope)
}

/// The read clock is excluded from content identity. Publication, dependency,
/// node and membership fields remain bound in full, including validity windows.
pub fn org_authority_evidence_hash(
    evidence: &OrgAdmissionEvidence,
) -> Result<String, AuthorizationAuthorityError> {
    evidence
        .validate()
        .map_err(|_| AuthorizationAuthorityError::ScopeMismatch)?;
    org_evidence_content_digest(evidence, b"ASTRAL_ORG_AUTHORITY_EVIDENCE_V7\0")
}

/// Content identity of an ORG REVOCATION admission evidence (V7).
///
/// Allowed ONLY for evidence whose node or membership is inactive (at least
/// one): an all-active evidence is a positive admission input and must go
/// through [`org_authority_evidence_hash`]; expiry alone (still active) is
/// never a revocation. The full structural binding is enforced exactly as on
/// the positive path (shared single owner on
/// `OrgAdmissionEvidence::validate_structure`): tenant/root identity, node
/// head fences, dependency pinning and the complete publication/node/
/// membership content. `checked_at_unix` stays excluded from content
/// identity; membership validity bytes remain bound in full.
pub fn org_authority_revocation_evidence_hash(
    evidence: &OrgAdmissionEvidence,
) -> Result<String, AuthorizationAuthorityError> {
    evidence
        .validate_structure()
        .map_err(|_| AuthorizationAuthorityError::ScopeMismatch)?;
    if evidence.node.active && evidence.membership.active {
        return Err(AuthorizationAuthorityError::ScopeMismatch);
    }
    org_evidence_content_digest(evidence, b"ASTRAL_ORG_AUTHORITY_REVOCATION_EVIDENCE_V7\0")
}

/// Shared canonical content digest for the positive and revocation ORG
/// evidence identities: the complete publication/node/membership content
/// (validity windows included, read clock excluded) under one
/// domain-separated V7 header.
fn org_evidence_content_digest(
    evidence: &OrgAdmissionEvidence,
    domain: &[u8],
) -> Result<String, AuthorizationAuthorityError> {
    let content =
        serde_json::to_vec(&(&evidence.publication, &evidence.node, &evidence.membership))
            .map_err(|_| AuthorizationAuthorityError::ScopeMismatch)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(content);
    Ok(hex::encode(digest.finalize()))
}

/// Validate an ORG proof against the exact request and its immutable evidence.
///
/// `snapshot_hash` is the ORG evidence content identity. It is intentionally
/// independent from the certified-memory root attestation hash; the latter is
/// checked by the memory repository as a global root identity.
pub fn validate_org_authority_proof(
    proof: &AuthorizationFenceProof,
    context: &PolicyContext,
    evidence: &OrgAdmissionEvidence,
    nonce: &str,
    now_seconds: i64,
) -> Result<(), AuthorizationAuthorityError> {
    proof.validate_at(now_seconds)?;
    if proof.request_binding_digest.is_none() || proof.scope_certificate_hash.is_none() {
        return Err(AuthorizationAuthorityError::ScopeMismatch);
    }
    proof
        .scope
        .matches_evidence_scope(&org_authority_evidence_scope(context)?)?;
    let domain_matches = match proof.scope.domain {
        AuthorizationDomainScope::Any => false,
        AuthorizationDomainScope::NoDomain => context.domain_id.is_none(),
        AuthorizationDomainScope::Exact(domain_id) => context.domain_id == Some(domain_id),
    };
    let request_binding_digest = authorization_request_digest(context)
        .map_err(|_| AuthorizationAuthorityError::ScopeMismatch)?;
    let request_binding_matches =
        proof.request_binding_digest.as_deref() == Some(request_binding_digest.as_str());
    if proof.request_nonce != nonce
        || !domain_matches
        || !request_binding_matches
        || context.user_id != Some(evidence.membership.user_id)
        || context.identity_card_id != Some(evidence.membership.identity_card_id)
        || context.card_id != Some(evidence.membership.card_id)
        || context.tenant_id != Some(evidence.membership.tenant_id)
        || proof.scope_generation != evidence.publication.generation
        || proof.revoke_watermark != evidence.publication.revoke_fence
        || proof.snapshot_hash != org_authority_evidence_hash(evidence)?
    {
        return Err(AuthorizationAuthorityError::ScopeMismatch);
    }
    Ok(())
}

/// The publication certificate's mutation identity and signer may legitimately
/// differ from the fresh request proof: the proof authorizes a read of an
/// existing publication, while the certificate records the publication
/// operation. The authority transport must verify the certificate signature
/// against its registered signer before this value-level binding is accepted.
pub fn validate_org_authority_proof_with_certificate(
    proof: &AuthorizationFenceProof,
    context: &PolicyContext,
    evidence: &OrgAdmissionEvidence,
    certificate: &AuthorityScopePublicationCertificate,
    nonce: &str,
    now_seconds: i64,
) -> Result<(), AuthorizationAuthorityError> {
    validate_org_authority_proof(proof, context, evidence, nonce, now_seconds)?;
    certificate
        .validate()
        .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?;
    let expected_scope = AuthorityProtocolScope::Org(AuthorityOrgScope {
        tenant_id: evidence.publication.tenant_id,
        root_tenant_id: Some(evidence.publication.root_tenant_id),
        member: crate::AuthorityOrgMemberSubject {
            user_id: evidence.membership.user_id,
            identity_card_id: evidence.membership.identity_card_id,
            card_id: evidence.membership.card_id,
        },
    });
    let certificate_hash = certificate
        .record_digest()
        .map_err(|_| AuthorizationAuthorityError::EvidenceInvalid)?;
    let evidence_hash = org_authority_evidence_hash(evidence)?;
    let (certificate_generation, certificate_revoke_watermark) =
        certificate
            .manifests
            .iter()
            .fold((0, 0), |(generation, revoke_watermark), manifest| {
                (
                    generation.max(manifest.generation),
                    revoke_watermark.max(manifest.revoke_fence),
                )
            });
    if proof.scope_certificate_hash.as_deref() != Some(certificate_hash.as_str())
        || certificate.scope != expected_scope
        || certificate.snapshot_hash != evidence_hash
        || certificate.authority_id != proof.authority_id
        || certificate.authority_term > proof.authority_term
        || certificate.global_fence_sequence > proof.global_fence_sequence
        || certificate_generation != proof.scope_generation
        || certificate_revoke_watermark != proof.revoke_watermark
    {
        return Err(AuthorizationAuthorityError::EvidenceFrontierMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org_scope::{
        org_build_segment, org_manifest_digest_hex, OrgContribution, OrgGrant, OrgGrantRef,
        OrgManifestDigestMaterial, OrgProvenance, OrgScope, OrgScopeKey, OrgSegmentContent,
    };
    use crate::AuthorizationAuthorityScope;
    use crate::ValidityWindow;
    use uuid::Uuid;

    const ROOT_TENANT: i64 = 100;

    fn uuid(seed: u8) -> String {
        Uuid::from_u128(0xA57A_0000_0000_0000_0000_0000_0000_0000u128 | seed as u128).to_string()
    }

    fn root_genesis_grant() -> OrgGrant {
        OrgGrant {
            grant_id: uuid(1),
            revision: 1,
            receiving_tenant_id: ROOT_TENANT,
            origin_tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            scope: OrgScope {
                resource_tenant_id: ROOT_TENANT,
                domain_id: None,
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
                validity: ValidityWindow::between(1_000, 2_000),
            },
            delegable: true,
            parent: None,
            subject: None,
            active: true,
            operation_id: "op-grant-1".to_owned(),
        }
    }

    fn contribution(grant: &OrgGrant) -> OrgContribution {
        OrgContribution {
            grant_ref: OrgGrantRef {
                tenant_id: grant.receiving_tenant_id,
                grant_id: grant.grant_id.clone(),
                revision: grant.revision,
            },
            scope: grant.scope.clone(),
            delegable: grant.delegable,
            subject: grant.subject,
            provenance: OrgProvenance {
                origin_tenant_id: grant.origin_tenant_id,
                parent_chain: Vec::new(),
                operation_id: grant.operation_id.clone(),
            },
        }
    }

    /// A fully valid sealed root publication: one segment, one contribution,
    /// manifest digest recomputed over the exact publication material.
    fn single_segment_publication() -> crate::org_scope::OrgPublication {
        let grant = root_genesis_grant();
        let content = OrgSegmentContent {
            key: OrgScopeKey {
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
            },
            contributions: vec![contribution(&grant)],
        };
        let segment = org_build_segment(0, content).expect("valid fixture segment");
        let publication = crate::org_scope::OrgPublication {
            tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: Vec::new(),
            manifest_digest_hex: String::new(),
            compiler_version: crate::AUTHORIZATION_ORG_COMPILER_VERSION.to_owned(),
            segments: vec![segment],
            operation_id: "op-publish-1".to_owned(),
        };
        let digest = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .expect("valid fixture digest");
        crate::org_scope::OrgPublication {
            manifest_digest_hex: digest,
            ..publication
        }
    }

    fn node(active: bool) -> crate::org_scope::OrgNode {
        crate::org_scope::OrgNode {
            tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active,
            operation_id: "op-root".to_owned(),
            root_activation: Some(crate::org_scope::OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".to_owned(),
            }),
        }
    }

    fn membership(active: bool) -> crate::org_scope::OrgMembership {
        crate::org_scope::OrgMembership {
            membership_id: uuid(9),
            tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            user_id: 11,
            identity_card_id: 111,
            card_id: 222,
            revision: 1,
            active,
            validity: ValidityWindow::between(0, 9_999),
            operation_id: "op-member-1".to_owned(),
        }
    }

    fn active_evidence() -> OrgAdmissionEvidence {
        OrgAdmissionEvidence {
            publication: single_segment_publication(),
            node: node(true),
            membership: membership(true),
            checked_at_unix: 1_500,
        }
    }

    fn authority_context() -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(11))
            .principal_kind(Some("PLATFORM_USER".to_owned()))
            .card_id(Some(222))
            .identity_card_id(Some(111))
            .tenant_id(Some(ROOT_TENANT))
            .resource(Some("doc:42".to_owned()))
            .action("read".to_owned())
            .target_id(Some(42))
            .request_fingerprint(Some("a".repeat(64)))
            .request_operation_id(Some("op-request-1".to_owned()))
            .build()
    }

    fn authority_proof(
        context: &PolicyContext,
        evidence: &OrgAdmissionEvidence,
    ) -> AuthorizationFenceProof {
        AuthorizationFenceProof {
            authorization_edition: crate::AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: AuthorizationAuthorityScope::from_evidence_scope(
                &org_authority_evidence_scope(context).unwrap(),
            ),
            scope_generation: evidence.publication.generation,
            revoke_watermark: evidence.publication.revoke_fence,
            snapshot_hash: org_authority_evidence_hash(evidence).unwrap(),
            parent_hash: None,
            operation_id: "op-authority-1".to_owned(),
            event_id: "event-authority-1".to_owned(),
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 2_000,
            request_nonce: "nonce-1".to_owned(),
            request_binding_digest: Some(authorization_request_digest(context).unwrap()),
            scope_certificate_hash: Some("cd".repeat(32)),
            proof_id: "proof-1".to_owned(),
            signature: "00".repeat(64),
        }
    }

    fn revoked_evidence() -> OrgAdmissionEvidence {
        let mut evidence = active_evidence();
        evidence.membership.active = false;
        evidence
    }

    fn authority_certificate(
        context: &PolicyContext,
        evidence: &OrgAdmissionEvidence,
        proof: &AuthorizationFenceProof,
    ) -> AuthorityScopePublicationCertificate {
        AuthorityScopePublicationCertificate {
            protocol_version: crate::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: crate::AUTHORIZATION_EDITION,
            authority_id: proof.authority_id.clone(),
            authority_term: proof.authority_term,
            global_fence_sequence: proof.global_fence_sequence,
            certificate_id: "certificate-1".to_owned(),
            intent_digest: "11".repeat(32),
            reservation_id: "reservation-1".to_owned(),
            operation_id: proof.operation_id.clone(),
            event_id: proof.event_id.clone(),
            scope: AuthorityProtocolScope::Org(AuthorityOrgScope {
                tenant_id: evidence.publication.tenant_id,
                root_tenant_id: Some(evidence.publication.root_tenant_id),
                member: crate::AuthorityOrgMemberSubject {
                    user_id: evidence.membership.user_id,
                    identity_card_id: evidence.membership.identity_card_id,
                    card_id: evidence.membership.card_id,
                },
            }),
            approved_request_digest: authorization_request_digest(context).unwrap(),
            before_image_digest: None,
            after_image_digest: "22".repeat(32),
            source_commit_digest: "33".repeat(32),
            completion_digest: "44".repeat(32),
            snapshot_hash: org_authority_evidence_hash(evidence).unwrap(),
            source_outcome_digest: "55".repeat(32),
            parent_certificate_hash: None,
            manifests: vec![crate::AuthorityManifestIdentity {
                aggregate_type: "ORG_PUBLICATION".to_owned(),
                aggregate_id: evidence.publication.tenant_id,
                manifest_digest_hex: evidence.publication.manifest_digest_hex.clone(),
                dependency_hash_hex: "66".repeat(32),
                semantic_hash_hex: "77".repeat(32),
                generation: evidence.publication.generation,
                revoke_fence: evidence.publication.revoke_fence,
                event_id: proof.event_id.clone(),
                operation_id: proof.operation_id.clone(),
            }],
            key_id: proof.key_id.clone(),
            key_epoch: proof.key_epoch,
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: None,
            certificate_nonce: "certificate-nonce-1".to_owned(),
            signature: "00".repeat(64),
        }
    }

    #[test]
    fn validator_rejects_missing_request_binding_digest() {
        let context = authority_context();
        let evidence = active_evidence();
        let mut proof = authority_proof(&context, &evidence);
        proof.request_binding_digest = None;

        assert_eq!(
            validate_org_authority_proof(&proof, &context, &evidence, "nonce-1", 1_500),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
    }

    #[test]
    fn validator_rejects_mismatched_request_binding_digest() {
        let context = authority_context();
        let evidence = active_evidence();
        let mut proof = authority_proof(&context, &evidence);
        proof.request_binding_digest = Some("b".repeat(64));

        assert_eq!(
            validate_org_authority_proof(&proof, &context, &evidence, "nonce-1", 1_500),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
    }

    #[test]
    fn validator_binds_evidence_identity_separately_from_any_memory_root_hash() {
        let context = authority_context();
        let evidence = active_evidence();
        let proof = authority_proof(&context, &evidence);
        let root_hash = "ef".repeat(32);
        assert_ne!(root_hash, proof.snapshot_hash);
        assert!(
            validate_org_authority_proof(&proof, &context, &evidence, "nonce-1", 1_500).is_ok()
        );
    }

    #[test]
    fn certificate_binding_requires_the_real_record_digest_and_frontier_fields() {
        let context = authority_context();
        let evidence = active_evidence();
        let mut proof = authority_proof(&context, &evidence);
        let certificate = authority_certificate(&context, &evidence, &proof);
        proof.scope_certificate_hash = Some(certificate.record_digest().unwrap());
        assert!(validate_org_authority_proof_with_certificate(
            &proof,
            &context,
            &evidence,
            &certificate,
            "nonce-1",
            1_500,
        )
        .is_ok());

        let mut changed = certificate.clone();
        changed.key_id = "different-key".to_owned();
        assert_eq!(
            validate_org_authority_proof_with_certificate(
                &proof, &context, &evidence, &changed, "nonce-1", 1_500,
            ),
            Err(AuthorizationAuthorityError::EvidenceFrontierMismatch)
        );

        let mut changed_proof = proof.clone();
        changed_proof.scope_certificate_hash = Some("ab".repeat(32));
        assert_eq!(
            validate_org_authority_proof_with_certificate(
                &changed_proof,
                &context,
                &evidence,
                &certificate,
                "nonce-1",
                1_500,
            ),
            Err(AuthorizationAuthorityError::EvidenceFrontierMismatch)
        );
    }

    #[test]
    fn positive_hash_is_stable_and_domain_separated_from_revocation() {
        let evidence = active_evidence();
        let hash = org_authority_evidence_hash(&evidence).unwrap();
        // Same content twice → same digest (extraction did not move content).
        assert_eq!(hash, org_authority_evidence_hash(&evidence).unwrap());
        // The revocation identity is a DIFFERENT domain over the same bytes.
        assert_ne!(
            hash,
            org_authority_revocation_evidence_hash(&revoked_evidence()).unwrap()
        );
        // The read clock is excluded from both identities (a different but
        // still-valid clock produces the same digests).
        let mut later = evidence.clone();
        later.checked_at_unix = 5_000;
        assert_eq!(hash, org_authority_evidence_hash(&later).unwrap());
        let revoked = revoked_evidence();
        let revocation_hash = org_authority_revocation_evidence_hash(&revoked).unwrap();
        let mut later_revoked = revoked.clone();
        later_revoked.checked_at_unix = 5_000;
        assert_eq!(
            revocation_hash,
            org_authority_revocation_evidence_hash(&later_revoked).unwrap()
        );
    }

    #[test]
    fn revocation_validity_bytes_stay_bound_but_expiry_alone_is_not_revocation() {
        let evidence = active_evidence();
        // Expiry alone (membership still active, window passed) is NOT a
        // revocation: the all-active gate refuses, independent of the clock.
        let mut expired = evidence.clone();
        expired.membership.validity = ValidityWindow::between(0, 100);
        assert!(expired.validate().is_err());
        assert_eq!(
            org_authority_revocation_evidence_hash(&expired),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
        // The same inactive membership keeps its validity bytes in the
        // identity: changing the window changes the revocation digest.
        let mut revoked = revoked_evidence();
        let hash = org_authority_revocation_evidence_hash(&revoked).unwrap();
        revoked.membership.validity = ValidityWindow::between(0, 8_888);
        assert_ne!(
            hash,
            org_authority_revocation_evidence_hash(&revoked).unwrap()
        );
    }

    #[test]
    fn positive_path_rejects_inactive_evidence() {
        let mut node_inactive = active_evidence();
        node_inactive.node.active = false;
        assert!(org_authority_evidence_hash(&node_inactive).is_err());
        assert!(org_authority_evidence_hash(&revoked_evidence()).is_err());
    }

    #[test]
    fn revocation_refuses_cross_tenant_and_fence_drifted_structure() {
        // Cross-tenant membership never binds, even when inactive.
        let mut cross_tenant = revoked_evidence();
        cross_tenant.membership.tenant_id = 999;
        assert_eq!(
            org_authority_revocation_evidence_hash(&cross_tenant),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
        // Node head fence drift (generation/fence/relationship) is refused.
        let mut fence_drift = revoked_evidence();
        fence_drift.node.generation += 1;
        assert_eq!(
            org_authority_revocation_evidence_hash(&fence_drift),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
        // A different root unit is refused as well.
        let mut other_root = revoked_evidence();
        other_root.publication.root_tenant_id = 555;
        other_root.node.root_tenant_id = 555;
        other_root.membership.root_tenant_id = 555;
        assert_eq!(
            org_authority_revocation_evidence_hash(&other_root),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
    }

    #[test]
    fn revocation_refuses_all_active_evidence() {
        assert_eq!(
            org_authority_revocation_evidence_hash(&active_evidence()),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
        // Expiry alone does not flip the gate (still active).
        let mut expired = active_evidence();
        expired.checked_at_unix = 9_999;
        assert_eq!(
            org_authority_revocation_evidence_hash(&expired),
            Err(AuthorizationAuthorityError::ScopeMismatch)
        );
    }
}
