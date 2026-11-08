//! Binding of administrative publication and membership facts to a fence proof.

use sha2::{Digest, Sha256};

use crate::org_scope::OrgAdmissionEvidence;
use crate::{
    AuthorizationAuthorityError, AuthorizationDomainScope, AuthorizationFenceProof,
    DomainScopeRequirement, PolicyContext, PublishedCardEvidenceScope,
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
/// [`OrgAdmissionEvidence::validate_structure`]): tenant/root identity, node
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

pub fn validate_org_authority_proof(
    proof: &AuthorizationFenceProof,
    context: &PolicyContext,
    evidence: &OrgAdmissionEvidence,
    nonce: &str,
    now_seconds: i64,
) -> Result<(), AuthorizationAuthorityError> {
    proof.validate_at(now_seconds)?;
    proof
        .scope
        .matches_evidence_scope(&org_authority_evidence_scope(context)?)?;
    let domain_matches = match proof.scope.domain {
        AuthorizationDomainScope::Any => false,
        AuthorizationDomainScope::NoDomain => context.domain_id.is_none(),
        AuthorizationDomainScope::Exact(domain_id) => context.domain_id == Some(domain_id),
    };
    if proof.request_nonce != nonce
        || !domain_matches
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::org_scope::{
        org_build_segment, org_manifest_digest_hex, OrgContribution, OrgGrant, OrgGrantRef,
        OrgManifestDigestMaterial, OrgProvenance, OrgScope, OrgScopeKey, OrgSegmentContent,
    };
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

    fn revoked_evidence() -> OrgAdmissionEvidence {
        let mut evidence = active_evidence();
        evidence.membership.active = false;
        evidence
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
