//! Immutable identity of a verified policy request, shared by proof and mutation owners.

use sha2::{Digest, Sha256};

use crate::{PolicyContext, PolicyError, ResourceOwnershipScope};

/// Hash the complete verified context, including the trusted HTTP payload fingerprint.
/// Client-supplied JSON must never be used to construct this context for a mutation.
pub fn authorization_request_digest(context: &PolicyContext) -> Result<String, PolicyError> {
    if context.principal_kind.as_deref() != Some("PLATFORM_USER")
        || context.user_id.is_none_or(|id| id <= 0)
        || context.identity_card_id.is_none_or(|id| id <= 0)
        || context.card_id.is_none_or(|id| id <= 0)
        || context.tenant_id.is_none_or(|id| id <= 0)
        || context.domain_id.is_some_and(|id| id <= 0)
        || context.target_id.is_some_and(|id| id <= 0)
        || context
            .resource
            .as_ref()
            .is_none_or(|value| value.is_empty() || value.len() > 128)
        || context.action.is_empty()
        || context.action.len() > 128
        || matches!(
            context.resource_ownership_scope,
            ResourceOwnershipScope::Unresolved | ResourceOwnershipScope::Unavailable
        )
    {
        return Err(PolicyError::InvalidContext(
            "authority request requires a verified actor, action and resolved ownership".into(),
        ));
    }
    let fingerprint = context.request_fingerprint.as_deref().ok_or_else(|| {
        PolicyError::InvalidContext("authority request payload fingerprint is missing".into())
    })?;
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::InvalidContext(
            "authority request payload fingerprint is invalid".into(),
        ));
    }
    let operation_id = context.request_operation_id.as_deref().ok_or_else(|| {
        PolicyError::InvalidContext("authority request operation is missing".into())
    })?;
    if operation_id.is_empty()
        || operation_id.len() > 64
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        return Err(PolicyError::InvalidContext(
            "authority request operation is invalid".into(),
        ));
    }
    let encoded = serde_json::to_vec(context)
        .map_err(|_| PolicyError::InvalidContext("authority request cannot be encoded".into()))?;
    if encoded.len() > 256 * 1024 {
        return Err(PolicyError::InvalidContext(
            "authority request context exceeds its bounded identity size".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_POLICY_REQUEST_V7\0");
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(1))
            .identity_card_id(Some(2))
            .card_id(Some(3))
            .tenant_id(Some(4))
            .principal_kind(Some("PLATFORM_USER".into()))
            .resource(Some("monitor".into()))
            .action("update".into())
            .target_id(Some(5))
            .request_fingerprint(Some("a".repeat(64)))
            .request_operation_id(Some("operation-1".into()))
            .build()
    }

    #[test]
    fn binds_actor_target_action_ownership_and_payload() {
        let original = context();
        let expected = authorization_request_digest(&original).unwrap();
        let mut variants = vec![original.clone(); 9];
        variants[0].user_id = Some(11);
        variants[1].card_id = Some(12);
        variants[2].tenant_id = Some(13);
        variants[3].target_id = Some(14);
        variants[4].action = "delete".into();
        variants[5].resource_tenant_id = Some(15);
        variants[6].request_fingerprint = Some("b".repeat(64));
        variants[7].request_operation_id = Some("operation-2".into());
        variants[8].request_mutation_kind = Some(crate::AuthorityMutationKind::ProtectedBusiness);
        for variant in variants {
            assert_ne!(expected, authorization_request_digest(&variant).unwrap());
        }
    }

    #[test]
    fn rejects_missing_unresolved_or_malformed_context() {
        let mut variants = vec![context(); 4];
        variants[0].request_fingerprint = None;
        variants[1].request_fingerprint = Some("A".repeat(64));
        variants[2].identity_card_id = None;
        variants[3].resource_ownership_scope = ResourceOwnershipScope::Unresolved;
        for variant in variants {
            assert!(authorization_request_digest(&variant).is_err());
        }
    }
}
