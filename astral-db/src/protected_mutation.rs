//! Verified request context for non-authorization business mutations.
//!
//! The caller supplies the PolicyContext installed by its permission middleware.
//! This owner binds that context to the admission, locks the active actor, and
//! records a stable operation/result in the caller's short business transaction.
//! It neither creates authorization deltas nor publishes messages.

use astral_types::{
    AstralError, AuthorityMutationKind, AuthorizationAdmission, AuthorizationDomainScope,
    PolicyContext,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};

pub mod evidence;
pub use evidence::{
    core_evidence, fingerprint_secret, redact_secrets, source_commit_digest, EvidenceError,
    ProtectedSourceEvidence, RowPresence, SourceReceipt, TargetRowEvidence, WriteKind,
};

#[derive(Debug, Clone)]
pub struct ProtectedMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    tenant_id: i64,
    domain_id: Option<i64>,
    operation_id: String,
    resource: String,
    action: String,
    target_id: Option<i64>,
    policy_request_digest: String,
    admission: AuthorizationAdmission,
}

impl ProtectedMutationContext {
    /// This constructor validates binding, not the Gateway signature. Only pass
    /// a context obtained from the permission middleware's verified extension.
    pub fn from_policy_context(
        context: &PolicyContext,
        admission: AuthorizationAdmission,
        operation_id: Option<&str>,
        resource: &str,
        action: &str,
        target_id: Option<i64>,
    ) -> Result<Self, AstralError> {
        let positive = |value: Option<i64>| value.filter(|value| *value > 0);
        let (Some(actor_id), Some(actor_card_id), Some(tenant_id)) = (
            positive(context.user_id),
            positive(context.card_id),
            positive(context.tenant_id),
        ) else {
            return Err(AstralError::Auth(
                "verified mutation actor is incomplete".into(),
            ));
        };
        if context.principal_kind.as_deref() != Some("PLATFORM_USER")
            || context.resource.as_deref() != Some(resource)
            || context.action != action
            || context.target_id != target_id
            || target_id.is_some_and(|value| value <= 0)
            || context.domain_id.is_some_and(|value| value <= 0)
        {
            return Err(AstralError::Permission(
                "mutation does not match the verified policy request".into(),
            ));
        }
        let scope = &admission.proof().scope;
        let domain_matches = match scope.domain {
            AuthorizationDomainScope::Exact(id) => context.domain_id == Some(id),
            AuthorizationDomainScope::NoDomain => context.domain_id.is_none(),
            AuthorizationDomainScope::Any => false,
        };
        if scope.user_id != Some(actor_id)
            || scope.card_id != actor_card_id
            || scope.tenant_id != tenant_id
            || !domain_matches
        {
            return Err(AstralError::Permission(
                "mutation admission actor scope mismatch".into(),
            ));
        }
        let policy_request_digest = astral_types::authorization_request_digest(context)?;
        if admission.proof().request_binding_digest.as_deref()
            != Some(policy_request_digest.as_str())
        {
            return Err(AstralError::Permission(
                "mutation proof belongs to another verified request".into(),
            ));
        }
        let operation_id = crate::grant_ledger::validated_request_operation_id(operation_id)?
            .ok_or_else(|| {
                AstralError::Validation("mutation requires a stable request id".into())
            })?;
        if context.request_operation_id.as_deref() != Some(operation_id.as_str())
            || admission.operation_id() != operation_id
        {
            return Err(AstralError::Permission(
                "mutation operation differs from its signed admission".into(),
            ));
        }
        Ok(Self {
            actor_id,
            actor_card_id,
            tenant_id,
            domain_id: context.domain_id,
            operation_id,
            resource: resource.to_owned(),
            action: action.to_owned(),
            target_id,
            policy_request_digest,
            admission,
        })
    }

    pub fn require_request(
        &self,
        resource: &str,
        action: &str,
        target_id: Option<i64>,
    ) -> Result<(), AstralError> {
        if self.resource != resource || self.action != action || self.target_id != target_id {
            return Err(AstralError::Permission(
                "business mutation differs from the admitted request".into(),
            ));
        }
        Ok(())
    }

    pub fn actor_id(&self) -> i64 {
        self.actor_id
    }

    pub fn actor_card_id(&self) -> i64 {
        self.actor_card_id
    }

    pub fn domain_id(&self) -> Option<i64> {
        self.domain_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn tenant_id(&self) -> i64 {
        self.tenant_id
    }

    pub fn admission(&self) -> &AuthorizationAdmission {
        &self.admission
    }
}

#[derive(Debug)]
pub enum ProtectedMutationStart {
    New,
    Completed(Value),
}

fn request_digest(
    context: &ProtectedMutationContext,
    payload: &Value,
) -> Result<[u8; 32], AstralError> {
    let content = serde_json::to_vec(&(
        context.actor_id,
        context.actor_card_id,
        context.tenant_id,
        context.domain_id,
        &context.resource,
        &context.action,
        context.target_id,
        &context.policy_request_digest,
        payload,
    ))
    .map_err(|error| AstralError::Validation(error.to_string()))?;
    if content.len() > 256 * 1024 {
        return Err(AstralError::Validation(
            "mutation payload exceeds bounds".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_PROTECTED_MUTATION_V7\0");
    digest.update(content);
    Ok(digest.finalize().into())
}

fn database(error: sqlx::Error) -> AstralError {
    AstralError::Database(error.to_string())
}

#[derive(sqlx::FromRow)]
struct ProtectedMutationActor {
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    card_status: String,
    currently_valid: bool,
}

/// Lock order: actor, admission authority rows, operation identity, business target.
/// The operation row and its result are committed atomically with the mutation.
pub async fn begin_protected_mutation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    context: &ProtectedMutationContext,
    payload: &Value,
) -> Result<ProtectedMutationStart, AstralError> {
    let actor: Option<ProtectedMutationActor> = sqlx::query_as(
        "SELECT user_id, tenant_id, domain_id, card_status, \
         ((valid_from IS NULL OR valid_from <= UTC_TIMESTAMP()) AND \
          (valid_until IS NULL OR valid_until >= UTC_TIMESTAMP())) AS currently_valid \
         FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(context.actor_card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database)?;
    if !actor.as_ref().is_some_and(|actor| {
        actor.user_id == Some(context.actor_id)
            && actor.tenant_id == Some(context.tenant_id)
            && actor.domain_id == context.domain_id
            && actor.card_status == "ACTIVE"
            && actor.currently_valid
    }) {
        return Err(AstralError::Permission(
            "mutation actor is no longer active in the verified scope".into(),
        ));
    }
    crate::validate_authorization_admission_in_tx(tx, context.admission())
        .await
        .map_err(|error| AstralError::Pending(error.to_string()))?;
    let digest = request_digest(context, payload)?;
    sqlx::query(
        "INSERT INTO protected_mutation_operation \
         (operation_id, resource, request_digest, result_json, created_at) \
         VALUES (?, ?, ?, NULL, UNIX_TIMESTAMP()) \
         ON DUPLICATE KEY UPDATE operation_id = operation_id",
    )
    .bind(&context.operation_id)
    .bind(&context.resource)
    .bind(digest.as_slice())
    .execute(&mut **tx)
    .await
    .map_err(database)?;
    let (stored_digest, result): (Vec<u8>, Option<String>) = sqlx::query_as(
        "SELECT request_digest, CAST(result_json AS CHAR) FROM protected_mutation_operation \
         WHERE operation_id = ? AND resource = ? FOR UPDATE",
    )
    .bind(&context.operation_id)
    .bind(&context.resource)
    .fetch_one(&mut **tx)
    .await
    .map_err(database)?;
    if stored_digest.as_slice() != digest {
        return Err(AstralError::Validation(
            "operation identity conflicts with an earlier mutation payload or actor".into(),
        ));
    }
    match result {
        Some(result) => serde_json::from_str(&result)
            .map(ProtectedMutationStart::Completed)
            .map_err(|error| {
                AstralError::Database(format!("invalid durable mutation result: {error}"))
            }),
        None => Ok(ProtectedMutationStart::New),
    }
}

/// Complete only after the business write. Durable admission use, operation result
/// and audit, AND the typed source-outcome stage/promote remain in this same
/// transaction; the caller then awaits COMMIT once.
///
/// `evidence` must be captured from the SAME transaction: the locked target
/// rows read before and after the business write (absence is a real probe)
/// and the actual statement receipts. It is staged and promoted through
/// `crate::stage_admitted_source_outcome_in_tx` (ProtectedBusiness) after the
/// durable admission consume/audit, so a committed protected mutation always
/// carries its actual protected source outcome — never a hash of the result
/// alone and never an actor authorization snapshot.
pub async fn finish_protected_mutation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    context: &ProtectedMutationContext,
    result: &Value,
    evidence: &ProtectedSourceEvidence,
) -> Result<(), AstralError> {
    let result = serde_json::to_string(result)
        .map_err(|error| AstralError::Validation(error.to_string()))?;
    if result.len() > 64 * 1024 {
        return Err(AstralError::Validation(
            "mutation result exceeds bounds".into(),
        ));
    }
    crate::consume_authorization_admission_in_tx(tx, context.admission())
        .await
        .map_err(|error| AstralError::Pending(error.to_string()))?;
    context
        .admission()
        .consume_once()
        .map_err(|error| AstralError::Permission(error.to_string()))?;
    let updated = sqlx::query(
        "UPDATE protected_mutation_operation SET result_json = ? \
         WHERE operation_id = ? AND resource = ? AND result_json IS NULL",
    )
    .bind(&result)
    .bind(&context.operation_id)
    .bind(&context.resource)
    .execute(&mut **tx)
    .await
    .map_err(database)?
    .rows_affected();
    if updated != 1 {
        return Err(AstralError::Pending(
            "mutation operation completion was not proven".into(),
        ));
    }
    let detail = serde_json::json!({
        "operationId": context.operation_id, "targetId": context.target_id,
        "admissionProofId": context.admission().proof_id(),
    })
    .to_string();
    let audit = sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, event_type, request_id, domain_id, tenant_id, detail) \
         VALUES (?, ?, ?, ?, 'SUCCESS', 'PROTECTED_MUTATION', ?, ?, ?, ?)",
    ).bind(context.actor_id).bind(context.actor_card_id).bind(&context.action).bind(&context.resource)
        .bind(&context.operation_id).bind(context.domain_id).bind(context.tenant_id).bind(detail)
        .execute(&mut **tx).await.map_err(database)?;
    if audit.rows_affected() != 1 || audit.last_insert_id() == 0 {
        return Err(AstralError::Pending(
            "protected mutation audit receipt is not proven".into(),
        ));
    }
    let evidence = evidence.clone().receipt(
        "audit_log",
        serde_json::json!({"id": audit.last_insert_id()}),
        WriteKind::Insert,
        audit.rows_affected(),
    );
    // Typed source outcome: stage + promote inside this tx (the durable
    // admission use row required by the binder exists after the consume above).
    let staged_evidence_json = evidence.to_staged_json()?;
    let core = evidence::core_evidence(&evidence, &staged_evidence_json, &result);
    crate::stage_admitted_source_outcome_in_tx(
        tx,
        context.admission(),
        AuthorityMutationKind::ProtectedBusiness,
        staged_evidence_json,
        &core,
    )
    .await
    .map_err(|error| AstralError::Pending(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_identity_is_unambiguous_and_bounded() {
        use astral_types::{
            AuthorizationAuthorityScope, AuthorizationFenceProof, AUTHORIZATION_EDITION,
        };
        let mut policy = PolicyContext::builder()
            .principal_kind(Some("PLATFORM_USER".into()))
            .user_id(Some(1))
            .identity_card_id(Some(6))
            .card_id(Some(2))
            .tenant_id(Some(3))
            .domain_id(Some(4))
            .resource(Some("monitor".into()))
            .action("update".into())
            .target_id(Some(5))
            .request_fingerprint(Some("aa".repeat(32)))
            .request_operation_id(Some("request-1".into()))
            .build();
        let proof = AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "test".into(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: AuthorizationAuthorityScope {
                tenant_id: 3,
                card_id: 2,
                user_id: Some(1),
                domain: AuthorizationDomainScope::Exact(4),
            },
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "11".repeat(32),
            parent_hash: None,
            operation_id: "request-1".into(),
            event_id: "request-1:commit".into(),
            key_id: "key".into(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 100,
            expires_at: 200,
            request_nonce: "nonce".into(),
            request_binding_digest: Some(
                astral_types::authorization_request_digest(&policy).unwrap(),
            ),
            scope_certificate_hash: Some("33".repeat(32)),
            proof_id: "proof".into(),
            signature: "22".repeat(64),
        };
        let admission = AuthorizationAdmission::from_verified_request_bound_proof(proof).unwrap();
        let ctx = ProtectedMutationContext::from_policy_context(
            &policy,
            admission.clone(),
            Some("request-1"),
            "monitor",
            "update",
            Some(5),
        )
        .unwrap();
        let payload = serde_json::json!({"threshold": 42});
        let digest = request_digest(&ctx, &payload).unwrap();
        assert_ne!(
            digest,
            request_digest(&ctx, &serde_json::json!({"threshold": 43})).unwrap()
        );
        let mut changed = ctx.clone();
        changed.target_id = Some(6);
        assert_ne!(digest, request_digest(&changed, &payload).unwrap());
        policy.action = "delete".into();
        assert!(ProtectedMutationContext::from_policy_context(
            &policy,
            admission.clone(),
            Some("request-1"),
            "monitor",
            "update",
            Some(5)
        )
        .is_err());
        assert!(ProtectedMutationContext::from_policy_context(
            &policy,
            admission,
            None,
            "monitor",
            "delete",
            Some(5)
        )
        .is_err());
        assert!(
            request_digest(&ctx, &serde_json::json!({"value": "a".repeat(256 * 1024)})).is_err()
        );
    }
}
