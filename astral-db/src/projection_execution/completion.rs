use sqlx::MySqlPool;

use crate::{
    AuthorizationProjectionError, DeltaEventAppendRequest, GrantRepositoryError,
    ProjectionAggregateIdentity, Sha256Digest,
};
use astral_types::AUTHORIZATION_COMPILER_VERSION;

/// Immutable receipt identity; it cannot be replaced by an operation-only query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCompletionIdentity {
    request: DeltaEventAppendRequest,
}

impl OwnedCompletionIdentity {
    /// Validate the complete committed contribution receipt before waiting.
    pub fn from_request(request: &DeltaEventAppendRequest) -> Result<Self, GrantRepositoryError> {
        ProjectionAggregateIdentity::new(
            request.tenant_id,
            request.aggregate_type.clone(),
            request.aggregate_id,
        )
        .map_err(|_| {
            GrantRepositoryError::ScopeViolation(
                "code=projection_execution.invalid_completion_aggregate".to_owned(),
            )
        })?;
        if request.event_id.is_empty()
            || request.event_id.chars().count() > crate::MAX_EVENT_ID_LENGTH
            || request.operation_id.is_empty()
            || request.operation_id.chars().count() > crate::MAX_GRANT_OPERATION_ID_LENGTH
            || request.source_generation == 0
            || request.source_generation > i64::MAX as u64
            || request.revoke_fence > request.source_generation
            || request.base_version < 0
            || request.target_version <= request.base_version
            || request.card_id.is_some_and(|id| id <= 0)
        {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=projection_execution.invalid_completion_receipt".to_owned(),
            ));
        }
        if request.compiler_version != AUTHORIZATION_COMPILER_VERSION {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=projection_execution.non_current_completion_compiler".to_owned(),
            ));
        }
        Sha256Digest::from_hex(&request.semantic_hash_hex)?;
        Sha256Digest::from_hex(&request.dependency_hash_hex)?;
        let delta = crate::decode_delta_event_payload(&request.delta_json)?;
        if delta.operation_name() != request.event_type.as_str()
            || delta.target_grant_id()? != request.grant_id
        {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=projection_execution.completion_delta_binding_mismatch".to_owned(),
            ));
        }
        match (&request.before_image_json, &request.before_digest_hex) {
            (None, None) => {}
            (Some(image), Some(digest)) => {
                serde_json::from_str::<serde_json::Value>(image).map_err(|_| {
                    GrantRepositoryError::ScopeViolation(
                        "code=projection_execution.invalid_completion_before_image".to_owned(),
                    )
                })?;
                Sha256Digest::from_hex(digest)?;
            }
            _ => {
                return Err(GrantRepositoryError::ScopeViolation(
                    "code=projection_execution.completion_before_image_pairing".to_owned(),
                ));
            }
        }
        Ok(Self {
            request: request.clone(),
        })
    }
}

/// Historical publication closure, not permission to authorize a current read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedDeltaCompletionProof {
    identity: OwnedCompletionIdentity,
    manifest_id: i64,
    generation: u64,
    manifest_digest: Sha256Digest,
    plan_id: i64,
}

impl OwnedDeltaCompletionProof {
    /// Aggregate publication generation that durably completed this event.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Prove this exact historical event, including superseded sealed publications.
pub async fn load_owned_delta_completion(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
) -> Result<Option<OwnedDeltaCompletionProof>, AuthorizationProjectionError> {
    let identity = OwnedCompletionIdentity::from_request(request)?;
    let mut tx = pool.begin().await?;
    let evidence =
        crate::authorization_projection_repository::load_owned_completion_in_tx(&mut tx, request)
            .await?;
    // This transaction is read-only. Rollback releases its consistency locks;
    // no acknowledgement or uncertain COMMIT can invent a publication proof.
    tx.rollback().await?;
    Ok(
        evidence.map(|(manifest_id, generation, manifest_digest, plan_id)| {
            OwnedDeltaCompletionProof {
                identity,
                manifest_id,
                generation,
                manifest_digest,
                plan_id,
            }
        }),
    )
}
