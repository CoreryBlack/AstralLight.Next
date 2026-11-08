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
    parent_manifest_digest: Option<Sha256Digest>,
    revoke_fence: u64,
    plan_id: i64,
}

impl OwnedDeltaCompletionProof {
    /// Aggregate publication generation that durably completed this event.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn from_test_receipt(
        request: &DeltaEventAppendRequest,
        manifest_id: i64,
        generation: u64,
        digest: &str,
    ) -> Self {
        Self {
            identity: OwnedCompletionIdentity::from_request(request).unwrap(),
            manifest_id,
            generation,
            manifest_digest: Sha256Digest::from_hex(digest).unwrap(),
            parent_manifest_digest: (generation > 1)
                .then(|| Sha256Digest::from_hex(&format!("{:064x}", generation - 1)).unwrap()),
            revoke_fence: request.revoke_fence,
            plan_id: 1,
        }
    }

    pub(crate) fn extends_manifest(
        &self,
        previous_digest: Option<&str>,
        previous_fence: u64,
    ) -> bool {
        self.parent_manifest_digest
            .as_ref()
            .map(Sha256Digest::as_hex)
            .as_deref()
            == previous_digest
            && self.revoke_fence >= previous_fence
    }

    pub(crate) fn manifest_digest_hex(&self) -> String {
        self.manifest_digest.as_hex()
    }
    pub(crate) fn revoke_fence(&self) -> u64 {
        self.revoke_fence
    }

    /// Match one fully verified current manifest to this exact historical event.
    pub(crate) fn matches_manifest(
        &self,
        manifest: &astral_types::PublishedAggregateManifestSummary,
    ) -> bool {
        let request = &self.identity.request;
        manifest.tenant_id == request.tenant_id
            && request
                .card_id
                .is_none_or(|card_id| manifest.card_id == card_id)
            && manifest.aggregate_type == request.aggregate_type
            && manifest.aggregate_id == request.aggregate_id
            && manifest.manifest_id == self.manifest_id
            && manifest.generation == self.generation
            && manifest.manifest_digest_hex == self.manifest_digest.as_hex()
            && manifest.event_id == request.event_id
            && manifest.operation_id == request.operation_id
            && manifest.compiler_version == request.compiler_version
    }
}

/// Read-only result of reconciling one exact projection event after an
/// uncertain publication outcome. None of these variants authorizes a current
/// read or permits replay by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum OwnedCompletionReconciliation {
    /// The exact event reached durable publication completion.
    Published { proof: OwnedDeltaCompletionProof },
    /// No completion proof exists and the supplied ownership episode is
    /// durably retired. This is not a rollback proof and must not be treated as
    /// permission to recreate the source mutation.
    NotPublished {
        event_id: String,
        operation_id: String,
    },
    /// The event may still be owned or its durable terminal state cannot yet be
    /// reconciled. Callers must retain the fence and refuse replay.
    InDoubt { event_id: String, reason: String },
    /// The exact readback failed. Callers must preserve the unknown boundary.
    ReadFailure { event_id: String, reason: String },
}
/// Prove this exact historical event, including superseded sealed publications.
pub async fn load_owned_delta_completion(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
) -> Result<Option<OwnedDeltaCompletionProof>, AuthorizationProjectionError> {
    let mut tx = pool.begin().await?;
    let evidence = completion_in_tx(&mut tx, request).await?;
    // This transaction is read-only. Rollback releases its consistency locks;
    // no acknowledgement or uncertain COMMIT can invent a publication proof.
    tx.rollback().await?;
    Ok(evidence)
}

pub(crate) async fn completion_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    request: &DeltaEventAppendRequest,
) -> Result<Option<OwnedDeltaCompletionProof>, AuthorizationProjectionError> {
    let identity = OwnedCompletionIdentity::from_request(request)?;
    Ok(
        crate::authorization_projection_repository::load_owned_completion_in_tx(tx, request)
            .await?
            .map(
                |(
                    manifest_id,
                    generation,
                    manifest_digest,
                    plan_id,
                    parent_manifest_digest,
                    revoke_fence,
                )| OwnedDeltaCompletionProof {
                    identity,
                    manifest_id,
                    generation,
                    manifest_digest,
                    plan_id,
                    parent_manifest_digest,
                    revoke_fence,
                },
            ),
    )
}

/// Reconcile one exact event after an uncertain publication outcome.
///
/// This is a read-only boundary. `NotPublished` is returned only when the
/// caller supplies the exact opaque ownership episode and durable readback
/// proves that episode is retired. It is not a rollback proof and does not
/// authorize source replay. Without that proof, the result remains `InDoubt`.
pub async fn reconcile_owned_delta_completion(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
    lease: Option<&super::OwnedDeltaLease>,
) -> Result<OwnedCompletionReconciliation, AuthorizationProjectionError> {
    OwnedCompletionIdentity::from_request(request)?;
    let event_id = request.event_id.clone();
    let operation_id = request.operation_id.clone();
    match load_owned_delta_completion(pool, request).await {
        Ok(Some(proof)) => {
            return Ok(OwnedCompletionReconciliation::Published { proof });
        }
        Ok(None) => {}
        Err(error) => {
            return Ok(OwnedCompletionReconciliation::ReadFailure {
                event_id,
                reason: error.to_string(),
            });
        }
    };
    let Some(lease) = lease else {
        return Ok(OwnedCompletionReconciliation::InDoubt {
            event_id,
            reason: "exact completion is absent and no ownership lease was supplied".to_owned(),
        });
    };
    match super::transitions::owned_delta_lease_is_retired(pool, lease).await {
        Ok(true) => Ok(OwnedCompletionReconciliation::NotPublished {
            event_id,
            operation_id,
        }),
        Ok(false) => Ok(OwnedCompletionReconciliation::InDoubt {
            event_id,
            reason: "exact completion is absent while the ownership episode remains live"
                .to_owned(),
        }),
        Err(error) => Ok(OwnedCompletionReconciliation::ReadFailure {
            event_id,
            reason: error.to_string(),
        }),
    }
}
