use sqlx::{MySql, Transaction};

use super::{
    fetch_manifest_for_update, load_authorization_impact_plan_by_event_in_tx,
    load_verified_chain_with_references, verify_parent_manifest_chain,
    AuthorizationImpactPlanStatus, AuthorizationProjectionError, ProjectionAggregateIdentity,
    MANIFEST_STATUS_COMMITTED, MANIFEST_STATUS_SUPERSEDED,
};
use crate::{DeltaEventAppendRequest, Sha256Digest};

mod seal;

#[cfg(test)]
mod tests;

pub(super) async fn record_publication_in_tx(
    tx: &mut Transaction<'_, MySql>,
    command: &super::DeltaProjectorPublishCommand,
    outcome: &super::DeltaProjectorPublishOutcome,
) -> Result<(), AuthorizationProjectionError> {
    let plan = load_authorization_impact_plan_by_event_in_tx(
        tx,
        &command.expectation.identity,
        &command.expectation.event_id,
    )
    .await?
    .ok_or_else(|| {
        AuthorizationProjectionError::Corrupt(
            "code=projection_execution.completion_plan_missing".to_owned(),
        )
    })?;
    let manifest = fetch_manifest_for_update(tx, outcome.stage.manifest_id)
        .await?
        .ok_or_else(|| {
            AuthorizationProjectionError::Corrupt(
                "code=projection_execution.completion_manifest_missing".to_owned(),
            )
        })?;
    let published = &outcome.publish.published_state;
    if manifest.decode_seal()? != published.seal
        || manifest.decode_seal()? != outcome.stage.seal
        || manifest.decode_hashes()?.2 != published.manifest_digest
        || manifest.decode_hashes()?.2 != outcome.stage.manifest_digest
    {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=projection_execution.completion_publication_seal_split".to_owned(),
        ));
    }
    seal::record_in_tx(
        tx,
        &plan,
        command.expectation.source_generation,
        manifest.manifest_id,
        &manifest.decode_hashes()?.2,
        &command.impact_plan.items,
    )
    .await
}

#[derive(Debug)]
pub(super) struct CompletionEvidence {
    pub(super) manifest_id: i64,
    pub(super) generation: u64,
    pub(super) manifest_digest: Sha256Digest,
    pub(super) plan_id: i64,
}

pub(super) async fn load_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &DeltaEventAppendRequest,
) -> Result<Option<CompletionEvidence>, AuthorizationProjectionError> {
    // Every owned writer starts with this lane lock. Waiting here also waits out
    // an uncertain publication COMMIT without taking event/pointer locks first.
    let lane: Option<(i64,)> = sqlx::query_as(
        "SELECT execution_epoch FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? \
           AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) AND aggregate_id = ? FOR UPDATE",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .fetch_optional(&mut **tx)
    .await?;
    if !matches!(lane, Some((epoch,)) if epoch > 0) {
        return Ok(None);
    }
    let identity = ProjectionAggregateIdentity::new(
        request.tenant_id,
        request.aggregate_type.clone(),
        request.aggregate_id,
    )?;
    // Planning readers take published delta locks after the pointer. The lane
    // serializes owned writers, so completion must follow the reader order here.
    let Some(pointer) = super::lock_current_pointer_in_tx(tx, &identity).await? else {
        return Ok(None);
    };
    if !crate::grant_repository::exact_owned_event_succeeded_in_tx(tx, request).await? {
        return Ok(None);
    }
    if pointer.current_generation > super::MAX_PUBLISHED_FRONTIER_GENERATIONS as u64 {
        return Err(AuthorizationProjectionError::ScopeViolation(
            "code=projection_execution.completion_history_cap_exceeded".to_owned(),
        ));
    }
    let Some(plan) =
        load_authorization_impact_plan_by_event_in_tx(tx, &identity, &request.event_id).await?
    else {
        return Ok(None);
    };
    if plan.status != AuthorizationImpactPlanStatus::Succeeded
        || plan.event_id != request.event_id
        || plan.operation_id != request.operation_id
        || plan.card_id != request.card_id
        || plan.base_version != request.base_version
        || plan.target_version != request.target_version
        || plan.compiler_version != request.compiler_version
        || plan.semantic_hash != Sha256Digest::from_hex(&request.semantic_hash_hex)?
        || plan.dependency_hash != Sha256Digest::from_hex(&request.dependency_hash_hex)?
        || plan.items.is_empty()
    {
        return Ok(None);
    }
    let manifest_ids: Vec<(i64,)> = sqlx::query_as(
        "SELECT manifest_id FROM authorization_projection_manifest \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
           AND generation = ? LIMIT 2 FOR UPDATE",
    )
    .bind(identity.tenant_id)
    .bind(&identity.aggregate_type)
    .bind(identity.aggregate_id)
    .bind(super::bind_u64(
        plan.target_generation,
        "completion.generation",
    )?)
    .fetch_all(&mut **tx)
    .await?;
    if manifest_ids.len() != 1 {
        return Ok(None);
    }
    let Some(manifest) = fetch_manifest_for_update(tx, manifest_ids[0].0).await? else {
        return Ok(None);
    };
    if !matches!(
        manifest.status.as_str(),
        MANIFEST_STATUS_COMMITTED | MANIFEST_STATUS_SUPERSEDED
    ) || manifest.decode_identity()? != identity
        || manifest.card_id != request.card_id
        || manifest.event_id != request.event_id
        || manifest.operation_id != request.operation_id
        || manifest.compiler_version != request.compiler_version
    {
        return Ok(None);
    }
    let (generation, source_generation, projected_generation) = manifest.decode_generations()?;
    let (semantic_hash, dependency_hash, manifest_digest) = manifest.decode_hashes()?;
    if generation != plan.target_generation
        || source_generation != request.source_generation
        || projected_generation != source_generation
        || semantic_hash != plan.semantic_hash
        || dependency_hash != plan.dependency_hash
        || manifest.decode_revoke_fence()? < request.revoke_fence
    {
        return Ok(None);
    }
    if generation == 1 {
        if manifest.decode_parent_manifest_id()?.is_some() || plan.base_generation != 0 {
            return Ok(None);
        }
    } else {
        let Some(parent_id) = manifest.decode_parent_manifest_id()? else {
            return Ok(None);
        };
        let Some(parent) = fetch_manifest_for_update(tx, parent_id).await? else {
            return Ok(None);
        };
        if parent.decode_identity()? != identity
            || parent.card_id != request.card_id
            || parent.decode_generations()?.0 != plan.base_generation
            || parent.decode_generations()?.0.checked_add(1) != Some(generation)
            || parent.status != MANIFEST_STATUS_SUPERSEDED
            || parent.decode_revoke_fence()? > manifest.decode_revoke_fence()?
        {
            return Ok(None);
        }
    }
    if !seal::verify_in_tx(
        tx,
        &plan,
        source_generation,
        manifest.manifest_id,
        &manifest_digest,
    )
    .await?
    {
        return Ok(None);
    }
    if !verify_retained_history_in_tx(
        tx,
        &identity,
        request.card_id,
        manifest.manifest_id,
        generation,
    )
    .await?
    {
        return Ok(None);
    }
    Ok(Some(CompletionEvidence {
        manifest_id: manifest.manifest_id,
        generation,
        manifest_digest,
        plan_id: plan.plan_id,
    }))
}

async fn verify_retained_history_in_tx(
    tx: &mut Transaction<'_, MySql>,
    identity: &ProjectionAggregateIdentity,
    card_id: Option<i64>,
    target_manifest_id: i64,
    target_generation: u64,
) -> Result<bool, AuthorizationProjectionError> {
    let published = super::read_published_authorization_state_in_tx(tx, identity).await?;
    if published.generation < target_generation || published.pointer.card_id != card_id {
        return Ok(false);
    }
    if published.generation > super::MAX_PUBLISHED_FRONTIER_GENERATIONS as u64 {
        return Err(AuthorizationProjectionError::ScopeViolation(
            "code=projection_execution.completion_history_cap_exceeded".to_owned(),
        ));
    }
    let mut manifest_id = published.manifest_id;
    let mut generation = published.generation;
    let mut child_fence: Option<u64> = None;
    let mut target_seen = false;
    loop {
        let Some(manifest) = fetch_manifest_for_update(tx, manifest_id).await? else {
            return Ok(false);
        };
        let expected_status = if generation == published.generation {
            MANIFEST_STATUS_COMMITTED
        } else {
            MANIFEST_STATUS_SUPERSEDED
        };
        let (_, source_generation, projected_generation) = manifest.decode_generations()?;
        let fence = manifest.decode_revoke_fence()?;
        if manifest.decode_identity()? != *identity
            || manifest.card_id != card_id
            || manifest.decode_generations()?.0 != generation
            || manifest.status != expected_status
            || source_generation < projected_generation
            || child_fence.is_some_and(|child| fence > child)
        {
            return Ok(false);
        }
        let (references, segments) =
            load_verified_chain_with_references(tx, identity, &manifest).await?;
        verify_parent_manifest_chain(&manifest, &references)?;
        if references.len() != segments.len() {
            return Ok(false);
        }
        if generation == target_generation {
            if manifest.manifest_id != target_manifest_id {
                return Ok(false);
            }
            target_seen = true;
        }
        if manifest.status == MANIFEST_STATUS_SUPERSEDED {
            let Some(raw_intent) =
                super::fetch_archive_intent_by_generation(tx, identity, generation).await?
            else {
                return Ok(false);
            };
            let intent = raw_intent.decode()?;
            if intent.identity != *identity
                || intent.card_id != card_id
                || intent.archived_manifest_id != manifest.manifest_id
                || intent.archived_generation != generation
                || intent.archive_key != super::derive_archive_key(identity, generation)?
                || intent.event_id != manifest.event_id
                || intent.operation_id != manifest.operation_id
                || intent.semantic_hash != manifest.decode_hashes()?.0
                || intent.dependency_hash != manifest.decode_hashes()?.1
                || intent.compiler_version != manifest.compiler_version
                || intent.archived_revoke_fence != fence
            {
                return Ok(false);
            }
            if let Some(proof) =
                super::load_authorization_archive_proof_in_tx(tx, identity, generation).await?
            {
                super::ensure_archive_proof_matches_intent(&intent, &proof)?;
                super::verify_authorization_archive_proof_in_tx(tx, &proof).await?;
                if intent.status == super::AuthorizationArchiveOutboxStatus::Succeeded {
                    super::validate_terminal_archive_proof(&proof)?;
                }
            } else if intent.status == super::AuthorizationArchiveOutboxStatus::Succeeded {
                return Ok(false);
            }
        }
        if generation == 1 {
            return Ok(target_seen && manifest.decode_parent_manifest_id()?.is_none());
        }
        let Some(parent_id) = manifest.decode_parent_manifest_id()? else {
            return Ok(false);
        };
        manifest_id = parent_id;
        generation -= 1;
        child_fence = Some(fence);
    }
}
