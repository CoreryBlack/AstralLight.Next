use sqlx::{MySql, Transaction};

use super::{
    decode_grant_id_sql, install_owned_claimed_event, load_claimed_delta_event_for_update_in_tx,
    positive_i64, validate_lease_seconds, validated_aggregate_type, validated_text,
    verify_owned_stable_event_request_binding, DeltaEventAppendRequest, DeltaEventClaimScope,
    DeltaEventType, DeltaLeaseIdentity, DeltaLeaseToken, GrantRepositoryError, OwnedStableEventRow,
    Sha256Digest, DELTA_STATUS_LEASED, DELTA_STATUS_PENDING, DELTA_STATUS_QUARANTINED,
    DELTA_STATUS_SUCCEEDED, MAX_EVENT_ID_LENGTH, MAX_GRANT_LEASE_OWNER_LENGTH,
    OWNED_DELTA_CLAIM_ELIGIBILITY, OWNED_DELTA_CLAIM_SIBLING_ORDER_GATE,
    OWNED_STABLE_EVENT_SELECT_SQL, OWNED_STABLE_EVENT_SIBLING_ORDER_PROBE_SQL,
};
use crate::{
    OwnedDeltaClaim, OwnedDeltaLease, OwnedStableEventOutcome, ProjectionAggregateIdentity,
};

const OWNED_CANDIDATE_LIMIT: i64 = 16;

#[derive(sqlx::FromRow)]
struct LaneState {
    execution_epoch: i64,
    generation: i64,
    cas_version: i64,
    lease_owner: String,
    lease_token_hash: Vec<u8>,
    lease_live: i64,
    active_delta_event_id: Option<i64>,
    active_delta_token_hash: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct AccountingState {
    execution_attempts: i64,
    execution_failures: i64,
    execution_accounting_version: i32,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_live: i64,
    claimable: i64,
}

fn in_doubt(request: &DeltaEventAppendRequest, reason: &str) -> OwnedStableEventOutcome {
    OwnedStableEventOutcome::InDoubt {
        event_id: request.event_id.clone(),
        reason: format!("code=projection_execution.{reason}"),
    }
}

fn busy(request: &DeltaEventAppendRequest) -> OwnedStableEventOutcome {
    OwnedStableEventOutcome::Busy {
        event_id: request.event_id.clone(),
    }
}

async fn read_stable_event(
    tx: &mut Transaction<'_, MySql>,
    request: &DeltaEventAppendRequest,
    locking: bool,
) -> Result<OwnedStableEventRow, GrantRepositoryError> {
    let statement = if locking {
        OWNED_STABLE_EVENT_SELECT_SQL
    } else {
        OWNED_STABLE_EVENT_SELECT_SQL
            .strip_suffix(" FOR UPDATE")
            .expect("stable-event select has a locking tail")
    };
    let row = sqlx::query_as(statement)
        .bind(&request.event_id)
        .bind(request.tenant_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            GrantRepositoryError::ScopeViolation(
                "code=projection_execution.stable_event_missing".to_owned(),
            )
        })?;
    verify_owned_stable_event_request_binding(request, &row)?;
    Ok(row)
}

pub(super) async fn claim_exact_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &DeltaEventAppendRequest,
    owner: &str,
    lease_seconds: i64,
) -> Result<OwnedStableEventOutcome, GrantRepositoryError> {
    positive_i64(request.tenant_id, "tenant_id")?;
    positive_i64(request.aggregate_id, "aggregate_id")?;
    validated_aggregate_type(&request.aggregate_type)?;
    validated_text(&request.event_id, MAX_EVENT_ID_LENGTH, "event_id")?;
    validated_text(owner, MAX_GRANT_LEASE_OWNER_LENGTH, "lease_owner")?;
    validate_lease_seconds(lease_seconds)?;

    // Reject a forged receipt before even creating an inactive lane row.
    read_stable_event(tx, request, false).await?;
    sqlx::query(
        "INSERT INTO authorization_projection_partition_lease \
         (tenant_id, aggregate_type, aggregate_id, lease_owner, lease_token_hash, \
          lease_expires_at, execution_epoch) \
         VALUES (?, ?, ?, '', ?, TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)), 0) \
         ON DUPLICATE KEY UPDATE tenant_id = tenant_id",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .bind([0_u8; 32].as_slice())
    .execute(&mut **tx)
    .await?;
    let lane: LaneState = sqlx::query_as(
        "SELECT execution_epoch, generation, cas_version, lease_owner, lease_token_hash, \
         CAST(lease_expires_at > UTC_TIMESTAMP(6) AS SIGNED) AS lease_live, \
         active_delta_event_id, active_delta_token_hash \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? \
           AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) AND aggregate_id = ? \
         FOR UPDATE",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .fetch_one(&mut **tx)
    .await?;
    if lane.execution_epoch < 0 || lane.generation < 1 || lane.cas_version < 0 {
        return Ok(in_doubt(request, "invalid_lane_counters"));
    }
    if lane.lease_live != 0 {
        return Ok(busy(request));
    }
    if lane.active_delta_event_id.is_some() != lane.active_delta_token_hash.is_some() {
        return Ok(in_doubt(request, "partial_active_slot"));
    }

    let row = read_stable_event(tx, request, true).await?;
    match row.status.as_str() {
        DELTA_STATUS_SUCCEEDED => {
            return Ok(OwnedStableEventOutcome::AlreadyProcessed {
                event_id: row.event_id,
            });
        }
        DELTA_STATUS_QUARANTINED => {
            return Ok(OwnedStableEventOutcome::TerminalGated {
                event_id: row.event_id,
                status: row.status,
            });
        }
        DELTA_STATUS_PENDING | DELTA_STATUS_LEASED => {}
        _ => return Ok(in_doubt(request, "unknown_delta_status")),
    }
    if let Some(active_id) = lane.active_delta_event_id {
        // Recovery resumes the exact expired episode before a sibling can enter.
        if active_id != row.delta_event_id {
            return Ok(busy(request));
        }
        if lane.execution_epoch == 0 || row.status != DELTA_STATUS_LEASED {
            return Ok(in_doubt(request, "active_slot_status_mismatch"));
        }
    } else if row.status == DELTA_STATUS_LEASED {
        return Ok(in_doubt(request, "leased_event_without_active_slot"));
    }

    let accounting: AccountingState = sqlx::query_as(
        "SELECT execution_attempts, execution_failures, execution_accounting_version, \
         lease_owner, lease_token_hash, \
         CAST(COALESCE(lease_expires_at > UTC_TIMESTAMP(6), 0) AS SIGNED) AS lease_live, \
         CAST(((status = 'PENDING' AND \
             (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6))) \
           OR (status = 'LEASED' AND lease_expires_at IS NOT NULL \
             AND lease_expires_at <= UTC_TIMESTAMP(6))) AS SIGNED) AS claimable \
         FROM authorization_delta_event WHERE delta_event_id = ? FOR UPDATE",
    )
    .bind(row.delta_event_id)
    .fetch_one(&mut **tx)
    .await?;
    if accounting.claimable != 1 || accounting.lease_live != 0 {
        return Ok(busy(request));
    }
    if let Some(active_hash) = &lane.active_delta_token_hash {
        if accounting.lease_owner.as_deref() != Some(lane.lease_owner.as_str())
            || accounting.lease_token_hash.as_deref() != Some(active_hash.as_slice())
            || lane.lease_token_hash.len() != 32
        {
            return Ok(in_doubt(request, "expired_episode_binding_mismatch"));
        }
        // Locking the exact delta waits out a possible COMMIT. A terminal plan or
        // manifest with a still-LEASED delta is inconsistent, not a retry signal.
        let plans: Vec<(String,)> = sqlx::query_as(
            "SELECT status FROM authorization_impact_plan \
             WHERE tenant_id = ? AND event_id = ? FOR UPDATE",
        )
        .bind(row.tenant_id)
        .bind(&row.event_id)
        .fetch_all(&mut **tx)
        .await?;
        let manifests: Vec<(i64,)> = sqlx::query_as(
            "SELECT manifest_id FROM authorization_projection_manifest \
             WHERE tenant_id = ? AND event_id = ? \
               AND status IN ('COMMITTED', 'SUPERSEDED') FOR UPDATE",
        )
        .bind(row.tenant_id)
        .bind(&row.event_id)
        .fetch_all(&mut **tx)
        .await?;
        if plans.iter().any(|(status,)| status == "SUCCEEDED") || !manifests.is_empty() {
            return Ok(in_doubt(
                request,
                "expired_episode_publication_requires_reconciliation",
            ));
        }
    }
    let aggregate_predecessor: Option<(i64,)> = sqlx::query_as(
        "SELECT delta_event_id FROM authorization_delta_event \
         WHERE tenant_id = ? AND aggregate_type = ? \
           AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) \
           AND aggregate_id = ? AND status <> 'SUCCEEDED' \
           AND (source_generation < ? OR \
             (source_generation = ? AND delta_event_id < ?)) \
         ORDER BY source_generation, delta_event_id LIMIT 1 FOR UPDATE",
    )
    .bind(row.tenant_id)
    .bind(&row.aggregate_type)
    .bind(&row.aggregate_type)
    .bind(row.aggregate_id)
    .bind(row.source_generation)
    .bind(row.source_generation)
    .bind(row.delta_event_id)
    .fetch_optional(&mut **tx)
    .await?;
    if aggregate_predecessor.is_some() {
        return Ok(busy(request));
    }
    let predecessor: Option<(i64,)> = sqlx::query_as(OWNED_STABLE_EVENT_SIBLING_ORDER_PROBE_SQL)
        .bind(row.tenant_id)
        .bind(&row.grant_id)
        .bind(row.target_version)
        .fetch_optional(&mut **tx)
        .await?;
    if predecessor.is_some() {
        return Ok(busy(request));
    }
    if row.attempts < 0
        || row.attempts == i64::MAX
        || row.cas_version < 0
        || row.cas_version == i64::MAX
        || accounting.execution_attempts < 0
        || accounting.execution_failures < 0
        || accounting.execution_failures > accounting.execution_attempts
        || !matches!(accounting.execution_accounting_version, 1 | 2)
    {
        return Ok(in_doubt(request, "invalid_execution_accounting"));
    }
    let failures = if accounting.execution_accounting_version == 1 {
        accounting.execution_failures.max(row.attempts)
    } else {
        accounting.execution_failures
    };
    let Ok(failures) = u32::try_from(failures) else {
        return Ok(in_doubt(request, "execution_failure_counter_overflow"));
    };
    let Some(epoch) = lane.execution_epoch.checked_add(1) else {
        return Ok(in_doubt(request, "ownership_epoch_exhausted"));
    };
    if lane.generation == i64::MAX || lane.cas_version == i64::MAX {
        return Ok(in_doubt(request, "lane_counter_exhausted"));
    }
    if accounting.execution_accounting_version == 1 {
        sqlx::query(
            "UPDATE authorization_delta_event \
             SET execution_attempts = GREATEST(execution_attempts, attempts), \
                 execution_failures = GREATEST(execution_failures, attempts), \
                 execution_accounting_version = 2 WHERE delta_event_id = ?",
        )
        .bind(row.delta_event_id)
        .execute(&mut **tx)
        .await?;
    }
    let claim = install_owned_claimed_event(tx, row.to_candidate(), owner, lease_seconds).await?;
    let identity = DeltaLeaseIdentity {
        delta_event_id: claim.delta_event_id,
        event_id: claim.event_id.clone(),
        lease_owner: claim.lease_owner.clone(),
        lease_token: claim.lease_token.clone(),
    };
    let event = load_claimed_delta_event_for_update_in_tx(tx, &identity).await?;
    let lane_token = DeltaLeaseToken::new_run_scoped();
    let installed = sqlx::query(
        "UPDATE authorization_projection_partition_lease \
         SET lease_owner = ?, lease_token_hash = ?, \
             lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), \
             execution_epoch = ?, generation = generation + 1, cas_version = cas_version + 1, \
             acquired_at = UTC_TIMESTAMP(6), last_renewed_at = NULL, \
             active_delta_event_id = ?, active_delta_token_hash = ? \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
           AND execution_epoch = ? AND cas_version = ?",
    )
    .bind(owner)
    .bind(lane_token.token_hash().as_bytes().to_vec())
    .bind(lease_seconds)
    .bind(epoch)
    .bind(claim.delta_event_id)
    .bind(claim.lease_token.token_hash().as_bytes().to_vec())
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .bind(lane.execution_epoch)
    .bind(lane.cas_version)
    .execute(&mut **tx)
    .await?;
    if installed.rows_affected() != 1 {
        return Err(GrantRepositoryError::ClaimRace);
    }
    let lease = OwnedDeltaLease::from_owned_claim(
        ProjectionAggregateIdentity {
            tenant_id: request.tenant_id,
            aggregate_type: request.aggregate_type.clone(),
            aggregate_id: request.aggregate_id,
        },
        epoch,
        lane_token,
        &claim,
        failures,
    )?;
    Ok(OwnedStableEventOutcome::Claimed(Box::new(
        OwnedDeltaClaim {
            claim,
            event,
            lease,
        },
    )))
}

pub(super) async fn candidate_receipts(
    pool: &sqlx::MySqlPool,
    scope: DeltaEventClaimScope,
    aggregate: Option<&ProjectionAggregateIdentity>,
) -> Result<Vec<DeltaEventAppendRequest>, GrantRepositoryError> {
    positive_i64(scope.tenant_id, "tenant_id")?;
    if let Some(card_id) = scope.card_id {
        positive_i64(card_id, "card_id")?;
    }
    let columns = OWNED_STABLE_EVENT_SELECT_SQL
        .split_once(" FROM authorization_delta_event ")
        .expect("stable-event select has its table")
        .0;
    let card_filter = if scope.card_id.is_some() {
        " AND card_id = ?"
    } else {
        ""
    };
    let aggregate_filter = if let Some(identity) = aggregate {
        if identity.tenant_id != scope.tenant_id {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=projection_execution.cross_tenant_candidate_scope".to_owned(),
            ));
        }
        " AND aggregate_type = ? AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) AND aggregate_id = ?"
    } else {
        ""
    };
    let statement = format!(
        "{columns} FROM authorization_delta_event \
         WHERE tenant_id = ?{card_filter}{aggregate_filter} \
           {OWNED_DELTA_CLAIM_ELIGIBILITY} \
           {OWNED_DELTA_CLAIM_SIBLING_ORDER_GATE} \
           AND NOT EXISTS (SELECT 1 FROM authorization_delta_event predecessor \
             WHERE predecessor.tenant_id = authorization_delta_event.tenant_id \
               AND predecessor.aggregate_type = authorization_delta_event.aggregate_type \
               AND CAST(predecessor.aggregate_type AS BINARY) = \
                   CAST(authorization_delta_event.aggregate_type AS BINARY) \
               AND predecessor.aggregate_id = authorization_delta_event.aggregate_id \
               AND predecessor.status <> 'SUCCEEDED' \
               AND (predecessor.source_generation < authorization_delta_event.source_generation \
                 OR (predecessor.source_generation = authorization_delta_event.source_generation \
                   AND predecessor.delta_event_id < authorization_delta_event.delta_event_id))) \
           AND NOT EXISTS (SELECT 1 FROM authorization_projection_partition_lease lane \
             WHERE lane.tenant_id = authorization_delta_event.tenant_id \
               AND CAST(lane.aggregate_type AS BINARY) = \
                   CAST(authorization_delta_event.aggregate_type AS BINARY) \
               AND lane.aggregate_id = authorization_delta_event.aggregate_id \
               AND (lane.lease_expires_at > UTC_TIMESTAMP(6) \
                 OR (lane.active_delta_event_id IS NOT NULL \
                     AND lane.active_delta_event_id <> authorization_delta_event.delta_event_id))) \
         ORDER BY COALESCE(next_attempt_at, created_at), delta_event_id LIMIT ?"
    );
    let mut query = sqlx::query_as::<_, OwnedStableEventRow>(&statement).bind(scope.tenant_id);
    if let Some(card_id) = scope.card_id {
        query = query.bind(card_id);
    }
    if let Some(identity) = aggregate {
        query = query
            .bind(&identity.aggregate_type)
            .bind(&identity.aggregate_type)
            .bind(identity.aggregate_id);
    }
    query
        .bind(OWNED_CANDIDATE_LIMIT)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| {
            Ok(DeltaEventAppendRequest {
                tenant_id: row.tenant_id,
                card_id: row.card_id,
                aggregate_type: row.aggregate_type,
                aggregate_id: row.aggregate_id,
                grant_id: decode_grant_id_sql(&row.grant_id)?,
                event_id: row.event_id,
                operation_id: row.operation_id,
                event_type: DeltaEventType::from_sql(&row.event_type)?,
                base_version: row.base_version,
                target_version: row.target_version,
                source_generation: u64::try_from(row.source_generation).map_err(|_| {
                    GrantRepositoryError::Mapping(
                        "code=projection_execution.invalid_source_generation".to_owned(),
                    )
                })?,
                revoke_fence: u64::try_from(row.revoke_fence).map_err(|_| {
                    GrantRepositoryError::Mapping(
                        "code=projection_execution.invalid_revoke_fence".to_owned(),
                    )
                })?,
                invalidates_published_evidence: row.invalidates_published_evidence != 0,
                before_image_json: row.before_image_json,
                before_digest_hex: Sha256Digest::from_optional_bytes(row.before_digest.as_deref())?
                    .map(|digest| digest.as_hex()),
                delta_json: row.delta_json,
                semantic_hash_hex: Sha256Digest::from_bytes(row.semantic_hash)?.as_hex(),
                dependency_hash_hex: Sha256Digest::from_bytes(row.dependency_hash)?.as_hex(),
                compiler_version: row.compiler_version,
                next_attempt_at: None,
            })
        })
        .collect()
}
