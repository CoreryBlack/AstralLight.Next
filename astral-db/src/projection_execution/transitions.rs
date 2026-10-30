use astral_types::SYSTEM_ACTOR_ID;
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Transaction};

use crate::{
    GrantRepositoryError, OwnedDeltaLease, MAX_BACKOFF_SECONDS, MAX_DELTA_LEASE_SECONDS,
    MAX_LAST_ERROR_LENGTH,
};

#[derive(sqlx::FromRow)]
struct OwnedLaneRow {
    execution_epoch: i64,
    lease_owner: String,
    lease_token_hash: Vec<u8>,
    lease_live: i64,
    active_delta_event_id: Option<i64>,
    active_delta_token_hash: Option<Vec<u8>>,
}

const OWNED_LANE_FOR_UPDATE_SQL: &str = "SELECT execution_epoch, lease_owner, lease_token_hash, \
    CAST(lease_expires_at > UTC_TIMESTAMP(6) AS SIGNED) AS lease_live, \
    active_delta_event_id, active_delta_token_hash \
    FROM authorization_projection_partition_lease \
    WHERE tenant_id = ? AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) \
      AND aggregate_id = ? FOR UPDATE";

const OWNED_LANE_CLEAR_SQL: &str = "UPDATE authorization_projection_partition_lease \
    SET lease_owner = '', lease_token_hash = ?, \
        lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)), \
        last_renewed_at = NULL, active_delta_event_id = NULL, active_delta_token_hash = NULL, \
        cas_version = cas_version + 1 \
    WHERE tenant_id = ? AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) \
      AND aggregate_id = ? AND execution_epoch = ? \
      AND CAST(lease_owner AS BINARY) = CAST(? AS BINARY) AND lease_token_hash = ? \
      AND active_delta_event_id = ? AND active_delta_token_hash = ? \
      AND cas_version < 9223372036854775807";

const OWNED_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
    (user_id, card_id, action, resource, decision, reason, event_type, request_id, tenant_id, detail) \
    VALUES (?, NULL, ?, 'authorization_projection_owned_lane', 'INTERNAL', ?, \
            'AUTHZ_OWNED_PROJECTION_LANE', ?, ?, ?)";

fn lane_guard_matches(row: &OwnedLaneRow, lease: &OwnedDeltaLease) -> bool {
    row.lease_live == 1
        && row.execution_epoch == lease.lane_epoch
        && row.lease_owner == lease.lane_owner
        && row.lease_token_hash.as_slice() == lease.lane_token.token_hash().as_bytes()
        && row.active_delta_event_id == Some(lease.event_identity.delta_event_id)
        && row.active_delta_token_hash.as_deref()
            == Some(
                lease
                    .event_identity
                    .lease_token
                    .token_hash()
                    .as_bytes()
                    .as_slice(),
            )
        && lease.active_event_id == lease.event_identity.event_id
        && lease.lane_owner == lease.event_identity.lease_owner
}

fn truncate_last_error(value: &str) -> String {
    value.chars().take(MAX_LAST_ERROR_LENGTH).collect()
}

pub(super) async fn lock_owned_lane_in_tx(
    tx: &mut Transaction<'_, MySql>,
    lease: &OwnedDeltaLease,
) -> Result<bool, GrantRepositoryError> {
    let identity = &lease.lane_identity;
    if identity.tenant_id <= 0 || identity.aggregate_id <= 0 || lease.lane_epoch <= 0 {
        return Ok(false);
    }
    let row: Option<OwnedLaneRow> = sqlx::query_as(OWNED_LANE_FOR_UPDATE_SQL)
        .bind(identity.tenant_id)
        .bind(&identity.aggregate_type)
        .bind(identity.aggregate_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.is_some_and(|row| lane_guard_matches(&row, lease)))
}

// The caller retains the lane lock through publication or event release; expiry
// cannot install a successor while that transaction holds the row lock.
pub(super) async fn clear_owned_lane_in_tx(
    tx: &mut Transaction<'_, MySql>,
    lease: &OwnedDeltaLease,
) -> Result<bool, GrantRepositoryError> {
    let result = sqlx::query(OWNED_LANE_CLEAR_SQL)
        .bind([0_u8; 32].as_slice())
        .bind(lease.lane_identity.tenant_id)
        .bind(&lease.lane_identity.aggregate_type)
        .bind(lease.lane_identity.aggregate_id)
        .bind(lease.lane_epoch)
        .bind(&lease.lane_owner)
        .bind(lease.lane_token.token_hash().as_bytes().as_slice())
        .bind(lease.event_identity.delta_event_id)
        .bind(
            lease
                .event_identity
                .lease_token
                .token_hash()
                .as_bytes()
                .as_slice(),
        )
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Ok(false);
    }
    audit_owned_lane_in_tx(tx, lease, "CLEAR").await?;
    Ok(true)
}

fn audit_request_id(lease: &OwnedDeltaLease, outcome: &str) -> String {
    let mut digest = Sha256::new();
    for component in [
        "v1:owned-projection-lane-audit",
        lease.operation_id.as_str(),
        lease.active_event_id.as_str(),
        lease.lane_owner.as_str(),
        outcome,
    ] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component.as_bytes());
    }
    digest.update(lease.lane_epoch.to_be_bytes());
    hex::encode(digest.finalize())
}

pub(super) async fn audit_owned_lane_in_tx(
    tx: &mut Transaction<'_, MySql>,
    lease: &OwnedDeltaLease,
    outcome: &str,
) -> Result<(), GrantRepositoryError> {
    let request_id = audit_request_id(lease, outcome);
    let detail = serde_json::json!({
        "code": "projection_execution.owned_lane_transition",
        "outcome": outcome,
        "tenantId": lease.lane_identity.tenant_id,
        "aggregateType": lease.lane_identity.aggregate_type,
        "aggregateId": lease.lane_identity.aggregate_id,
        "eventId": lease.active_event_id,
        "operationId": lease.operation_id,
        "leaseOwner": lease.lane_owner,
        "ownershipEpoch": lease.lane_epoch,
        "requestId": request_id,
    });
    sqlx::query(OWNED_AUDIT_INSERT_SQL)
        .bind(SYSTEM_ACTOR_ID)
        .bind(format!("owned_lane_{outcome}"))
        .bind(format!(
            "code=projection_execution.owned_lane;outcome={outcome}"
        ))
        .bind(request_id)
        .bind(lease.lane_identity.tenant_id)
        .bind(detail.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn commit_owned_transition(
    tx: Transaction<'_, MySql>,
    stage: &'static str,
) -> Result<(), GrantRepositoryError> {
    tx.commit().await.map_err(|_| {
        GrantRepositoryError::Mapping(format!(
            "code=projection_execution.commit_outcome_unknown;stage={stage}"
        ))
    })
}

/// Reconcile whether a capability is durably fenced out; time alone is insufficient.
pub async fn owned_delta_lease_is_retired(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
) -> Result<bool, GrantRepositoryError> {
    let mut tx = pool.begin().await?;
    let row: Option<OwnedLaneRow> = sqlx::query_as(OWNED_LANE_FOR_UPDATE_SQL)
        .bind(lease.lane_identity.tenant_id)
        .bind(&lease.lane_identity.aggregate_type)
        .bind(lease.lane_identity.aggregate_id)
        .fetch_optional(&mut *tx)
        .await?;
    let retired = row.is_some_and(|row| {
        row.execution_epoch > lease.lane_epoch
            || (row.execution_epoch == lease.lane_epoch
                && row.active_delta_event_id.is_none()
                && row.active_delta_token_hash.is_none()
                && row.lease_owner.is_empty()
                && row.lease_token_hash.as_slice() == [0_u8; 32]
                && row.lease_live == 0)
    });
    tx.rollback().await?;
    Ok(retired)
}

/// Re-read the exact event only after proving its live aggregate capability.
pub async fn load_owned_claimed_delta_event(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
) -> Result<crate::ClaimedDeltaEvent, GrantRepositoryError> {
    let mut tx = pool.begin().await?;
    if !lock_owned_lane_in_tx(&mut tx, lease).await? {
        return Err(GrantRepositoryError::LeaseCasFailed(
            "code=projection_execution.readback_lane_lost".to_owned(),
        ));
    }
    let event = crate::grant_repository::load_claimed_delta_event_for_update_in_tx(
        &mut tx,
        lease.identity(),
    )
    .await?;
    tx.rollback().await?;
    Ok(event)
}

/// Whether an owned transaction reached COMMIT without a proven result.
/// Callers must reconcile durable state before any release or execution retry.
pub fn owned_execution_outcome_is_unknown(error: &GrantRepositoryError) -> bool {
    matches!(error, GrantRepositoryError::Mapping(message)
        if message.starts_with("code=projection_execution.commit_outcome_unknown;"))
}

const OWNED_EVENT_STATE_FOR_UPDATE_SQL: &str = "SELECT execution_attempts, execution_failures, \
    execution_episode_token_hash, failure_recorded_token_hash, execution_accounting_version \
    FROM authorization_delta_event WHERE delta_event_id = ? \
      AND CAST(event_id AS BINARY) = CAST(? AS BINARY) \
      AND CAST(lease_owner AS BINARY) = CAST(? AS BINARY) \
      AND lease_token_hash = ? AND status = 'LEASED' \
      AND tenant_id = ? AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) \
      AND aggregate_id = ? AND CAST(operation_id AS BINARY) = CAST(? AS BINARY) \
      AND lease_expires_at IS NOT NULL AND lease_expires_at > UTC_TIMESTAMP(6) FOR UPDATE";

#[derive(sqlx::FromRow)]
struct OwnedEventAccountingRow {
    execution_attempts: i64,
    execution_failures: i64,
    execution_episode_token_hash: Option<Vec<u8>>,
    failure_recorded_token_hash: Option<Vec<u8>>,
    execution_accounting_version: i32,
}

impl OwnedEventAccountingRow {
    fn validate(&self) -> Result<u32, GrantRepositoryError> {
        if self.execution_accounting_version != 2
            || self.execution_attempts < 0
            || self.execution_failures < 0
            || self.execution_failures > self.execution_attempts
        {
            return Err(GrantRepositoryError::Mapping(
                "code=projection_execution.invalid_execution_accounting".to_owned(),
            ));
        }
        u32::try_from(self.execution_failures).map_err(|_| {
            GrantRepositoryError::Mapping(
                "code=projection_execution.execution_failures_overflow".to_owned(),
            )
        })
    }
}

fn can_record_owned_episode_failure(
    accounting: &OwnedEventAccountingRow,
    token_hash: &[u8],
) -> bool {
    accounting.execution_episode_token_hash.as_deref() == Some(token_hash)
        && accounting.failure_recorded_token_hash.as_deref() != Some(token_hash)
        && accounting.execution_failures < accounting.execution_attempts
        && accounting.execution_failures < i64::from(u32::MAX)
}

async fn lock_owned_event_accounting(
    tx: &mut Transaction<'_, MySql>,
    lease: &OwnedDeltaLease,
) -> Result<Option<OwnedEventAccountingRow>, GrantRepositoryError> {
    let identity = &lease.event_identity;
    Ok(sqlx::query_as(OWNED_EVENT_STATE_FOR_UPDATE_SQL)
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(identity.lease_token.token_hash().as_bytes().as_slice())
        .bind(lease.lane_identity.tenant_id)
        .bind(&lease.lane_identity.aggregate_type)
        .bind(lease.lane_identity.aggregate_id)
        .bind(&lease.operation_id)
        .fetch_optional(&mut **tx)
        .await?)
}

const OWNED_BEGIN_EPISODE_SQL: &str = "UPDATE authorization_delta_event \
    SET execution_attempts = execution_attempts + 1, execution_episode_token_hash = ?, \
        failure_recorded_token_hash = NULL \
    WHERE delta_event_id = ? AND CAST(event_id AS BINARY) = CAST(? AS BINARY) \
      AND CAST(lease_owner AS BINARY) = CAST(? AS BINARY) AND lease_token_hash = ? \
      AND status = 'LEASED' AND lease_expires_at > UTC_TIMESTAMP(6) \
      AND execution_accounting_version = 2 \
      AND (execution_episode_token_hash IS NULL OR execution_episode_token_hash <> ?) \
      AND execution_attempts < 9223372036854775807";

/// Begin a real execution episode; repeated calls for this token are idempotent.
/// Returns the authoritative number of proven execution failures.
pub async fn begin_owned_delta_execution(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
) -> Result<u32, GrantRepositoryError> {
    let mut tx = pool.begin().await?;
    if !lock_owned_lane_in_tx(&mut tx, lease).await? {
        tx.rollback().await?;
        return Err(GrantRepositoryError::LeaseCasFailed(
            "code=projection_execution.begin_lane_lost".to_owned(),
        ));
    }
    let Some(row) = lock_owned_event_accounting(&mut tx, lease).await? else {
        tx.rollback().await?;
        return Err(GrantRepositoryError::LeaseCasFailed(
            "code=projection_execution.begin_event_lost".to_owned(),
        ));
    };
    let failures = row.validate()?;
    let identity = &lease.event_identity;
    let token_hash = identity.lease_token.token_hash();
    if row.execution_episode_token_hash.as_deref() != Some(token_hash.as_bytes().as_slice()) {
        let updated = sqlx::query(OWNED_BEGIN_EPISODE_SQL)
            .bind(token_hash.as_bytes().as_slice())
            .bind(identity.delta_event_id)
            .bind(&identity.event_id)
            .bind(&identity.lease_owner)
            .bind(token_hash.as_bytes().as_slice())
            .bind(token_hash.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(GrantRepositoryError::LeaseCasFailed(
                "code=projection_execution.begin_episode_cas_lost".to_owned(),
            ));
        }
        audit_owned_lane_in_tx(&mut tx, lease, "BEGIN").await?;
    }
    commit_owned_transition(tx, "begin").await?;
    Ok(failures)
}

/// Renew both live leases atomically. An expired capability cannot revive itself.
pub async fn extend_owned_delta_execution_lease(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
    lease_seconds: i64,
) -> Result<bool, GrantRepositoryError> {
    if !(1..=MAX_DELTA_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=projection_execution.invalid_lease_seconds".to_owned(),
        ));
    }
    let mut tx = pool.begin().await?;
    if !lock_owned_lane_in_tx(&mut tx, lease).await?
        || lock_owned_event_accounting(&mut tx, lease).await?.is_none()
    {
        tx.rollback().await?;
        return Ok(false);
    }
    let lane = sqlx::query(
        "UPDATE authorization_projection_partition_lease \
         SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), \
             last_renewed_at = UTC_TIMESTAMP(6), cas_version = cas_version + 1 \
         WHERE tenant_id = ? AND CAST(aggregate_type AS BINARY) = CAST(? AS BINARY) \
           AND aggregate_id = ? AND execution_epoch = ? \
           AND CAST(lease_owner AS BINARY) = CAST(? AS BINARY) AND lease_token_hash = ? \
           AND active_delta_event_id = ? AND active_delta_token_hash = ? \
           AND lease_expires_at > UTC_TIMESTAMP(6) AND cas_version < 9223372036854775807",
    )
    .bind(lease_seconds)
    .bind(lease.lane_identity.tenant_id)
    .bind(&lease.lane_identity.aggregate_type)
    .bind(lease.lane_identity.aggregate_id)
    .bind(lease.lane_epoch)
    .bind(&lease.lane_owner)
    .bind(lease.lane_token.token_hash().as_bytes().as_slice())
    .bind(lease.event_identity.delta_event_id)
    .bind(
        lease
            .event_identity
            .lease_token
            .token_hash()
            .as_bytes()
            .as_slice(),
    )
    .execute(&mut *tx)
    .await?;
    let event = sqlx::query(
        "UPDATE authorization_delta_event \
         SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)) \
         WHERE delta_event_id = ? AND CAST(event_id AS BINARY) = CAST(? AS BINARY) \
           AND CAST(lease_owner AS BINARY) = CAST(? AS BINARY) \
           AND lease_token_hash = ? AND status = 'LEASED' \
           AND lease_expires_at > UTC_TIMESTAMP(6)",
    )
    .bind(lease_seconds)
    .bind(lease.event_identity.delta_event_id)
    .bind(&lease.event_identity.event_id)
    .bind(&lease.event_identity.lease_owner)
    .bind(
        lease
            .event_identity
            .lease_token
            .token_hash()
            .as_bytes()
            .as_slice(),
    )
    .execute(&mut *tx)
    .await?;
    if lane.rows_affected() != 1 || event.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    commit_owned_transition(tx, "renew").await?;
    Ok(true)
}

#[derive(Clone, Copy)]
enum OwnedReleaseKind<'a> {
    Fail {
        code: &'a str,
        backoff_seconds: i64,
        count_failure: bool,
    },
    Release,
    Quarantine {
        reason_code: &'a str,
        detail: Option<&'a str>,
    },
}

async fn finish_owned_event(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
    kind: OwnedReleaseKind<'_>,
) -> Result<bool, GrantRepositoryError> {
    if let OwnedReleaseKind::Fail {
        backoff_seconds,
        code,
        ..
    } = kind
    {
        if !(0..=MAX_BACKOFF_SECONDS).contains(&backoff_seconds) || code.trim().is_empty() {
            return Err(GrantRepositoryError::ScopeViolation(
                "code=projection_execution.invalid_failure_schedule".to_owned(),
            ));
        }
    }
    if matches!(kind, OwnedReleaseKind::Quarantine { reason_code, .. } if reason_code.trim().is_empty())
    {
        return Err(GrantRepositoryError::ScopeViolation(
            "code=projection_execution.empty_quarantine_reason".to_owned(),
        ));
    }
    let mut tx = pool.begin().await?;
    if !lock_owned_lane_in_tx(&mut tx, lease).await? {
        tx.rollback().await?;
        return Ok(false);
    }
    let Some(accounting) = lock_owned_event_accounting(&mut tx, lease).await? else {
        tx.rollback().await?;
        return Ok(false);
    };
    accounting.validate()?;
    let identity = &lease.event_identity;
    let token_hash = identity.lease_token.token_hash();
    let (set_clause, outcome) = match kind {
        OwnedReleaseKind::Fail {
            count_failure: true,
            ..
        } => {
            if !can_record_owned_episode_failure(&accounting, token_hash.as_bytes().as_slice()) {
                tx.rollback().await?;
                return Ok(false);
            }
            ("next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), last_error = ?, execution_failures = execution_failures + 1, failure_recorded_token_hash = ?", "FAIL")
        }
        OwnedReleaseKind::Fail { .. } => (
            "next_attempt_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP(6)), last_error = ?",
            "DEFER",
        ),
        OwnedReleaseKind::Release => ("next_attempt_at = NULL", "RELEASE"),
        OwnedReleaseKind::Quarantine { .. } => {
            ("next_attempt_at = NULL, last_error = ?", "QUARANTINE")
        }
    };
    let status = if matches!(kind, OwnedReleaseKind::Quarantine { .. }) {
        "QUARANTINED"
    } else {
        "PENDING"
    };
    // Only closed protocol fragments are interpolated; all caller data is bound.
    let statement = format!(
        "UPDATE authorization_delta_event SET status = '{status}', lease_owner = NULL, \
         lease_token_hash = NULL, lease_expires_at = NULL, {set_clause} \
         WHERE delta_event_id = ? AND CAST(event_id AS BINARY) = CAST(? AS BINARY) \
           AND CAST(lease_owner AS BINARY) = CAST(? AS BINARY) AND lease_token_hash = ? \
           AND status = 'LEASED' AND lease_expires_at > UTC_TIMESTAMP(6)"
    );
    let mut query = sqlx::query(&statement);
    match kind {
        OwnedReleaseKind::Fail {
            code,
            backoff_seconds,
            count_failure,
        } => {
            query = query.bind(backoff_seconds).bind(truncate_last_error(code));
            if count_failure {
                query = query.bind(token_hash.as_bytes().to_vec());
            }
        }
        OwnedReleaseKind::Quarantine {
            reason_code,
            detail,
        } => {
            let detail = detail.map_or_else(
                || format!("code={reason_code}"),
                |detail| format!("code={reason_code};detail={detail}"),
            );
            query = query.bind(truncate_last_error(&detail));
        }
        OwnedReleaseKind::Release => {}
    }
    let updated = query
        .bind(identity.delta_event_id)
        .bind(&identity.event_id)
        .bind(&identity.lease_owner)
        .bind(token_hash.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;
    if updated.rows_affected() != 1 || !clear_owned_lane_in_tx(&mut tx, lease).await? {
        tx.rollback().await?;
        return Ok(false);
    }
    audit_owned_lane_in_tx(&mut tx, lease, outcome).await?;
    commit_owned_transition(tx, outcome).await?;
    Ok(true)
}

/// Release after a proven execution failure, or defer without charging the failure budget.
pub async fn fail_owned_delta_event(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
    code: &str,
    backoff_seconds: i64,
    count_failure: bool,
) -> Result<bool, GrantRepositoryError> {
    finish_owned_event(
        pool,
        lease,
        OwnedReleaseKind::Fail {
            code,
            backoff_seconds,
            count_failure,
        },
    )
    .await
}

/// Yield this exact live episode without charging an execution failure.
pub async fn release_owned_delta_event(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
) -> Result<bool, GrantRepositoryError> {
    finish_owned_event(pool, lease, OwnedReleaseKind::Release).await
}

/// Quarantine a proven invalid event while preserving aggregate fencing history.
pub async fn quarantine_owned_delta_event(
    pool: &MySqlPool,
    lease: &OwnedDeltaLease,
    reason_code: &str,
    detail: Option<&str>,
) -> Result<bool, GrantRepositoryError> {
    finish_owned_event(
        pool,
        lease,
        OwnedReleaseKind::Quarantine {
            reason_code,
            detail,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_lease() -> OwnedDeltaLease {
        let lease_owner = "projection-worker:synthetic-run".to_owned();
        let event_id = "synthetic-event-91".to_owned();
        OwnedDeltaLease {
            lane_identity: crate::ProjectionAggregateIdentity::new(7, "CARD", 17)
                .expect("valid synthetic aggregate identity"),
            lane_epoch: 3,
            lane_owner: lease_owner.clone(),
            lane_token: crate::DeltaLeaseToken::for_test("synthetic-lane-token"),
            active_event_id: event_id.clone(),
            operation_id: "synthetic-operation-91".to_owned(),
            event_identity: crate::DeltaLeaseIdentity {
                delta_event_id: 91,
                event_id,
                lease_owner,
                lease_token: crate::DeltaLeaseToken::for_test("synthetic-event-token"),
            },
            execution_failures: 2,
        }
    }

    fn owned_lane_row(lease: &OwnedDeltaLease) -> OwnedLaneRow {
        OwnedLaneRow {
            execution_epoch: lease.lane_epoch,
            lease_owner: lease.lane_owner.clone(),
            lease_token_hash: lease.lane_token.token_hash().as_bytes().to_vec(),
            lease_live: 1,
            active_delta_event_id: Some(lease.event_identity.delta_event_id),
            active_delta_token_hash: Some(
                lease
                    .event_identity
                    .lease_token
                    .token_hash()
                    .as_bytes()
                    .to_vec(),
            ),
        }
    }

    fn accounting_row(
        execution_accounting_version: i32,
        execution_attempts: i64,
        execution_failures: i64,
        execution_episode_token_hash: Option<Vec<u8>>,
        failure_recorded_token_hash: Option<Vec<u8>>,
    ) -> OwnedEventAccountingRow {
        OwnedEventAccountingRow {
            execution_attempts,
            execution_failures,
            execution_episode_token_hash,
            failure_recorded_token_hash,
            execution_accounting_version,
        }
    }

    #[test]
    fn owned_lane_guard_requires_live_epoch_owner_tokens_and_active_event_match() {
        let lease = owned_lease();
        assert!(lane_guard_matches(&owned_lane_row(&lease), &lease));

        let mut row = owned_lane_row(&lease);
        row.lease_live = 0;
        assert!(
            !lane_guard_matches(&row, &lease),
            "expired lane is not live"
        );

        let mut row = owned_lane_row(&lease);
        row.execution_epoch += 1;
        assert!(
            !lane_guard_matches(&row, &lease),
            "stale epoch must not match"
        );

        let mut row = owned_lane_row(&lease);
        row.lease_owner.push_str("-different");
        assert!(!lane_guard_matches(&row, &lease), "lane owner must match");

        let mut row = owned_lane_row(&lease);
        row.lease_token_hash[0] ^= 1;
        assert!(
            !lane_guard_matches(&row, &lease),
            "lane token hash must match"
        );

        let mut row = owned_lane_row(&lease);
        row.active_delta_event_id = Some(lease.event_identity.delta_event_id + 1);
        assert!(!lane_guard_matches(&row, &lease), "active delta must match");

        let mut row = owned_lane_row(&lease);
        row.active_delta_token_hash
            .as_mut()
            .expect("active event token")[0] ^= 1;
        assert!(
            !lane_guard_matches(&row, &lease),
            "active event token must match"
        );

        let mut inconsistent_lease = lease.clone();
        inconsistent_lease.active_event_id.push_str("-different");
        assert!(!lane_guard_matches(
            &owned_lane_row(&inconsistent_lease),
            &inconsistent_lease
        ));

        let mut inconsistent_lease = lease.clone();
        inconsistent_lease.lane_owner.push_str("-different");
        assert!(!lane_guard_matches(
            &owned_lane_row(&inconsistent_lease),
            &inconsistent_lease
        ));
    }

    #[test]
    fn owned_event_accounting_enforces_v2_counter_bounds_and_u32_width() {
        assert_eq!(
            accounting_row(2, 4, 3, None, None)
                .validate()
                .expect("valid v2 accounting"),
            3
        );
        assert_eq!(
            accounting_row(2, i64::from(u32::MAX), i64::from(u32::MAX), None, None)
                .validate()
                .expect("maximum representable failure count"),
            u32::MAX
        );

        let invalid_rows = [
            accounting_row(1, 1, 0, None, None),
            accounting_row(2, -1, 0, None, None),
            accounting_row(2, 1, -1, None, None),
            accounting_row(2, 1, 2, None, None),
        ];
        for row in invalid_rows {
            assert!(matches!(
                row.validate(),
                Err(GrantRepositoryError::Mapping(message))
                    if message == "code=projection_execution.invalid_execution_accounting"
            ));
        }

        let overflow = accounting_row(
            2,
            i64::from(u32::MAX) + 1,
            i64::from(u32::MAX) + 1,
            None,
            None,
        );
        assert!(matches!(
            overflow.validate(),
            Err(GrantRepositoryError::Mapping(message))
                if message == "code=projection_execution.execution_failures_overflow"
        ));
    }

    #[test]
    fn owned_episode_failure_is_counted_once_only_within_its_bounded_episode() {
        let token_hash = [0x5a; 32];
        let other_token_hash = [0xa5; 32];
        let eligible = accounting_row(2, 4, 2, Some(token_hash.to_vec()), None);
        assert!(can_record_owned_episode_failure(&eligible, &token_hash));

        let already_recorded = accounting_row(
            2,
            4,
            2,
            Some(token_hash.to_vec()),
            Some(token_hash.to_vec()),
        );
        assert!(!can_record_owned_episode_failure(
            &already_recorded,
            &token_hash
        ));

        let different_episode = accounting_row(2, 4, 2, Some(other_token_hash.to_vec()), None);
        assert!(!can_record_owned_episode_failure(
            &different_episode,
            &token_hash
        ));

        let attempts_exhausted = accounting_row(2, 2, 2, Some(token_hash.to_vec()), None);
        assert!(!can_record_owned_episode_failure(
            &attempts_exhausted,
            &token_hash
        ));

        let failure_width_exhausted = accounting_row(
            2,
            i64::from(u32::MAX) + 1,
            i64::from(u32::MAX),
            Some(token_hash.to_vec()),
            None,
        );
        assert!(!can_record_owned_episode_failure(
            &failure_width_exhausted,
            &token_hash
        ));
    }

    #[test]
    fn owned_lane_audit_request_id_is_stable_and_binds_transition_dimensions() {
        let lease = owned_lease();
        let request_id = audit_request_id(&lease, "BEGIN");
        assert_eq!(request_id.len(), 64, "SHA-256 hex fits audit request_id");
        assert!(request_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(request_id, audit_request_id(&lease, "BEGIN"));
        assert_ne!(request_id, lease.lane_token.as_str());
        assert_ne!(request_id, lease.event_identity.lease_token.as_str());

        let mut changed = lease.clone();
        changed.operation_id.push_str("-other");
        assert_ne!(request_id, audit_request_id(&changed, "BEGIN"));

        let mut changed = lease.clone();
        changed.active_event_id.push_str("-other");
        assert_ne!(request_id, audit_request_id(&changed, "BEGIN"));

        let mut changed = lease.clone();
        changed.lane_owner.push_str("-other");
        assert_ne!(request_id, audit_request_id(&changed, "BEGIN"));

        let mut changed = lease.clone();
        changed.lane_epoch += 1;
        assert_ne!(request_id, audit_request_id(&changed, "BEGIN"));
        assert_ne!(request_id, audit_request_id(&lease, "FAIL"));
    }

    #[test]
    fn last_error_truncation_preserves_code_and_unicode_character_limit() {
        let code = "code=projection_execution.synthetic_failure;detail=";
        let value = format!("{code}{}", "界".repeat(MAX_LAST_ERROR_LENGTH));
        let truncated = truncate_last_error(&value);

        assert!(truncated.starts_with(code));
        assert_eq!(truncated.chars().count(), MAX_LAST_ERROR_LENGTH);
        assert!(truncated.len() > MAX_LAST_ERROR_LENGTH);
        assert!(truncated.ends_with('界'));
        assert_eq!(truncate_last_error("短错误"), "短错误");
    }

    #[test]
    fn commit_unknown_is_distinct_from_precommit_query_failure() {
        assert!(owned_execution_outcome_is_unknown(
            &GrantRepositoryError::Mapping(
                "code=projection_execution.commit_outcome_unknown;stage=begin".to_owned()
            )
        ));
        assert!(!owned_execution_outcome_is_unknown(
            &GrantRepositoryError::LeaseCasFailed("lost".to_owned())
        ));
        assert!(!owned_execution_outcome_is_unknown(
            &GrantRepositoryError::Query(sqlx::Error::PoolClosed)
        ));
    }
}
