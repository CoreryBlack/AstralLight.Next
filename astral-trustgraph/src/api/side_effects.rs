//! Durable delivery of session-revocation intents after source COMMIT.
//!
//! Source transactions own authorization deltas, source correlation and audit.
//! Compensation can redeliver an existing revocation intent; it cannot create a
//! projection request or report retired snapshot work as completed.

use std::sync::OnceLock;

use lapin::Channel;
use sqlx::MySqlPool;

use astral_mq::producer::{AuthSessionRevocationPayload, Producer};

use crate::repository::global_admin_repository::revocation_intent_type;

static MQ_PRODUCER: OnceLock<Producer> = OnceLock::new();

pub fn init_mq_producer(channel: Channel) {
    let _ = MQ_PRODUCER.set(Producer::new(channel));
}

pub fn init_local_mq_producer(
    bus: astral_mq::local_bus::LocalBus,
    origin_region: impl Into<String>,
) {
    let _ = MQ_PRODUCER.set(Producer::new_local(bus, origin_region));
}

/// Deliver only an intent already committed by the source transaction.
/// Broker confirmation is insufficient: the exact session outbox must be PROCESSED.
pub(crate) async fn publish_auth_session_revocation_with_operation(
    pool: &MySqlPool,
    user_id: i64,
    reason: &str,
    operation_id: &str,
) -> Result<(), astral_types::AstralError> {
    let operation_type = revocation_intent_type(operation_id)?;
    let intent: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM pending_compensation WHERE entity_id = ? AND op_type = ? ORDER BY id LIMIT 1",
    )
    .bind(user_id)
    .bind(&operation_type)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        astral_types::AstralError::Database(format!(
            "auth session revocation intent lookup failed: {error}"
        ))
    })?;
    if intent.is_none() {
        return Err(astral_types::AstralError::Internal(
            "auth session revocation has no durable intent".into(),
        ));
    }
    if revocation_outbox_processed(pool, operation_id, user_id).await? {
        return Ok(());
    }
    let Some(producer) = MQ_PRODUCER.get() else {
        return Err(astral_types::AstralError::Internal(
            "auth session revocation pending: MQ producer not initialized".into(),
        ));
    };
    producer
        .publish_auth_session_revocation_and_wait(
            AuthSessionRevocationPayload {
                operation_id: operation_id.to_owned(),
                user_id,
                reason: reason.to_string(),
            },
            std::time::Duration::from_secs(5),
        )
        .await
        .map_err(|error| {
            tracing::warn!(user_id, operation_id, error = %error, "auth session revocation publish pending");
            astral_types::AstralError::Internal("auth session revocation pending".into())
        })?;
    if revocation_outbox_processed(pool, operation_id, user_id).await? {
        Ok(())
    } else {
        Err(astral_types::AstralError::Internal(
            "auth session revocation pending".into(),
        ))
    }
}

fn revocation_proof_matches(
    status: &str,
    projection_key: &str,
    event_type: &str,
    payload: Option<&str>,
    user_id: i64,
) -> bool {
    let Some(payload) = payload.and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
    else {
        return false;
    };
    status == "PROCESSED"
        && user_id > 0
        && projection_key == format!("user:{user_id}")
        && event_type == "REVOKE"
        && payload.get("v").and_then(serde_json::Value::as_i64) == Some(2)
        && payload.get("userId").and_then(serde_json::Value::as_i64) == Some(user_id)
        && payload
            .get("jtis")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|jtis| {
                jtis.iter()
                    .all(|jti| jti.as_str().is_some_and(|jti| !jti.trim().is_empty()))
            })
}

async fn revocation_outbox_processed(
    pool: &MySqlPool,
    operation_id: &str,
    user_id: i64,
) -> Result<bool, astral_types::AstralError> {
    let proof: Option<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT status, projection_key, event_type, payload_json FROM auth_session_outbox \
         WHERE operation_id = ? AND sequence_number = 1",
    )
    .bind(operation_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        astral_types::AstralError::Database(format!(
            "auth session revocation proof lookup failed: {error}"
        ))
    })?;
    Ok(
        proof.is_some_and(|(status, projection_key, event_type, payload)| {
            revocation_proof_matches(
                &status,
                &projection_key,
                &event_type,
                payload.as_deref(),
                user_id,
            )
        }),
    )
}

const COMPENSATION_LEASE_SECS: i64 = 60;
const MAX_COMPENSATION_RETRY: i32 = 10;

fn compensation_revocation_operation(op_type: &str) -> Result<&str, String> {
    let operation_id = op_type
        .strip_prefix("AUTH_SESSION_REVOCATION:")
        .ok_or_else(|| {
            format!("unsupported compensation op; manual reconciliation required: {op_type}")
        })?;
    let expected = revocation_intent_type(operation_id).map_err(|error| error.to_string())?;
    if expected != op_type {
        return Err("revocation compensation identity mismatch".into());
    }
    Ok(operation_id)
}

const COMPENSATION_CLAIM_SQL: &str =
    "UPDATE pending_compensation SET status = 'PROCESSING', retry_count = retry_count + 1, updated_at = NOW() \
     WHERE id = ? AND retry_count = ? AND retry_count >= 0 AND retry_count < ? AND ( \
       (status = 'PENDING' AND (retry_count = 0 OR updated_at <= NOW() - INTERVAL ? SECOND)) \
       OR (status = 'PROCESSING' AND updated_at <= NOW() - INTERVAL ? SECOND) \
     )";

const COMPENSATION_FINISH_SQL: &str =
    "UPDATE pending_compensation SET status = ?, error_msg = ?, updated_at = NOW() \
     WHERE id = ? AND status = 'PROCESSING' AND retry_count = ?";

/// Retry committed revocation delivery with the original stable operation id.
/// Unsupported historical work is FAILED for manual reconciliation, never completed.
pub async fn retry_pending_compensations(
    pool: &MySqlPool,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    let batch_size = batch_size.clamp(1, 100);
    let rows = sqlx::query_as::<_, (i64, i64, String, i32)>(
        "SELECT id, entity_id, op_type, retry_count \
         FROM pending_compensation \
         WHERE (status = 'PENDING' \
                AND (retry_count = 0 OR updated_at <= NOW() - INTERVAL ? SECOND)) \
            OR (status = 'PROCESSING' AND updated_at <= NOW() - INTERVAL ? SECOND) \
         ORDER BY id LIMIT ?",
    )
    .bind(COMPENSATION_LEASE_SECS)
    .bind(COMPENSATION_LEASE_SECS)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;

    let mut completed = 0;
    for (id, entity_id, op_type, retry_count) in rows {
        if !(0..MAX_COMPENSATION_RETRY).contains(&retry_count) {
            sqlx::query(
                "UPDATE pending_compensation SET status = 'FAILED', error_msg = \
                 'compensation retry budget exhausted or invalid; manual reconciliation required', updated_at = NOW() \
                 WHERE id = ? AND retry_count = ? AND status IN ('PENDING', 'PROCESSING') \
                 AND updated_at <= NOW() - INTERVAL ? SECOND",
            )
            .bind(id)
            .bind(retry_count)
            .bind(COMPENSATION_LEASE_SECS)
            .execute(pool)
            .await?;
            continue;
        }
        // retry_count is also the monotonic claim generation: a stale worker
        // cannot finish a later claimant's episode, even if its delivery completes.
        let claimed = sqlx::query(COMPENSATION_CLAIM_SQL)
            .bind(id)
            .bind(retry_count)
            .bind(MAX_COMPENSATION_RETRY)
            .bind(COMPENSATION_LEASE_SECS)
            .bind(COMPENSATION_LEASE_SECS)
            .execute(pool)
            .await?
            .rows_affected();
        if claimed != 1 {
            continue;
        }
        let claim_generation = retry_count + 1;
        let result = match compensation_revocation_operation(&op_type) {
            Ok(operation_id) => publish_auth_session_revocation_with_operation(
                pool,
                entity_id,
                "GLOBAL_ADMIN_REVOCATION_RECOVERY",
                operation_id,
            )
            .await
            .map_err(|error| error.to_string()),
            Err(error) => {
                tracing::error!(
                    id,
                    entity_id,
                    op_type,
                    error,
                    "compensation requires manual reconciliation"
                );
                sqlx::query(COMPENSATION_FINISH_SQL)
                    .bind("FAILED")
                    .bind(error)
                    .bind(id)
                    .bind(claim_generation)
                    .execute(pool)
                    .await?;
                continue;
            }
        };
        let (status, error) = match result {
            Ok(()) => ("COMPLETED", None),
            Err(error) => {
                let status = if claim_generation >= MAX_COMPENSATION_RETRY {
                    tracing::error!(id, entity_id, op_type, error, "compensation exhausted");
                    "FAILED"
                } else {
                    "PROCESSING"
                };
                (status, Some(error))
            }
        };
        let result = sqlx::query(COMPENSATION_FINISH_SQL)
            .bind(status)
            .bind(error)
            .bind(id)
            .bind(claim_generation)
            .execute(pool)
            .await?;
        if status == "COMPLETED" {
            completed += result.rows_affected();
        }
    }
    Ok(completed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compensation_accepts_only_complete_stable_revocation_identity() {
        assert_eq!(
            compensation_revocation_operation("AUTH_SESSION_REVOCATION:operation-17").unwrap(),
            "operation-17"
        );
        for op_type in [
            "REBUILD_SNAPSHOT",
            "REQUEST_PROJECTION:CARD_UPDATE",
            "REQUEST_RULE_SET_PROJECTION",
            "FIND_BOUND_CARDS",
            "AUTH_SESSION_REVOCATION:",
            "AUTH_SESSION_REVOCATION:invalid:operation",
            "UNKNOWN",
        ] {
            assert!(
                compensation_revocation_operation(op_type).is_err(),
                "{op_type}"
            );
        }
    }

    #[test]
    fn revocation_completion_requires_exact_processed_user_snapshot() {
        let payload = r#"{"v":2,"userId":17,"jtis":["revoked-jti"]}"#;
        assert!(revocation_proof_matches(
            "PROCESSED",
            "user:17",
            "REVOKE",
            Some(payload),
            17
        ));
        for (status, key, event, payload, user) in [
            ("PENDING", "user:17", "REVOKE", Some(payload), 17),
            ("PROCESSED", "user:18", "REVOKE", Some(payload), 17),
            ("PROCESSED", "user:17", "ACTIVATE", Some(payload), 17),
            ("PROCESSED", "user:17", "REVOKE", Some(payload), 18),
            ("PROCESSED", "user:17", "REVOKE", None, 17),
            ("PROCESSED", "user:17", "REVOKE", Some("{}"), 17),
            (
                "PROCESSED",
                "user:17",
                "REVOKE",
                Some(r#"{"v":2,"userId":17,"jtis":[null]}"#),
                17,
            ),
        ] {
            assert!(!revocation_proof_matches(status, key, event, payload, user));
        }
    }

    #[test]
    fn compensation_claim_and_finish_are_generation_fenced() {
        assert!(COMPENSATION_CLAIM_SQL.contains("retry_count = retry_count + 1"));
        assert!(COMPENSATION_CLAIM_SQL.contains("retry_count = ?"));
        assert!(COMPENSATION_CLAIM_SQL.contains("retry_count < ?"));
        assert!(COMPENSATION_FINISH_SQL.contains("status = 'PROCESSING' AND retry_count = ?"));
    }

    #[test]
    fn native_side_effects_do_not_recreate_projection_source_mutations() {
        let production = include_str!("side_effects.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for retired in [
            "request_card_projection",
            "append_rule_set_projection_in_tx",
            "rebuild_card_snapshot_inner",
            "rebuild_rule_set_snapshot_inner",
            "record_compensation",
        ] {
            assert!(!production.contains(retired), "retired effect {retired}");
        }
        for source in [
            include_str!("../service/user_card_service.rs"),
            include_str!("../service/projection_worker.rs"),
        ] {
            let production = source.split("#[cfg(test)]").next().unwrap();
            assert!(production.contains("astral_db::evict_l1_card_active_cache(card_id)"));
        }
        let delivery = production
            .split("async fn publish_auth_session_revocation_with_operation")
            .nth(1)
            .unwrap();
        let intent = delivery.find("if intent.is_none()").unwrap();
        let publish = delivery
            .find(".publish_auth_session_revocation_and_wait(")
            .unwrap();
        let proof = delivery
            .rfind("revocation_outbox_processed(pool, operation_id, user_id).await?")
            .unwrap();
        assert!(intent < publish && publish < proof);
    }
}
