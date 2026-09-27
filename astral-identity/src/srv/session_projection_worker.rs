//! Distributed auth-session projection recovery worker.
//!
//! Every Identity replica runs the same loop. MySQL lease ownership is the
//! only coordinator; Redis operations are idempotent and never reopen durable
//! sessions.

use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde_json::Value;
use sqlx::MySqlPool;
use time::PrimitiveDateTime;
use uuid::Uuid;

use astral_types::AstralError;

const LEASE_SECONDS: i64 = 30;
const POLL_MILLIS: u64 = 1000;
const MAX_BACKOFF_SECONDS: i64 = 300;

#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
struct OutboxRow {
    outbox_id: i64,
    operation_id: String,
    event_type: String,
    projection_key: String,
    payload_json: Option<String>,
    created_at: PrimitiveDateTime,
    attempts: i32,
}

pub fn spawn(pool: MySqlPool, redis: ConnectionManager) {
    let worker_id = format!("identity-{}", Uuid::new_v4());
    tokio::spawn(async move {
        loop {
            match claim_one(&pool, &worker_id).await {
                Ok(Some(row)) => {
                    if let Err(error) = process_one(&pool, &redis, &worker_id, row).await {
                        tracing::warn!(worker_id = %worker_id, %error, "auth session outbox item will retry");
                    }
                }
                Ok(None) => tokio::time::sleep(Duration::from_millis(POLL_MILLIS)).await,
                Err(error) => {
                    tracing::error!(worker_id = %worker_id, %error, "auth session outbox claim failed");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    });
}

async fn claim_one(pool: &MySqlPool, worker_id: &str) -> Result<Option<OutboxRow>, AstralError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| AstralError::Database(format!("Begin outbox claim failed: {error}")))?;
    let row = sqlx::query_as::<_, OutboxRow>(
        "SELECT outbox_id, operation_id, event_type, projection_key, payload_json, created_at, attempts \
         FROM auth_session_outbox \
         WHERE (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at < UTC_TIMESTAMP())) \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()) \
         ORDER BY created_at ASC, outbox_id ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Load outbox item failed: {error}")))?;
    let Some(row) = row else {
        tx.commit().await.map_err(|error| {
            AstralError::Database(format!("Commit empty outbox claim failed: {error}"))
        })?;
        return Ok(None);
    };
    let updated = sqlx::query(
        "UPDATE auth_session_outbox SET status = 'PROCESSING', lease_owner = ?, \
         lease_expires_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), attempts = attempts + 1, \
         updated_at = UTC_TIMESTAMP() WHERE outbox_id = ? \
         AND (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at < UTC_TIMESTAMP()))",
    )
    .bind(worker_id)
    .bind(LEASE_SECONDS)
    .bind(row.outbox_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Claim outbox item failed: {error}")))?;
    if updated.rows_affected() != 1 {
        tx.rollback().await.ok();
        return Ok(None);
    }
    tx.commit()
        .await
        .map_err(|error| AstralError::Database(format!("Commit outbox claim failed: {error}")))?;
    Ok(Some(row))
}

async fn process_one(
    pool: &MySqlPool,
    redis: &ConnectionManager,
    worker_id: &str,
    row: OutboxRow,
) -> Result<(), AstralError> {
    let redis_result = apply_redis_projection(pool, redis, &row).await;
    match redis_result {
        Ok(()) => {
            let result = sqlx::query(
                "UPDATE auth_session_outbox SET status = 'PROCESSED', processed_at = UTC_TIMESTAMP(), \
                 processed_by = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
                 WHERE outbox_id = ? AND status = 'PROCESSING' AND lease_owner = ?",
            )
            .bind(worker_id)
            .bind(row.outbox_id)
            .bind(worker_id)
            .execute(pool)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Complete outbox item failed: {error}"))
            })?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Internal(
                    "outbox completion lease was lost".into(),
                ));
            }
            Ok(())
        }
        Err(error) => {
            let delay = (2_i64.pow((row.attempts.max(0) as u32).min(8))).min(MAX_BACKOFF_SECONDS);
            sqlx::query(
                "UPDATE auth_session_outbox SET status = 'PENDING', next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), \
                 lease_owner = NULL, lease_expires_at = NULL, last_error = ?, updated_at = UTC_TIMESTAMP() \
                 WHERE outbox_id = ? AND status = 'PROCESSING' AND lease_owner = ?",
            )
            .bind(delay)
            .bind(error.to_string())
            .bind(row.outbox_id)
            .bind(worker_id)
            .execute(pool)
            .await
            .map_err(|db_error| AstralError::Database(format!("Release outbox lease failed: {db_error}")))?;
            Err(error)
        }
    }
}

async fn apply_redis_projection(
    pool: &MySqlPool,
    redis: &ConnectionManager,
    row: &OutboxRow,
) -> Result<(), AstralError> {
    let indexed_jtis = load_projection_jtis(pool, row).await?;
    if indexed_jtis.is_empty() {
        if !(row.event_type == "REVOKE"
            && row
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
                .is_some_and(|payload| payload.get("v").and_then(Value::as_i64) == Some(2)))
        {
            return Err(AstralError::Internal(
                "auth revocation projection has no proven JTI snapshot".into(),
            ));
        }
        return Ok(());
    }
    let mut conn = redis.clone();
    for jti in indexed_jtis {
        let _: () = conn
            .del((format!("access:jti:{jti}"), format!("access:grant:{jti}")))
            .await
            .map_err(|error| {
                AstralError::Cache(format!("Delete auth projections failed: {error}"))
            })?;
        let _: () = conn
            .set_ex::<_, _, ()>(format!("jwt:revoked:{jti}"), "1", 7 * 24 * 3600)
            .await
            .map_err(|error| AstralError::Cache(format!("Mark revoked JTI failed: {error}")))?;
    }
    Ok(())
}

async fn load_projection_jtis(
    pool: &MySqlPool,
    row: &OutboxRow,
) -> Result<Vec<String>, AstralError> {
    if row.event_type != "REVOKE" {
        return Err(AstralError::Validation(format!(
            "Unsupported auth projection event type: {}",
            row.event_type
        )));
    }
    if let Some(payload) = row.payload_json.as_deref() {
        let value: Value = serde_json::from_str(payload).map_err(|_| {
            AstralError::Validation("Auth revocation outbox payload is malformed".into())
        })?;
        match value.get("v") {
            Some(Value::Number(version)) if version.as_i64() == Some(2) => {
                let expected_user = row
                    .projection_key
                    .strip_prefix("user:")
                    .and_then(|id| id.parse::<i64>().ok())
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        AstralError::Validation("Auth revocation snapshot has invalid scope".into())
                    })?;
                if value.get("userId").and_then(Value::as_i64) != Some(expected_user) {
                    return Err(AstralError::Validation(
                        "Auth revocation snapshot user does not match projection key".into(),
                    ));
                }
                let jtis = value
                    .get("jtis")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        AstralError::Validation("Auth revocation snapshot is missing jtis".into())
                    })?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|jti| !jti.trim().is_empty())
                            .map(ToOwned::to_owned)
                            .ok_or_else(|| {
                                AstralError::Validation(
                                    "Auth revocation snapshot contains invalid jti".into(),
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(jtis);
            }
            Some(_) => {
                return Err(AstralError::Validation(
                    "Unsupported auth revocation outbox version".into(),
                ));
            }
            None => {}
        }
    }

    let (kind, value) = row
        .projection_key
        .split_once(':')
        .ok_or_else(|| AstralError::Validation("Invalid auth projection key".into()))?;
    let id = value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Validation("Invalid auth projection id".into()))?;
    let rows = match kind {
        "session" => {
            sqlx::query_scalar::<_, String>(
                "SELECT jti FROM auth_session_jti_index \
             WHERE session_id = ? AND issued_at <= ? \
               AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
            )
            .bind(id)
            .bind(row.created_at)
            .fetch_all(pool)
            .await
        }
        "family" => {
            sqlx::query_scalar::<_, String>(
                "SELECT i.jti FROM auth_session_jti_index i \
             INNER JOIN auth_device_session s ON s.session_id = i.session_id \
             WHERE s.family_id = ? AND i.issued_at <= ? \
               AND (i.expires_at IS NULL OR i.expires_at > UTC_TIMESTAMP())",
            )
            .bind(id)
            .bind(row.created_at)
            .fetch_all(pool)
            .await
        }
        "user" => {
            sqlx::query_scalar::<_, String>(
                "SELECT i.jti FROM auth_session_jti_index i \
             WHERE i.user_id = ? AND i.issued_at <= ? \
               AND (i.expires_at IS NULL OR i.expires_at > UTC_TIMESTAMP())",
            )
            .bind(id)
            .bind(row.created_at)
            .fetch_all(pool)
            .await
        }
        _ => {
            return Err(AstralError::Validation(
                "Unknown auth projection key".into(),
            ))
        }
    };
    rows.map_err(|error| {
        AstralError::Database(format!("Load auth projection JTIs failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::{load_projection_jtis, OutboxRow};
    use time::{Date, Month, PrimitiveDateTime, Time};

    #[tokio::test]
    async fn projection_key_validation_fails_before_database_access() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap();
        let row = OutboxRow {
            outbox_id: 1,
            operation_id: "op".into(),
            event_type: "REVOKE".into(),
            projection_key: "session:0".into(),
            payload_json: None,
            created_at: PrimitiveDateTime::new(
                Date::from_calendar_date(2026, Month::January, 1).unwrap(),
                Time::MIDNIGHT,
            ),
            attempts: 0,
        };
        assert!(load_projection_jtis(&pool, &row).await.is_err());
        let mut invalid = row;
        invalid.projection_key = "card:1".into();
        assert!(load_projection_jtis(&pool, &invalid).await.is_err());
    }
}
