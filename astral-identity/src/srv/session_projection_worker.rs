//! Distributed auth-session projection recovery worker.
//!
//! Every Identity replica runs the same loop. MySQL lease ownership is the
//! only coordinator; Redis operations are idempotent and never reopen durable
//! sessions.

use std::time::Duration;

use redis::AsyncCommands;
use sqlx::MySqlPool;
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
    projection_key: String,
    payload_json: Option<String>,
    attempts: i32,
}

pub fn spawn(pool: MySqlPool, redis_url: String) {
    let worker_id = format!("identity-{}", Uuid::new_v4());
    tokio::spawn(async move {
        loop {
            match claim_one(&pool, &worker_id).await {
                Ok(Some(row)) => {
                    if let Err(error) = process_one(&pool, &redis_url, &worker_id, row).await {
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
        "SELECT outbox_id, operation_id, projection_key, payload_json, attempts \
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
    redis_url: &str,
    worker_id: &str,
    row: OutboxRow,
) -> Result<(), AstralError> {
    let redis_result = apply_redis_projection(pool, redis_url, &row.projection_key).await;
    match redis_result {
        Ok(()) => {
            sqlx::query(
                "UPDATE auth_session_outbox SET status = 'PROCESSED', processed_at = UTC_TIMESTAMP(), \
                 processed_by = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
                 WHERE outbox_id = ? AND status = 'PROCESSING' AND lease_owner = ?",
            )
            .bind(worker_id)
            .bind(row.outbox_id)
            .bind(worker_id)
            .execute(pool)
            .await
            .map_err(|error| AstralError::Database(format!("Complete outbox item failed: {error}")))?;
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
    redis_url: &str,
    projection_key: &str,
) -> Result<(), AstralError> {
    let indexed_jtis = load_projection_jtis(pool, projection_key).await?;
    if indexed_jtis.is_empty() {
        return Ok(());
    }
    let client = redis::Client::open(redis_url)
        .map_err(|error| AstralError::Cache(format!("Open Redis client failed: {error}")))?;
    let mut conn = client
        .get_connection_manager()
        .await
        .map_err(|error| AstralError::Cache(format!("Connect Redis failed: {error}")))?;
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
    projection_key: &str,
) -> Result<Vec<String>, AstralError> {
    let (kind, value) = projection_key
        .split_once(':')
        .ok_or_else(|| AstralError::Validation("Invalid auth projection key".into()))?;
    let id = value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Validation("Invalid auth projection id".into()))?;
    let rows = match kind {
        "session" => sqlx::query_scalar::<_, String>(
            "SELECT jti FROM auth_session_jti_index WHERE session_id = ? AND status = 'ACTIVE'",
        )
        .bind(id)
        .fetch_all(pool)
        .await,
        "family" => sqlx::query_scalar::<_, String>(
            "SELECT i.jti FROM auth_session_jti_index i \
             INNER JOIN auth_device_session s ON s.session_id = i.session_id \
             WHERE s.family_id = ? AND i.status = 'ACTIVE'",
        )
        .bind(id)
        .fetch_all(pool)
        .await,
        "user" => sqlx::query_scalar::<_, String>(
            "SELECT i.jti FROM auth_session_jti_index i WHERE i.user_id = ? AND i.status = 'ACTIVE'",
        )
        .bind(id)
        .fetch_all(pool)
        .await,
        _ => return Err(AstralError::Validation("Unknown auth projection key".into())),
    };
    rows.map_err(|error| {
        AstralError::Database(format!("Load auth projection JTIs failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::load_projection_jtis;

    #[tokio::test]
    async fn projection_key_validation_fails_before_database_access() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap();
        assert!(load_projection_jtis(&pool, "session:0").await.is_err());
        assert!(load_projection_jtis(&pool, "card:1").await.is_err());
    }
}
