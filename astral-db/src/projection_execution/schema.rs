//! Startup verification for the additive owned-execution schema.

use sqlx::MySqlPool;

use crate::{GrantRepositoryError, ProjectionExecutionMode};

const COLUMN_SQL: &str = "SELECT CAST(LOWER(COLUMN_TYPE) AS BINARY), \
    CAST(IS_NULLABLE AS BINARY), CAST(COLUMN_DEFAULT AS BINARY) \
    FROM information_schema.COLUMNS \
    WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
      AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
      AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";

type ColumnContract = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

const REQUIRED_COLUMNS: &[ColumnContract] = &[
    (
        "authorization_projection_partition_lease",
        "execution_epoch",
        "bigint",
        "NO",
        Some("0"),
    ),
    (
        "authorization_projection_partition_lease",
        "active_delta_event_id",
        "bigint",
        "YES",
        None,
    ),
    (
        "authorization_projection_partition_lease",
        "active_delta_token_hash",
        "binary(32)",
        "YES",
        None,
    ),
    (
        "authorization_delta_event",
        "execution_attempts",
        "bigint",
        "NO",
        Some("0"),
    ),
    (
        "authorization_delta_event",
        "execution_failures",
        "bigint",
        "NO",
        Some("0"),
    ),
    (
        "authorization_delta_event",
        "execution_episode_token_hash",
        "binary(32)",
        "YES",
        None,
    ),
    (
        "authorization_delta_event",
        "failure_recorded_token_hash",
        "binary(32)",
        "YES",
        None,
    ),
    (
        "authorization_delta_event",
        "execution_accounting_version",
        "int",
        "NO",
        Some("1"),
    ),
];

type ColumnMetadata = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);
type IndexMetadata = (Vec<u8>, u32, i32);

fn schema_error(code: &str) -> GrantRepositoryError {
    GrantRepositoryError::Mapping(format!("code=projection_execution.{code}"))
}

async fn validate_index(
    pool: &MySqlPool,
    name: &str,
    columns: &[&str],
    unique: bool,
) -> Result<(), GrantRepositoryError> {
    let rows: Vec<IndexMetadata> = sqlx::query_as(
        "SELECT CAST(COLUMN_NAME AS BINARY), SEQ_IN_INDEX, NON_UNIQUE \
         FROM information_schema.STATISTICS \
         WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
           AND TABLE_NAME = 'authorization_projection_partition_lease' \
           AND CAST(INDEX_NAME AS BINARY) = CAST(? AS BINARY) ORDER BY SEQ_IN_INDEX",
    )
    .bind(name)
    .fetch_all(pool)
    .await?;
    if rows.len() != columns.len()
        || rows.iter().zip(columns).enumerate().any(
            |(index, ((column, ordinal, non_unique), expected))| {
                column.as_slice() != expected.as_bytes()
                    || *ordinal as usize != index + 1
                    || *non_unique != i32::from(!unique)
            },
        )
    {
        return Err(schema_error(&format!("schema_index_mismatch;index={name}")));
    }
    Ok(())
}

/// Validate physical schema, historical accounting and persistent ownership invariants.
/// This is read-only; missing or incompatible state requires the explicit migration job.
pub async fn validate_projection_owned_schema(
    pool: &MySqlPool,
) -> Result<(), GrantRepositoryError> {
    for &(table, column, column_type, nullable, default) in REQUIRED_COLUMNS {
        let actual: Option<ColumnMetadata> = sqlx::query_as(COLUMN_SQL)
            .bind(table)
            .bind(column)
            .fetch_optional(pool)
            .await?;
        if !actual
            .as_ref()
            .is_some_and(|(actual_type, actual_nullable, actual_default)| {
                actual_type.as_slice() == column_type.as_bytes()
                    && actual_nullable.as_slice() == nullable.as_bytes()
                    && actual_default.as_deref() == default.map(str::as_bytes)
            })
        {
            return Err(schema_error(&format!(
                "schema_column_mismatch;table={table};column={column}"
            )));
        }
    }
    validate_index(
        pool,
        "PRIMARY",
        &["tenant_id", "aggregate_type", "aggregate_id"],
        true,
    )
    .await?;
    validate_index(
        pool,
        "idx_appl_active_delta_event",
        &["active_delta_event_id"],
        false,
    )
    .await?;
    validate_index(pool, "idx_appl_expiry", &["lease_expires_at"], false).await?;

    let invalid_counters: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM authorization_delta_event \
         WHERE attempts < 0 OR execution_attempts < 0 OR execution_failures < 0 \
            OR execution_failures > execution_attempts OR execution_failures > 4294967295 \
            OR execution_accounting_version NOT IN (1, 2) LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    if invalid_counters.is_some() {
        return Err(schema_error("schema_execution_counter_invariant_violation"));
    }

    let invalid_lane: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM authorization_projection_partition_lease l \
         WHERE l.execution_epoch < 0 OR l.generation < 1 OR l.cas_version < 0 \
            OR ((l.active_delta_event_id IS NULL) <> (l.active_delta_token_hash IS NULL)) \
            OR (l.execution_epoch = 0 AND l.active_delta_event_id IS NOT NULL) \
            OR (l.execution_epoch > 0 AND l.active_delta_event_id IS NULL \
                AND (l.lease_owner <> '' OR l.lease_token_hash <> UNHEX(REPEAT('00',32)) \
                     OR l.lease_expires_at > UTC_TIMESTAMP(6))) \
            OR (l.active_delta_event_id IS NOT NULL \
                AND (l.lease_owner = '' OR l.lease_token_hash = UNHEX(REPEAT('00',32)) \
                     OR NOT EXISTS (SELECT 1 FROM authorization_delta_event e \
                       WHERE e.delta_event_id = l.active_delta_event_id \
                         AND e.tenant_id = l.tenant_id \
                         AND CAST(e.aggregate_type AS BINARY) = CAST(l.aggregate_type AS BINARY) \
                         AND e.aggregate_id = l.aggregate_id AND e.status = 'LEASED' \
                         AND CAST(e.lease_owner AS BINARY) = CAST(l.lease_owner AS BINARY) \
                         AND e.lease_token_hash = l.active_delta_token_hash))) LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    if invalid_lane.is_some() {
        return Err(schema_error("schema_lane_invariant_violation"));
    }

    if super::projection_execution_mode() == ProjectionExecutionMode::WorkerOwned {
        let legacy_execution: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM authorization_projection_partition_lease \
             WHERE execution_epoch = 0 AND lease_expires_at > UTC_TIMESTAMP(6) \
             UNION ALL SELECT 1 FROM authorization_delta_event e \
             WHERE e.status = 'LEASED' AND NOT EXISTS \
               (SELECT 1 FROM authorization_projection_partition_lease l \
                WHERE l.tenant_id = e.tenant_id \
                  AND CAST(l.aggregate_type AS BINARY) = CAST(e.aggregate_type AS BINARY) \
                  AND l.aggregate_id = e.aggregate_id AND l.execution_epoch > 0 \
                  AND l.active_delta_event_id = e.delta_event_id \
                  AND l.active_delta_token_hash = e.lease_token_hash \
                  AND CAST(l.lease_owner AS BINARY) = CAST(e.lease_owner AS BINARY)) LIMIT 1",
        )
        .fetch_optional(pool)
        .await?;
        if legacy_execution.is_some() {
            return Err(schema_error(
                "legacy_execution_requires_drain_and_reconciliation",
            ));
        }
    }
    Ok(())
}
