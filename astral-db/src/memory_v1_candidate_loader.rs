//! Isolated, unverified MySQL row capture for the memory-v1 nine-table candidate.
//!
//! This is not an authorization reader or an installer. The returned rows do not
//! prove current versions, complete facts, valid confirmations, hashes, freshness,
//! or readiness. Callers may use `CandidateRows::build_candidate` with their own
//! explicit selections; neither that validation nor this capture grants authority.

use std::time::Duration;

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, IdentityCardRow,
    RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
};
use sqlx::{mysql::MySqlRow, Connection, MySql, MySqlPool, Row, Transaction};
use thiserror::Error;

// These are capture limits, not protocol limits. Transient SQLx row buffers and
// container overhead are additional; each of at most five variable fields is
// capped server-side at the remaining byte budget plus one overflow byte.
const MAX_ROWS: usize = 100_000;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

/// Caller-chosen total limits across all nine tables, bounded by implementation caps.
#[derive(Clone, Copy, Debug)]
pub struct CaptureBudget {
    /// Maximum number of rows across the nine tables.
    pub max_rows: usize,
    /// Maximum sum of returned field bytes, including IDs and the binding layer.
    pub max_bytes: usize,
}

/// Unverified captured rows. Empty tables do not prove absence of authorization facts.
#[derive(Debug)]
pub struct UnverifiedCandidateRows {
    /// Nine tables as observed in one attempted consistent snapshot.
    pub rows: CandidateRows,
    /// Number of captured rows across all tables.
    pub row_count: usize,
    /// Sum of captured field bytes, excluding allocation and protocol overhead.
    pub field_bytes: usize,
}

/// Capture failure; no partial candidate is returned.
#[derive(Debug, Error)]
pub enum CandidateCaptureError {
    /// A caller limit is zero or exceeds the implementation cap.
    #[error("invalid candidate capture budget")]
    InvalidBudget,
    /// The total row or field-byte budget would be exceeded.
    #[error("candidate capture {0} budget exceeded")]
    BudgetExceeded(&'static str),
    /// A table/column does not satisfy the narrow storage prerequisites.
    #[error("candidate schema prerequisite failed: {0}")]
    Schema(&'static str),
    /// A field has an invalid value or an unsupported byte length.
    #[error("invalid candidate field: {0}")]
    InvalidField(&'static str),
    /// Database or decoding failure.
    #[error("candidate database error during {context}: {source}")]
    Database {
        /// Operation in progress.
        context: &'static str,
        /// SQLx error.
        #[source]
        source: sqlx::Error,
    },
    /// An error occurred and the explicit rollback also failed.
    #[error("candidate capture failed ({capture}); rollback failed: {rollback}")]
    Rollback {
        /// Original capture failure.
        capture: Box<CandidateCaptureError>,
        /// Rollback failure.
        rollback: sqlx::Error,
    },
    /// The capture timed out; the detached connection is discarded.
    #[error("candidate capture deadline exceeded")]
    Deadline,
}

// memory—v1: Attach a static operation name without exposing captured bytes.
fn db_error(context: &'static str, source: sqlx::Error) -> CandidateCaptureError {
    CandidateCaptureError::Database { context, source }
}

struct Meter {
    budget: CaptureBudget,
    rows: usize,
    bytes: usize,
}

impl Meter {
    // memory—v1: Validate caller caps before acquiring a connection.
    fn new(budget: CaptureBudget) -> Result<Self, CandidateCaptureError> {
        if budget.max_rows == 0
            || budget.max_rows > MAX_ROWS
            || budget.max_bytes == 0
            || budget.max_bytes > MAX_BYTES
        {
            return Err(CandidateCaptureError::InvalidBudget);
        }
        Ok(Self {
            budget,
            rows: 0,
            bytes: 0,
        })
    }

    // memory—v1: Charge before admitting a row; the extra fetched row detects truncation.
    fn row(&mut self) -> Result<(), CandidateCaptureError> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(CandidateCaptureError::BudgetExceeded("row"))?;
        if self.rows > self.budget.max_rows {
            return Err(CandidateCaptureError::BudgetExceeded("row"));
        }
        Ok(())
    }

    // memory—v1: Charge exact field bytes and reject overflow without truncating.
    fn bytes(&mut self, len: usize) -> Result<(), CandidateCaptureError> {
        self.bytes = self
            .bytes
            .checked_add(len)
            .ok_or(CandidateCaptureError::BudgetExceeded("byte"))?;
        if self.bytes > self.budget.max_bytes {
            return Err(CandidateCaptureError::BudgetExceeded("byte"));
        }
        Ok(())
    }

    // memory—v1: Limit every variable field before SQLx receives it.
    fn sentinel(&self) -> i64 {
        (self.budget.max_bytes - self.bytes + 1) as i64
    }
}

// memory—v1: Decode exact opaque bytes and count them against the shared budget.
fn bytes(
    row: &MySqlRow,
    name: &'static str,
    meter: &mut Meter,
) -> Result<Vec<u8>, CandidateCaptureError> {
    let value: Vec<u8> = row.try_get(name).map_err(|e| db_error(name, e))?;
    meter.bytes(value.len())?;
    Ok(value)
}

// memory—v1: Require exactly sixteen bytes, preserving zeros and byte order.
fn binary_id(
    row: &MySqlRow,
    name: &'static str,
    meter: &mut Meter,
) -> Result<BinaryId, CandidateCaptureError> {
    bytes(row, name, meter)?
        .try_into()
        .map_err(|_| CandidateCaptureError::InvalidField(name))
}

// memory—v1: Preserve NULL separately from a sixteen-byte parent identifier.
fn optional_id(
    row: &MySqlRow,
    name: &'static str,
    meter: &mut Meter,
) -> Result<Option<BinaryId>, CandidateCaptureError> {
    let value: Option<Vec<u8>> = row.try_get(name).map_err(|e| db_error(name, e))?;
    value
        .map(|value| {
            meter.bytes(value.len())?;
            value
                .try_into()
                .map_err(|_| CandidateCaptureError::InvalidField(name))
        })
        .transpose()
}

// memory—v1: Reject unsupported layer bytes instead of interpreting them as permissions.
fn layer(row: &MySqlRow, meter: &mut Meter) -> Result<BindingLayer, CandidateCaptureError> {
    match bytes(row, "binding_layer", meter)?.as_slice() {
        b"BASE" => Ok(BindingLayer::Base),
        b"OVERLAY" => Ok(BindingLayer::Overlay),
        _ => Err(CandidateCaptureError::InvalidField("binding_layer")),
    }
}

// Fixed queries use server-side byte caps and fetch at most one row at a time.
// OFFSET is bounded by MAX_ROWS and the whole capture has a deadline. No order
// determines currentness; primary-key ordering only makes pagination stable.
struct TableSpec {
    name: &'static str,
    ids: &'static [&'static str],
    sql: &'static str,
    variable_fields: usize,
}

const TABLES: &[TableSpec] = &[
    TableSpec { name: "memory_user", ids: &["user_id"], sql: "SELECT LEFT(user_id,17) AS user_id FROM memory_user ORDER BY user_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_identity_card", ids: &["identity_card_id", "user_id"], sql: "SELECT LEFT(identity_card_id,17) AS identity_card_id, LEFT(user_id,17) AS user_id FROM memory_identity_card ORDER BY identity_card_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_tenant", ids: &["tenant_id", "parent_tenant_id"], sql: "SELECT LEFT(tenant_id,17) AS tenant_id, LEFT(parent_tenant_id,17) AS parent_tenant_id FROM memory_tenant ORDER BY tenant_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_user_card", ids: &["user_card_id", "user_id", "tenant_id"], sql: "SELECT LEFT(user_card_id,17) AS user_card_id, LEFT(user_id,17) AS user_id, LEFT(tenant_id,17) AS tenant_id FROM memory_user_card ORDER BY user_card_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_rule_set", ids: &["rule_set_id", "owner_tenant_id"], sql: "SELECT LEFT(rule_set_id,17) AS rule_set_id, LEFT(owner_tenant_id,17) AS owner_tenant_id FROM memory_rule_set ORDER BY rule_set_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_rule_set_version", ids: &["rule_set_id"], sql: "SELECT LEFT(rule_set_id,17) AS rule_set_id, LEFT(version_bytes,?) AS version_bytes, LEFT(content_bytes,?) AS content_bytes, LEFT(timestamp_bytes,?) AS timestamp_bytes, LEFT(hash_input_bytes,?) AS hash_input_bytes, LEFT(hash_bytes,?) AS hash_bytes FROM memory_rule_set_version ORDER BY rule_set_id, version_bytes LIMIT 1 OFFSET ?", variable_fields: 5 },
    TableSpec { name: "memory_card_rule_set_binding", ids: &["binding_id", "user_card_id", "rule_set_id"], sql: "SELECT LEFT(binding_id,17) AS binding_id, LEFT(user_card_id,17) AS user_card_id, LEFT(rule_set_id,17) AS rule_set_id, LEFT(CAST(binding_layer AS BINARY),8) AS binding_layer FROM memory_card_rule_set_binding ORDER BY binding_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_binding_confirmation", ids: &["confirmation_id", "binding_id", "rule_set_id", "confirmer_user_id"], sql: "SELECT LEFT(confirmation_id,17) AS confirmation_id, LEFT(binding_id,17) AS binding_id, LEFT(rule_set_id,17) AS rule_set_id, LEFT(version_bytes,?) AS version_bytes, LEFT(confirmer_user_id,17) AS confirmer_user_id, LEFT(scope_bytes,?) AS scope_bytes, LEFT(operation_id,?) AS operation_id, LEFT(confirmed_at_bytes,?) AS confirmed_at_bytes FROM memory_binding_confirmation ORDER BY confirmation_id LIMIT 1 OFFSET ?", variable_fields: 4 },
    TableSpec { name: "memory_rule_set_change_confirmation", ids: &["confirmation_id", "rule_set_id", "confirmer_user_id"], sql: "SELECT LEFT(confirmation_id,17) AS confirmation_id, LEFT(rule_set_id,17) AS rule_set_id, LEFT(version_bytes,?) AS version_bytes, LEFT(confirmer_user_id,17) AS confirmer_user_id, LEFT(affected_scope_bytes,?) AS affected_scope_bytes, LEFT(operation_id,?) AS operation_id, LEFT(confirmed_at_bytes,?) AS confirmed_at_bytes FROM memory_rule_set_change_confirmation ORDER BY confirmation_id LIMIT 1 OFFSET ?", variable_fields: 4 },
];

// memory—v1: Require actual InnoDB tables and BINARY(16) columns, not merely 16-byte values.
async fn check_schema(tx: &mut Transaction<'_, MySql>) -> Result<(), CandidateCaptureError> {
    for table in TABLES {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND BINARY TABLE_NAME = BINARY ? AND TABLE_TYPE = 'BASE TABLE' AND ENGINE = 'InnoDB'")
            .bind(table.name).fetch_one(&mut **tx).await.map_err(|e| db_error("table metadata", e))?;
        if count != 1 {
            return Err(CandidateCaptureError::Schema(table.name));
        }
        for id in table.ids {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND BINARY TABLE_NAME = BINARY ? AND BINARY COLUMN_NAME = BINARY ? AND DATA_TYPE = 'binary' AND CHARACTER_MAXIMUM_LENGTH = 16")
                .bind(table.name).bind(*id).fetch_one(&mut **tx).await.map_err(|e| db_error("column metadata", e))?;
            if count != 1 {
                return Err(CandidateCaptureError::Schema(id));
            }
        }
    }
    // These columns must be binary storage, or LEFT could transcode opaque data.
    for (table, column, data_type, max_len) in [
        (
            "memory_rule_set_version",
            "version_bytes",
            "varbinary",
            255_u64,
        ),
        (
            "memory_rule_set_version",
            "content_bytes",
            "longblob",
            u32::MAX as u64,
        ),
        (
            "memory_rule_set_version",
            "timestamp_bytes",
            "varbinary",
            255,
        ),
        (
            "memory_rule_set_version",
            "hash_input_bytes",
            "longblob",
            u32::MAX as u64,
        ),
        ("memory_rule_set_version", "hash_bytes", "varbinary", 255),
        (
            "memory_binding_confirmation",
            "version_bytes",
            "varbinary",
            255,
        ),
        (
            "memory_binding_confirmation",
            "scope_bytes",
            "longblob",
            u32::MAX as u64,
        ),
        (
            "memory_binding_confirmation",
            "operation_id",
            "varbinary",
            255,
        ),
        (
            "memory_binding_confirmation",
            "confirmed_at_bytes",
            "varbinary",
            255,
        ),
        (
            "memory_rule_set_change_confirmation",
            "version_bytes",
            "varbinary",
            255,
        ),
        (
            "memory_rule_set_change_confirmation",
            "affected_scope_bytes",
            "longblob",
            u32::MAX as u64,
        ),
        (
            "memory_rule_set_change_confirmation",
            "operation_id",
            "varbinary",
            255,
        ),
        (
            "memory_rule_set_change_confirmation",
            "confirmed_at_bytes",
            "varbinary",
            255,
        ),
    ] {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND BINARY TABLE_NAME = BINARY ? AND BINARY COLUMN_NAME = BINARY ? AND DATA_TYPE = ? AND CHARACTER_MAXIMUM_LENGTH = ?")
            .bind(table).bind(column).bind(data_type).bind(max_len)
            .fetch_one(&mut **tx).await.map_err(|e| db_error("opaque column metadata", e))?;
        if count != 1 {
            return Err(CandidateCaptureError::Schema(column));
        }
    }
    let layer: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND BINARY TABLE_NAME = BINARY 'memory_card_rule_set_binding' AND BINARY COLUMN_NAME = BINARY 'binding_layer' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 7 AND CHARACTER_SET_NAME = 'ascii' AND COLLATION_NAME = 'ascii_bin'")
        .fetch_one(&mut **tx).await.map_err(|e| db_error("binding layer metadata", e))?;
    if layer != 1 {
        return Err(CandidateCaptureError::Schema("binding_layer"));
    }
    Ok(())
}

// memory—v1: Map a bounded row to the root crate's unverified data structures.
fn append(
    table: &str,
    row: &MySqlRow,
    meter: &mut Meter,
    out: &mut CandidateRows,
) -> Result<(), CandidateCaptureError> {
    match table {
        "memory_user" => out.users.push(UserRow {
            user_id: binary_id(row, "user_id", meter)?,
        }),
        "memory_identity_card" => out.identity_cards.push(IdentityCardRow {
            identity_card_id: binary_id(row, "identity_card_id", meter)?,
            user_id: binary_id(row, "user_id", meter)?,
        }),
        "memory_tenant" => out.tenants.push(TenantRow {
            tenant_id: binary_id(row, "tenant_id", meter)?,
            parent_tenant_id: optional_id(row, "parent_tenant_id", meter)?,
        }),
        "memory_user_card" => out.user_cards.push(UserCardRow {
            user_card_id: binary_id(row, "user_card_id", meter)?,
            user_id: binary_id(row, "user_id", meter)?,
            tenant_id: binary_id(row, "tenant_id", meter)?,
        }),
        "memory_rule_set" => out.rule_sets.push(RuleSetRow {
            rule_set_id: binary_id(row, "rule_set_id", meter)?,
            owner_tenant_id: binary_id(row, "owner_tenant_id", meter)?,
        }),
        "memory_rule_set_version" => out.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id: binary_id(row, "rule_set_id", meter)?,
            version_bytes: bytes(row, "version_bytes", meter)?,
            content_bytes: bytes(row, "content_bytes", meter)?,
            timestamp_bytes: bytes(row, "timestamp_bytes", meter)?,
            hash_input_bytes: bytes(row, "hash_input_bytes", meter)?,
            hash_bytes: bytes(row, "hash_bytes", meter)?,
        }),
        "memory_card_rule_set_binding" => out.bindings.push(BindingRow {
            binding_id: binary_id(row, "binding_id", meter)?,
            user_card_id: binary_id(row, "user_card_id", meter)?,
            rule_set_id: binary_id(row, "rule_set_id", meter)?,
            binding_layer: layer(row, meter)?,
        }),
        "memory_binding_confirmation" => out.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: binary_id(row, "confirmation_id", meter)?,
            binding_id: binary_id(row, "binding_id", meter)?,
            rule_set_id: binary_id(row, "rule_set_id", meter)?,
            version_bytes: bytes(row, "version_bytes", meter)?,
            confirmer_user_id: binary_id(row, "confirmer_user_id", meter)?,
            scope_bytes: bytes(row, "scope_bytes", meter)?,
            operation_id: bytes(row, "operation_id", meter)?,
            confirmed_at_bytes: bytes(row, "confirmed_at_bytes", meter)?,
        }),
        "memory_rule_set_change_confirmation" => {
            out.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: binary_id(row, "confirmation_id", meter)?,
                    rule_set_id: binary_id(row, "rule_set_id", meter)?,
                    version_bytes: bytes(row, "version_bytes", meter)?,
                    confirmer_user_id: binary_id(row, "confirmer_user_id", meter)?,
                    affected_scope_bytes: bytes(row, "affected_scope_bytes", meter)?,
                    operation_id: bytes(row, "operation_id", meter)?,
                    confirmed_at_bytes: bytes(row, "confirmed_at_bytes", meter)?,
                })
        }
        _ => return Err(CandidateCaptureError::Schema("unknown table")),
    }
    Ok(())
}

// memory—v1: Read all nine tables without returning a partial or truncated capture.
async fn read_rows(
    tx: &mut Transaction<'_, MySql>,
    mut meter: Meter,
) -> Result<UnverifiedCandidateRows, CandidateCaptureError> {
    check_schema(tx).await?;
    let mut out = CandidateRows::default();
    for table in TABLES {
        let mut offset = 0_i64;
        loop {
            let mut query = sqlx::query(table.sql);
            for _ in 0..table.variable_fields {
                query = query.bind(meter.sentinel());
            }
            let row = query
                .bind(offset)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| db_error(table.name, e))?;
            let Some(row) = row else { break };
            meter.row()?;
            append(table.name, &row, &mut meter, &mut out)?;
            offset += 1;
        }
    }
    Ok(UnverifiedCandidateRows {
        rows: out,
        row_count: meter.rows,
        field_bytes: meter.bytes,
    })
}

/// memory—v1: Capture nine tables in a detached, read-only consistent snapshot.
///
/// The caller provides an already configured pool and bounded budget. This does not
/// connect until called, install a root, determine current versions or authorize.
/// On ordinary errors an explicit rollback is attempted. On cancellation or the
/// deadline, dropping the detached connection ends the transaction server-side;
/// no partial rows are returned. Metadata and DDL concurrency are not a coverage
/// or schema-stability proof and require separate adoption controls.
pub async fn capture_unverified_candidate_rows(
    pool: &MySqlPool,
    budget: CaptureBudget,
) -> Result<UnverifiedCandidateRows, CandidateCaptureError> {
    let meter = Meter::new(budget)?;
    tokio::time::timeout(DEADLINE, capture_inner(pool, meter))
        .await
        .map_err(|_| CandidateCaptureError::Deadline)?
}

// memory—v1: Isolate transaction settings from the pool and roll back on read failure.
async fn capture_inner(
    pool: &MySqlPool,
    meter: Meter,
) -> Result<UnverifiedCandidateRows, CandidateCaptureError> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(|e| db_error("acquire", e))?
        .detach();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut connection)
        .await
        .map_err(|e| db_error("set isolation", e))?;
    let mut tx = connection
        .begin_with("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
        .await
        .map_err(|e| db_error("begin snapshot", e))?;
    match read_rows(&mut tx, meter).await {
        Ok(rows) => {
            tx.commit()
                .await
                .map_err(|e| db_error("finish snapshot", e))?;
            Ok(rows)
        }
        Err(capture) => match tx.rollback().await {
            Ok(()) => Err(capture),
            Err(rollback) => Err(CandidateCaptureError::Rollback {
                capture: Box::new(capture),
                rollback,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // memory—v1: Budgets cover all rows and bytes and fail at the first excess.
    fn aggregate_budget_rejects_overflow() {
        assert!(matches!(
            Meter::new(CaptureBudget {
                max_rows: 0,
                max_bytes: 1
            }),
            Err(CandidateCaptureError::InvalidBudget)
        ));
        assert!(matches!(
            Meter::new(CaptureBudget {
                max_rows: MAX_ROWS + 1,
                max_bytes: 1
            }),
            Err(CandidateCaptureError::InvalidBudget)
        ));
        let mut meter = Meter::new(CaptureBudget {
            max_rows: 1,
            max_bytes: 3,
        })
        .unwrap();
        assert_eq!(meter.sentinel(), 4);
        meter.row().unwrap();
        meter.bytes(3).unwrap();
        assert_eq!(meter.sentinel(), 1);
        assert!(matches!(
            meter.bytes(1),
            Err(CandidateCaptureError::BudgetExceeded("byte"))
        ));
        assert!(matches!(
            meter.row(),
            Err(CandidateCaptureError::BudgetExceeded("row"))
        ));
    }

    #[test]
    // memory—v1: Every captured table uses fixed bounded queries and no inferred version.
    fn table_queries_cover_candidate_schema() {
        assert_eq!(TABLES.len(), 9);
        for table in TABLES {
            assert!(table.sql.contains("LIMIT 1 OFFSET ?"));
            assert!(!table.sql.to_ascii_uppercase().contains("MAX("));
            assert_eq!(table.sql.matches('?').count(), table.variable_fields + 1);
        }
    }
}
