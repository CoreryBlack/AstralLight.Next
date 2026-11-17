//! Isolated, unverified MySQL row capture for the memory-v1 nine-table candidate.
//!
//! This is not an authorization reader or an installer. The returned rows do not
//! prove current versions, complete facts, valid confirmations, hashes, freshness,
//! or readiness. Callers may use `CandidateRows::build_candidate` with their own
//! explicit selections; neither that validation nor this capture grants authority.
//!
//! The capture report does carry the measurements an experimental adoption can
//! check (`CandidateCaptureReport::cold_load_facts`): the validated schema
//! identity and, per table, both the rows an ordered scan reached the end of and a
//! `COUNT(*)` read inside the same snapshot transaction. The adoption verifier
//! compares those against the rows the root actually holds; this module proves
//! nothing by itself.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::memory_v1_schema::{
    candidate_schema_diagnostic, validate_candidate_schema, validate_candidate_schema_constraints,
    CandidateSchemaConstraintError, CandidateSchemaConstraintObservation,
    CandidateSchemaDiagnostic, CandidateSchemaObservation, ObservedColumn, ObservedGeneratedColumn,
    ObservedIndex, ObservedTable, BINDING_GENERATED_METADATA_LIMIT, BINDING_INDEX_METADATA_LIMIT,
    BINDING_TABLE, CANDIDATE_COLUMN_METADATA_LIMIT, CANDIDATE_TABLE_METADATA_LIMIT,
    MAX_GENERATION_EXPRESSION_BYTES,
};
use astral_authorization_root::memory_v1_adoption::ColdLoadFacts;
use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, IdentityCardRow,
    RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus, RuleSetVersionRow, TableCounts,
    TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
use sqlx::{mysql::MySqlRow, Connection, MySql, MySqlPool, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

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

/// Correlation identifier for one candidate capture attempt. It is diagnostic
/// only and is not a MySQL snapshot identity or authorization proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CaptureAttemptId(Uuid);

impl CaptureAttemptId {
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// A table scan reached the end of its ordered query in one capture attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableScanReport {
    pub table: &'static str,
    /// Rows the ordered scan returned before it reached the end of the table.
    pub rows: usize,
    /// `COUNT(*)` of the table, read in the same snapshot transaction as the scan.
    pub snapshot_rows: u64,
}

/// Capture coverage is deliberately unknown until a future complete verifier
/// proves the full authorization fact inventory and all writer boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateCaptureCoverage {
    Unknown,
}

/// Diagnostic report attached to one successful unverified capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCaptureReport {
    pub attempt_id: CaptureAttemptId,
    pub schema: CandidateSchemaObservation,
    pub scans: Vec<TableScanReport>,
    pub coverage: CandidateCaptureCoverage,
    /// Host-clock time at which the snapshot read began, in Unix seconds. The host
    /// clock is not an independent time source.
    pub captured_at_unix_seconds: i64,
}

impl CandidateCaptureReport {
    pub const fn is_adoption_ready(&self) -> bool {
        false
    }

    /// memory—v1: The adapter-side facts of this capture, for an experimental
    /// adoption.
    ///
    /// Returns `None` unless every candidate table was scanned exactly once and
    /// every count fits the platform; nothing is inferred for a missing table.
    /// The result attests only what this adapter observed. The root re-derives
    /// coverage from the rows it holds and treats these values as claims to check.
    pub fn cold_load_facts(&self) -> Option<ColdLoadFacts> {
        let (scanned_counts, snapshot_counts) = scan_counts(&self.scans)?;
        Some(ColdLoadFacts {
            schema_contract_version: self.schema.contract_version,
            schema_fingerprint: self.schema.fingerprint.as_bytes(),
            snapshot_counts,
            scanned_counts,
            captured_at_unix_seconds: self.captured_at_unix_seconds,
        })
    }
}

// memory—v1: Map per-table scan reports to the root's table counts. Both views must
// cover each of the nine tables exactly once, or no counts are produced.
fn scan_counts(scans: &[TableScanReport]) -> Option<(TableCounts, TableCounts)> {
    let mut scanned = TableCounts::default();
    let mut counted = TableCounts::default();
    let mut seen = [false; 9];
    for scan in scans {
        let scan_rows = scan.rows;
        let snapshot_rows = usize::try_from(scan.snapshot_rows).ok()?;
        let (index, scanned_slot, counted_slot) = match scan.table {
            "memory_user" => (0, &mut scanned.users, &mut counted.users),
            "memory_identity_card" => (1, &mut scanned.identity_cards, &mut counted.identity_cards),
            "memory_tenant" => (2, &mut scanned.tenants, &mut counted.tenants),
            "memory_user_card" => (3, &mut scanned.user_cards, &mut counted.user_cards),
            "memory_rule_set" => (4, &mut scanned.rule_sets, &mut counted.rule_sets),
            "memory_rule_set_version" => (
                5,
                &mut scanned.rule_set_versions,
                &mut counted.rule_set_versions,
            ),
            "memory_card_rule_set_binding" => (6, &mut scanned.bindings, &mut counted.bindings),
            "memory_binding_confirmation" => (
                7,
                &mut scanned.binding_confirmations,
                &mut counted.binding_confirmations,
            ),
            "memory_rule_set_change_confirmation" => (
                8,
                &mut scanned.rule_set_change_confirmations,
                &mut counted.rule_set_change_confirmations,
            ),
            _ => return None,
        };
        if std::mem::replace(&mut seen[index], true) {
            return None;
        }
        *scanned_slot = scan_rows;
        *counted_slot = snapshot_rows;
    }
    seen.iter().all(|seen| *seen).then_some((scanned, counted))
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
    /// Diagnostic capture report; this never establishes serving readiness.
    pub report: Option<CandidateCaptureReport>,
}

/// Diagnostic capture with the schema constraint observation from the same
/// transaction. This value is not evidence of database provenance, concurrent
/// DDL stability, or live constraint enforcement.
#[derive(Debug)]
pub struct CandidateCaptureWithSchemaDiagnostic {
    pub capture: UnverifiedCandidateRows,
    pub schema_diagnostic: CandidateSchemaDiagnostic,
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
    #[error("candidate schema prerequisite failed: {0}")]
    Schema(&'static str),
    /// The full manifest comparison failed without exposing raw metadata values.
    #[error("memory-v1 candidate schema contract failed: {0}")]
    SchemaContract(String),
    /// A field has an invalid value or an unsupported byte length.
    #[error("invalid candidate field: {0}")]
    InvalidField(&'static str),
    /// The ordered scan and the same-snapshot `COUNT(*)` disagree for one table.
    #[error("candidate table {table} scanned {scanned} rows but the snapshot counted {counted}")]
    CountMismatch {
        /// Candidate table whose two views disagree.
        table: &'static str,
        /// Rows returned by the ordered scan.
        scanned: usize,
        /// `COUNT(*)` of the same table in the same transaction.
        counted: i64,
    },
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

// memory—v1 §4.4: read an optional trusted-seconds binding window bound.
fn optional_window_bound(
    row: &MySqlRow,
    name: &'static str,
    meter: &mut Meter,
) -> Result<Option<i64>, CandidateCaptureError> {
    let value: Option<i64> = row.try_get(name).map_err(|e| db_error(name, e))?;
    if value.is_some() {
        meter.bytes(8)?;
    }
    Ok(value)
}

// memory—v1 §4.12 B-2.2: read an optional removal operator ID.
fn optional_binary_id(
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

// memory—v1 §4.12 B-2.3: parse user-card lifecycle status; NULL is invalid.
fn decode_user_card_status(
    value: Option<Vec<u8>>,
    meter: &mut Meter,
) -> Result<UserCardStatus, CandidateCaptureError> {
    let value = value.ok_or(CandidateCaptureError::InvalidField("status"))?;
    meter.bytes(value.len())?;
    match value.as_slice() {
        b"ACTIVE" => Ok(UserCardStatus::Active),
        b"DISABLED" => Ok(UserCardStatus::Disabled),
        _ => Err(CandidateCaptureError::InvalidField("status")),
    }
}

// memory—v1: Decode the required lifecycle status from a database row.
fn user_card_status(
    row: &MySqlRow,
    meter: &mut Meter,
) -> Result<UserCardStatus, CandidateCaptureError> {
    let value: Option<Vec<u8>> = row.try_get("status").map_err(|e| db_error("status", e))?;
    decode_user_card_status(value, meter)
}

// memory—v1 §4.12 B-2.5: only exact rule-set lifecycle bytes are accepted.
fn decode_rule_set_status(
    value: Option<Vec<u8>>,
    meter: &mut Meter,
) -> Result<RuleSetStatus, CandidateCaptureError> {
    let value = value.ok_or(CandidateCaptureError::InvalidField("status"))?;
    meter.bytes(value.len())?;
    match value.as_slice() {
        b"ACTIVE" => Ok(RuleSetStatus::Active),
        b"RETIRED" => Ok(RuleSetStatus::Retired),
        _ => Err(CandidateCaptureError::InvalidField("status")),
    }
}

// memory—v1: Capture the status without defaulting missing or malformed data.
fn rule_set_status(
    row: &MySqlRow,
    meter: &mut Meter,
) -> Result<RuleSetStatus, CandidateCaptureError> {
    let value: Option<Vec<u8>> = row.try_get("status").map_err(|e| db_error("status", e))?;
    decode_rule_set_status(value, meter)
}

// memory—v1 §4.10: absent owner scope defaults to the strictest `self`;
// unsupported scope bytes are rejected, never widened.
fn owner_scope(
    row: &MySqlRow,
    meter: &mut Meter,
) -> Result<MemoryV1OwnerScope, CandidateCaptureError> {
    let value: Option<Vec<u8>> = row
        .try_get("owner_scope")
        .map_err(|e| db_error("owner_scope", e))?;
    let Some(value) = value else {
        return Ok(MemoryV1OwnerScope::SelfUser);
    };
    meter.bytes(value.len())?;
    match value.as_slice() {
        b"SELF" => Ok(MemoryV1OwnerScope::SelfUser),
        b"ALL" => Ok(MemoryV1OwnerScope::AllUsers),
        _ => Err(CandidateCaptureError::InvalidField("owner_scope")),
    }
}

// memory—v1 §4.10: absent tenant scope defaults to the strictest `self`.
fn tenant_scope(
    row: &MySqlRow,
    meter: &mut Meter,
) -> Result<MemoryV1TenantScope, CandidateCaptureError> {
    let value: Option<Vec<u8>> = row
        .try_get("tenant_scope")
        .map_err(|e| db_error("tenant_scope", e))?;
    let Some(value) = value else {
        return Ok(MemoryV1TenantScope::SelfTenant);
    };
    meter.bytes(value.len())?;
    match value.as_slice() {
        b"SELF" => Ok(MemoryV1TenantScope::SelfTenant),
        b"SELF_AND_DESCENDANTS" => Ok(MemoryV1TenantScope::SelfAndDescendants),
        _ => Err(CandidateCaptureError::InvalidField("tenant_scope")),
    }
}

// Fixed queries use server-side byte caps and fetch at most one row at a time.
// OFFSET is bounded by MAX_ROWS and the whole capture has a deadline. Ordering
// uses the original key columns, but uniqueness is not yet verified; a completed
// scan therefore remains diagnostic and does not prove coverage.
struct TableSpec {
    name: &'static str,
    sql: &'static str,
    variable_fields: usize,
}

const TABLES: &[TableSpec] = &[
    TableSpec { name: "memory_user", sql: "SELECT LEFT(user_id,17) AS user_id FROM memory_user ORDER BY user_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_identity_card", sql: "SELECT LEFT(identity_card_id,17) AS identity_card_id, LEFT(user_id,17) AS user_id FROM memory_identity_card ORDER BY identity_card_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_tenant", sql: "SELECT LEFT(tenant_id,17) AS tenant_id, LEFT(parent_tenant_id,17) AS parent_tenant_id FROM memory_tenant ORDER BY tenant_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_user_card", sql: "SELECT LEFT(user_card_id,17) AS user_card_id, LEFT(user_id,17) AS user_id, LEFT(tenant_id,17) AS tenant_id, LEFT(CAST(status AS BINARY),16) AS status FROM memory_user_card ORDER BY user_card_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_rule_set", sql: "SELECT LEFT(rule_set_id,17) AS rule_set_id, LEFT(owner_tenant_id,17) AS owner_tenant_id, LEFT(current_version_bytes,?) AS current_version_bytes, LEFT(CAST(status AS BINARY),17) AS status FROM memory_rule_set ORDER BY rule_set_id LIMIT 1 OFFSET ?", variable_fields: 1 },
    TableSpec { name: "memory_rule_set_version", sql: "SELECT LEFT(rule_set_id,17) AS rule_set_id, LEFT(version_bytes,?) AS version_bytes, LEFT(content_bytes,?) AS content_bytes, LEFT(timestamp_bytes,?) AS timestamp_bytes, LEFT(hash_input_bytes,?) AS hash_input_bytes, LEFT(hash_bytes,?) AS hash_bytes FROM memory_rule_set_version ORDER BY memory_rule_set_version.rule_set_id, memory_rule_set_version.version_bytes LIMIT 1 OFFSET ?", variable_fields: 5 },
    TableSpec { name: "memory_card_rule_set_binding", sql: "SELECT LEFT(binding_id,17) AS binding_id, LEFT(user_card_id,17) AS user_card_id, LEFT(rule_set_id,17) AS rule_set_id, LEFT(CAST(binding_layer AS BINARY),8) AS binding_layer, valid_from, valid_until, LEFT(CAST(owner_scope AS BINARY),32) AS owner_scope, LEFT(CAST(tenant_scope AS BINARY),32) AS tenant_scope, removed_at, LEFT(removed_by,17) AS removed_by FROM memory_card_rule_set_binding ORDER BY binding_id LIMIT 1 OFFSET ?", variable_fields: 0 },
    TableSpec { name: "memory_binding_confirmation", sql: "SELECT LEFT(confirmation_id,17) AS confirmation_id, LEFT(binding_id,17) AS binding_id, LEFT(rule_set_id,17) AS rule_set_id, LEFT(version_bytes,?) AS version_bytes, LEFT(confirmer_user_id,17) AS confirmer_user_id, LEFT(scope_bytes,?) AS scope_bytes, LEFT(operation_id,?) AS operation_id, LEFT(confirmed_at_bytes,?) AS confirmed_at_bytes, revoked_at, LEFT(revoked_by,17) AS revoked_by FROM memory_binding_confirmation ORDER BY confirmation_id LIMIT 1 OFFSET ?", variable_fields: 4 },
    TableSpec { name: "memory_rule_set_change_confirmation", sql: "SELECT LEFT(confirmation_id,17) AS confirmation_id, LEFT(rule_set_id,17) AS rule_set_id, LEFT(version_bytes,?) AS version_bytes, LEFT(confirmer_user_id,17) AS confirmer_user_id, LEFT(affected_scope_bytes,?) AS affected_scope_bytes, LEFT(operation_id,?) AS operation_id, LEFT(confirmed_at_bytes,?) AS confirmed_at_bytes, revoked_at, LEFT(revoked_by,17) AS revoked_by FROM memory_rule_set_change_confirmation ORDER BY confirmation_id LIMIT 1 OFFSET ?", variable_fields: 4 },
];

// memory—v1: Fixed metadata queries fetch one extra row as an overflow sentinel.
// `CHARACTER_MAXIMUM_LENGTH` is signed `BIGINT` on MySQL 8 and `BIGINT UNSIGNED` on
// 5.7; the explicit cast pins one type so the decode cannot depend on the server
// version (found by the first run against a real MySQL 8.0 server).
const TABLE_METADATA_SQL: &str =
    "SELECT CAST(TABLE_NAME AS BINARY) AS table_name, CAST(TABLE_TYPE AS BINARY) AS table_type, CAST(ENGINE AS BINARY) AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'memory\\_%' ESCAPE '\\\\' ORDER BY TABLE_NAME LIMIT ?";
const COLUMN_METADATA_SQL: &str =
    "SELECT CAST(TABLE_NAME AS BINARY) AS table_name, CAST(COLUMN_NAME AS BINARY) AS column_name, CAST(DATA_TYPE AS BINARY) AS data_type, CAST(CHARACTER_MAXIMUM_LENGTH AS UNSIGNED) AS max_length, CAST(IS_NULLABLE AS BINARY) AS is_nullable, CAST(CHARACTER_SET_NAME AS BINARY) AS character_set, CAST(COLLATION_NAME AS BINARY) AS collation FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE 'memory\\_%' ESCAPE '\\\\' ORDER BY TABLE_NAME, ORDINAL_POSITION LIMIT ?";

// memory—v1: Index and generated-column metadata are read from fixed,
// parameterized information_schema statements. The binding table name is a
// parameter, never interpolated. The bounded LIMIT fetches one sentinel row so
// a metadata explosion cannot be mistaken for a complete observation.
const CONSTRAINT_INDEX_METADATA_SQL: &str =
    "SELECT CAST(TABLE_NAME AS BINARY) AS table_name, CAST(INDEX_NAME AS BINARY) AS index_name, CAST(NON_UNIQUE AS SIGNED) AS non_unique, CAST(SEQ_IN_INDEX AS UNSIGNED) AS sequence, CAST(COLUMN_NAME AS BINARY) AS column_name, CAST(SUB_PART AS UNSIGNED) AS sub_part, CAST(EXPRESSION AS BINARY) AS expression, CAST(INDEX_TYPE AS BINARY) AS index_type, CAST(IS_VISIBLE AS BINARY) AS is_visible FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX LIMIT ?";

const GENERATED_COLUMN_METADATA_SQL: &str =
    "SELECT CAST(TABLE_NAME AS BINARY) AS table_name, CAST(COLUMN_NAME AS BINARY) AS column_name, CAST(EXTRA AS BINARY) AS extra, LEFT(CAST(GENERATION_EXPRESSION AS BINARY), 4097) AS generation_expression FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION LIMIT ?";

/// memory—v1: Read the independent physical constraint observation for the candidate.
///
/// The capture path requires this structural observation before scanning rows. The
/// generated expression is accepted only when the pure closed parser matches the
/// frozen contract; the observation is still not promoted to complete schema or
/// production-adoption evidence. It does not prove live MySQL evaluation,
/// collation, SQL mode, or metadata provenance.
pub async fn observe_candidate_schema_constraints(
    tx: &mut Transaction<'_, MySql>,
) -> Result<CandidateSchemaConstraintObservation, CandidateCaptureError> {
    let (indexes, generated_columns) = read_candidate_schema_constraints(tx).await?;
    validate_candidate_schema_constraints(&indexes, &generated_columns)
        .map_err(|error| CandidateCaptureError::SchemaContract(error.to_string()))
}

// memory—v1: Keep raw metadata together until validation and diagnostic binding.
async fn read_candidate_schema_constraints(
    tx: &mut Transaction<'_, MySql>,
) -> Result<(Vec<ObservedIndex>, Vec<ObservedGeneratedColumn>), CandidateCaptureError> {
    let index_rows = sqlx::query(CONSTRAINT_INDEX_METADATA_SQL)
        .bind(BINDING_TABLE)
        .bind(BINDING_INDEX_METADATA_LIMIT + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| db_error("candidate constraint index metadata", error))?;
    check_metadata_count(index_rows.len(), BINDING_INDEX_METADATA_LIMIT, "index")?;
    let indexes = index_rows
        .iter()
        .map(|row| {
            Ok(ObservedIndex {
                table: metadata_text(row, "table_name", "candidate index table")?,
                name: metadata_text(row, "index_name", "candidate index name")?,
                non_unique: row
                    .try_get("non_unique")
                    .map_err(|error| db_error("candidate index uniqueness", error))?,
                sequence: row
                    .try_get("sequence")
                    .map_err(|error| db_error("candidate index sequence", error))?,
                column_name: metadata_optional_text(row, "column_name", "candidate index column")?,
                sub_part: row
                    .try_get("sub_part")
                    .map_err(|error| db_error("candidate index prefix", error))?,
                expression: metadata_optional_text(
                    row,
                    "expression",
                    "candidate index expression",
                )?,
                index_type: metadata_text(row, "index_type", "candidate index type")?,
                is_visible: match metadata_text(row, "is_visible", "candidate index visibility")?
                    .as_str()
                {
                    "YES" => true,
                    "NO" => false,
                    _ => {
                        return Err(CandidateCaptureError::SchemaContract(
                            "unknown candidate index visibility".to_owned(),
                        ))
                    }
                },
            })
        })
        .collect::<Result<Vec<_>, CandidateCaptureError>>()?;

    let generated_rows = sqlx::query(GENERATED_COLUMN_METADATA_SQL)
        .bind(BINDING_TABLE)
        .bind(BINDING_GENERATED_METADATA_LIMIT + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| db_error("candidate generated-column metadata", error))?;
    check_metadata_count(
        generated_rows.len(),
        BINDING_GENERATED_METADATA_LIMIT,
        "generated column",
    )?;
    let generated_columns = generated_rows
        .iter()
        .map(|row| {
            let generation_expression = metadata_optional_text(
                row,
                "generation_expression",
                "candidate generation expression",
            )?;
            if generation_expression
                .as_ref()
                .is_some_and(|expression| expression.len() > MAX_GENERATION_EXPRESSION_BYTES)
            {
                return Err(CandidateCaptureError::SchemaContract(
                    "candidate generation expression exceeds its byte limit".to_owned(),
                ));
            }
            Ok(ObservedGeneratedColumn {
                table: metadata_text(row, "table_name", "candidate generated-column table")?,
                column: metadata_text(row, "column_name", "candidate generated-column name")?,
                extra: metadata_text(row, "extra", "candidate generated-column storage")?,
                generation_expression,
            })
        })
        .collect::<Result<Vec<_>, CandidateCaptureError>>()?;

    Ok((indexes, generated_columns))
}

// memory—v1: Refuse truncated metadata before constructing an observation.
fn check_metadata_count(
    count: usize,
    limit: i64,
    kind: &'static str,
) -> Result<(), CandidateCaptureError> {
    if count > limit as usize {
        return Err(CandidateCaptureError::SchemaContract(
            CandidateSchemaConstraintError::MetadataLimitExceeded { kind }.to_string(),
        ));
    }
    Ok(())
}

// memory—v1: Read the bounded candidate metadata set in the same transaction.
async fn check_schema(
    tx: &mut Transaction<'_, MySql>,
) -> Result<CandidateSchemaObservation, CandidateCaptureError> {
    let table_rows = sqlx::query(TABLE_METADATA_SQL)
        .bind(CANDIDATE_TABLE_METADATA_LIMIT + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| db_error("candidate table metadata", error))?;
    check_metadata_count(table_rows.len(), CANDIDATE_TABLE_METADATA_LIMIT, "table")?;
    let mut tables = BTreeMap::new();
    for row in table_rows {
        let name = metadata_text(&row, "table_name", "candidate table name")?;
        let table_type = metadata_text(&row, "table_type", "candidate table type")?;
        let engine = metadata_optional_text(&row, "engine", "candidate table engine")?;
        if tables.insert(name.clone(), (table_type, engine)).is_some() {
            return Err(CandidateCaptureError::SchemaContract(format!(
                "duplicate table metadata for {name}"
            )));
        }
    }

    let column_rows = sqlx::query(COLUMN_METADATA_SQL)
        .bind(CANDIDATE_COLUMN_METADATA_LIMIT + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| db_error("candidate column metadata", error))?;
    check_metadata_count(column_rows.len(), CANDIDATE_COLUMN_METADATA_LIMIT, "column")?;
    let mut columns: BTreeMap<String, Vec<ObservedColumn>> = BTreeMap::new();
    for row in column_rows {
        let table = metadata_text(&row, "table_name", "candidate column table")?;
        let column = ObservedColumn {
            name: metadata_text(&row, "column_name", "candidate column name")?,
            data_type: metadata_text(&row, "data_type", "candidate column type")?,
            max_length: row
                .try_get::<Option<u64>, _>("max_length")
                .map_err(|error| db_error("candidate column length", error))?,
            nullable: match metadata_text(&row, "is_nullable", "candidate column nullability")?
                .as_str()
            {
                "NO" => false,
                "YES" => true,
                _ => {
                    return Err(CandidateCaptureError::SchemaContract(
                        "unknown column nullability".to_owned(),
                    ))
                }
            },
            character_set: metadata_optional_text(
                &row,
                "character_set",
                "candidate column charset",
            )?,
            collation: metadata_optional_text(&row, "collation", "candidate column collation")?,
        };
        columns.entry(table).or_default().push(column);
    }

    let observed = tables
        .into_iter()
        .map(|(name, (table_type, engine))| ObservedTable {
            name: name.clone(),
            table_type,
            engine,
            columns: columns.remove(&name).unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    if !columns.is_empty() {
        return Err(CandidateCaptureError::SchemaContract(
            "column metadata references an unlisted table".to_owned(),
        ));
    }
    validate_candidate_schema(&observed)
        .map_err(|error| CandidateCaptureError::SchemaContract(error.to_string()))
}

fn metadata_text(
    row: &sqlx::mysql::MySqlRow,
    name: &'static str,
    context: &'static str,
) -> Result<String, CandidateCaptureError> {
    let bytes: Vec<u8> = row
        .try_get(name)
        .map_err(|error| db_error(context, error))?;
    String::from_utf8(bytes).map_err(|_| CandidateCaptureError::SchemaContract(context.to_owned()))
}

fn metadata_optional_text(
    row: &sqlx::mysql::MySqlRow,
    name: &'static str,
    context: &'static str,
) -> Result<Option<String>, CandidateCaptureError> {
    let bytes: Option<Vec<u8>> = row
        .try_get(name)
        .map_err(|error| db_error(context, error))?;
    bytes
        .map(|value| {
            String::from_utf8(value)
                .map_err(|_| CandidateCaptureError::SchemaContract(context.to_owned()))
        })
        .transpose()
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
            status: user_card_status(row, meter)?,
        }),
        "memory_rule_set" => out.rule_sets.push(RuleSetRow {
            rule_set_id: binary_id(row, "rule_set_id", meter)?,
            owner_tenant_id: binary_id(row, "owner_tenant_id", meter)?,
            current_version_bytes: bytes(row, "current_version_bytes", meter)?,
            status: rule_set_status(row, meter)?,
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
            valid_from: optional_window_bound(row, "valid_from", meter)?,
            valid_until: optional_window_bound(row, "valid_until", meter)?,
            owner_scope: owner_scope(row, meter)?,
            tenant_scope: tenant_scope(row, meter)?,
            removed_at: optional_window_bound(row, "removed_at", meter)?,
            removed_by: optional_binary_id(row, "removed_by", meter)?,
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
            revoked_at: optional_window_bound(row, "revoked_at", meter)?,
            revoked_by: optional_binary_id(row, "revoked_by", meter)?,
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
                    revoked_at: optional_window_bound(row, "revoked_at", meter)?,
                    revoked_by: optional_binary_id(row, "revoked_by", meter)?,
                })
        }
        _ => return Err(CandidateCaptureError::Schema("unknown table")),
    }
    Ok(())
}

// memory—v1: Fixed count statements, one per candidate table, so no SQL is assembled
// from a name at run time. `CAST ... AS SIGNED` pins the column to a signed BIGINT.
fn count_sql(table: &str) -> Option<&'static str> {
    Some(match table {
        "memory_user" => "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_user",
        "memory_identity_card" => "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_identity_card",
        "memory_tenant" => "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_tenant",
        "memory_user_card" => "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_user_card",
        "memory_rule_set" => "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_rule_set",
        "memory_rule_set_version" => {
            "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_rule_set_version"
        }
        "memory_card_rule_set_binding" => {
            "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_card_rule_set_binding"
        }
        "memory_binding_confirmation" => {
            "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_binding_confirmation"
        }
        "memory_rule_set_change_confirmation" => {
            "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_rule_set_change_confirmation"
        }
        _ => return None,
    })
}

// memory—v1: Read the host clock once per capture; a clock before the epoch is refused.
fn host_unix_seconds() -> Result<i64, CandidateCaptureError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CandidateCaptureError::InvalidField("host clock"))?;
    i64::try_from(elapsed.as_secs()).map_err(|_| CandidateCaptureError::InvalidField("host clock"))
}

// memory—v1: Read all nine tables without returning a partial or truncated capture.
async fn read_rows(
    tx: &mut Transaction<'_, MySql>,
    mut meter: Meter,
) -> Result<CandidateCaptureWithSchemaDiagnostic, CandidateCaptureError> {
    let captured_at_unix_seconds = host_unix_seconds()?;
    let schema = check_schema(tx).await?;
    // memory—v1: Validate before scanning and retain a diagnostic for every
    // checked index and generated expression; this is not live MySQL proof.
    let (indexes, generated_columns) = read_candidate_schema_constraints(tx).await?;
    let schema_diagnostic = candidate_schema_diagnostic(schema, &indexes, &generated_columns)
        .map_err(|error| CandidateCaptureError::SchemaContract(error.to_string()))?;
    let mut out = CandidateRows::default();
    let mut scans = Vec::with_capacity(TABLES.len());
    for table in TABLES {
        let mut offset = 0_i64;
        let mut table_rows = 0_usize;
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
            table_rows = table_rows
                .checked_add(1)
                .ok_or(CandidateCaptureError::BudgetExceeded("table row"))?;
            append(table.name, &row, &mut meter, &mut out)?;
            offset += 1;
        }
        // The count is read after the scan inside the same REPEATABLE READ snapshot,
        // so it is an independent view of the same rows, not a later state.
        let counted = count_rows(tx, table.name).await?;
        if u64::try_from(counted).ok() != u64::try_from(table_rows).ok() {
            return Err(CandidateCaptureError::CountMismatch {
                table: table.name,
                scanned: table_rows,
                counted,
            });
        }
        scans.push(TableScanReport {
            table: table.name,
            rows: table_rows,
            snapshot_rows: u64::try_from(counted)
                .map_err(|_| CandidateCaptureError::InvalidField("snapshot count"))?,
        });
    }
    Ok(CandidateCaptureWithSchemaDiagnostic {
        capture: UnverifiedCandidateRows {
            rows: out,
            row_count: meter.rows,
            field_bytes: meter.bytes,
            report: Some(CandidateCaptureReport {
                attempt_id: CaptureAttemptId(Uuid::new_v4()),
                schema,
                scans,
                coverage: CandidateCaptureCoverage::Unknown,
                captured_at_unix_seconds,
            }),
        },
        schema_diagnostic,
    })
}

// memory—v1: `COUNT(*)` of one candidate table inside the open snapshot transaction.
async fn count_rows(
    tx: &mut Transaction<'_, MySql>,
    table: &'static str,
) -> Result<i64, CandidateCaptureError> {
    let sql = count_sql(table).ok_or(CandidateCaptureError::Schema("unknown table"))?;
    let row = sqlx::query(sql)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| db_error(table, e))?;
    row.try_get::<i64, _>("n").map_err(|e| db_error(table, e))
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
    capture_unverified_candidate_rows_with_schema_diagnostic(pool, budget)
        .await
        .map(|result| result.capture)
}

/// memory—v1: Capture candidate rows with a separate versioned schema
/// diagnostic. The legacy capture and cold-load facts keep their original shape.
pub async fn capture_unverified_candidate_rows_with_schema_diagnostic(
    pool: &MySqlPool,
    budget: CaptureBudget,
) -> Result<CandidateCaptureWithSchemaDiagnostic, CandidateCaptureError> {
    let meter = Meter::new(budget)?;
    tokio::time::timeout(DEADLINE, capture_inner(pool, meter))
        .await
        .map_err(|_| CandidateCaptureError::Deadline)?
}

// memory—v1: Isolate transaction settings from the pool and roll back on read failure.
async fn capture_inner(
    pool: &MySqlPool,
    meter: Meter,
) -> Result<CandidateCaptureWithSchemaDiagnostic, CandidateCaptureError> {
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
    // memory—v1: The capped projection must not become the pagination sort key.
    fn version_scan_orders_by_untruncated_source_columns() {
        let query = TABLES
            .iter()
            .find(|table| table.name == "memory_rule_set_version")
            .unwrap()
            .sql;
        assert!(query.contains(
            "ORDER BY memory_rule_set_version.rule_set_id, memory_rule_set_version.version_bytes"
        ));
    }

    #[test]
    // memory—v1: Metadata queries fetch one sentinel row and refuse excess
    // before decoding, so no truncated manifest can be mistaken for a match.
    fn schema_metadata_queries_are_bounded_and_reject_the_sentinel() {
        for sql in [TABLE_METADATA_SQL, COLUMN_METADATA_SQL] {
            assert!(sql.contains("TABLE_SCHEMA = DATABASE()"));
            assert!(sql.contains("TABLE_NAME LIKE 'memory\\_%'"));
            assert!(sql.ends_with("LIMIT ?"));
            assert_eq!(sql.matches('?').count(), 1);
        }
        for (limit, kind) in [
            (CANDIDATE_TABLE_METADATA_LIMIT, "table"),
            (CANDIDATE_COLUMN_METADATA_LIMIT, "column"),
            (BINDING_INDEX_METADATA_LIMIT, "index"),
            (BINDING_GENERATED_METADATA_LIMIT, "generated column"),
        ] {
            assert!(check_metadata_count(limit as usize, limit, kind).is_ok());
            assert!(matches!(
                check_metadata_count(limit as usize + 1, limit, kind),
                Err(CandidateCaptureError::SchemaContract(message))
                    if message == CandidateSchemaConstraintError::MetadataLimitExceeded { kind }.to_string()
            ));
        }
    }

    #[test]
    // memory—v1: Metadata integers are cast so their decode does not depend on the server.
    fn column_metadata_pins_the_length_type() {
        assert!(COLUMN_METADATA_SQL
            .contains("CAST(CHARACTER_MAXIMUM_LENGTH AS UNSIGNED) AS max_length"));
        assert!(!COLUMN_METADATA_SQL.contains(", CHARACTER_MAXIMUM_LENGTH AS"));
        assert!(COLUMN_METADATA_SQL.contains("TABLE_SCHEMA = DATABASE()"));
    }

    #[test]
    // memory—v1: Constraint metadata is read with fixed information_schema SQL;
    // identifiers are bound rather than interpolated.
    fn constraint_metadata_queries_are_fixed_and_parameterized() {
        assert!(CONSTRAINT_INDEX_METADATA_SQL.contains("information_schema.STATISTICS"));
        assert!(CONSTRAINT_INDEX_METADATA_SQL.contains("TABLE_SCHEMA = DATABASE()"));
        assert!(CONSTRAINT_INDEX_METADATA_SQL.contains("TABLE_NAME = ?"));
        assert!(CONSTRAINT_INDEX_METADATA_SQL.contains("LIMIT ?"));
        assert!(!CONSTRAINT_INDEX_METADATA_SQL.contains("INDEX_NAME IN"));
        for field in [
            "NON_UNIQUE",
            "SEQ_IN_INDEX",
            "COLUMN_NAME",
            "SUB_PART",
            "EXPRESSION",
            "INDEX_TYPE",
            "IS_VISIBLE",
        ] {
            assert!(CONSTRAINT_INDEX_METADATA_SQL.contains(field));
        }
        assert_eq!(CONSTRAINT_INDEX_METADATA_SQL.matches('?').count(), 2);
        assert!(GENERATED_COLUMN_METADATA_SQL.contains("information_schema.COLUMNS"));
        assert!(GENERATED_COLUMN_METADATA_SQL.contains("TABLE_SCHEMA = DATABASE()"));
        assert!(GENERATED_COLUMN_METADATA_SQL.contains("TABLE_NAME = ?"));
        assert!(GENERATED_COLUMN_METADATA_SQL.contains("LIMIT ?"));
        assert!(GENERATED_COLUMN_METADATA_SQL.contains(
            "LEFT(CAST(GENERATION_EXPRESSION AS BINARY), 4097) AS generation_expression"
        ));
        assert_eq!(MAX_GENERATION_EXPRESSION_BYTES + 1, 4097);
        assert!(!GENERATED_COLUMN_METADATA_SQL.contains("COLUMN_NAME = ?"));
        for field in ["EXTRA", "GENERATION_EXPRESSION"] {
            assert!(GENERATED_COLUMN_METADATA_SQL.contains(field));
        }
        assert_eq!(GENERATED_COLUMN_METADATA_SQL.matches('?').count(), 2);
        assert!(!CONSTRAINT_INDEX_METADATA_SQL.contains("memory_card_rule_set_binding"));
        assert!(!GENERATED_COLUMN_METADATA_SQL.contains("memory_card_rule_set_binding"));
    }

    #[test]
    // memory—v1: The scan uses the v4 manifest column names and keeps tombstones nullable.
    fn v4_queries_select_pointer_status_and_tombstones() {
        let user_card = TABLES
            .iter()
            .find(|table| table.name == "memory_user_card")
            .unwrap()
            .sql;
        assert!(user_card.contains("CAST(status AS BINARY),16) AS status"));
        assert!(!user_card.contains("COALESCE"));

        let rule_set = TABLES
            .iter()
            .find(|table| table.name == "memory_rule_set")
            .unwrap()
            .sql;
        assert!(rule_set.contains("LEFT(current_version_bytes,?) AS current_version_bytes"));
        assert!(rule_set.contains("LEFT(CAST(status AS BINARY),17) AS status"));
        assert!(!rule_set.contains("COALESCE"));
        assert!(
            rule_set
                .find("LEFT(current_version_bytes,?) AS current_version_bytes")
                .unwrap()
                < rule_set.find("LIMIT 1 OFFSET ?").unwrap()
        );

        let binding = TABLES
            .iter()
            .find(|table| table.name == "memory_card_rule_set_binding")
            .unwrap()
            .sql;
        for field in ["removed_at", "LEFT(removed_by,17) AS removed_by"] {
            assert!(binding.contains(field));
        }
        assert!(!binding.contains("COALESCE"));

        let confirmation = TABLES
            .iter()
            .find(|table| table.name == "memory_binding_confirmation")
            .unwrap()
            .sql;
        for field in ["revoked_at", "LEFT(revoked_by,17) AS revoked_by"] {
            assert!(confirmation.contains(field));
        }
        assert!(!confirmation.contains("COALESCE"));

        let change_confirmation = TABLES
            .iter()
            .find(|table| table.name == "memory_rule_set_change_confirmation")
            .unwrap()
            .sql;
        for field in ["revoked_at", "LEFT(revoked_by,17) AS revoked_by"] {
            assert!(change_confirmation.contains(field));
        }
        assert!(!change_confirmation.contains("COALESCE"));

        let version = TABLES
            .iter()
            .find(|table| table.name == "memory_rule_set_version")
            .unwrap()
            .sql;
        let version_fields = [
            "LEFT(version_bytes,?)",
            "LEFT(content_bytes,?)",
            "LEFT(timestamp_bytes,?)",
            "LEFT(hash_input_bytes,?)",
            "LEFT(hash_bytes,?)",
        ];
        for pair in version_fields.windows(2) {
            assert!(version.find(pair[0]).unwrap() < version.find(pair[1]).unwrap());
        }
        assert!(
            version.find("LEFT(hash_bytes,?)").unwrap() < version.find("LIMIT 1 OFFSET ?").unwrap()
        );

        assert_eq!(
            TABLES
                .iter()
                .find(|table| table.name == "memory_rule_set")
                .unwrap()
                .variable_fields,
            1
        );
        assert_eq!(
            TABLES
                .iter()
                .find(|table| table.name == "memory_rule_set_version")
                .unwrap()
                .variable_fields,
            5
        );
        assert_eq!(
            TABLES
                .iter()
                .find(|table| table.name == "memory_binding_confirmation")
                .unwrap()
                .variable_fields,
            4
        );
        assert_eq!(
            TABLES
                .iter()
                .find(|table| table.name == "memory_rule_set_change_confirmation")
                .unwrap()
                .variable_fields,
            4
        );
    }

    #[test]
    // memory—v1: Rule-set lifecycle decoding is exact and charges the byte budget.
    fn rule_set_status_decode_is_strict_and_budgeted() {
        let mut meter = Meter::new(CaptureBudget {
            max_rows: 1,
            max_bytes: 128,
        })
        .unwrap();
        assert!(matches!(
            decode_rule_set_status(None, &mut meter),
            Err(CandidateCaptureError::InvalidField("status"))
        ));
        assert_eq!(meter.bytes, 0);
        assert_eq!(
            decode_rule_set_status(Some(b"ACTIVE".to_vec()), &mut meter).unwrap(),
            RuleSetStatus::Active
        );
        assert_eq!(
            decode_rule_set_status(Some(b"RETIRED".to_vec()), &mut meter).unwrap(),
            RuleSetStatus::Retired
        );
        assert_eq!(meter.bytes, 13);
        for value in [
            &b""[..],
            &b"UNKNOWN"[..],
            &b"active"[..],
            &b"ACTIVE "[..],
            &b"RETIRED\0"[..],
            &b"ACTIVE01234567890"[..],
        ] {
            assert!(matches!(
                decode_rule_set_status(Some(value.to_vec()), &mut meter),
                Err(CandidateCaptureError::InvalidField("status"))
            ));
        }
        let mut limited = Meter::new(CaptureBudget {
            max_rows: 1,
            max_bytes: 6,
        })
        .unwrap();
        assert!(matches!(
            decode_rule_set_status(Some(b"RETIRED".to_vec()), &mut limited),
            Err(CandidateCaptureError::BudgetExceeded("byte"))
        ));
    }

    #[test]
    // memory—v1 §4.12 B-2.3: a missing or unsupported lifecycle status cannot
    // silently become ACTIVE, and valid values retain their exact meaning.
    fn user_card_status_decode_is_fail_closed_for_null_and_unknown_values() {
        let mut meter = Meter::new(CaptureBudget {
            max_rows: 1,
            max_bytes: 32,
        })
        .unwrap();
        assert!(matches!(
            decode_user_card_status(None, &mut meter),
            Err(CandidateCaptureError::InvalidField("status"))
        ));
        assert_eq!(meter.bytes, 0);
        assert!(matches!(
            decode_user_card_status(Some(b"UNKNOWN".to_vec()), &mut meter),
            Err(CandidateCaptureError::InvalidField("status"))
        ));
        assert_eq!(meter.bytes, 7);
        assert_eq!(
            decode_user_card_status(Some(b"ACTIVE".to_vec()), &mut meter).unwrap(),
            UserCardStatus::Active
        );
        assert_eq!(
            decode_user_card_status(Some(b"DISABLED".to_vec()), &mut meter).unwrap(),
            UserCardStatus::Disabled
        );
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

    #[test]
    // memory—v1: Each table has one fixed, parameter-free count statement naming only itself.
    fn count_statements_are_fixed_and_cover_every_table() {
        for table in TABLES {
            let sql = count_sql(table.name).expect("every captured table has a count statement");
            assert_eq!(
                sql,
                format!("SELECT CAST(COUNT(*) AS SIGNED) AS n FROM {}", table.name)
            );
            assert!(!sql.contains('?'));
        }
        assert_eq!(count_sql("memory_user; DROP TABLE memory_user"), None);
        assert_eq!(count_sql("information_schema.TABLES"), None);
        assert_eq!(count_sql(""), None);
    }

    fn scan(table: &'static str, rows: usize, snapshot_rows: u64) -> TableScanReport {
        TableScanReport {
            table,
            rows,
            snapshot_rows,
        }
    }

    fn all_scans() -> Vec<TableScanReport> {
        TABLES
            .iter()
            .enumerate()
            .map(|(index, table)| scan(table.name, index + 1, (index as u64 + 1) * 10))
            .collect()
    }

    #[test]
    // memory—v1: Scan reports map to the root's table counts, both views kept apart.
    fn scan_counts_maps_every_table_into_its_own_field() {
        let (scanned, counted) = scan_counts(&all_scans()).expect("nine tables once each");
        assert_eq!(
            scanned,
            TableCounts {
                users: 1,
                identity_cards: 2,
                tenants: 3,
                user_cards: 4,
                rule_sets: 5,
                rule_set_versions: 6,
                bindings: 7,
                binding_confirmations: 8,
                rule_set_change_confirmations: 9,
            }
        );
        assert_eq!(
            counted,
            TableCounts {
                users: 10,
                identity_cards: 20,
                tenants: 30,
                user_cards: 40,
                rule_sets: 50,
                rule_set_versions: 60,
                bindings: 70,
                binding_confirmations: 80,
                rule_set_change_confirmations: 90,
            }
        );
        // Order of the reports must not matter.
        let mut reversed = all_scans();
        reversed.reverse();
        assert_eq!(scan_counts(&reversed), Some((scanned, counted)));
    }

    #[test]
    // memory—v1: A missing, duplicated or unknown table yields no facts instead of a guess.
    fn scan_counts_refuses_incomplete_or_ambiguous_reports() {
        let mut missing = all_scans();
        missing.pop();
        assert_eq!(scan_counts(&missing), None);
        assert_eq!(scan_counts(&[]), None);

        let mut duplicated = all_scans();
        duplicated.push(duplicated[0]);
        assert_eq!(scan_counts(&duplicated), None);

        let mut unknown = all_scans();
        unknown[0].table = "memory_unknown";
        assert_eq!(scan_counts(&unknown), None);
    }

    #[test]
    // memory—v1: A count mismatch names the table and both counts, never row contents.
    fn count_mismatch_error_names_the_table_without_row_contents() {
        let error = CandidateCaptureError::CountMismatch {
            table: "memory_user",
            scanned: 3,
            counted: 4,
        };
        let text = error.to_string();
        assert!(text.contains("memory_user"));
        assert!(text.contains('3') && text.contains('4'));
    }
}
