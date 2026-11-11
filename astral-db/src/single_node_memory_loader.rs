//! Read-only, fail-closed MySQL snapshot loader for the single-node root.
//!
//! Membership identities and user status are represented in the root model, but
//! complete publication evidence is still missing. This loader reads and validates
//! source rows but cannot produce a usable root until that evidence is available.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use astral_types::{BindingLayer, GrantEffect, ValidityWindow};
use sqlx::{mysql::MySqlRow, Acquire, FromRow, MySql, MySqlPool, Transaction};
use thiserror::Error;
use time::PrimitiveDateTime;

use crate::certified_memory_authority::{CertifiedSodConflictType, CertifiedSodPolicy};
use crate::single_node_memory_root::{
    SingleNodeCardRuleSetRef, SingleNodeDatabaseSnapshot, SingleNodeDomain, SingleNodeGlobalAdmin,
    SingleNodeIdentityCard, SingleNodeMemoryRoot, SingleNodeOrgMembership,
    SingleNodePermissionRule, SingleNodePublishedPointer, SingleNodeRootVersion, SingleNodeRuleSet,
    SingleNodeRuleSetEntry, SingleNodeTenant, SingleNodeTenantDomain, SingleNodeUser,
    SingleNodeUserCard,
};
use crate::sod_check::{validate_dynamic_sod_condition_script, MAX_DYNAMIC_CONDITION_SCRIPT_BYTES};

// A hard bound applies independently to each table. Never accept a truncated root.
const ROW_CAP: usize = 100_000;
static SNAPSHOT_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

struct SnapshotPermit;

impl SnapshotPermit {
    fn acquire() -> Result<Self, SingleNodeMemoryLoaderError> {
        SNAPSHOT_IN_PROGRESS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                SingleNodeMemoryLoaderError::Pending("snapshot already in progress".into())
            })?;
        Ok(Self)
    }
}

impl Drop for SnapshotPermit {
    fn drop(&mut self) {
        SNAPSHOT_IN_PROGRESS.store(false, Ordering::Release);
    }
}
// Match the durable SoD reader's per-kind cap and aggregate content budget.
const SOD_ROW_CAP: usize = 4096;
const SOD_MAX_BYTES: usize = 4 * 1024 * 1024;
const SOD_PAGE_SIZE: i64 = 128;

// Truncate as binary on the server, before SQLx allocates a TEXT value. The extra
// byte is an overflow sentinel, including when it splits a UTF-8 character.
const SOD_PAGE_SQL: &str = "SELECT policy_id, \
    LEFT(CAST(policy_name AS BINARY), 257) AS policy_name, \
    LEFT(CAST(conflict_type AS BINARY), 33) AS conflict_type, \
    LEFT(CAST(status AS BINARY), 33) AS status, \
    LEFT(CAST(permission_a AS BINARY), 513) AS permission_a, \
    LEFT(CAST(permission_b AS BINARY), 513) AS permission_b, \
    LEFT(CAST(condition_script AS BINARY), 513) AS condition_script, \
    LEFT(CAST(resource_type AS BINARY), 513) AS resource_type, \
    LEFT(CAST(action_code AS BINARY), 513) AS action_code, limit_count, \
    LEFT(CAST(limit_window AS BINARY), 513) AS limit_window \
    FROM sod_policy WHERE BINARY status = BINARY 'ACTIVE' AND (? IS NULL OR policy_id > ?) \
    ORDER BY policy_id LIMIT ?";

#[derive(Debug, Error)]
pub enum SingleNodeMemoryLoaderError {
    #[error("single-node snapshot pending: {0}")]
    Pending(String),
    #[error("single-node snapshot schema error: {0}")]
    Schema(String),
    #[error("single-node snapshot database error during {context}: {source}")]
    Database {
        context: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("single-node snapshot invalid: {0}")]
    Invalid(String),
}

fn db_error(context: &'static str, error: sqlx::Error) -> SingleNodeMemoryLoaderError {
    let schema_error = match &error {
        sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::Decode(_)
        | sqlx::Error::TypeNotFound { .. } => true,
        sqlx::Error::Database(db) => {
            db.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .is_some_and(|mysql| matches!(mysql.number(), 1049 | 1054 | 1146))
                || matches!(db.code().as_deref(), Some("42S02" | "42S22"))
        }
        _ => false,
    };
    if schema_error {
        SingleNodeMemoryLoaderError::Schema(format!("{context}: {error}"))
    } else {
        SingleNodeMemoryLoaderError::Database {
            context,
            source: error,
        }
    }
}

async fn rows<T>(
    tx: &mut Transaction<'_, MySql>,
    context: &'static str,
    sql: &'static str,
) -> Result<Vec<T>, SingleNodeMemoryLoaderError>
where
    T: for<'r> FromRow<'r, MySqlRow> + Send + Unpin,
{
    let result = sqlx::query_as::<_, T>(sql)
        .bind((ROW_CAP + 1) as i64)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| db_error(context, error))?;
    if result.len() > ROW_CAP {
        return Err(SingleNodeMemoryLoaderError::Invalid(format!(
            "{context} exceeds row cap {ROW_CAP}"
        )));
    }
    Ok(result)
}

fn seconds(value: Option<PrimitiveDateTime>) -> Option<i64> {
    value.map(|time| time.assume_utc().unix_timestamp())
}
fn flag(value: i8, field: &str) -> Result<bool, SingleNodeMemoryLoaderError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SingleNodeMemoryLoaderError::Invalid(format!(
            "{field} must be 0 or 1"
        ))),
    }
}
fn effect(value: &str, field: &str) -> Result<GrantEffect, SingleNodeMemoryLoaderError> {
    match value {
        "ALLOW" => Ok(GrantEffect::Allow),
        _ => Err(SingleNodeMemoryLoaderError::Invalid(format!(
            "{field} has unsupported effect {value:?}"
        ))),
    }
}
fn layer(value: &str) -> Result<BindingLayer, SingleNodeMemoryLoaderError> {
    match value {
        "BASE" => Ok(BindingLayer::Base),
        "OVERLAY" => Ok(BindingLayer::Overlay),
        _ => Err(SingleNodeMemoryLoaderError::Invalid(format!(
            "card_rule_set_ref.ref_type has unsupported value {value:?}"
        ))),
    }
}
fn digest(value: &[u8], field: &str) -> Result<String, SingleNodeMemoryLoaderError> {
    if value.len() != 32 {
        return Err(SingleNodeMemoryLoaderError::Invalid(format!(
            "{field} must contain 32 bytes"
        )));
    }
    Ok(hex::encode(value))
}
fn required_id(value: Option<i64>, field: &str) -> Result<i64, SingleNodeMemoryLoaderError> {
    value.ok_or_else(|| SingleNodeMemoryLoaderError::Invalid(format!("{field} is NULL")))
}
fn validate_rule_condition_presence(value: i64) -> Result<(), SingleNodeMemoryLoaderError> {
    match value {
        0 => Ok(()),
        1 => Err(SingleNodeMemoryLoaderError::Pending(
            "permission_rule conditions are not supported by the loader".into(),
        )),
        _ => Err(SingleNodeMemoryLoaderError::Invalid(
            "permission_rule condition presence is invalid".into(),
        )),
    }
}

fn missing_publication() -> Result<Vec<SingleNodePublishedPointer>, SingleNodeMemoryLoaderError> {
    Err(SingleNodeMemoryLoaderError::Pending(
        "published manifest/segment and revoke fence evidence are not loaded".into(),
    ))
}
fn root_version() -> Result<SingleNodeRootVersion, SingleNodeMemoryLoaderError> {
    Err(SingleNodeMemoryLoaderError::Pending("no unified snapshot metadata proves source_snapshot_id, generation, dependency_frontier_digest and revoke_watermark; publication/segment and SoD evidence are also incomplete".into()))
}

#[derive(FromRow)]
struct IdentityRow {
    card_id: i64,
    user_id: i64,
    status: String,
    expires_at: Option<PrimitiveDateTime>,
}
#[derive(FromRow)]
struct UserRow {
    user_id: i64,
    status: String,
    deleted_at: Option<PrimitiveDateTime>,
}
#[derive(FromRow)]
struct CardRow {
    card_id: i64,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    card_status: String,
    valid_from: Option<PrimitiveDateTime>,
    valid_until: Option<PrimitiveDateTime>,
}
#[derive(FromRow)]
struct TenantRow {
    tenant_id: i64,
    tenant_code: String,
    parent_tenant_id: Option<i64>,
}
#[derive(FromRow)]
struct DomainRow {
    domain_id: i64,
    domain_code: Option<String>,
}
#[derive(FromRow)]
struct TenantDomainRow {
    id: i64,
    tenant_id: i64,
    domain_id: i64,
    status: String,
}
#[derive(FromRow)]
struct MembershipRow {
    membership_id: String,
    tenant_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_id: i64,
    revision: i64,
    active: i8,
}
#[derive(FromRow)]
struct RuleSetRow {
    rule_set_id: i64,
    code: String,
    tenant_id: Option<i64>,
    source_type: String,
    source_id: Option<i64>,
    enabled: i8,
}
#[derive(FromRow)]
struct EntryRow {
    entry_id: i64,
    rule_set_id: i64,
    resource_type: String,
    resource_id: Option<i64>,
    action_code: String,
    effect: String,
    condition_json: Option<String>,
    priority: i32,
    enabled: i8,
    valid_from: Option<PrimitiveDateTime>,
    valid_to: Option<PrimitiveDateTime>,
}
#[derive(FromRow)]
struct BindingRow {
    id: i64,
    card_id: i64,
    rule_set_id: i64,
    tenant_id: Option<i64>,
    ref_type: String,
}
#[derive(FromRow)]
struct RuleRow {
    rule_id: i64,
    card_id: i64,
    tenant_id: Option<i64>,
    resource_type: String,
    resource_id: Option<i64>,
    action_code: String,
    effect: String,
    has_condition: i64,
    priority: i32,
    source_type: String,
    source_id: Option<i64>,
    enabled: i8,
    valid_from: Option<PrimitiveDateTime>,
    valid_to: Option<PrimitiveDateTime>,
}
#[derive(FromRow)]
struct AdminRow {
    id: i64,
    user_id: i64,
    status: String,
}
#[derive(FromRow)]
struct PointerRow {
    pointer_id: i64,
    tenant_id: i64,
    aggregate_type: String,
    aggregate_id: i64,
    current_generation: i64,
    manifest_id: i64,
    semantic_hash: Vec<u8>,
    dependency_hash: Vec<u8>,
    status: String,
}
#[derive(FromRow)]
struct TableRow {
    table_name: String,
    engine: Option<String>,
}
#[derive(FromRow)]
struct ColumnTypeRow {
    data_type: String,
}

#[derive(FromRow)]
struct SodColumnRow {
    column_name: String,
    data_type: String,
    is_nullable: String,
    column_key: String,
}

#[derive(FromRow)]
struct SodRow {
    policy_id: i64,
    policy_name: Vec<u8>,
    conflict_type: Vec<u8>,
    status: Option<Vec<u8>>,
    permission_a: Option<Vec<u8>>,
    permission_b: Option<Vec<u8>>,
    condition_script: Option<Vec<u8>>,
    resource_type: Option<Vec<u8>>,
    action_code: Option<Vec<u8>>,
    limit_count: Option<i32>,
    limit_window: Option<Vec<u8>>,
}

fn sod_pending(detail: impl std::fmt::Display) -> SingleNodeMemoryLoaderError {
    SingleNodeMemoryLoaderError::Pending(format!("sod_policy: {detail}"))
}

fn sod_text(
    bytes: Vec<u8>,
    max: usize,
    field: &str,
) -> Result<String, SingleNodeMemoryLoaderError> {
    if bytes.len() > max {
        return Err(sod_pending(format!("{field} exceeds its byte bound")));
    }
    let text =
        String::from_utf8(bytes).map_err(|_| sod_pending(format!("{field} is not UTF-8")))?;
    if text.contains('\0') {
        return Err(sod_pending(format!("{field} contains NUL")));
    }
    Ok(text)
}

fn sod_optional_text(
    bytes: Option<Vec<u8>>,
    max: usize,
    field: &str,
) -> Result<Option<String>, SingleNodeMemoryLoaderError> {
    bytes.map(|value| sod_text(value, max, field)).transpose()
}

fn valid_sod_permission(value: &str) -> bool {
    value.split_once(':').is_some_and(|(resource, action)| {
        !resource.is_empty()
            && !action.is_empty()
            && resource.trim() == resource
            && action.trim() == action
    })
}

fn decode_sod_row(row: SodRow) -> Result<(i64, CertifiedSodPolicy), SingleNodeMemoryLoaderError> {
    if row.policy_id <= 0 {
        return Err(sod_pending("policy_id is not positive"));
    }
    let status = row.status.ok_or_else(|| sod_pending("status is NULL"))?;
    if sod_text(status, 32, "status")? != "ACTIVE" {
        return Err(sod_pending("selected policy is not ACTIVE"));
    }
    let conflict_type = match sod_text(row.conflict_type, 32, "conflict_type")?.as_str() {
        "STATIC" => CertifiedSodConflictType::Static,
        "DYNAMIC" => CertifiedSodConflictType::Dynamic,
        _ => return Err(sod_pending("unsupported ACTIVE conflict_type")),
    };
    if row.limit_count.is_some_and(|count| count != 0) || row.limit_window.is_some() {
        return Err(sod_pending("behavioral limits are unsupported"));
    }
    let policy = CertifiedSodPolicy {
        policy_name: sod_text(row.policy_name, 256, "policy_name")?,
        conflict_type,
        permission_a: sod_optional_text(row.permission_a, 512, "permission_a")?,
        permission_b: sod_optional_text(row.permission_b, 512, "permission_b")?,
        condition_script: sod_optional_text(row.condition_script, 512, "condition_script")?,
        resource_type: sod_optional_text(row.resource_type, 512, "resource_type")?,
        action_code: sod_optional_text(row.action_code, 512, "action_code")?,
    };
    policy.validate().map_err(sod_pending)?;
    match policy.conflict_type {
        CertifiedSodConflictType::Static => {
            if policy.condition_script.is_some()
                || policy.resource_type.is_some()
                || policy.action_code.is_some()
            {
                return Err(sod_pending(
                    "STATIC policy has unsupported additional fields",
                ));
            }
            if !policy
                .permission_a
                .as_deref()
                .is_some_and(valid_sod_permission)
                || !policy
                    .permission_b
                    .as_deref()
                    .is_some_and(valid_sod_permission)
            {
                return Err(sod_pending(
                    "STATIC permissions are not resource:action pairs",
                ));
            }
        }
        CertifiedSodConflictType::Dynamic => {
            if policy.permission_a.is_some() || policy.permission_b.is_some() {
                return Err(sod_pending(
                    "DYNAMIC policy has unsupported permission fields",
                ));
            }
            let script = policy
                .condition_script
                .as_deref()
                .ok_or_else(|| sod_pending("missing condition"))?;
            if script.len() > MAX_DYNAMIC_CONDITION_SCRIPT_BYTES
                || validate_dynamic_sod_condition_script(script).is_err()
            {
                return Err(sod_pending("unsupported DYNAMIC condition"));
            }
            if [
                policy.resource_type.as_deref(),
                policy.action_code.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.is_empty() || value.trim() != value)
            {
                return Err(sod_pending("invalid DYNAMIC resource/action filter"));
            }
        }
    }
    Ok((row.policy_id, policy))
}

fn sod_policy_bytes(policy: &CertifiedSodPolicy) -> usize {
    [
        Some(policy.policy_name.as_str()),
        policy.permission_a.as_deref(),
        policy.permission_b.as_deref(),
        policy.condition_script.as_deref(),
        policy.resource_type.as_deref(),
        policy.action_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .fold(0usize, |sum, value| sum.saturating_add(value.len()))
}

#[derive(Default)]
struct SodBudget {
    counts: [usize; 2],
    bytes: usize,
}

impl SodBudget {
    fn accept(&mut self, policy: &CertifiedSodPolicy) -> Result<(), SingleNodeMemoryLoaderError> {
        let index = match policy.conflict_type {
            CertifiedSodConflictType::Static => 0,
            CertifiedSodConflictType::Dynamic => 1,
        };
        self.counts[index] = self.counts[index].saturating_add(1);
        self.bytes = self.bytes.saturating_add(sod_policy_bytes(policy));
        if self.counts[index] > SOD_ROW_CAP || self.bytes > SOD_MAX_BYTES {
            return Err(sod_pending("policy snapshot capacity exceeded"));
        }
        Ok(())
    }
}

fn validate_sod_schema(
    columns: &[SodColumnRow],
    primary_parts: i64,
) -> Result<(), SingleNodeMemoryLoaderError> {
    if primary_parts != 1 {
        return Err(sod_pending("policy_id must be the sole primary key"));
    }
    for name in [
        "policy_id",
        "policy_name",
        "conflict_type",
        "status",
        "permission_a",
        "permission_b",
        "condition_script",
        "resource_type",
        "action_code",
        "limit_count",
        "limit_window",
    ] {
        let column = columns
            .iter()
            .find(|column| column.column_name == name)
            .ok_or_else(|| sod_pending(format!("missing column {name}")))?;
        let valid_type = match name {
            "policy_id" => {
                column.data_type == "bigint"
                    && column.is_nullable == "NO"
                    && column.column_key == "PRI"
            }
            "limit_count" => column.data_type == "int",
            _ => matches!(
                column.data_type.as_str(),
                "char" | "varchar" | "tinytext" | "text" | "mediumtext" | "longtext"
            ),
        };
        if !valid_type {
            return Err(sod_pending(format!("unsupported schema for {name}")));
        }
    }
    Ok(())
}

async fn load_sod_policies_inner(
    tx: &mut Transaction<'_, MySql>,
) -> Result<Vec<(i64, CertifiedSodPolicy)>, SingleNodeMemoryLoaderError> {
    let columns = sqlx::query_as::<_, SodColumnRow>(
        "SELECT COLUMN_NAME AS column_name, DATA_TYPE AS data_type, IS_NULLABLE AS is_nullable, COLUMN_KEY AS column_key FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sod_policy' ORDER BY ORDINAL_POSITION LIMIT 128",
    ).fetch_all(&mut **tx).await.map_err(sod_pending)?;
    if columns.len() == 128 {
        return Err(sod_pending("schema column limit reached"));
    }
    let primary_parts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sod_policy' AND INDEX_NAME = 'PRIMARY'",
    ).fetch_one(&mut **tx).await.map_err(sod_pending)?;
    validate_sod_schema(&columns, primary_parts)?;

    // Reject non-canonical or NULL statuses instead of silently omitting them via
    // MySQL's case/accent-insensitive default collation.
    let unknown: Option<i64> = sqlx::query_scalar(
        "SELECT policy_id FROM sod_policy WHERE status IS NULL OR (BINARY status <> BINARY 'ACTIVE' AND BINARY status <> BINARY 'INACTIVE') LIMIT 1",
    ).fetch_optional(&mut **tx).await.map_err(sod_pending)?;
    if unknown.is_some() {
        return Err(sod_pending("unknown or non-canonical status"));
    }

    let mut policies = Vec::new();
    let mut last_id: Option<i64> = None;
    let mut budget = SodBudget::default();
    loop {
        let page = sqlx::query_as::<_, SodRow>(SOD_PAGE_SQL)
            .bind(last_id)
            .bind(last_id)
            .bind(SOD_PAGE_SIZE)
            .fetch_all(&mut **tx)
            .await
            .map_err(sod_pending)?;
        let page_len = page.len();
        for row in page {
            let (id, policy) = decode_sod_row(row)?;
            if last_id.is_some_and(|last| id <= last) {
                return Err(sod_pending("policy primary keys are not strictly ordered"));
            }
            last_id = Some(id);
            budget.accept(&policy)?;
            policies.push((id, policy));
        }
        if page_len < SOD_PAGE_SIZE as usize {
            break;
        }
    }
    Ok(policies)
}

async fn load_sod_policies(
    tx: &mut Transaction<'_, MySql>,
) -> Result<Vec<(i64, CertifiedSodPolicy)>, SingleNodeMemoryLoaderError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        load_sod_policies_inner(tx),
    )
    .await
    .map_err(|_| sod_pending("query deadline exceeded"))?
}

/// Acquire a dedicated connection and read all source tables in one repeatable-read
/// transaction. This function currently returns Pending or Schema for the documented
/// evidence/model gaps; it never installs a root.
pub async fn load_single_node_memory_root(
    pool: &MySqlPool,
) -> Result<Arc<SingleNodeMemoryRoot>, SingleNodeMemoryLoaderError> {
    let _permit = SnapshotPermit::acquire()?;
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        load_single_node_memory_root_inner(pool),
    )
    .await
    .map_err(|_| SingleNodeMemoryLoaderError::Pending("snapshot deadline exceeded".into()))?
}

async fn load_single_node_memory_root_inner(
    pool: &MySqlPool,
) -> Result<Arc<SingleNodeMemoryRoot>, SingleNodeMemoryLoaderError> {
    // Detach so cancellation after SET TRANSACTION cannot return altered session
    // state to the pool. Dropping the connection closes it.
    let mut connection = pool
        .acquire()
        .await
        .map_err(|e| db_error("acquire", e))?
        .detach();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut connection)
        .await
        .map_err(|e| db_error("set repeatable read", e))?;
    let mut tx = connection.begin().await.map_err(|e| db_error("begin", e))?;

    // Consistent non-locking reads require transactional tables, not just an
    // isolation level. Metadata is checked before any source row is accepted.
    let tables = rows::<TableRow>(&mut tx, "table engines", "SELECT TABLE_NAME AS table_name, ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('identity_card','platform_user','user_card','tenant','platform_domain','tenant_domain_map','org_scope_membership','rule_set','rule_set_entry','card_rule_set_ref','permission_rule','identity_global_admin','authorization_projection_current') ORDER BY TABLE_NAME LIMIT ?").await?;
    for name in [
        "identity_card",
        "platform_user",
        "user_card",
        "tenant",
        "platform_domain",
        "tenant_domain_map",
        "org_scope_membership",
        "rule_set",
        "rule_set_entry",
        "card_rule_set_ref",
        "permission_rule",
        "identity_global_admin",
        "authorization_projection_current",
    ] {
        let table = tables
            .iter()
            .find(|table| table.table_name == name)
            .ok_or_else(|| SingleNodeMemoryLoaderError::Schema(format!("missing table {name}")))?;
        if !table
            .engine
            .as_deref()
            .is_some_and(|engine| engine.eq_ignore_ascii_case("InnoDB"))
        {
            return Err(SingleNodeMemoryLoaderError::Schema(format!(
                "{name} is not an InnoDB table"
            )));
        }
    }
    let sod_engine: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sod_policy'",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(sod_pending)?;
    if !sod_engine
        .and_then(|(engine,)| engine)
        .is_some_and(|engine| engine.eq_ignore_ascii_case("InnoDB"))
    {
        return Err(sod_pending("table missing or not InnoDB"));
    }
    let membership_types = rows::<ColumnTypeRow>(&mut tx, "org_scope_membership.membership_id", "SELECT DATA_TYPE AS data_type FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_scope_membership' AND COLUMN_NAME = 'membership_id' ORDER BY ORDINAL_POSITION LIMIT ?").await?;
    if membership_types.len() != 1
        || !matches!(membership_types[0].data_type.as_str(), "char" | "varchar")
    {
        return Err(SingleNodeMemoryLoaderError::Schema(
            "org_scope_membership.membership_id must be a bounded character key".into(),
        ));
    }
    let identities = rows::<IdentityRow>(
        &mut tx,
        "identity_card",
        "SELECT card_id,user_id,status,expires_at FROM identity_card ORDER BY card_id LIMIT ?",
    )
    .await?;
    let users = rows::<UserRow>(
        &mut tx,
        "platform_user",
        "SELECT user_id,status,deleted_at FROM platform_user ORDER BY user_id LIMIT ?",
    )
    .await?;
    let cards = rows::<CardRow>(&mut tx, "user_card", "SELECT card_id,user_id,tenant_id,domain_id,card_status,valid_from,valid_until FROM user_card ORDER BY card_id LIMIT ?").await?;
    let tenants = rows::<TenantRow>(
        &mut tx,
        "tenant",
        "SELECT tenant_id,tenant_code,parent_tenant_id FROM tenant ORDER BY tenant_id LIMIT ?",
    )
    .await?;
    let domains = rows::<DomainRow>(
        &mut tx,
        "platform_domain",
        "SELECT domain_id,domain_code FROM platform_domain ORDER BY domain_id LIMIT ?",
    )
    .await?;
    let tenant_domains = rows::<TenantDomainRow>(
        &mut tx,
        "tenant_domain_map",
        "SELECT id,tenant_id,domain_id,status FROM tenant_domain_map ORDER BY id LIMIT ?",
    )
    .await?;
    let memberships = rows::<MembershipRow>(&mut tx, "org_scope_membership", "SELECT membership_id,tenant_id,user_id,identity_card_id,card_id,revision,active FROM org_scope_membership ORDER BY membership_id LIMIT ?").await?;
    let sets = rows::<RuleSetRow>(&mut tx, "rule_set", "SELECT rule_set_id,code,tenant_id,source_type,source_id,enabled FROM rule_set ORDER BY rule_set_id LIMIT ?").await?;
    let entries = rows::<EntryRow>(&mut tx, "rule_set_entry", "SELECT entry_id,rule_set_id,resource_type,resource_id,action_code,effect,CAST(condition_json AS CHAR) AS condition_json,priority,enabled,valid_from,valid_to FROM rule_set_entry ORDER BY entry_id LIMIT ?").await?;
    let bindings = rows::<BindingRow>(&mut tx, "card_rule_set_ref", "SELECT id,card_id,rule_set_id,tenant_id,ref_type FROM card_rule_set_ref ORDER BY id LIMIT ?").await?;
    let rules = rows::<RuleRow>(&mut tx, "permission_rule", "SELECT rule_id,card_id,tenant_id,resource_type,resource_id,action_code,effect,CAST(condition_json IS NOT NULL AS SIGNED) AS has_condition,priority,source_type,source_id,enabled,valid_from,valid_to FROM permission_rule ORDER BY rule_id LIMIT ?").await?;
    let admins = rows::<AdminRow>(
        &mut tx,
        "identity_global_admin",
        "SELECT id,user_id,status FROM identity_global_admin ORDER BY id LIMIT ?",
    )
    .await?;
    let pointers = rows::<PointerRow>(&mut tx, "authorization_projection_current", "SELECT pointer_id,tenant_id,aggregate_type,aggregate_id,current_generation,manifest_id,semantic_hash,dependency_hash,status FROM authorization_projection_current ORDER BY pointer_id LIMIT ?").await?;
    let sod_policies = load_sod_policies(&mut tx).await?;

    let users = users
        .into_iter()
        .map(|r| SingleNodeUser {
            user_id: r.user_id,
            status: r.status,
            deleted_at_unix: seconds(r.deleted_at),
        })
        .collect();
    let identity_cards = identities
        .into_iter()
        .map(|r| SingleNodeIdentityCard {
            card_id: r.card_id,
            user_id: r.user_id,
            status: r.status,
            expires_at_unix: seconds(r.expires_at),
        })
        .collect();
    let user_cards = cards
        .into_iter()
        .map(|r| {
            Ok(SingleNodeUserCard {
                card_id: r.card_id,
                user_id: r.user_id,
                tenant_id: required_id(r.tenant_id, "user_card.tenant_id")?,
                domain_id: r.domain_id,
                status: r.card_status,
                valid_from_unix: seconds(r.valid_from),
                valid_to_unix: seconds(r.valid_until),
            })
        })
        .collect::<Result<Vec<_>, SingleNodeMemoryLoaderError>>()?;
    let tenants = tenants
        .into_iter()
        .map(|r| SingleNodeTenant {
            tenant_id: r.tenant_id,
            tenant_code: r.tenant_code,
            parent_tenant_id: r.parent_tenant_id,
        })
        .collect();
    let domains = domains
        .into_iter()
        .map(|r| SingleNodeDomain {
            domain_id: r.domain_id,
            domain_code: r.domain_code,
        })
        .collect();
    let tenant_domains = tenant_domains
        .into_iter()
        .map(|r| SingleNodeTenantDomain {
            id: r.id,
            tenant_id: r.tenant_id,
            domain_id: r.domain_id,
            status: r.status,
        })
        .collect();
    let org_memberships = memberships
        .into_iter()
        .map(|r| {
            Ok(SingleNodeOrgMembership {
                membership_id: r.membership_id.trim().to_owned(),
                tenant_id: r.tenant_id,
                user_id: r.user_id,
                identity_card_id: r.identity_card_id,
                card_id: r.card_id,
                revision: u64::try_from(r.revision).map_err(|_| {
                    SingleNodeMemoryLoaderError::Invalid(
                        "org_scope_membership.revision is negative".into(),
                    )
                })?,
                active: flag(r.active, "org_scope_membership.active")?,
            })
        })
        .collect::<Result<Vec<_>, SingleNodeMemoryLoaderError>>()?;
    let rule_sets = sets
        .into_iter()
        .map(|r| {
            Ok(SingleNodeRuleSet {
                rule_set_id: r.rule_set_id,
                code: r.code,
                tenant_id: r.tenant_id,
                source_type: r.source_type,
                source_id: r.source_id,
                status: if flag(r.enabled, "rule_set.enabled")? {
                    "ACTIVE"
                } else {
                    "DISABLED"
                }
                .to_owned(),
            })
        })
        .collect::<Result<Vec<_>, SingleNodeMemoryLoaderError>>()?;
    let rule_set_entries = entries
        .into_iter()
        .map(|r| {
            Ok(SingleNodeRuleSetEntry {
                entry_id: r.entry_id,
                rule_set_id: r.rule_set_id,
                resource_type: r.resource_type,
                resource_id: r.resource_id,
                action_code: r.action_code,
                effect: effect(&r.effect, "rule_set_entry.effect")?,
                condition_json: r.condition_json,
                priority: i64::from(r.priority),
                enabled: flag(r.enabled, "rule_set_entry.enabled")?,
                validity: ValidityWindow {
                    not_before: seconds(r.valid_from),
                    expires_at: seconds(r.valid_to),
                },
            })
        })
        .collect::<Result<Vec<_>, SingleNodeMemoryLoaderError>>()?;
    let card_rule_set_refs = bindings
        .into_iter()
        .map(|r| {
            Ok(SingleNodeCardRuleSetRef {
                binding_id: r.id,
                card_id: r.card_id,
                rule_set_id: r.rule_set_id,
                tenant_id: required_id(r.tenant_id, "card_rule_set_ref.tenant_id")?,
                binding_layer: layer(&r.ref_type)?,
            })
        })
        .collect::<Result<Vec<_>, SingleNodeMemoryLoaderError>>()?;
    let permission_rules = rules
        .into_iter()
        .map(|r| {
            let rule_effect = effect(&r.effect, "permission_rule.effect")?;
            validate_rule_condition_presence(r.has_condition)?;
            Ok(SingleNodePermissionRule {
                rule_id: r.rule_id,
                card_id: r.card_id,
                tenant_id: required_id(r.tenant_id, "permission_rule.tenant_id")?,
                resource_type: r.resource_type,
                resource_id: r.resource_id,
                action_code: r.action_code,
                effect: rule_effect,
                condition_json: None,
                priority: i64::from(r.priority),
                source_type: r.source_type,
                source_id: r.source_id,
                enabled: flag(r.enabled, "permission_rule.enabled")?,
                validity: ValidityWindow {
                    not_before: seconds(r.valid_from),
                    expires_at: seconds(r.valid_to),
                },
            })
        })
        .collect::<Result<Vec<_>, SingleNodeMemoryLoaderError>>()?;
    let global_admins = admins
        .into_iter()
        .map(|r| match r.status.as_str() {
            "ACTIVE" => Ok(SingleNodeGlobalAdmin {
                id: r.id,
                user_id: r.user_id,
                active: true,
            }),
            "DISABLED" | "REVOKED" => Ok(SingleNodeGlobalAdmin {
                id: r.id,
                user_id: r.user_id,
                active: false,
            }),
            _ => Err(SingleNodeMemoryLoaderError::Invalid(format!(
                "identity_global_admin.status has unsupported value {:?}",
                r.status
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    for r in pointers {
        let _ = (
            r.pointer_id,
            r.tenant_id,
            r.aggregate_type,
            r.aggregate_id,
            r.current_generation,
            r.manifest_id,
            digest(
                &r.semantic_hash,
                "authorization_projection_current.semantic_hash",
            )?,
            digest(
                &r.dependency_hash,
                "authorization_projection_current.dependency_hash",
            )?,
            r.status,
        );
    }
    let version = root_version()?;
    let published_pointers = missing_publication()?;
    let snapshot = SingleNodeDatabaseSnapshot {
        version,
        users,
        identity_cards,
        user_cards,
        tenants,
        domains,
        tenant_domains,
        org_memberships,
        rule_sets,
        rule_set_entries,
        card_rule_set_refs,
        permission_rules,
        published_pointers,
        global_admins,
        sod_policies,
    };
    let root = SingleNodeMemoryRoot::build(snapshot)
        .map_err(|e| SingleNodeMemoryLoaderError::Invalid(e.to_string()))?;
    tx.commit().await.map_err(|e| db_error("commit", e))?;
    Ok(Arc::new(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month, Time};

    #[test]
    fn time_is_utc_unix_seconds() {
        let value = PrimitiveDateTime::new(
            Date::from_calendar_date(1970, Month::January, 2).unwrap(),
            Time::MIDNIGHT,
        );
        assert_eq!(seconds(Some(value)), Some(86_400));
        assert_eq!(seconds(None), None);
    }
    #[test]
    fn digest_must_be_exactly_sha256_length() {
        assert_eq!(digest(&[0xab; 32], "digest").unwrap(), "ab".repeat(32));
        assert!(matches!(
            digest(&[0; 31], "digest"),
            Err(SingleNodeMemoryLoaderError::Invalid(_))
        ));
        assert!(matches!(
            digest(&[0; 33], "digest"),
            Err(SingleNodeMemoryLoaderError::Invalid(_))
        ));
    }
    #[test]
    fn snapshot_permit_rejects_concurrent_loads_and_releases_on_drop() {
        let permit = SnapshotPermit::acquire().unwrap();
        assert!(matches!(
            SnapshotPermit::acquire(),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        drop(permit);
        assert!(SnapshotPermit::acquire().is_ok());
    }

    #[test]
    fn direct_rule_condition_presence_fails_closed() {
        assert!(validate_rule_condition_presence(0).is_ok());
        assert!(matches!(
            validate_rule_condition_presence(1),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        assert!(matches!(
            validate_rule_condition_presence(2),
            Err(SingleNodeMemoryLoaderError::Invalid(_))
        ));
    }

    #[test]
    fn unsupported_effect_layer_and_flags_fail_closed() {
        assert_eq!(effect("ALLOW", "effect").unwrap(), GrantEffect::Allow);
        assert!(matches!(
            effect("DENY", "effect"),
            Err(SingleNodeMemoryLoaderError::Invalid(_))
        ));
        assert!(layer("NONE").is_err());
        assert!(flag(2, "flag").is_err());
        assert!(required_id(None, "tenant_id").is_err());
    }
    fn static_sod_row() -> SodRow {
        SodRow {
            policy_id: 7,
            policy_name: b"payment segregation".to_vec(),
            conflict_type: b"STATIC".to_vec(),
            status: Some(b"ACTIVE".to_vec()),
            permission_a: Some(b"payment:create".to_vec()),
            permission_b: Some(b"payment:approve".to_vec()),
            condition_script: None,
            resource_type: None,
            action_code: None,
            limit_count: Some(0),
            limit_window: None,
        }
    }

    fn dynamic_sod_row() -> SodRow {
        let mut row = static_sod_row();
        row.policy_id = 8;
        row.conflict_type = b"DYNAMIC".to_vec();
        row.permission_a = None;
        row.permission_b = None;
        row.condition_script = Some(b"resourceOwnerId == currentUserId".to_vec());
        row.resource_type = Some(b"payment".to_vec());
        row.action_code = Some(b"approve".to_vec());
        row
    }

    #[test]
    fn sod_rows_decode_actual_identity_and_fields() {
        let (id, policy) = decode_sod_row(static_sod_row()).unwrap();
        assert_eq!(id, 7);
        assert_eq!(policy.conflict_type, CertifiedSodConflictType::Static);
        assert_eq!(policy.permission_a.as_deref(), Some("payment:create"));
        assert_eq!(policy.permission_b.as_deref(), Some("payment:approve"));
        let (id, policy) = decode_sod_row(dynamic_sod_row()).unwrap();
        assert_eq!(id, 8);
        assert_eq!(policy.conflict_type, CertifiedSodConflictType::Dynamic);
        assert_eq!(policy.resource_type.as_deref(), Some("payment"));
        assert_eq!(policy.action_code.as_deref(), Some("approve"));
        assert_eq!(
            policy.condition_script.as_deref(),
            Some("resourceOwnerId == currentUserId")
        );
    }

    #[test]
    fn sod_invalid_or_unsupported_rows_are_pending() {
        let mut row = static_sod_row();
        row.permission_b = Some(b"missing_separator".to_vec());
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = static_sod_row();
        row.conflict_type = b"BEHAVIORAL".to_vec();
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = static_sod_row();
        row.status = Some(b"active".to_vec());
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = static_sod_row();
        row.policy_id = 0;
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = static_sod_row();
        row.limit_count = Some(1);
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = static_sod_row();
        row.limit_window = Some(b"1h".to_vec());
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = dynamic_sod_row();
        row.condition_script = Some(b"resourceOwnerId != currentUserId".to_vec());
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = dynamic_sod_row();
        row.condition_script = Some(vec![b'x'; 513]);
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut row = dynamic_sod_row();
        row.resource_type = Some(vec![0xff]);
        assert!(matches!(
            decode_sod_row(row),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
    }

    #[test]
    fn sod_budgets_reject_overflow_without_truncating() {
        let (_, static_policy) = decode_sod_row(static_sod_row()).unwrap();
        let (_, dynamic_policy) = decode_sod_row(dynamic_sod_row()).unwrap();
        let mut budget = SodBudget::default();
        for _ in 0..SOD_ROW_CAP {
            budget.accept(&static_policy).unwrap();
            budget.accept(&dynamic_policy).unwrap();
        }
        assert!(matches!(
            budget.accept(&static_policy),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut budget = SodBudget {
            bytes: SOD_MAX_BYTES - sod_policy_bytes(&static_policy),
            ..Default::default()
        };
        budget.accept(&static_policy).unwrap();
        assert!(matches!(
            budget.accept(&dynamic_policy),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
    }

    #[test]
    fn sod_schema_requires_supported_columns_and_single_primary_key() {
        let columns = [
            "policy_id",
            "policy_name",
            "conflict_type",
            "status",
            "permission_a",
            "permission_b",
            "condition_script",
            "resource_type",
            "action_code",
            "limit_count",
            "limit_window",
        ]
        .into_iter()
        .map(|name| SodColumnRow {
            column_name: name.into(),
            data_type: match name {
                "policy_id" => "bigint",
                "limit_count" => "int",
                "condition_script" => "text",
                _ => "varchar",
            }
            .into(),
            is_nullable: if name == "policy_id" { "NO" } else { "YES" }.into(),
            column_key: if name == "policy_id" { "PRI" } else { "" }.into(),
        })
        .collect::<Vec<_>>();
        assert!(validate_sod_schema(&columns, 1).is_ok());
        assert!(matches!(
            validate_sod_schema(&columns, 2),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        assert!(matches!(
            validate_sod_schema(&columns[..10], 1),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        let mut columns = columns;
        columns[0].data_type = "varchar".into();
        assert!(matches!(
            validate_sod_schema(&columns, 1),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
    }

    #[test]
    fn sod_queries_are_nonlocking_and_gates_remain_pending() {
        assert!(!SOD_PAGE_SQL.contains("FOR UPDATE"));
        assert!(!SOD_PAGE_SQL.contains("FOR SHARE"));
        assert!(SOD_PAGE_SQL.contains("ORDER BY policy_id"));
        assert!(matches!(
            missing_publication(),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        assert!(matches!(
            root_version(),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
    }

    #[test]
    fn missing_version_is_pending_and_decode_is_schema() {
        assert!(matches!(
            root_version(),
            Err(SingleNodeMemoryLoaderError::Pending(_))
        ));
        assert!(matches!(
            db_error("test", sqlx::Error::ColumnNotFound("field".into())),
            SingleNodeMemoryLoaderError::Schema(_)
        ));
        assert!(matches!(
            db_error("test", sqlx::Error::PoolClosed),
            SingleNodeMemoryLoaderError::Database { .. }
        ));
    }
}
