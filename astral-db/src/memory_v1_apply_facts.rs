//! memory—v1 apply fact executor: parameterized SQL for the nine candidate
//! authorization-fact tables, driven by [`MemoryV1ApplyPlan`].
//!
//! Every statement in this module is a static SQL string with `?` placeholders;
//! mutation values only ever travel as bound parameters. Each write captures a
//! before image (read under `FOR UPDATE` inside the apply transaction), the
//! exact rows affected, and an after image (re-read inside the same
//! transaction). Precondition failures and cardinality mismatches surface as
//! typed [`FactFailure`] values the executor converts into a fail-closed DENY
//! with the transaction rolled back — no partial fact state survives.
//!
//! This module performs no authorization: it applies an already-authorized,
//! already-journaled governance mutation whose plan status is Complete. A
//! database row written here is a durable fact, never an ALLOW.

use serde_json::{json, Value};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, RuleSetChangeConfirmationRow, RuleSetRow,
    RuleSetStatus, RuleSetVersionRow, UserCardRow, UserCardStatus,
};
use astral_authorization_root::memory_v1_root::ManagementMutationV2;
use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

use crate::memory_v1_apply::{MemoryV1AppliedOperation, MemoryV1ApplyDenialReason};
use crate::memory_v1_apply_plan::{MemoryV1ApplyPlan, OperationKind, TableOwner};

// ─────────────────────────────────────────────────────────────────────────────
// Static parameterized SQL. Every value is bound; nothing is interpolated.
// Keep every statement registered in ALL_APPLY_FACT_SQL so the offline guard
// test can prove the placeholder-only invariant.
// ─────────────────────────────────────────────────────────────────────────────

pub const USER_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_user WHERE user_id = ?";
pub const IDENTITY_CARD_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_identity_card WHERE user_id = ?";
pub const TENANT_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_tenant WHERE tenant_id = ?";

pub const USER_CARD_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT user_id, tenant_id, CONVERT(status USING utf8mb4) FROM memory_user_card WHERE user_card_id = ? FOR UPDATE";
pub const USER_CARD_INSERT_SQL: &str =
    "INSERT INTO memory_user_card (user_card_id, user_id, tenant_id, status) VALUES (?, ?, ?, ?)";
pub const USER_CARD_STATUS_UPDATE_CAS_SQL: &str =
    "UPDATE memory_user_card SET status = ? WHERE user_card_id = ? AND status = ?";

pub const RULE_SET_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT owner_tenant_id, current_version_bytes, CONVERT(status USING utf8mb4) FROM memory_rule_set WHERE rule_set_id = ? FOR UPDATE";
pub const RULE_SET_INSERT_SQL: &str =
    "INSERT INTO memory_rule_set (rule_set_id, owner_tenant_id, current_version_bytes, status) VALUES (?, ?, ?, 'ACTIVE')";
pub const RULE_SET_POINTER_UPDATE_CAS_SQL: &str =
    "UPDATE memory_rule_set SET current_version_bytes = ? WHERE rule_set_id = ? AND current_version_bytes = ? AND status = 'ACTIVE'";
pub const RULE_SET_RETIRE_UPDATE_CAS_SQL: &str =
    "UPDATE memory_rule_set SET status = 'RETIRED' WHERE rule_set_id = ? AND status = 'ACTIVE'";

pub const RULE_SET_VERSION_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_rule_set_version WHERE rule_set_id = ? AND version_bytes = ?";
pub const RULE_SET_VERSION_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT content_bytes, timestamp_bytes, hash_input_bytes, hash_bytes FROM memory_rule_set_version WHERE rule_set_id = ? AND version_bytes = ? FOR UPDATE";
pub const RULE_SET_VERSION_INSERT_SQL: &str =
    "INSERT INTO memory_rule_set_version (rule_set_id, version_bytes, content_bytes, timestamp_bytes, hash_input_bytes, hash_bytes) VALUES (?, ?, ?, ?, ?, ?)";

pub const BINDING_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT user_card_id, rule_set_id, CONVERT(binding_layer USING utf8mb4), valid_from, valid_until, CONVERT(owner_scope USING utf8mb4), CONVERT(tenant_scope USING utf8mb4), removed_at, removed_by FROM memory_card_rule_set_binding WHERE binding_id = ? FOR UPDATE";
pub const BINDING_INSERT_SQL: &str =
    "INSERT INTO memory_card_rule_set_binding (binding_id, user_card_id, rule_set_id, binding_layer, valid_from, valid_until, owner_scope, tenant_scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
pub const BINDING_REMOVE_UPDATE_SQL: &str =
    "UPDATE memory_card_rule_set_binding SET removed_at = ?, removed_by = ? WHERE binding_id = ? AND removed_at IS NULL";
pub const ACTIVE_BINDING_CARD_COUNT_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_card_rule_set_binding b JOIN memory_user_card c ON c.user_card_id = b.user_card_id WHERE b.rule_set_id = ? AND b.removed_at IS NULL AND c.status = 'ACTIVE'";
pub const CARD_INACTIVE_RULESET_COUNT_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_card_rule_set_binding b JOIN memory_rule_set r ON r.rule_set_id = b.rule_set_id WHERE b.user_card_id = ? AND b.removed_at IS NULL AND r.status <> 'ACTIVE'";

pub const BINDING_CONFIRMATION_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT binding_id, rule_set_id, version_bytes, confirmer_user_id, scope_bytes, operation_id, confirmed_at_bytes, revoked_at, revoked_by FROM memory_binding_confirmation WHERE confirmation_id = ? FOR UPDATE";
pub const BINDING_CONFIRMATION_INSERT_SQL: &str =
    "INSERT INTO memory_binding_confirmation (confirmation_id, binding_id, rule_set_id, version_bytes, confirmer_user_id, scope_bytes, operation_id, confirmed_at_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
pub const BINDING_CONFIRMATION_REVOKE_UPDATE_SQL: &str =
    "UPDATE memory_binding_confirmation SET revoked_at = ?, revoked_by = ? WHERE confirmation_id = ? AND revoked_at IS NULL";
pub const ACTIVE_CONFIRMATION_COUNT_FOR_BINDING_SQL: &str =
    "SELECT CAST(COUNT(*) AS SIGNED) AS n FROM memory_binding_confirmation WHERE binding_id = ? AND revoked_at IS NULL";

pub const CHANGE_CONFIRMATION_SELECT_FOR_UPDATE_SQL: &str =
    "SELECT rule_set_id, version_bytes, confirmer_user_id, affected_scope_bytes, operation_id, confirmed_at_bytes, revoked_at, revoked_by FROM memory_rule_set_change_confirmation WHERE confirmation_id = ? FOR UPDATE";
pub const CHANGE_CONFIRMATION_INSERT_SQL: &str =
    "INSERT INTO memory_rule_set_change_confirmation (confirmation_id, rule_set_id, version_bytes, confirmer_user_id, affected_scope_bytes, operation_id, confirmed_at_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)";
pub const CHANGE_CONFIRMATION_REVOKE_UPDATE_SQL: &str =
    "UPDATE memory_rule_set_change_confirmation SET revoked_at = ?, revoked_by = ? WHERE confirmation_id = ? AND revoked_at IS NULL";

/// Every statement above, for the offline parameterization guard test.
pub const ALL_APPLY_FACT_SQL: &[&str] = &[
    USER_EXISTS_SQL,
    IDENTITY_CARD_EXISTS_SQL,
    TENANT_EXISTS_SQL,
    USER_CARD_SELECT_FOR_UPDATE_SQL,
    USER_CARD_INSERT_SQL,
    USER_CARD_STATUS_UPDATE_CAS_SQL,
    RULE_SET_SELECT_FOR_UPDATE_SQL,
    RULE_SET_INSERT_SQL,
    RULE_SET_POINTER_UPDATE_CAS_SQL,
    RULE_SET_RETIRE_UPDATE_CAS_SQL,
    RULE_SET_VERSION_EXISTS_SQL,
    RULE_SET_VERSION_SELECT_FOR_UPDATE_SQL,
    RULE_SET_VERSION_INSERT_SQL,
    BINDING_SELECT_FOR_UPDATE_SQL,
    BINDING_INSERT_SQL,
    BINDING_REMOVE_UPDATE_SQL,
    ACTIVE_BINDING_CARD_COUNT_SQL,
    CARD_INACTIVE_RULESET_COUNT_SQL,
    BINDING_CONFIRMATION_SELECT_FOR_UPDATE_SQL,
    BINDING_CONFIRMATION_INSERT_SQL,
    BINDING_CONFIRMATION_REVOKE_UPDATE_SQL,
    ACTIVE_CONFIRMATION_COUNT_FOR_BINDING_SQL,
    CHANGE_CONFIRMATION_SELECT_FOR_UPDATE_SQL,
    CHANGE_CONFIRMATION_INSERT_SQL,
    CHANGE_CONFIRMATION_REVOKE_UPDATE_SQL,
];

/// Why a fact operation could not be applied. The apply executor converts
/// every failure into a fail-closed DENY and rolls the transaction back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FactFailure {
    pub reason: MemoryV1ApplyDenialReason,
    pub detail: String,
}

// memory—v1
impl FactFailure {
    pub(crate) fn new(reason: MemoryV1ApplyDenialReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: truncate_detail(detail.into()),
        }
    }
}

/// Keep denial details bounded; they may carry hex identifiers only.
// memory—v1
pub(crate) fn truncate_detail(detail: String) -> String {
    const MAX_DETAIL_BYTES: usize = 512;
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail;
    }
    let mut cut = MAX_DETAIL_BYTES;
    while !detail.is_char_boundary(cut) {
        cut -= 1;
    }
    detail[..cut].to_string()
}

// memory—v1
fn hex_id(id: &[u8]) -> String {
    hex::encode(id)
}

// memory—v1
type BindingRowTuple = (
    Vec<u8>,
    Vec<u8>,
    String,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<Vec<u8>>,
);

// memory—v1
type BindingConfirmationRowTuple = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<i64>,
    Option<Vec<u8>>,
);

// memory—v1
type ChangeConfirmationRowTuple = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<i64>,
    Option<Vec<u8>>,
);

// memory—v1
type UserCardRowTuple = (Vec<u8>, Vec<u8>, String);

// memory—v1
type RuleSetRowTuple = (Vec<u8>, Vec<u8>, String);

// memory—v1
type RuleSetVersionRowTuple = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// The fact-operation sequence the executor will run for one governed
/// mutation, in exact transaction order (the durable tail is appended after
/// these by the executor).
///
/// This pure function is the executor/plan agreement anchor: the offline
/// regression asserts it matches [`MemoryV1ApplyPlan::operations`] for every
/// governed mutation kind, so the SQL executor can never drift from the
/// reviewed transaction shape.
// memory—v1
pub fn executor_operation_sequence(
    mutation: &ManagementMutationV2,
) -> Vec<(TableOwner, OperationKind)> {
    match mutation {
        ManagementMutationV2::BindingCreate { .. } => vec![
            (TableOwner::Binding, OperationKind::Insert),
            (TableOwner::BindingConfirmation, OperationKind::Insert),
        ],
        ManagementMutationV2::BindingRemove { .. } => {
            vec![(TableOwner::Binding, OperationKind::Update)]
        }
        ManagementMutationV2::ConfirmationCreate { .. } => {
            vec![(TableOwner::BindingConfirmation, OperationKind::Insert)]
        }
        ManagementMutationV2::ConfirmationRevoke { .. } => {
            vec![(TableOwner::BindingConfirmation, OperationKind::Update)]
        }
        ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => {
            vec![(TableOwner::RuleSetChangeConfirmation, OperationKind::Update)]
        }
        ManagementMutationV2::ConfirmationBatch { rows } => rows
            .iter()
            .map(|_| (TableOwner::BindingConfirmation, OperationKind::Insert))
            .collect(),
        ManagementMutationV2::UserCardCreate { .. } => {
            vec![(TableOwner::UserCard, OperationKind::Insert)]
        }
        ManagementMutationV2::UserCardStatus { .. } => {
            vec![(TableOwner::UserCard, OperationKind::Update)]
        }
        ManagementMutationV2::RuleSetCreate { .. } => vec![
            (TableOwner::RuleSet, OperationKind::Insert),
            (TableOwner::RuleSetVersion, OperationKind::Insert),
            (TableOwner::RuleSetChangeConfirmation, OperationKind::Insert),
        ],
        ManagementMutationV2::RuleSetRetire { .. } => vec![
            (TableOwner::Binding, OperationKind::Verify),
            (TableOwner::RuleSet, OperationKind::Update),
        ],
        ManagementMutationV2::VersionPublish { .. } => vec![
            (TableOwner::RuleSetVersion, OperationKind::Insert),
            (TableOwner::RuleSet, OperationKind::Update),
            (TableOwner::RuleSetChangeConfirmation, OperationKind::Insert),
        ],
        // An ungoverned context load has no fact operations; the executor
        // refuses it before opening any transaction.
        ManagementMutationV2::ContextLoad { .. } => Vec::new(),
    }
}

/// The durable-tail sequence appended after the fact operations.
// memory—v1
pub const TAIL_SEQUENCE: [(TableOwner, OperationKind); 3] = [
    (TableOwner::AuditLog, OperationKind::AppendAudit),
    (TableOwner::ApplyReceipt, OperationKind::AppendReceipt),
    (TableOwner::ApplyProgress, OperationKind::AdvanceProgress),
];

// memory—v1
type Tx<'c> = sqlx::Transaction<'c, sqlx::MySql>;

/// The apply-side transaction handle shared by the executor modules.
// memory—v1
pub(crate) type ApplyTx<'c> = sqlx::Transaction<'c, sqlx::MySql>;

// memory—v1
fn sqlx_failure(error: sqlx::Error) -> FactFailure {
    // A database error inside the fact path is infrastructure, not a decision:
    // the executor rolls everything back and reports the statement failure
    // without fabricating a precondition fact.
    FactFailure::new(
        MemoryV1ApplyDenialReason::InfraFailureRolledBack,
        format!("fact SQL failed: {error}"),
    )
}

// memory—v1
fn require(
    condition: bool,
    reason: MemoryV1ApplyDenialReason,
    detail: impl Into<String>,
) -> Result<(), FactFailure> {
    if condition {
        Ok(())
    } else {
        Err(FactFailure::new(reason, detail))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Database row parsers (fail-closed on unexpected stored shapes)
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
fn parse_rule_set_status(text: &str) -> Result<RuleSetStatus, FactFailure> {
    match text {
        "ACTIVE" => Ok(RuleSetStatus::Active),
        "RETIRED" => Ok(RuleSetStatus::Retired),
        other => Err(FactFailure::new(
            MemoryV1ApplyDenialReason::RowShapeUnexpected,
            format!("unexpected rule-set status in database row: {other}"),
        )),
    }
}

// memory—v1
fn status_text(status: RuleSetStatus) -> &'static str {
    match status {
        RuleSetStatus::Active => "ACTIVE",
        RuleSetStatus::Retired => "RETIRED",
    }
}

// memory—v1
fn parse_user_card_status(text: &str) -> Result<UserCardStatus, FactFailure> {
    match text {
        "ACTIVE" => Ok(UserCardStatus::Active),
        "DISABLED" => Ok(UserCardStatus::Disabled),
        other => Err(FactFailure::new(
            MemoryV1ApplyDenialReason::RowShapeUnexpected,
            format!("unexpected user-card status in database row: {other}"),
        )),
    }
}

// memory—v1
fn parse_binding_layer(text: &str) -> Result<BindingLayer, FactFailure> {
    match text {
        "BASE" => Ok(BindingLayer::Base),
        "OVERLAY" => Ok(BindingLayer::Overlay),
        other => Err(FactFailure::new(
            MemoryV1ApplyDenialReason::RowShapeUnexpected,
            format!("unexpected binding layer in database row: {other}"),
        )),
    }
}

// memory—v1
fn parse_owner_scope(text: &str) -> Result<MemoryV1OwnerScope, FactFailure> {
    match text {
        "self" => Ok(MemoryV1OwnerScope::SelfUser),
        "all" => Ok(MemoryV1OwnerScope::AllUsers),
        other => Err(FactFailure::new(
            MemoryV1ApplyDenialReason::RowShapeUnexpected,
            format!("unexpected owner scope in database row: {other}"),
        )),
    }
}

// memory—v1
fn parse_tenant_scope(text: &str) -> Result<MemoryV1TenantScope, FactFailure> {
    match text {
        "self" => Ok(MemoryV1TenantScope::SelfTenant),
        "self+descendants" => Ok(MemoryV1TenantScope::SelfAndDescendants),
        other => Err(FactFailure::new(
            MemoryV1ApplyDenialReason::RowShapeUnexpected,
            format!("unexpected tenant scope in database row: {other}"),
        )),
    }
}

// memory—v1
fn scope_text(scope: &MemoryV1OwnerScope) -> &'static str {
    match scope {
        MemoryV1OwnerScope::SelfUser => "self",
        MemoryV1OwnerScope::AllUsers => "all",
    }
}

// memory—v1
fn tenant_scope_text(scope: &MemoryV1TenantScope) -> &'static str {
    match scope {
        MemoryV1TenantScope::SelfTenant => "self",
        MemoryV1TenantScope::SelfAndDescendants => "self+descendants",
    }
}

// memory—v1
fn layer_text(layer: BindingLayer) -> &'static str {
    match layer {
        BindingLayer::Base => "BASE",
        BindingLayer::Overlay => "OVERLAY",
    }
}

// memory—v1
fn card_status_text(status: UserCardStatus) -> &'static str {
    match status {
        UserCardStatus::Active => "ACTIVE",
        UserCardStatus::Disabled => "DISABLED",
    }
}

// memory—v1
fn must_be_absent(found: Option<impl Sized>, what: &str, id: &str) -> Result<(), FactFailure> {
    require(
        found.is_none(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("{what} already exists: {id}"),
    )
}

// memory—v1
fn count_is_zero(count: i64, what: &str) -> Result<(), FactFailure> {
    require(
        count == 0,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("{what} count nonzero: {count}"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared row-image readers (before/after evidence from the database)
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
async fn read_binding_image(tx: &mut Tx<'_>, binding_id: &[u8]) -> Result<Value, FactFailure> {
    let row: Option<BindingRowTuple> = sqlx::query_as(BINDING_SELECT_FOR_UPDATE_SQL)
        .bind(binding_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let Some((
        user_card_id,
        rule_set_id,
        binding_layer,
        valid_from,
        valid_until,
        owner_scope,
        tenant_scope,
        removed_at,
        removed_by,
    )) = row
    else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!("binding absent: {}", hex_id(binding_id)),
        ));
    };
    let binding_layer = parse_binding_layer(&binding_layer)?;
    let owner_scope = match owner_scope.as_deref() {
        None => MemoryV1OwnerScope::SelfUser,
        Some(text) => parse_owner_scope(text)?,
    };
    let tenant_scope = match tenant_scope.as_deref() {
        None => MemoryV1TenantScope::SelfTenant,
        Some(text) => parse_tenant_scope(text)?,
    };
    Ok(json!({
        "table": "memory_card_rule_set_binding",
        "binding_id": hex_id(binding_id),
        "user_card_id": hex::encode(&user_card_id),
        "rule_set_id": hex::encode(&rule_set_id),
        "binding_layer": layer_text(binding_layer),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "owner_scope": scope_text(&owner_scope),
        "tenant_scope": tenant_scope_text(&tenant_scope),
        "removed_at": removed_at,
        "removed_by": removed_by.as_deref().map(hex::encode),
    }))
}

// memory—v1
async fn read_user_card_image(tx: &mut Tx<'_>, user_card_id: &[u8]) -> Result<Value, FactFailure> {
    let row: Option<UserCardRowTuple> = sqlx::query_as(USER_CARD_SELECT_FOR_UPDATE_SQL)
        .bind(user_card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let Some((user_id, tenant_id, status)) = row else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!("user card absent: {}", hex_id(user_card_id)),
        ));
    };
    let status = parse_user_card_status(&status)?;
    Ok(json!({
        "table": "memory_user_card",
        "user_card_id": hex_id(user_card_id),
        "user_id": hex::encode(&user_id),
        "tenant_id": hex::encode(&tenant_id),
        "status": card_status_text(status),
    }))
}

// memory—v1
async fn read_rule_set_image(tx: &mut Tx<'_>, rule_set_id: &[u8]) -> Result<Value, FactFailure> {
    let row: Option<RuleSetRowTuple> = sqlx::query_as(RULE_SET_SELECT_FOR_UPDATE_SQL)
        .bind(rule_set_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let Some((owner_tenant_id, current_version, status)) = row else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!("rule set absent: {}", hex_id(rule_set_id)),
        ));
    };
    let status = parse_rule_set_status(&status)?;
    Ok(json!({
        "table": "memory_rule_set",
        "rule_set_id": hex_id(rule_set_id),
        "owner_tenant_id": hex::encode(&owner_tenant_id),
        "current_version_bytes_hex": hex::encode(&current_version),
        "status": status_text(status),
    }))
}

// memory—v1
async fn read_rule_set_version_image(
    tx: &mut Tx<'_>,
    version: &RuleSetVersionRow,
) -> Result<Value, FactFailure> {
    let row: Option<RuleSetVersionRowTuple> =
        sqlx::query_as(RULE_SET_VERSION_SELECT_FOR_UPDATE_SQL)
            .bind(&version.rule_set_id[..])
            .bind(&version.version_bytes)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sqlx_failure)?;
    let Some((content_bytes, timestamp_bytes, hash_input_bytes, hash_bytes)) = row else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!(
                "rule-set version absent: {}:{}",
                hex_id(&version.rule_set_id),
                hex::encode(&version.version_bytes)
            ),
        ));
    };
    Ok(json!({
        "table": "memory_rule_set_version",
        "rule_set_id": hex_id(&version.rule_set_id),
        "version_bytes_hex": hex::encode(&version.version_bytes),
        "content_bytes_hex": hex::encode(&content_bytes),
        "timestamp_bytes_hex": hex::encode(&timestamp_bytes),
        "hash_input_bytes_hex": hex::encode(&hash_input_bytes),
        "hash_bytes_hex": hex::encode(&hash_bytes),
    }))
}

// memory—v1
async fn read_binding_confirmation_image(
    tx: &mut Tx<'_>,
    confirmation_id: &[u8],
) -> Result<Value, FactFailure> {
    let row: Option<BindingConfirmationRowTuple> =
        sqlx::query_as(BINDING_CONFIRMATION_SELECT_FOR_UPDATE_SQL)
            .bind(confirmation_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sqlx_failure)?;
    let Some((
        binding_id,
        rule_set_id,
        version_bytes,
        confirmer_user_id,
        scope_bytes,
        operation_id,
        confirmed_at_bytes,
        revoked_at,
        revoked_by,
    )) = row
    else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!("binding confirmation absent: {}", hex_id(confirmation_id)),
        ));
    };
    Ok(json!({
        "table": "memory_binding_confirmation",
        "confirmation_id": hex_id(confirmation_id),
        "binding_id": hex::encode(&binding_id),
        "rule_set_id": hex::encode(&rule_set_id),
        "version_bytes_hex": hex::encode(&version_bytes),
        "confirmer_user_id": hex::encode(&confirmer_user_id),
        "scope_bytes_hex": hex::encode(&scope_bytes),
        "operation_id_hex": hex::encode(&operation_id),
        "confirmed_at_bytes_hex": hex::encode(&confirmed_at_bytes),
        "revoked_at": revoked_at,
        "revoked_by": revoked_by.as_deref().map(hex::encode),
    }))
}

// memory—v1
async fn read_change_confirmation_image(
    tx: &mut Tx<'_>,
    confirmation_id: &[u8],
) -> Result<Value, FactFailure> {
    let row: Option<ChangeConfirmationRowTuple> =
        sqlx::query_as(CHANGE_CONFIRMATION_SELECT_FOR_UPDATE_SQL)
            .bind(confirmation_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sqlx_failure)?;
    let Some((
        rule_set_id,
        version_bytes,
        confirmer_user_id,
        affected_scope_bytes,
        operation_id,
        confirmed_at_bytes,
        revoked_at,
        revoked_by,
    )) = row
    else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!(
                "rule-set change confirmation absent: {}",
                hex_id(confirmation_id)
            ),
        ));
    };
    Ok(json!({
        "table": "memory_rule_set_change_confirmation",
        "confirmation_id": hex_id(confirmation_id),
        "rule_set_id": hex::encode(&rule_set_id),
        "version_bytes_hex": hex::encode(&version_bytes),
        "confirmer_user_id": hex::encode(&confirmer_user_id),
        "affected_scope_bytes_hex": hex::encode(&affected_scope_bytes),
        "operation_id_hex": hex::encode(&operation_id),
        "confirmed_at_bytes_hex": hex::encode(&confirmed_at_bytes),
        "revoked_at": revoked_at,
        "revoked_by": revoked_by.as_deref().map(hex::encode),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared precondition reads
// ─────────────────────────────────────────────────────────────────────────────

/// Read the rule-set row under lock and require `ACTIVE`.
// memory—v1
async fn rule_set_active_row(
    tx: &mut Tx<'_>,
    rule_set_id: [u8; 16],
) -> Result<Vec<u8>, FactFailure> {
    let image = read_rule_set_image(tx, &rule_set_id).await?;
    require(
        image["status"] == json!("ACTIVE"),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("rule set not ACTIVE: {}", hex_id(&rule_set_id)),
    )?;
    let pointer = image["current_version_bytes_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    hex::decode(&pointer).map_err(|_| {
        FactFailure::new(
            MemoryV1ApplyDenialReason::RowShapeUnexpected,
            format!(
                "rule-set pointer image is not valid hex: {}",
                hex_id(&rule_set_id)
            ),
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply-transaction fact execution
// ─────────────────────────────────────────────────────────────────────────────

/// Apply the plan's fact operations inside the caller's transaction.
///
/// The plan must be complete; the executor first re-derives its operation
/// sequence from the mutation and refuses any disagreement with the reviewed
/// plan (executor/plan agreement), then executes exactly that sequence.
// memory—v1
pub(crate) async fn execute_fact_operations(
    tx: &mut Tx<'_>,
    plan: &MemoryV1ApplyPlan<'_>,
) -> Result<Vec<MemoryV1AppliedOperation>, FactFailure> {
    let mutation = plan.mutation();
    let expected = executor_operation_sequence(mutation);
    let planned: Vec<(TableOwner, OperationKind)> = plan
        .operations()
        .iter()
        .take(expected.len())
        .map(|operation| (operation.owner(), operation.kind()))
        .collect();
    if expected != planned {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PlanOperationMismatch,
            "executor operation sequence disagrees with the reviewed plan",
        ));
    }

    let mut applied = Vec::with_capacity(expected.len());
    match mutation {
        ManagementMutationV2::BindingCreate { row, confirmation } => {
            insert_binding(tx, row, &mut applied).await?;
            insert_binding_confirmation(tx, confirmation, &mut applied).await?;
        }
        ManagementMutationV2::BindingRemove {
            binding_id,
            removed_at,
            removed_by,
        } => {
            remove_binding(tx, *binding_id, *removed_at, removed_by, &mut applied).await?;
        }
        ManagementMutationV2::ConfirmationCreate { row } => {
            insert_binding_confirmation(tx, row, &mut applied).await?;
        }
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id,
            revoked_at,
            revoked_by,
        } => {
            revoke_binding_confirmation(
                tx,
                *confirmation_id,
                *revoked_at,
                revoked_by,
                &mut applied,
            )
            .await?;
        }
        ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id,
            revoked_at,
            revoked_by,
        } => {
            revoke_change_confirmation(tx, *confirmation_id, *revoked_at, revoked_by, &mut applied)
                .await?;
        }
        ManagementMutationV2::ConfirmationBatch { rows } => {
            for row in rows {
                insert_binding_confirmation(tx, row, &mut applied).await?;
            }
        }
        ManagementMutationV2::UserCardCreate { row } => {
            insert_user_card(tx, row, &mut applied).await?;
        }
        ManagementMutationV2::UserCardStatus {
            user_card_id,
            status,
        } => {
            update_user_card_status(tx, *user_card_id, *status, &mut applied).await?;
        }
        ManagementMutationV2::RuleSetCreate {
            rule_set,
            version,
            change_confirmation,
        } => {
            create_rule_set(tx, rule_set, version, change_confirmation, &mut applied).await?;
        }
        ManagementMutationV2::RuleSetRetire { rule_set_id } => {
            retire_rule_set(tx, *rule_set_id, &mut applied).await?;
        }
        ManagementMutationV2::VersionPublish {
            rule_set_id,
            version_row,
            new_current_version,
            change_confirmation,
        } => {
            publish_version(
                tx,
                *rule_set_id,
                version_row,
                new_current_version,
                change_confirmation,
                &mut applied,
            )
            .await?;
        }
        ManagementMutationV2::ContextLoad { .. } => {
            // Unreachable: the executor refuses ungoverned mutations before a
            // transaction exists. Kept explicit so a future variant cannot
            // silently fall through.
            return Err(FactFailure::new(
                MemoryV1ApplyDenialReason::MutationKindNotCovered,
                "context load has no governed apply contract",
            ));
        }
    }
    Ok(applied)
}

// memory—v1
fn push_applied(
    applied: &mut Vec<MemoryV1AppliedOperation>,
    owner: TableOwner,
    kind: OperationKind,
    target: String,
    rows_affected: u64,
    before: Option<Value>,
    after: Option<Value>,
) {
    applied.push(MemoryV1AppliedOperation {
        ordinal: applied.len(),
        owner,
        kind,
        target,
        rows_affected,
        before,
        after,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-kind fact executors
// ─────────────────────────────────────────────────────────────────────────────

// memory—v1
async fn insert_binding(
    tx: &mut Tx<'_>,
    row: &BindingRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_card_rule_set_binding:{}", hex_id(&row.binding_id));
    let existing: Option<(Vec<u8>,)> = sqlx::query_as(BINDING_SELECT_FOR_UPDATE_SQL)
        .bind(&row.binding_id[..])
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    must_be_absent(existing, "binding", &target)?;
    require(
        row.removed_at.is_none() && row.removed_by.is_none(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("new binding must carry complete live fields: {target}"),
    )?;

    // Card must be active: the row lock proves it inside this transaction.
    let card_image = read_user_card_image(tx, &row.user_card_id).await?;
    require(
        card_image["status"] == json!("ACTIVE"),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("user card not ACTIVE: {}", hex_id(&row.user_card_id)),
    )?;
    rule_set_active_row(tx, row.rule_set_id).await?;

    let result = sqlx::query(BINDING_INSERT_SQL)
        .bind(&row.binding_id[..])
        .bind(&row.user_card_id[..])
        .bind(&row.rule_set_id[..])
        .bind(layer_text(row.binding_layer))
        .bind(row.valid_from)
        .bind(row.valid_until)
        .bind(scope_text(&row.owner_scope))
        .bind(tenant_scope_text(&row.tenant_scope))
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("binding insert affected {rows_affected} rows: {target}"),
    )?;
    let after = read_binding_image(tx, &row.binding_id).await?;
    push_applied(
        applied,
        TableOwner::Binding,
        OperationKind::Insert,
        target,
        rows_affected,
        None,
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn remove_binding(
    tx: &mut Tx<'_>,
    binding_id: [u8; 16],
    removed_at: i64,
    removed_by: &[u8; 16],
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_card_rule_set_binding:{}", hex_id(&binding_id));
    let before = read_binding_image(tx, &binding_id).await?;
    require(
        before["removed_at"].is_null() && before["removed_by"].is_null(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("binding already removed: {target}"),
    )?;
    let result = sqlx::query(BINDING_REMOVE_UPDATE_SQL)
        .bind(removed_at)
        .bind(&removed_by[..])
        .bind(&binding_id[..])
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("binding remove affected {rows_affected} rows (must be exactly 1): {target}"),
    )?;
    let after = read_binding_image(tx, &binding_id).await?;
    push_applied(
        applied,
        TableOwner::Binding,
        OperationKind::Update,
        target,
        rows_affected,
        Some(before),
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn insert_binding_confirmation(
    tx: &mut Tx<'_>,
    row: &BindingConfirmationRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!(
        "memory_binding_confirmation:{}",
        hex_id(&row.confirmation_id)
    );
    let existing: Option<(Vec<u8>,)> = sqlx::query_as(BINDING_CONFIRMATION_SELECT_FOR_UPDATE_SQL)
        .bind(&row.confirmation_id[..])
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    must_be_absent(existing, "binding confirmation", &target)?;
    require(
        row.revoked_at.is_none() && row.revoked_by.is_none(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("new confirmation must carry complete live fields: {target}"),
    )?;

    // The binding must exist and be unremoved, and its rule set must match.
    let binding = read_binding_image(tx, &row.binding_id).await?;
    require(
        binding["removed_at"].is_null() && binding["removed_by"].is_null(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("binding already removed: {}", hex_id(&row.binding_id)),
    )?;
    require(
        binding["rule_set_id"] == json!(hex::encode(row.rule_set_id)),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("confirmation rule set does not match binding: {target}"),
    )?;
    rule_set_active_row(tx, row.rule_set_id).await?;

    let version_count: (i64,) = sqlx::query_as(RULE_SET_VERSION_EXISTS_SQL)
        .bind(&row.rule_set_id[..])
        .bind(&row.version_bytes)
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    require(
        version_count.0 == 1,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!(
            "referenced rule-set version absent: {} / {}",
            hex_id(&row.rule_set_id),
            hex::encode(&row.version_bytes)
        ),
    )?;
    let active_confirmations: (i64,) = sqlx::query_as(ACTIVE_CONFIRMATION_COUNT_FOR_BINDING_SQL)
        .bind(&row.binding_id[..])
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    count_is_zero(active_confirmations.0, "active confirmation for binding")?;

    let result = sqlx::query(BINDING_CONFIRMATION_INSERT_SQL)
        .bind(&row.confirmation_id[..])
        .bind(&row.binding_id[..])
        .bind(&row.rule_set_id[..])
        .bind(&row.version_bytes)
        .bind(&row.confirmer_user_id[..])
        .bind(&row.scope_bytes)
        .bind(&row.operation_id)
        .bind(&row.confirmed_at_bytes)
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("confirmation insert affected {rows_affected} rows: {target}"),
    )?;
    let after = read_binding_confirmation_image(tx, &row.confirmation_id).await?;
    push_applied(
        applied,
        TableOwner::BindingConfirmation,
        OperationKind::Insert,
        target,
        rows_affected,
        None,
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn revoke_binding_confirmation(
    tx: &mut Tx<'_>,
    confirmation_id: [u8; 16],
    revoked_at: i64,
    revoked_by: &[u8; 16],
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_binding_confirmation:{}", hex_id(&confirmation_id));
    let before = read_binding_confirmation_image(tx, &confirmation_id).await?;
    require(
        before["revoked_at"].is_null(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("confirmation already revoked: {target}"),
    )?;
    let result = sqlx::query(BINDING_CONFIRMATION_REVOKE_UPDATE_SQL)
        .bind(revoked_at)
        .bind(&revoked_by[..])
        .bind(&confirmation_id[..])
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("confirmation revoke affected {rows_affected} rows: {target}"),
    )?;
    let after = read_binding_confirmation_image(tx, &confirmation_id).await?;
    push_applied(
        applied,
        TableOwner::BindingConfirmation,
        OperationKind::Update,
        target,
        rows_affected,
        Some(before),
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn revoke_change_confirmation(
    tx: &mut Tx<'_>,
    confirmation_id: [u8; 16],
    revoked_at: i64,
    revoked_by: &[u8; 16],
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!(
        "memory_rule_set_change_confirmation:{}",
        hex_id(&confirmation_id)
    );
    let before = read_change_confirmation_image(tx, &confirmation_id).await?;
    require(
        before["revoked_at"].is_null(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("change confirmation already revoked: {target}"),
    )?;
    let result = sqlx::query(CHANGE_CONFIRMATION_REVOKE_UPDATE_SQL)
        .bind(revoked_at)
        .bind(&revoked_by[..])
        .bind(&confirmation_id[..])
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("change-confirmation revoke affected {rows_affected} rows: {target}"),
    )?;
    let after = read_change_confirmation_image(tx, &confirmation_id).await?;
    push_applied(
        applied,
        TableOwner::RuleSetChangeConfirmation,
        OperationKind::Update,
        target,
        rows_affected,
        Some(before),
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn insert_user_card(
    tx: &mut Tx<'_>,
    row: &UserCardRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_user_card:{}", hex_id(&row.user_card_id));
    let existing: Option<(String,)> = sqlx::query_as(USER_CARD_SELECT_FOR_UPDATE_SQL)
        .bind(&row.user_card_id[..])
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    must_be_absent(existing, "user card", &target)?;

    let user_count: (i64,) = sqlx::query_as(USER_EXISTS_SQL)
        .bind(&row.user_id[..])
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    require(
        user_count.0 == 1,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("user absent: {}", hex_id(&row.user_id)),
    )?;
    let identity_count: (i64,) = sqlx::query_as(IDENTITY_CARD_EXISTS_SQL)
        .bind(&row.user_id[..])
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    require(
        identity_count.0 == 1,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("identity card absent for user: {}", hex_id(&row.user_id)),
    )?;
    let tenant_count: (i64,) = sqlx::query_as(TENANT_EXISTS_SQL)
        .bind(&row.tenant_id[..])
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    require(
        tenant_count.0 == 1,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("tenant absent: {}", hex_id(&row.tenant_id)),
    )?;

    let result = sqlx::query(USER_CARD_INSERT_SQL)
        .bind(&row.user_card_id[..])
        .bind(&row.user_id[..])
        .bind(&row.tenant_id[..])
        .bind(card_status_text(row.status))
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("user-card insert affected {rows_affected} rows: {target}"),
    )?;
    let after = read_user_card_image(tx, &row.user_card_id).await?;
    push_applied(
        applied,
        TableOwner::UserCard,
        OperationKind::Insert,
        target,
        rows_affected,
        None,
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn update_user_card_status(
    tx: &mut Tx<'_>,
    user_card_id: [u8; 16],
    status: UserCardStatus,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_user_card:{}", hex_id(&user_card_id));
    let before = read_user_card_image(tx, &user_card_id).await?;
    let previous_status = before["status"].as_str().unwrap_or_default().to_string();
    if status == UserCardStatus::Active {
        // Enabling must coordinate with existing bindings: every rule set the
        // card is still bound to must be active.
        let inactive: (i64,) = sqlx::query_as(CARD_INACTIVE_RULESET_COUNT_SQL)
            .bind(&user_card_id[..])
            .fetch_one(&mut **tx)
            .await
            .map_err(sqlx_failure)?;
        count_is_zero(inactive.0, "binding to non-ACTIVE rule set on card enable")?;
    }

    let result = sqlx::query(USER_CARD_STATUS_UPDATE_CAS_SQL)
        .bind(card_status_text(status))
        .bind(&user_card_id[..])
        .bind(previous_status.as_str())
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!(
            "user-card status update affected {rows_affected} rows (CAS fence on previous status {previous_status}): {target}"
        ),
    )?;
    let after = read_user_card_image(tx, &user_card_id).await?;
    push_applied(
        applied,
        TableOwner::UserCard,
        OperationKind::Update,
        target,
        rows_affected,
        Some(before),
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn create_rule_set(
    tx: &mut Tx<'_>,
    rule_set: &RuleSetRow,
    version: &RuleSetVersionRow,
    change_confirmation: &RuleSetChangeConfirmationRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_rule_set:{}", hex_id(&rule_set.rule_set_id));
    // The administrative owner tenant must exist before the rule-set row
    // (ParentMustPrecedeVersion in the plan).
    let tenant_count: (i64,) = sqlx::query_as(TENANT_EXISTS_SQL)
        .bind(&rule_set.owner_tenant_id[..])
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    require(
        tenant_count.0 == 1,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("owner tenant absent: {}", hex_id(&rule_set.owner_tenant_id)),
    )?;
    let existing = read_rule_set_image(tx, &rule_set.rule_set_id).await;
    match existing {
        Ok(_) => {
            return Err(FactFailure::new(
                MemoryV1ApplyDenialReason::PreconditionFailed,
                format!("rule set already exists: {target}"),
            ));
        }
        Err(failure) => {
            // Only the explicit absent precondition may proceed; any other
            // read failure is infrastructure.
            require(
                failure.reason == MemoryV1ApplyDenialReason::PreconditionFailed
                    && failure.detail.contains("absent"),
                MemoryV1ApplyDenialReason::InfraFailureRolledBack,
                format!("rule-set existence read failed: {target}"),
            )?;
        }
    }
    require(
        rule_set.current_version_bytes == version.version_bytes,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("new rule-set pointer must match the initial version: {target}"),
    )?;
    require(
        rule_set.status == RuleSetStatus::Active,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("new rule set must be ACTIVE: {target}"),
    )?;

    let result = sqlx::query(RULE_SET_INSERT_SQL)
        .bind(&rule_set.rule_set_id[..])
        .bind(&rule_set.owner_tenant_id[..])
        .bind(&rule_set.current_version_bytes)
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("rule-set insert affected {rows_affected} rows: {target}"),
    )?;
    let after = read_rule_set_image(tx, &rule_set.rule_set_id).await?;
    push_applied(
        applied,
        TableOwner::RuleSet,
        OperationKind::Insert,
        target,
        rows_affected,
        None,
        Some(after),
    );

    insert_rule_set_version(tx, version, applied).await?;
    insert_change_confirmation(tx, change_confirmation, applied).await?;
    Ok(())
}

// memory—v1
async fn insert_rule_set_version(
    tx: &mut Tx<'_>,
    version: &RuleSetVersionRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!(
        "memory_rule_set_version:{}:{}",
        hex_id(&version.rule_set_id),
        hex::encode(&version.version_bytes)
    );
    let existing: Option<(Vec<u8>,)> = sqlx::query_as(RULE_SET_VERSION_SELECT_FOR_UPDATE_SQL)
        .bind(&version.rule_set_id[..])
        .bind(&version.version_bytes)
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    must_be_absent(existing, "rule-set version", &target)?;

    let result = sqlx::query(RULE_SET_VERSION_INSERT_SQL)
        .bind(&version.rule_set_id[..])
        .bind(&version.version_bytes)
        .bind(&version.content_bytes)
        .bind(&version.timestamp_bytes)
        .bind(&version.hash_input_bytes)
        .bind(&version.hash_bytes)
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("version insert affected {rows_affected} rows: {target}"),
    )?;
    let after = read_rule_set_version_image(tx, version).await?;
    push_applied(
        applied,
        TableOwner::RuleSetVersion,
        OperationKind::Insert,
        target,
        rows_affected,
        None,
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn insert_change_confirmation(
    tx: &mut Tx<'_>,
    row: &RuleSetChangeConfirmationRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!(
        "memory_rule_set_change_confirmation:{}",
        hex_id(&row.confirmation_id)
    );
    let existing = read_change_confirmation_image(tx, &row.confirmation_id).await;
    match existing {
        Ok(_) => {
            return Err(FactFailure::new(
                MemoryV1ApplyDenialReason::PreconditionFailed,
                format!("change confirmation already exists: {target}"),
            ));
        }
        Err(failure) => {
            require(
                failure.reason == MemoryV1ApplyDenialReason::PreconditionFailed
                    && failure.detail.contains("absent"),
                MemoryV1ApplyDenialReason::InfraFailureRolledBack,
                format!("change-confirmation existence read failed: {target}"),
            )?;
        }
    }
    require(
        row.revoked_at.is_none() && row.revoked_by.is_none(),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("new change confirmation must carry complete live fields: {target}"),
    )?;

    let result = sqlx::query(CHANGE_CONFIRMATION_INSERT_SQL)
        .bind(&row.confirmation_id[..])
        .bind(&row.rule_set_id[..])
        .bind(&row.version_bytes)
        .bind(&row.confirmer_user_id[..])
        .bind(&row.affected_scope_bytes)
        .bind(&row.operation_id)
        .bind(&row.confirmed_at_bytes)
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("change-confirmation insert affected {rows_affected} rows: {target}"),
    )?;
    let after = read_change_confirmation_image(tx, &row.confirmation_id).await?;
    push_applied(
        applied,
        TableOwner::RuleSetChangeConfirmation,
        OperationKind::Insert,
        target,
        rows_affected,
        None,
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn retire_rule_set(
    tx: &mut Tx<'_>,
    rule_set_id: [u8; 16],
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_rule_set:{}", hex_id(&rule_set_id));

    // Verify op: zero active bindings whose owner card is active. Retirement
    // retains every unremoved binding row; it writes no tombstones.
    let active: (i64,) = sqlx::query_as(ACTIVE_BINDING_CARD_COUNT_SQL)
        .bind(&rule_set_id[..])
        .fetch_one(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    require(
        active.0 == 0,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!(
            "rule set still has {} active bindings with an active card: {target}",
            active.0
        ),
    )?;
    let before = read_rule_set_image(tx, &rule_set_id).await?;
    require(
        before["status"] == json!("ACTIVE"),
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("rule set not ACTIVE: {target}"),
    )?;

    let result = sqlx::query(RULE_SET_RETIRE_UPDATE_CAS_SQL)
        .bind(&rule_set_id[..])
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!("rule-set retire affected {rows_affected} rows: {target}"),
    )?;
    let after = read_rule_set_image(tx, &rule_set_id).await?;
    push_applied(
        applied,
        TableOwner::Binding,
        OperationKind::Verify,
        format!("verify:{}", target),
        0,
        Some(json!({
            "check": "NoActiveBindingWithActiveCard",
            "active_binding_with_active_card_count": active.0,
            "rule_set_before": before,
        })),
        None,
    );
    push_applied(
        applied,
        TableOwner::RuleSet,
        OperationKind::Update,
        target,
        rows_affected,
        Some(before),
        Some(after),
    );
    Ok(())
}

// memory—v1
async fn publish_version(
    tx: &mut Tx<'_>,
    rule_set_id: [u8; 16],
    version_row: &RuleSetVersionRow,
    new_current_version: &[u8],
    change_confirmation: &RuleSetChangeConfirmationRow,
    applied: &mut Vec<MemoryV1AppliedOperation>,
) -> Result<(), FactFailure> {
    let target = format!("memory_rule_set:{}", hex_id(&rule_set_id));
    require(
        version_row.rule_set_id == rule_set_id && version_row.version_bytes == new_current_version,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("published version must match the new current pointer: {target}"),
    )?;

    // Order is part of the contract: version row, CAS pointer, then the
    // change confirmation.
    insert_rule_set_version(tx, version_row, applied).await?;

    // CAS pointer fence: the previous pointer is read under lock inside this
    // transaction and bound into the UPDATE predicate.
    let row: Option<RuleSetRowTuple> = sqlx::query_as(RULE_SET_SELECT_FOR_UPDATE_SQL)
        .bind(&rule_set_id[..])
        .fetch_optional(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let Some((owner_tenant_id, old_pointer, status)) = row else {
        return Err(FactFailure::new(
            MemoryV1ApplyDenialReason::PreconditionFailed,
            format!("rule set absent: {target}"),
        ));
    };
    let status = parse_rule_set_status(&status)?;
    require(
        status == RuleSetStatus::Active,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("rule set not ACTIVE: {target}"),
    )?;
    let before = json!({
        "table": "memory_rule_set",
        "rule_set_id": hex_id(&rule_set_id),
        "owner_tenant_id": hex::encode(&owner_tenant_id),
        "current_version_bytes_hex": hex::encode(&old_pointer),
        "status": status_text(status),
    });

    let result = sqlx::query(RULE_SET_POINTER_UPDATE_CAS_SQL)
        .bind(new_current_version)
        .bind(&rule_set_id[..])
        .bind(&old_pointer)
        .execute(&mut **tx)
        .await
        .map_err(sqlx_failure)?;
    let rows_affected = result.rows_affected();
    require(
        rows_affected == 1,
        MemoryV1ApplyDenialReason::CardinalityMismatch,
        format!(
            "current-version pointer CAS affected {rows_affected} rows (fence on previous pointer): {target}"
        ),
    )?;
    let after = read_rule_set_image(tx, &rule_set_id).await?;
    push_applied(
        applied,
        TableOwner::RuleSet,
        OperationKind::Update,
        target.clone(),
        rows_affected,
        Some(before),
        Some(after),
    );

    require(
        change_confirmation.rule_set_id == rule_set_id
            && change_confirmation.version_bytes == new_current_version,
        MemoryV1ApplyDenialReason::PreconditionFailed,
        format!("change confirmation must reference the published version: {target}"),
    )?;
    insert_change_confirmation(tx, change_confirmation, applied).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::memory_v1::MemoryId;
    use astral_types::memory_v1_audit::MemoryV1AuditObject;
    use astral_types::memory_v1_journal::JournalAnchor;

    // memory—v1
    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    // memory—v1
    fn memory_id(n: u8) -> MemoryId {
        MemoryId::from_bytes(id(n))
    }

    // memory—v1
    fn version(n: u8) -> Vec<u8> {
        vec![n]
    }

    // memory—v1
    fn binding(n: u8, rule_set_id: u8) -> BindingRow {
        BindingRow {
            binding_id: id(n),
            user_card_id: id(2),
            rule_set_id: id(rule_set_id),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::SelfUser,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        }
    }

    // memory—v1
    fn confirmation(n: u8, binding_id: u8, rule_set_id: u8) -> BindingConfirmationRow {
        BindingConfirmationRow {
            confirmation_id: id(n),
            binding_id: id(binding_id),
            rule_set_id: id(rule_set_id),
            version_bytes: version(1),
            confirmer_user_id: id(3),
            scope_bytes: vec![1],
            operation_id: vec![2],
            confirmed_at_bytes: vec![3],
            revoked_at: None,
            revoked_by: None,
        }
    }

    // memory—v1
    fn rule_set(n: u8, current: Vec<u8>) -> RuleSetRow {
        RuleSetRow {
            rule_set_id: id(n),
            owner_tenant_id: id(4),
            current_version_bytes: current,
            status: RuleSetStatus::Active,
        }
    }

    // memory—v1
    fn version_row(rule_set_id: u8, version_bytes: Vec<u8>) -> RuleSetVersionRow {
        RuleSetVersionRow {
            rule_set_id: id(rule_set_id),
            version_bytes,
            content_bytes: vec![1],
            timestamp_bytes: vec![2],
            hash_input_bytes: vec![3],
            hash_bytes: vec![4],
        }
    }

    // memory—v1
    fn change_confirmation(
        n: u8,
        rule_set_id: u8,
        version_bytes: Vec<u8>,
    ) -> RuleSetChangeConfirmationRow {
        RuleSetChangeConfirmationRow {
            confirmation_id: id(n),
            rule_set_id: id(rule_set_id),
            version_bytes,
            confirmer_user_id: id(3),
            affected_scope_bytes: vec![1],
            operation_id: vec![2],
            confirmed_at_bytes: vec![3],
            revoked_at: None,
            revoked_by: None,
        }
    }

    // memory—v1
    fn valid_mutations() -> Vec<(ManagementMutationV2, MemoryV1AuditObject, bool)> {
        vec![
            (
                ManagementMutationV2::BindingCreate {
                    row: binding(10, 5),
                    confirmation: confirmation(11, 10, 5),
                },
                MemoryV1AuditObject::Binding(memory_id(10)),
                false,
            ),
            (
                ManagementMutationV2::BindingRemove {
                    binding_id: id(10),
                    removed_at: 20,
                    removed_by: id(1),
                },
                MemoryV1AuditObject::Binding(memory_id(10)),
                false,
            ),
            (
                ManagementMutationV2::ConfirmationCreate {
                    row: confirmation(11, 10, 5),
                },
                MemoryV1AuditObject::Confirmation(memory_id(11)),
                false,
            ),
            (
                ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: id(11),
                    revoked_at: 20,
                    revoked_by: id(1),
                },
                MemoryV1AuditObject::Confirmation(memory_id(11)),
                false,
            ),
            (
                ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id: id(12),
                    revoked_at: 20,
                    revoked_by: id(1),
                },
                MemoryV1AuditObject::Confirmation(memory_id(12)),
                false,
            ),
            (
                ManagementMutationV2::ConfirmationBatch {
                    rows: vec![confirmation(11, 10, 5), confirmation(12, 13, 5)],
                },
                MemoryV1AuditObject::Confirmation(memory_id(11)),
                false,
            ),
            (
                ManagementMutationV2::UserCardCreate {
                    row: UserCardRow {
                        user_card_id: id(20),
                        user_id: id(1),
                        tenant_id: id(4),
                        status: UserCardStatus::Active,
                    },
                },
                MemoryV1AuditObject::UserCard(memory_id(20)),
                false,
            ),
            (
                ManagementMutationV2::UserCardStatus {
                    user_card_id: id(20),
                    status: UserCardStatus::Active,
                },
                MemoryV1AuditObject::UserCard(memory_id(20)),
                false,
            ),
            (
                ManagementMutationV2::RuleSetCreate {
                    rule_set: rule_set(5, version(1)),
                    version: version_row(5, version(1)),
                    change_confirmation: change_confirmation(12, 5, version(1)),
                },
                MemoryV1AuditObject::RuleSet(memory_id(5)),
                false,
            ),
            (
                ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                MemoryV1AuditObject::RuleSet(memory_id(5)),
                true,
            ),
            (
                ManagementMutationV2::VersionPublish {
                    rule_set_id: id(5),
                    version_row: version_row(5, version(2)),
                    new_current_version: version(2),
                    change_confirmation: change_confirmation(12, 5, version(2)),
                },
                MemoryV1AuditObject::RuleSet(memory_id(5)),
                false,
            ),
        ]
    }

    /// Every fact statement is placeholder-parameterized: no braces that could
    /// indicate interpolated values.
    #[test]
    // memory—v1
    fn all_fact_statements_are_placeholder_parameterized() {
        for statement in ALL_APPLY_FACT_SQL {
            assert!(
                !statement.contains('{') && !statement.contains('}'),
                "fact SQL must never interpolate values: {statement}"
            );
            assert!(
                statement.contains('?'),
                "statement must bind values: {statement}"
            );
        }
    }

    /// The executor sequence matches the reviewed plan for every governed
    /// mutation kind, and the durable tail always follows.
    #[test]
    // memory—v1
    fn executor_sequence_matches_plan_for_every_governed_kind() {
        for (mutation, target, retirement) in valid_mutations() {
            let event =
                crate::memory_v1_apply_plan::tests_support::sample_audit_event(target, retirement);
            let flow = JournalAnchor::new(memory_id(9), 1, 1, [6; 32]).unwrap();
            let plan = MemoryV1ApplyPlan::build(crate::memory_v1_apply_plan::ApplyPlanInput {
                mutation: &mutation,
                audit: Some(&event),
                flow: Some(flow),
            });
            // A multi-row batch never plans Complete (single-target evidence
            // is insufficient by design); every other sample must complete.
            let multi_row_batch = matches!(
                &mutation,
                ManagementMutationV2::ConfirmationBatch { rows } if rows.len() > 1
            );
            if !multi_row_batch {
                assert!(
                    plan.is_complete(),
                    "sample mutation must plan complete: {mutation:?}"
                );
            }
            let expected = executor_operation_sequence(&mutation);
            let planned: Vec<(TableOwner, OperationKind)> = plan
                .operations()
                .iter()
                .take(expected.len())
                .map(|operation| (operation.owner(), operation.kind()))
                .collect();
            assert_eq!(expected, planned, "sequence mismatch for {mutation:?}");
            let tail: Vec<(TableOwner, OperationKind)> = plan
                .operations()
                .iter()
                .skip(expected.len())
                .map(|operation| (operation.owner(), operation.kind()))
                .collect();
            assert_eq!(
                tail,
                TAIL_SEQUENCE.to_vec(),
                "tail mismatch for {mutation:?}"
            );
        }
    }

    /// A context load exposes no fact operations: the executor's sequence is
    /// empty and the plan is never complete.
    #[test]
    // memory—v1
    fn context_load_has_no_executor_sequence() {
        let mutation = ManagementMutationV2::ContextLoad {
            rows: Default::default(),
            selections: Vec::new(),
        };
        assert!(executor_operation_sequence(&mutation).is_empty());
    }

    /// Denial details are bounded so a long value cannot inflate the denial
    /// report.
    #[test]
    // memory—v1
    fn denial_details_are_truncated() {
        let long = "x".repeat(4096);
        let failure = FactFailure::new(MemoryV1ApplyDenialReason::PreconditionFailed, long);
        assert!(failure.detail.len() <= 512);
    }
}
