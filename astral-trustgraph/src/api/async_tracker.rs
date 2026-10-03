//! Durable tracking for asynchronous TrustGraph mutations.
//!
//! Batch bind status is stored in `async_operation` and `async_operation_item`;
//! the in-memory registry only owns task lifetimes and shutdown cancellation. A
//! restart never replays unfinished children: their durable state is reported as
//! `IN_DOUBT` until reconciled against source rows and audit evidence.

use std::collections::BTreeMap;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use astral_types::AstralError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tokio::sync::{oneshot, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

pub const MAX_TASK_ID_LENGTH: usize = 64;
pub const MAX_CARD_BIND_ITEMS: usize = 512;
pub const BATCH_BIND_TASK_TYPE: &str = "CARD_BIND";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    InDoubt,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncTask {
    pub task_id: String,
    pub task_type: String,
    pub status: TaskStatus,
    pub total: Option<usize>,
    pub completed: Option<usize>,
    pub failed: Option<usize>,
    pub in_doubt: Option<usize>,
    pub items: Vec<AsyncTaskItem>,
    pub error_message: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncTaskItem {
    pub card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub operation_id: String,
    pub status: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationItemScope {
    pub card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub status: String,
    pub operation_id: String,
    pub error_message: Option<String>,
}

impl OperationItemScope {
    fn with_unknown_outcome(&self) -> Self {
        if matches!(self.status.as_str(), "PENDING" | "RUNNING") {
            Self {
                status: "IN_DOUBT".into(),
                error_message: Some("outcome is unknown after operation owner changed".into()),
                ..self.clone()
            }
        } else {
            self.clone()
        }
    }
}

/// Server-side facts needed for an authenticated operation status lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationScope {
    pub task_id: String,
    pub task_type: String,
    pub status: TaskStatus,
    pub requester_user_id: i64,
    pub requester_card_id: i64,
    pub requester_tenant_id: i64,
    pub requester_domain_id: i64,
    pub authorization_target_card_id: i64,
    pub authorization_target_tenant_id: i64,
    pub authorization_target_domain_id: i64,
    pub target_user_id: i64,
    pub items: Vec<OperationItemScope>,
    pub total_items: usize,
    pub completed_items: usize,
    pub error_message: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct CardBindItemInput {
    pub card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
}

#[derive(Debug, Clone)]
pub struct CardBindRegistration {
    pub task_id: String,
    pub requester_user_id: i64,
    pub requester_card_id: i64,
    pub requester_tenant_id: i64,
    pub requester_domain_id: i64,
    pub authorization_target_card_id: i64,
    pub authorization_target_tenant_id: i64,
    pub authorization_target_domain_id: i64,
    pub target_user_id: i64,
    pub items: Vec<CardBindItemInput>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct OperationRow {
    task_id: String,
    task_type: String,
    status: String,
    requester_user_id: i64,
    requester_card_id: i64,
    requester_tenant_id: i64,
    requester_domain_id: i64,
    authorization_target_card_id: i64,
    authorization_target_tenant_id: i64,
    authorization_target_domain_id: i64,
    target_user_id: i64,
    total_items: u32,
    completed_items: u32,
    owner_instance_id: String,
    error_message: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct OperationItemRow {
    card_id: i64,
    tenant_id: i64,
    domain_id: i64,
    operation_id: String,
    status: String,
    error_message: Option<String>,
}

/// One statement's consistent parent/item view for status polling.
#[derive(Debug, Clone, sqlx::FromRow)]
struct OperationSnapshotRow {
    task_id: String,
    task_type: String,
    status: String,
    requester_user_id: i64,
    requester_card_id: i64,
    requester_tenant_id: i64,
    requester_domain_id: i64,
    authorization_target_card_id: i64,
    authorization_target_tenant_id: i64,
    authorization_target_domain_id: i64,
    target_user_id: i64,
    total_items: u32,
    completed_items: u32,
    owner_instance_id: String,
    error_message: Option<String>,
    created_at: i64,
    updated_at: i64,
    item_card_id: Option<i64>,
    item_tenant_id: Option<i64>,
    item_domain_id: Option<i64>,
    item_operation_id: Option<String>,
    item_status: Option<String>,
    item_error_message: Option<String>,
}

fn derive_card_bind_terminal_status(
    current_status: &str,
    item_statuses: &[String],
    total_items: u32,
    completed_items: u32,
) -> Result<&'static str, AstralError> {
    if item_statuses.len() != total_items as usize
        || item_statuses
            .iter()
            .filter(|status| status.as_str() == "COMPLETED")
            .count()
            != completed_items as usize
    {
        return Err(AstralError::Database(
            "async operation completion evidence is inconsistent".into(),
        ));
    }
    if current_status == "IN_DOUBT"
        || item_statuses
            .iter()
            .any(|status| matches!(status.as_str(), "PENDING" | "RUNNING" | "IN_DOUBT"))
    {
        Ok("IN_DOUBT")
    } else if item_statuses.iter().any(|status| status == "FAILED") {
        Ok("FAILED")
    } else if completed_items == total_items {
        Ok("COMPLETED")
    } else {
        Ok("IN_DOUBT")
    }
}

fn database_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("async operation repository query failed: {error}"))
}

#[derive(Debug)]
enum CardBindRegistrationError {
    BeforeCommit(AstralError),
    CommitOutcomeUnknown(AstralError),
}

impl From<AstralError> for CardBindRegistrationError {
    fn from(error: AstralError) -> Self {
        Self::BeforeCommit(error)
    }
}

fn validate_task_id(task_id: &str) -> Result<(), AstralError> {
    if task_id.is_empty()
        || task_id.len() > MAX_TASK_ID_LENGTH
        || !task_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(AstralError::Validation("async task id is invalid".into()));
    }
    Ok(())
}

fn task_status(status: &str) -> Result<TaskStatus, AstralError> {
    match status {
        "PENDING" => Ok(TaskStatus::Pending),
        "RUNNING" => Ok(TaskStatus::Running),
        "COMPLETED" => Ok(TaskStatus::Completed),
        "FAILED" => Ok(TaskStatus::Failed),
        "IN_DOUBT" => Ok(TaskStatus::InDoubt),
        _ => Err(AstralError::Database(format!(
            "async operation has unknown status {status:?}"
        ))),
    }
}

fn validate_operation_items(
    row: &OperationRow,
    items: &[OperationItemRow],
) -> Result<(), AstralError> {
    if items.len() != row.total_items as usize
        || items
            .iter()
            .filter(|item| item.status == "COMPLETED")
            .count()
            != row.completed_items as usize
        || items.iter().any(|item| {
            item.status == "RUNNING" && !matches!(row.status.as_str(), "RUNNING" | "IN_DOUBT")
        })
        || (row.task_type == BATCH_BIND_TASK_TYPE
            && !items.iter().any(|item| {
                item.card_id == row.authorization_target_card_id
                    && item.tenant_id == row.authorization_target_tenant_id
                    && item.domain_id == row.authorization_target_domain_id
            }))
        || items.iter().any(|item| {
            item.card_id <= 0
                || item.tenant_id <= 0
                || item.domain_id <= 0
                || item.operation_id.is_empty()
                || item.operation_id.len() > 64
                || !item.operation_id.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
                })
                || !matches!(
                    item.status.as_str(),
                    "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "IN_DOUBT"
                )
        })
    {
        return Err(AstralError::Database(
            "async operation item scope/count/status is inconsistent".into(),
        ));
    }
    Ok(())
}

fn operation_item_scope(item: OperationItemRow) -> OperationItemScope {
    OperationItemScope {
        card_id: item.card_id,
        tenant_id: item.tenant_id,
        domain_id: item.domain_id,
        status: item.status,
        operation_id: item.operation_id,
        error_message: item.error_message,
    }
}

fn operation_owner_changed(status: &str, owner_instance_id: &str, local_instance_id: &str) -> bool {
    matches!(status, "PENDING" | "RUNNING" | "IN_DOUBT") && owner_instance_id != local_instance_id
}

fn epoch_seconds(value: i64) -> Result<i64, AstralError> {
    if value < 0 {
        return Err(AstralError::Database(
            "async timestamp is outside epoch range".into(),
        ));
    }
    Ok(value)
}

fn operation_row_to_task(
    row: &OperationRow,
    items: Vec<OperationItemRow>,
) -> Result<AsyncTask, AstralError> {
    let failed = items.iter().filter(|item| item.status == "FAILED").count();
    let in_doubt = items
        .iter()
        .filter(|item| item.status == "IN_DOUBT")
        .count();
    Ok(AsyncTask {
        task_id: row.task_id.clone(),
        task_type: row.task_type.clone(),
        status: task_status(&row.status)?,
        total: Some(row.total_items as usize),
        completed: Some(row.completed_items as usize),
        failed: Some(failed),
        in_doubt: Some(in_doubt),
        items: items
            .into_iter()
            .map(|item| AsyncTaskItem {
                card_id: item.card_id,
                tenant_id: item.tenant_id,
                domain_id: item.domain_id,
                operation_id: item.operation_id,
                status: item.status,
                error_message: item.error_message,
            })
            .collect(),
        error_message: row.error_message.clone(),
        created_at: epoch_seconds(row.created_at)?,
        updated_at: epoch_seconds(row.updated_at)?,
    })
}

fn batch_card_operation_id(task_id: &str, card_id: i64) -> Result<String, AstralError> {
    if card_id <= 0 {
        return Err(AstralError::Validation(
            "card-bind item card id must be positive".into(),
        ));
    }
    let mut hash = Sha256::new();
    hash.update(b"astral:batch-card-bind:v1:");
    hash.update((task_id.len() as u64).to_be_bytes());
    hash.update(task_id.as_bytes());
    hash.update(card_id.to_be_bytes());
    let digest = hash.finalize();
    let encoded = digest[..24]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("batch-bind:{encoded}"))
}

fn validate_card_bind_registration(registration: &CardBindRegistration) -> Result<(), AstralError> {
    let task_id = registration.task_id.as_str();
    let requester_user_id = registration.requester_user_id;
    let requester_card_id = registration.requester_card_id;
    let requester_tenant_id = registration.requester_tenant_id;
    let requester_domain_id = registration.requester_domain_id;
    let authorization_target_card_id = registration.authorization_target_card_id;
    let authorization_target_tenant_id = registration.authorization_target_tenant_id;
    let authorization_target_domain_id = registration.authorization_target_domain_id;
    let target_user_id = registration.target_user_id;
    let items = registration.items.as_slice();
    validate_task_id(task_id)?;
    if items.len() > MAX_CARD_BIND_ITEMS {
        return Err(AstralError::Validation(format!(
            "card bind batch exceeds maximum size {MAX_CARD_BIND_ITEMS}"
        )));
    }
    if requester_user_id <= 0
        || requester_card_id <= 0
        || requester_tenant_id <= 0
        || requester_domain_id <= 0
        || authorization_target_card_id <= 0
        || authorization_target_tenant_id <= 0
        || authorization_target_domain_id <= 0
        || target_user_id <= 0
        || items.is_empty()
        || !items
            .iter()
            .any(|item| item.card_id == authorization_target_card_id)
        || items
            .iter()
            .any(|item| item.card_id <= 0 || item.tenant_id <= 0 || item.domain_id <= 0)
    {
        return Err(AstralError::Validation(
            "card bind operation requires verified requester, anchor, target, and item scope"
                .into(),
        ));
    }
    if items.iter().any(|item| {
        item.card_id == authorization_target_card_id
            && (item.tenant_id != authorization_target_tenant_id
                || item.domain_id != authorization_target_domain_id)
    }) {
        return Err(AstralError::Validation(
            "authorization anchor scope does not match its immutable batch item scope".into(),
        ));
    }
    let mut sorted = items.to_vec();
    sorted.sort_by_key(|item| item.card_id);
    sorted.dedup_by_key(|item| item.card_id);
    if sorted.len() != items.len() {
        return Err(AstralError::Validation(
            "card bind operation must contain unique card ids".into(),
        ));
    }
    Ok(())
}

/// Persist the accepted request and each child boundary before starting work.
async fn register_card_bind(
    pool: &MySqlPool,
    registration: &CardBindRegistration,
) -> Result<AsyncTask, CardBindRegistrationError> {
    let task_id = registration.task_id.as_str();
    let requester_user_id = registration.requester_user_id;
    let requester_card_id = registration.requester_card_id;
    let requester_tenant_id = registration.requester_tenant_id;
    let requester_domain_id = registration.requester_domain_id;
    let authorization_target_card_id = registration.authorization_target_card_id;
    let authorization_target_tenant_id = registration.authorization_target_tenant_id;
    let authorization_target_domain_id = registration.authorization_target_domain_id;
    let target_user_id = registration.target_user_id;
    let items = registration.items.as_slice();
    validate_card_bind_registration(registration)?;
    let total = u32::try_from(items.len())
        .map_err(|_| AstralError::Validation("card bind batch is too large".into()))?;
    let instance = current_instance_id();
    let mut tx = pool.begin().await.map_err(database_error)?;
    sqlx::query(
        "INSERT INTO async_operation \
         (task_id, task_type, status, requester_user_id, requester_card_id, requester_tenant_id, \
          requester_domain_id, authorization_target_card_id, authorization_target_tenant_id, \
          authorization_target_domain_id, target_user_id, total_items, completed_items, \
          owner_instance_id, created_at, updated_at) \
         VALUES (?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())",
    )
    .bind(task_id)
    .bind(BATCH_BIND_TASK_TYPE)
    .bind(requester_user_id)
    .bind(requester_card_id)
    .bind(requester_tenant_id)
    .bind(requester_domain_id)
    .bind(authorization_target_card_id)
    .bind(authorization_target_tenant_id)
    .bind(authorization_target_domain_id)
    .bind(target_user_id)
    .bind(total)
    .bind(instance)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;

    let mut sorted_items = items.to_vec();
    sorted_items.sort_by_key(|item| item.card_id);
    let persisted_items = sorted_items
        .iter()
        .map(|item| Ok((item, batch_card_operation_id(task_id, item.card_id)?)))
        .collect::<Result<Vec<_>, AstralError>>()?;
    for (item, operation_id) in &persisted_items {
        sqlx::query(
            "INSERT INTO async_operation_item \
             (task_id, card_id, tenant_id, domain_id, operation_id, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, 'PENDING', UNIX_TIMESTAMP(), UNIX_TIMESTAMP())",
        )
        .bind(task_id)
        .bind(item.card_id)
        .bind(item.tenant_id)
        .bind(item.domain_id)
        .bind(operation_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    }
    let (created_at, updated_at): (i64, i64) =
        sqlx::query_as("SELECT created_at, updated_at FROM async_operation WHERE task_id = ?")
            .bind(task_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
    let task = AsyncTask {
        task_id: task_id.to_owned(),
        task_type: BATCH_BIND_TASK_TYPE.to_owned(),
        status: TaskStatus::Pending,
        total: Some(items.len()),
        completed: Some(0),
        failed: Some(0),
        in_doubt: Some(0),
        items: persisted_items
            .iter()
            .map(|(item, operation_id)| AsyncTaskItem {
                card_id: item.card_id,
                tenant_id: item.tenant_id,
                domain_id: item.domain_id,
                operation_id: operation_id.clone(),
                status: "PENDING".into(),
                error_message: None,
            })
            .collect(),
        error_message: None,
        created_at: epoch_seconds(created_at)?,
        updated_at: epoch_seconds(updated_at)?,
    };
    // Registration's commit runs inside an already tracker-owned worker.
    tx.commit()
        .await
        .map_err(|error| CardBindRegistrationError::CommitOutcomeUnknown(database_error(error)))?;
    Ok(task)
}

async fn fetch_operation_row(
    pool: &MySqlPool,
    task_id: &str,
) -> Result<Option<OperationRow>, AstralError> {
    sqlx::query_as::<_, OperationRow>(
        "SELECT task_id, task_type, status, requester_user_id, requester_card_id, \\
                requester_tenant_id, requester_domain_id, authorization_target_card_id, \\
                authorization_target_tenant_id, authorization_target_domain_id, target_user_id, \\
                total_items, completed_items, owner_instance_id, error_message, \\
                created_at, updated_at \\
         FROM async_operation WHERE task_id = ?",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await
    .map_err(database_error)
}

async fn fetch_operation_snapshot(
    pool: &MySqlPool,
    task_id: &str,
    limit: u32,
) -> Result<Option<(OperationRow, Vec<OperationItemRow>)>, AstralError> {
    let rows = sqlx::query_as::<_, OperationSnapshotRow>(
        "SELECT op.task_id, op.task_type, op.status, op.requester_user_id, \
                op.requester_card_id, op.requester_tenant_id, op.requester_domain_id, \
                op.authorization_target_card_id, op.authorization_target_tenant_id, \
                op.authorization_target_domain_id, op.target_user_id, op.total_items, \
                op.completed_items, op.owner_instance_id, op.error_message, \
                op.created_at, op.updated_at, item.card_id AS item_card_id, \
                item.tenant_id AS item_tenant_id, item.domain_id AS item_domain_id, \
                item.operation_id AS item_operation_id, item.status AS item_status, \
                item.error_message AS item_error_message \
         FROM async_operation op LEFT JOIN async_operation_item item ON item.task_id = op.task_id \
         WHERE op.task_id = ? ORDER BY item.card_id LIMIT ?",
    )
    .bind(task_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(database_error)?;
    split_operation_snapshot(rows)
}

fn split_operation_snapshot(
    rows: Vec<OperationSnapshotRow>,
) -> Result<Option<(OperationRow, Vec<OperationItemRow>)>, AstralError> {
    let mut snapshots = rows.into_iter();
    let Some(first) = snapshots.next() else {
        return Ok(None);
    };
    let row = OperationRow {
        task_id: first.task_id.clone(),
        task_type: first.task_type.clone(),
        status: first.status.clone(),
        requester_user_id: first.requester_user_id,
        requester_card_id: first.requester_card_id,
        requester_tenant_id: first.requester_tenant_id,
        requester_domain_id: first.requester_domain_id,
        authorization_target_card_id: first.authorization_target_card_id,
        authorization_target_tenant_id: first.authorization_target_tenant_id,
        authorization_target_domain_id: first.authorization_target_domain_id,
        target_user_id: first.target_user_id,
        total_items: first.total_items,
        completed_items: first.completed_items,
        owner_instance_id: first.owner_instance_id.clone(),
        error_message: first.error_message.clone(),
        created_at: first.created_at,
        updated_at: first.updated_at,
    };
    let mut items = Vec::new();
    for snapshot in std::iter::once(first).chain(snapshots) {
        if let Some(card_id) = snapshot.item_card_id {
            let (Some(tenant_id), Some(domain_id), Some(operation_id), Some(status)) = (
                snapshot.item_tenant_id,
                snapshot.item_domain_id,
                snapshot.item_operation_id,
                snapshot.item_status,
            ) else {
                return Err(AstralError::Database(
                    "async operation item snapshot is incomplete".into(),
                ));
            };
            items.push(OperationItemRow {
                card_id,
                tenant_id,
                domain_id,
                operation_id,
                status,
                error_message: snapshot.item_error_message,
            });
        } else if snapshot.item_tenant_id.is_some()
            || snapshot.item_domain_id.is_some()
            || snapshot.item_operation_id.is_some()
            || snapshot.item_status.is_some()
            || snapshot.item_error_message.is_some()
        {
            return Err(AstralError::Database(
                "async operation item snapshot is incomplete".into(),
            ));
        }
    }
    Ok(Some((row, items)))
}

pub async fn get_task(pool: &MySqlPool, task_id: &str) -> Result<Option<AsyncTask>, AstralError> {
    validate_task_id(task_id)?;
    let Some((row, items)) =
        fetch_operation_snapshot(pool, task_id, (MAX_CARD_BIND_ITEMS + 1) as u32).await?
    else {
        return Ok(None);
    };
    validate_operation_items(&row, &items)?;
    Ok(Some(operation_row_to_task(&row, items)?))
}

pub async fn load_operation_scope(
    pool: &MySqlPool,
    task_id: &str,
) -> Result<Option<OperationScope>, AstralError> {
    validate_task_id(task_id)?;
    let Some((row, item_rows)) =
        fetch_operation_snapshot(pool, task_id, (MAX_CARD_BIND_ITEMS + 1) as u32).await?
    else {
        return Ok(None);
    };
    if row.total_items as usize > MAX_CARD_BIND_ITEMS {
        return Err(AstralError::Database(
            "async operation exceeds the supported item cap".into(),
        ));
    }
    validate_operation_items(&row, &item_rows)?;
    let items = item_rows
        .into_iter()
        .map(operation_item_scope)
        .collect::<Vec<_>>();

    // A process restart cannot prove the outcome of work whose owner changed.
    // Present IN_DOUBT without mutating a task owned by another live replica.
    let mut status = row.status.clone();
    let mut error_message = row.error_message.clone();
    let owner_changed =
        operation_owner_changed(&row.status, &row.owner_instance_id, current_instance_id());
    let items = if owner_changed {
        if row.status != "IN_DOUBT" {
            status = "IN_DOUBT".to_owned();
            error_message = Some(
                "operation owner is another process; reconcile per-card source and audit evidence"
                    .into(),
            );
        }
        items
            .iter()
            .map(OperationItemScope::with_unknown_outcome)
            .collect()
    } else {
        items
    };

    let completed_items = items
        .iter()
        .filter(|item| item.status == "COMPLETED")
        .count();
    Ok(Some(OperationScope {
        task_id: row.task_id,
        task_type: row.task_type,
        status: task_status(&status)?,
        requester_user_id: row.requester_user_id,
        requester_card_id: row.requester_card_id,
        requester_tenant_id: row.requester_tenant_id,
        requester_domain_id: row.requester_domain_id,
        authorization_target_card_id: row.authorization_target_card_id,
        authorization_target_tenant_id: row.authorization_target_tenant_id,
        authorization_target_domain_id: row.authorization_target_domain_id,
        target_user_id: row.target_user_id,
        total_items: row.total_items as usize,
        completed_items,
        items,
        error_message,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }))
}

pub async fn load_operation_for_requester(
    pool: &MySqlPool,
    task_id: &str,
    requester_user_id: i64,
    requester_card_id: i64,
    requester_tenant_id: i64,
    requester_domain_id: i64,
) -> Result<Option<AsyncTask>, AstralError> {
    let Some(scope) = load_operation_scope(pool, task_id).await? else {
        return Ok(None);
    };
    if scope.task_type != BATCH_BIND_TASK_TYPE
        || scope.requester_user_id != requester_user_id
        || scope.requester_card_id != requester_card_id
        || scope.requester_tenant_id != requester_tenant_id
        || scope.requester_domain_id != requester_domain_id
    {
        return Ok(None);
    }
    Ok(Some(AsyncTask {
        task_id: scope.task_id,
        task_type: scope.task_type,
        status: scope.status,
        total: Some(scope.total_items),
        completed: Some(scope.completed_items),
        failed: Some(
            scope
                .items
                .iter()
                .filter(|item| item.status == "FAILED")
                .count(),
        ),
        in_doubt: Some(
            scope
                .items
                .iter()
                .filter(|item| item.status == "IN_DOUBT")
                .count(),
        ),
        items: scope
            .items
            .into_iter()
            .map(|item| AsyncTaskItem {
                card_id: item.card_id,
                tenant_id: item.tenant_id,
                domain_id: item.domain_id,
                operation_id: item.operation_id,
                status: item.status,
                error_message: item.error_message,
            })
            .collect(),
        error_message: scope.error_message,
        created_at: scope.created_at,
        updated_at: scope.updated_at,
    }))
}

pub async fn start_card_bind(pool: &MySqlPool, task_id: &str) -> Result<(), AstralError> {
    validate_task_id(task_id)?;
    let result = sqlx::query(
        "UPDATE async_operation SET status = 'RUNNING', updated_at = UNIX_TIMESTAMP() \
         WHERE task_id = ? AND status = 'PENDING' AND owner_instance_id = ?",
    )
    .bind(task_id)
    .bind(current_instance_id())
    .execute(pool)
    .await
    .map_err(database_error)?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Database(
            "async task could not enter RUNNING".into(),
        ));
    }
    Ok(())
}

/// Persist only untouched child work as unknown after cooperative shutdown or an
/// owner task failure. In-flight item/source commits remain unknown if a result
/// was not durably recorded by their same-transaction source path.
pub async fn mark_card_bind_remaining_in_doubt(
    pool: &MySqlPool,
    task_id: &str,
    reason: &str,
) -> Result<(), AstralError> {
    validate_task_id(task_id)?;
    let reason = reason.chars().take(255).collect::<String>();
    let mut tx = pool.begin().await.map_err(database_error)?;
    let parent: Option<(String, String)> = sqlx::query_as(
        "SELECT status, owner_instance_id FROM async_operation WHERE task_id = ? FOR UPDATE",
    )
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    let Some((status, owner)) = parent else {
        return Err(AstralError::Database(
            "async operation disappeared while recording unknown outcome".into(),
        ));
    };
    if owner != current_instance_id() {
        return Err(AstralError::Database(
            "async operation unknown-outcome owner mismatch".into(),
        ));
    }
    if matches!(status.as_str(), "PENDING" | "RUNNING" | "IN_DOUBT") {
        let remaining = sqlx::query(
            "UPDATE async_operation_item SET status = 'IN_DOUBT', error_message = ?, \
                    updated_at = UNIX_TIMESTAMP() WHERE task_id = ? AND status IN ('PENDING', 'RUNNING')",
        )
        .bind(&reason)
        .bind(task_id)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if remaining.rows_affected() > 0 {
            sqlx::query(
                "UPDATE async_operation SET status = 'IN_DOUBT', error_message = ?, updated_at = UNIX_TIMESTAMP() \
                 WHERE task_id = ? AND status IN ('PENDING', 'RUNNING', 'IN_DOUBT') AND owner_instance_id = ?",
            )
            .bind(reason)
            .bind(task_id)
            .bind(current_instance_id())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        }
    }
    tx.commit().await.map_err(database_error)
}

pub async fn mark_card_bind_item_running(
    pool: &MySqlPool,
    task_id: &str,
    card_id: i64,
) -> Result<Option<OperationItemScope>, AstralError> {
    validate_task_id(task_id)?;
    let mut tx = pool.begin().await.map_err(database_error)?;
    let owner: Option<(String, String)> = sqlx::query_as(
        "SELECT status, owner_instance_id FROM async_operation WHERE task_id = ? FOR UPDATE",
    )
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    if owner
        .as_ref()
        .is_none_or(|(status, instance)| status != "RUNNING" || instance != current_instance_id())
    {
        return Err(AstralError::Database(
            "async task owner or status does not permit starting a child".into(),
        ));
    }
    let result = sqlx::query(
        "UPDATE async_operation_item SET status = 'RUNNING', updated_at = UNIX_TIMESTAMP() \
         WHERE task_id = ? AND card_id = ? AND status = 'PENDING'",
    )
    .bind(task_id)
    .bind(card_id)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    if result.rows_affected() != 1 {
        tx.commit().await.map_err(database_error)?;
        return Ok(None);
    }
    let row = sqlx::query_as::<_, OperationItemRow>(
        "SELECT card_id, tenant_id, domain_id, operation_id, status, error_message \
         FROM async_operation_item WHERE task_id = ? AND card_id = ?",
    )
    .bind(task_id)
    .bind(card_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(database_error)?;
    tx.commit().await.map_err(database_error)?;
    Ok(Some(operation_item_scope(row)))
}

pub async fn fail_card_bind_item(
    pool: &MySqlPool,
    task_id: &str,
    card_id: i64,
    status: &str,
    error: &str,
) -> Result<(), AstralError> {
    validate_task_id(task_id)?;
    if !matches!(status, "FAILED" | "IN_DOUBT") {
        return Err(AstralError::Validation(
            "card bind item outcome must be FAILED or IN_DOUBT".into(),
        ));
    }
    let error = error.chars().take(255).collect::<String>();
    let mut tx = pool.begin().await.map_err(database_error)?;
    let item = sqlx::query(
        "UPDATE async_operation_item SET status = ?, error_message = ?, \
                updated_at = UNIX_TIMESTAMP() WHERE task_id = ? AND card_id = ? AND status = 'RUNNING'",
    )
    .bind(status)
    .bind(error.clone())
    .bind(task_id)
    .bind(card_id)
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    if item.rows_affected() != 1 {
        return Err(AstralError::Database(
            "async operation item failure could not be proven".into(),
        ));
    }
    if status == "IN_DOUBT" {
        sqlx::query(
            "UPDATE async_operation SET status = 'IN_DOUBT', error_message = ?, updated_at = UNIX_TIMESTAMP() \
             WHERE task_id = ? AND status = 'RUNNING' AND owner_instance_id = ?",
        )
        .bind(error)
        .bind(task_id)
        .bind(current_instance_id())
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    }
    tx.commit().await.map_err(database_error)
}

const MARK_UNFINISHED_CARD_BIND_ITEMS_IN_DOUBT_SQL: &str =
    "UPDATE async_operation_item SET status = 'IN_DOUBT', \
     error_message = COALESCE(error_message, 'operation owner ended before completion was proven'), \
     updated_at = UNIX_TIMESTAMP() \
     WHERE task_id = ? AND status IN ('PENDING', 'RUNNING')";
const UPDATE_CARD_BIND_IN_DOUBT_PARENT_ERROR_SQL: &str =
    "UPDATE async_operation SET error_message = COALESCE(error_message, ?), \
     updated_at = UNIX_TIMESTAMP() WHERE task_id = ? AND status = 'IN_DOUBT' \
     AND owner_instance_id = ?";

pub async fn finish_card_bind(
    pool: &MySqlPool,
    task_id: &str,
    _cancelled: bool,
) -> Result<(), AstralError> {
    validate_task_id(task_id)?;
    let mut tx = pool.begin().await.map_err(database_error)?;
    let parent: Option<(u32, u32, String, String)> = sqlx::query_as(
        "SELECT total_items, completed_items, status, owner_instance_id \
         FROM async_operation WHERE task_id = ? FOR UPDATE",
    )
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    let Some((total_items, completed_items, current_status, owner)) = parent else {
        return Err(AstralError::Database(
            "async operation disappeared before finish".into(),
        ));
    };
    if owner != current_instance_id() {
        return Err(AstralError::Database(
            "async operation finish owner mismatch".into(),
        ));
    }
    if !matches!(current_status.as_str(), "PENDING" | "RUNNING") {
        if current_status == "IN_DOUBT" {
            let item_statuses: Vec<String> = sqlx::query_scalar(
                "SELECT status FROM async_operation_item WHERE task_id = ? ORDER BY card_id FOR UPDATE",
            )
            .bind(task_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(database_error)?;
            if item_statuses.len() != total_items as usize
                || item_statuses
                    .iter()
                    .filter(|status| *status == "COMPLETED")
                    .count()
                    != completed_items as usize
            {
                return Err(AstralError::Database(
                    "async operation completion evidence is inconsistent".into(),
                ));
            }
            let remaining = sqlx::query(MARK_UNFINISHED_CARD_BIND_ITEMS_IN_DOUBT_SQL)
                .bind(task_id)
                .execute(&mut *tx)
                .await
                .map_err(database_error)?;
            if remaining.rows_affected() > 0 {
                sqlx::query(UPDATE_CARD_BIND_IN_DOUBT_PARENT_ERROR_SQL)
                    .bind("operation owner ended before completion was proven")
                    .bind(task_id)
                    .bind(current_instance_id())
                    .execute(&mut *tx)
                    .await
                    .map_err(database_error)?;
            }
        }
        tx.commit().await.map_err(database_error)?;
        return Ok(());
    }
    let item_statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM async_operation_item WHERE task_id = ? ORDER BY card_id FOR UPDATE",
    )
    .bind(task_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(database_error)?;
    let status = derive_card_bind_terminal_status(
        &current_status,
        &item_statuses,
        total_items,
        completed_items,
    )?;
    let error_message = if status == "IN_DOUBT" {
        Some("operation ended without durable proof for every item".to_owned())
    } else {
        None
    };
    let result = sqlx::query(
        "UPDATE async_operation SET status = ?, error_message = ?, updated_at = UNIX_TIMESTAMP() \
         WHERE task_id = ? AND status IN ('PENDING', 'RUNNING') AND owner_instance_id = ?",
    )
    .bind(status)
    .bind(error_message)
    .bind(task_id)
    .bind(current_instance_id())
    .execute(&mut *tx)
    .await
    .map_err(database_error)?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Database(
            "async operation terminal status was not persisted".into(),
        ));
    }
    tx.commit().await.map_err(database_error)
}

pub async fn list_pending_card_bind_items(
    pool: &MySqlPool,
    task_id: &str,
) -> Result<Vec<OperationItemScope>, AstralError> {
    validate_task_id(task_id)?;
    let rows = sqlx::query_as::<_, OperationItemRow>(
        "SELECT card_id, tenant_id, domain_id, operation_id, status, error_message \
         FROM async_operation_item WHERE task_id = ? AND status = 'PENDING' ORDER BY card_id",
    )
    .bind(task_id)
    .fetch_all(pool)
    .await
    .map_err(database_error)?;
    Ok(rows.into_iter().map(operation_item_scope).collect())
}

/// Reconcile only a task registered by this process. It never resumes or replays
/// child source mutations; any unproven PENDING/RUNNING item becomes IN_DOUBT.
async fn reconcile_card_bind_after_owner_exit(
    pool: &MySqlPool,
    task_id: &str,
    reason: &str,
) -> Result<Option<()>, AstralError> {
    validate_task_id(task_id)?;
    let Some(row) = fetch_operation_row(pool, task_id).await? else {
        return Ok(None);
    };
    if row.task_type != BATCH_BIND_TASK_TYPE || row.owner_instance_id != current_instance_id() {
        return Err(AstralError::Database(
            "refusing to reconcile a card-bind task owned by another operation".into(),
        ));
    }
    if matches!(row.status.as_str(), "PENDING" | "RUNNING" | "IN_DOUBT") {
        mark_card_bind_remaining_in_doubt(pool, task_id, reason).await?;
        finish_card_bind(pool, task_id, true).await?;
    }
    Ok(Some(()))
}

const REGISTRATION_RECONCILIATION_ATTEMPTS: usize = 5;
const REGISTRATION_RECONCILIATION_DELAY: Duration = Duration::from_millis(100);
const REGISTRATION_RECONCILIATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Retry bounded reads after an ambiguous commit. A single missing row is not
/// proof of rollback; false leaves the local ownership record in place.
async fn reconcile_card_bind_after_owner_exit_bounded(
    pool: &MySqlPool,
    task_id: &str,
    reason: &str,
) -> Result<bool, AstralError> {
    let reconcile = async {
        let mut last_error = None;
        for attempt in 0..REGISTRATION_RECONCILIATION_ATTEMPTS {
            match reconcile_card_bind_after_owner_exit(pool, task_id, reason).await {
                Ok(Some(())) => return Ok(true),
                Ok(None) => {}
                Err(error) => last_error = Some(error),
            }
            if attempt + 1 < REGISTRATION_RECONCILIATION_ATTEMPTS {
                tokio::time::sleep(REGISTRATION_RECONCILIATION_DELAY).await;
            }
        }
        if let Some(error) = last_error {
            Err(error)
        } else {
            Ok(false)
        }
    };
    tokio::time::timeout(REGISTRATION_RECONCILIATION_TIMEOUT, reconcile)
        .await
        .map_err(|_| {
            AstralError::Database(
                "bounded card-bind reconciliation timed out; ownership remains unresolved".into(),
            )
        })?
}

fn current_instance_id() -> &'static str {
    static INSTANCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    INSTANCE.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_ids_are_bounded_and_canonical() {
        let id = generate_task_id("uc_bind");
        assert!(id.len() <= MAX_TASK_ID_LENGTH);
        assert!(validate_task_id(&id).is_ok());
        assert!(validate_task_id(&"x".repeat(MAX_TASK_ID_LENGTH + 1)).is_err());
        assert!(validate_task_id("contains space").is_err());
    }

    #[test]
    fn per_card_operation_ids_bind_task_and_card() {
        let left = batch_card_operation_id("uc_bind:task1", 7).unwrap();
        let right = batch_card_operation_id("uc_bind:task1", 8).unwrap();
        assert_ne!(left, right);
        assert!(left.starts_with("batch-bind:"));
        assert!(left.len() <= 64);
        assert_eq!(left, batch_card_operation_id("uc_bind:task1", 7).unwrap());
        assert!(batch_card_operation_id("uc_bind:task1", 0).is_err());
        assert!(batch_card_operation_id(&"x".repeat(60), 1).unwrap().len() <= 64);
    }

    #[test]
    fn restart_status_is_explicit_in_doubt_not_completed() {
        assert_eq!(task_status("IN_DOUBT").unwrap(), TaskStatus::InDoubt);
        assert!(task_status("RUNNING").is_ok());
        assert!(task_status("MYSTERY").is_err());
    }

    #[test]
    fn operation_items_require_exact_anchor_and_completion_evidence() {
        fn row() -> OperationRow {
            OperationRow {
                task_id: "task:1".into(),
                task_type: BATCH_BIND_TASK_TYPE.into(),
                status: "RUNNING".into(),
                requester_user_id: 1,
                requester_card_id: 2,
                requester_tenant_id: 3,
                requester_domain_id: 4,
                authorization_target_card_id: 9,
                authorization_target_tenant_id: 10,
                authorization_target_domain_id: 11,
                target_user_id: 12,
                total_items: 2,
                completed_items: 1,
                owner_instance_id: "owner".into(),
                error_message: None,
                created_at: 1,
                updated_at: 2,
            }
        }
        let items = vec![
            OperationItemRow {
                card_id: 9,
                tenant_id: 10,
                domain_id: 11,
                operation_id: "operation-9".into(),
                status: "COMPLETED".into(),
                error_message: None,
            },
            OperationItemRow {
                card_id: 13,
                tenant_id: 14,
                domain_id: 15,
                operation_id: "operation-13".into(),
                status: "RUNNING".into(),
                error_message: None,
            },
        ];
        validate_operation_items(&row(), &items).unwrap();
        let mut missing_anchor = items.clone();
        missing_anchor[0].tenant_id += 1;
        assert!(validate_operation_items(&row(), &missing_anchor).is_err());
        let mut false_completion = row();
        false_completion.completed_items = 2;
        assert!(validate_operation_items(&false_completion, &items).is_err());
        let mut unknown_status = items;
        unknown_status[1].status = "SUCCESS".into();
        assert!(validate_operation_items(&row(), &unknown_status).is_err());
    }

    #[test]
    fn foreign_in_doubt_parent_masks_unfinished_children() {
        assert!(operation_owner_changed("PENDING", "other", "this"));
        assert!(operation_owner_changed("RUNNING", "other", "this"));
        assert!(operation_owner_changed("IN_DOUBT", "other", "this"));
        assert!(!operation_owner_changed("IN_DOUBT", "this", "this"));

        let pending = OperationItemScope {
            card_id: 21,
            tenant_id: 4,
            domain_id: 5,
            status: "PENDING".into(),
            operation_id: "child-21".into(),
            error_message: None,
        };
        let unknown = pending.with_unknown_outcome();
        assert_eq!(unknown.status, "IN_DOUBT");
        assert_eq!(unknown.card_id, pending.card_id);
        assert_eq!(unknown.operation_id, pending.operation_id);
    }

    #[test]
    fn operation_snapshot_is_joined_in_one_parent_item_result() {
        let parent_fields = || OperationSnapshotRow {
            task_id: "task:1".into(),
            task_type: BATCH_BIND_TASK_TYPE.into(),
            status: "RUNNING".into(),
            requester_user_id: 1,
            requester_card_id: 2,
            requester_tenant_id: 3,
            requester_domain_id: 4,
            authorization_target_card_id: 9,
            authorization_target_tenant_id: 10,
            authorization_target_domain_id: 11,
            target_user_id: 12,
            total_items: 2,
            completed_items: 1,
            owner_instance_id: "owner".into(),
            error_message: None,
            created_at: 1,
            updated_at: 2,
            item_card_id: None,
            item_tenant_id: None,
            item_domain_id: None,
            item_operation_id: None,
            item_status: None,
            item_error_message: None,
        };
        let mut completed = parent_fields();
        completed.item_card_id = Some(9);
        completed.item_tenant_id = Some(10);
        completed.item_domain_id = Some(11);
        completed.item_operation_id = Some("operation-9".into());
        completed.item_status = Some("COMPLETED".into());
        let mut running = parent_fields();
        running.item_card_id = Some(13);
        running.item_tenant_id = Some(14);
        running.item_domain_id = Some(15);
        running.item_operation_id = Some("operation-13".into());
        running.item_status = Some("RUNNING".into());

        let (row, items) = split_operation_snapshot(vec![completed, running])
            .unwrap()
            .unwrap();
        validate_operation_items(&row, &items).unwrap();
        assert_eq!(row.completed_items, 1);
        assert_eq!(items.len(), 2);
        assert!(split_operation_snapshot(Vec::new()).unwrap().is_none());
    }

    #[test]
    fn tracker_owned_batch_registration_has_no_request_future_registration_await() {
        let source = include_str!("async_tracker.rs");
        let implementation_start = source
            .rfind("impl AsyncOperationTracker {")
            .expect("tracker implementation must exist");
        let implementation = &source[implementation_start..];
        let method_start = implementation
            .find("    pub(crate) async fn register_card_bind_and_spawn")
            .expect("registration method must exist");
        let method = &implementation[method_start..];
        let method_end = method
            .find("    pub async fn shutdown_tasks")
            .expect("shutdown method must follow registration");
        let body = &method[..method_end];
        let worker = body
            .find("let worker = async move")
            .expect("registration work must be captured by a tracker-owned future");
        let transaction = body
            .find("register_card_bind(&task_pool, &registration).await")
            .expect("registration transaction must run in the tracker-owned future");
        let spawn = body
            .find("spawn_owned_reserved_with_card_bind(reservation, task_id, pool.clone(), worker)")
            .expect("registration worker must be installed in the owned JoinSet");
        assert!(worker < transaction && transaction < spawn);
        assert!(body.contains("result_rx.await"));
        assert!(body.contains("oneshot::channel()"));
        assert!(body.contains("reconcile_card_bind_after_owner_exit_bounded"));
    }

    #[test]
    fn single_negative_reconciliation_does_not_discard_local_ownership() {
        let source = include_str!("async_tracker.rs");
        let helper = source
            .split("async fn reconcile_card_bind_after_owner_exit_bounded")
            .nth(1)
            .and_then(|rest| rest.split("fn current_instance_id").next())
            .expect("bounded reconciliation helper must exist");
        assert!(helper.contains("REGISTRATION_RECONCILIATION_ATTEMPTS"));
        assert!(helper.contains("Ok(false)"));
        assert!(helper.contains("REGISTRATION_RECONCILIATION_TIMEOUT"));
        let implementation_start = source
            .rfind("impl AsyncOperationTracker {")
            .expect("tracker implementation must exist");
        let implementation = &source[implementation_start..];
        let method_start = implementation
            .find("    pub(crate) async fn register_card_bind_and_spawn")
            .expect("registration method must exist");
        let method = &implementation[method_start..];
        let unknown_handling = method
            .split("Err(CardBindRegistrationError::CommitOutcomeUnknown(error))")
            .nth(1)
            .and_then(|rest| rest.split("let _ = result_tx.send(Ok(accepted))").next())
            .expect("ambiguous commit path must exist");
        assert!(unknown_handling.contains("Ok(false)"));
        assert!(unknown_handling.contains("terminal_failure"));
        assert!(!unknown_handling.contains("registered_card_binds.remove"));
    }

    #[test]
    fn in_doubt_finalizer_sql_has_no_literal_backslashes() {
        for sql in [
            MARK_UNFINISHED_CARD_BIND_ITEMS_IN_DOUBT_SQL,
            UPDATE_CARD_BIND_IN_DOUBT_PARENT_ERROR_SQL,
        ] {
            assert!(!sql.contains('\\'));
        }
    }

    #[test]
    fn terminal_status_uses_durable_child_evidence_not_shutdown_flag() {
        assert_eq!(
            derive_card_bind_terminal_status(
                "RUNNING",
                &["COMPLETED".into(), "COMPLETED".into()],
                2,
                2,
            )
            .unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            derive_card_bind_terminal_status(
                "RUNNING",
                &["COMPLETED".into(), "FAILED".into()],
                2,
                1,
            )
            .unwrap(),
            "FAILED"
        );
        assert_eq!(
            derive_card_bind_terminal_status(
                "RUNNING",
                &["COMPLETED".into(), "IN_DOUBT".into()],
                2,
                1,
            )
            .unwrap(),
            "IN_DOUBT"
        );
        assert!(derive_card_bind_terminal_status("RUNNING", &["COMPLETED".into()], 2, 1,).is_err());
    }

    #[test]
    fn batch_registration_and_shutdown_share_a_single_admission_gate() {
        let source = include_str!("async_tracker.rs");
        let implementation_start = source
            .rfind("impl AsyncOperationTracker {")
            .expect("tracker implementation must exist");
        let implementation = &source[implementation_start..];
        let method_start = implementation
            .find("    pub(crate) async fn register_card_bind_and_spawn")
            .expect("batch registration method must exist");
        let method = &implementation[method_start..];
        let method_end = method
            .find("    pub async fn shutdown_tasks")
            .expect("shutdown method must follow registration");
        let registration = &method[..method_end];
        let spawn = registration
            .find("spawn_owned_reserved_with_card_bind(reservation, task_id, pool.clone(), worker)")
            .unwrap();
        let register = registration
            .find("register_card_bind(&task_pool, &registration).await")
            .unwrap();
        assert!(register < spawn);
        let shutdown_start = implementation
            .find("    pub async fn shutdown_tasks")
            .expect("shutdown method must exist");
        let shutdown = &implementation[shutdown_start..];
        assert!(
            shutdown.find("state.closing = true").unwrap() < shutdown.find("join_next").unwrap()
        );
        assert!(
            shutdown.find("abort_all()").unwrap()
                < shutdown
                    .find("reconcile_card_bind_after_owner_exit")
                    .unwrap()
        );
    }

    #[test]
    fn aggregate_unknown_items_never_count_as_failed_or_completed() {
        let items = ["PENDING", "RUNNING", "FAILED", "IN_DOUBT", "COMPLETED"];
        let failed = items.iter().filter(|status| **status == "FAILED").count();
        let in_doubt = items.iter().filter(|status| **status == "IN_DOUBT").count();
        assert_eq!(failed, 1);
        assert_eq!(in_doubt, 1);
        assert_eq!(
            items
                .iter()
                .filter(|status| **status == "COMPLETED")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn owned_task_shutdown_preserves_panics_and_cancellations() {
        let tracker = AsyncOperationTracker::new();
        tracker
            .spawn_owned(async { panic!("worker evidence") })
            .await
            .unwrap();
        assert!(tracker
            .shutdown_tasks(Duration::from_secs(1))
            .await
            .is_err());
        assert!(tracker.reserve_admission().await.is_err());
        assert!(tracker.spawn_owned(async { Ok(()) }).await.is_err());
        let failure = tracker.terminal_failure.lock().await.clone().unwrap();
        assert!(failure.contains("join failed"));
    }

    #[tokio::test]
    async fn owned_task_admission_is_bounded() {
        let tracker = AsyncOperationTracker::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(0));
        for _ in 0..MAX_OWNED_TASKS {
            let semaphore = semaphore.clone();
            tracker
                .spawn_owned(async move {
                    let permit = semaphore
                        .acquire()
                        .await
                        .map_err(|error| error.to_string())?;
                    permit.forget();
                    Ok(())
                })
                .await
                .unwrap();
        }
        assert!(matches!(
            tracker.spawn_owned(async { Ok(()) }).await,
            Err(AstralError::Validation(_))
        ));
        semaphore.add_permits(MAX_OWNED_TASKS);
        assert!(tracker.shutdown_tasks(Duration::from_secs(1)).await.is_ok());
    }

    #[tokio::test]
    async fn owned_task_shutdown_rejects_new_work() {
        let tracker = Arc::new(AsyncOperationTracker::new());
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        tracker
            .spawn_owned(async move {
                let _ = wait.await;
                Ok(())
            })
            .await
            .unwrap();
        let joining = {
            let tracker = tracker.clone();
            tokio::spawn(async move { tracker.shutdown_tasks(Duration::from_secs(1)).await })
        };
        tokio::task::yield_now().await;
        assert!(matches!(
            tracker.spawn_owned(async { Ok(()) }).await,
            Err(AstralError::Internal(_))
        ));
        let _ = release.send(());
        assert!(joining.await.unwrap().is_ok());
    }
}

const MAX_OWNED_TASKS: usize = 128;
const ABORTED_BATCH_FINALIZATION_TIMEOUT: Duration = Duration::from_secs(15);

type OwnedTaskResult = (Option<String>, Result<(), String>);

pub(crate) struct BatchAdmissionPermit {
    permit: Option<OwnedSemaphorePermit>,
    active_admissions: Arc<AtomicUsize>,
    admissions_drained: Arc<Notify>,
}

impl BatchAdmissionPermit {
    fn into_task_permit(mut self) -> OwnedSemaphorePermit {
        self.release_reservation();
        self.permit.take().expect("admission permit is present")
    }

    fn release_reservation(&self) {
        if self.active_admissions.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.admissions_drained.notify_one();
        }
    }
}

impl Drop for BatchAdmissionPermit {
    fn drop(&mut self) {
        if self.permit.is_some() {
            self.release_reservation();
        }
    }
}

#[derive(Default)]
struct OwnedTasks {
    closing: bool,
    stop_requested: Arc<AtomicBool>,
    join_set: JoinSet<OwnedTaskResult>,
    registered_card_binds: BTreeMap<String, MySqlPool>,
}

/// Process-owned task registry. Runtime shutdown calls `shutdown_tasks` after
/// HTTP admission closes and before source relay/projector producer teardown.
pub struct AsyncOperationTracker {
    state: Mutex<OwnedTasks>,
    terminal_failure: Mutex<Option<String>>,
    admission: Arc<Semaphore>,
    closing: AtomicBool,
    active_admissions: Arc<AtomicUsize>,
    admissions_drained: Arc<Notify>,
}

impl Default for AsyncOperationTracker {
    fn default() -> Self {
        Self {
            state: Mutex::new(OwnedTasks::default()),
            terminal_failure: Mutex::new(None),
            admission: Arc::new(Semaphore::new(MAX_OWNED_TASKS)),
            closing: AtomicBool::new(false),
            active_admissions: Arc::new(AtomicUsize::new(0)),
            admissions_drained: Arc::new(Notify::new()),
        }
    }
}

impl AsyncOperationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn stop_requested(&self) -> Arc<AtomicBool> {
        self.state.lock().await.stop_requested.clone()
    }

    fn admission_reservation(&self, permit: OwnedSemaphorePermit) -> BatchAdmissionPermit {
        BatchAdmissionPermit {
            permit: Some(permit),
            active_admissions: self.active_admissions.clone(),
            admissions_drained: self.admissions_drained.clone(),
        }
    }

    pub(crate) async fn reserve_admission(&self) -> Result<BatchAdmissionPermit, AstralError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(AstralError::Internal(
                "async operation tracker is shutting down".into(),
            ));
        }
        let permit =
            self.admission.clone().try_acquire_owned().map_err(|_| {
                AstralError::Validation("too many active async operation tasks".into())
            })?;
        self.active_admissions.fetch_add(1, Ordering::AcqRel);
        if self.closing.load(Ordering::Acquire) {
            if self.active_admissions.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.admissions_drained.notify_one();
            }
            drop(permit);
            return Err(AstralError::Internal(
                "async operation tracker is shutting down".into(),
            ));
        }
        Ok(self.admission_reservation(permit))
    }

    fn reap_finished(state: &mut OwnedTasks) -> Vec<String> {
        let mut failures = Vec::new();
        while let Some(result) = state.join_set.try_join_next() {
            match result {
                Ok((task_id, Ok(()))) => {
                    if let Some(task_id) = task_id {
                        state.registered_card_binds.remove(&task_id);
                    }
                }
                Ok((_, Err(error))) => failures.push(error),
                Err(error) => failures.push(format!("async operation task join failed: {error}")),
            }
        }
        failures
    }

    async fn prepare_spawn(&self, state: &mut OwnedTasks) -> Result<(), AstralError> {
        if state.closing || self.closing.load(Ordering::Acquire) {
            return Err(AstralError::Internal(
                "async operation tracker is shutting down".into(),
            ));
        }
        let finished_failures = Self::reap_finished(state);
        if !finished_failures.is_empty() {
            let failure = finished_failures.join("; ");
            *self.terminal_failure.lock().await = Some(failure.clone());
            return Err(AstralError::Internal(format!(
                "async operation task failed: {failure}"
            )));
        }
        if let Some(failure) = self.terminal_failure.lock().await.as_ref() {
            return Err(AstralError::Internal(format!(
                "async operation tracker has a failed drain: {failure}"
            )));
        }
        if state.join_set.len() >= MAX_OWNED_TASKS {
            return Err(AstralError::Validation(
                "too many active async operation tasks".into(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    async fn spawn_owned<F>(&self, task: F) -> Result<(), AstralError>
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let reservation = self.reserve_admission().await?;
        self.spawn_owned_reserved(reservation, task).await
    }

    #[cfg(test)]
    async fn spawn_owned_reserved<F>(
        &self,
        reservation: BatchAdmissionPermit,
        task: F,
    ) -> Result<(), AstralError>
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut state = self.state.lock().await;
        self.prepare_spawn(&mut state).await?;
        let permit = reservation.into_task_permit();
        state.join_set.spawn(async move {
            let _permit = permit;
            (None, task.await)
        });
        Ok(())
    }

    /// Install the registration transaction and worker inside a tracker-owned
    /// future. Dropping the HTTP request cannot cancel this admission boundary.
    /// Shutdown reconciles any accepted row without replaying source mutations.
    pub(crate) async fn register_card_bind_and_spawn<F>(
        &'static self,
        pool: &MySqlPool,
        reservation: BatchAdmissionPermit,
        registration: CardBindRegistration,
        task: F,
    ) -> Result<AsyncTask, AstralError>
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        validate_card_bind_registration(&registration)?;
        let task_id = registration.task_id.clone();
        let (result_tx, result_rx) = oneshot::channel();
        let tracker = self;
        let task_pool = pool.clone();
        let registration_task_id = registration.task_id.clone();
        let worker = async move {
            let registration_result = register_card_bind(&task_pool, &registration).await;
            let accepted = match registration_result {
                Ok(accepted) => accepted,
                Err(CardBindRegistrationError::BeforeCommit(error)) => {
                    // No commit was attempted, so the transaction cannot have
                    // created a durable registration. A successful owner exit
                    // lets JoinSet reap the local ID without a DB lookup.
                    let _ = result_tx.send(Err(error));
                    return Ok(());
                }
                Err(CardBindRegistrationError::CommitOutcomeUnknown(error)) => {
                    let reconciliation = reconcile_card_bind_after_owner_exit_bounded(
                        &task_pool,
                        &registration_task_id,
                        "batch registration commit outcome is unknown",
                    )
                    .await;
                    match reconciliation {
                        Ok(true) => {
                            let _ = result_tx.send(Err(error));
                            return Ok(());
                        }
                        Ok(false) => {
                            let message = format!(
                                "batch registration commit outcome remains unknown: {error}"
                            );
                            *tracker.terminal_failure.lock().await = Some(message.clone());
                            let _ = result_tx.send(Err(AstralError::Database(message.clone())));
                            return Err(message);
                        }
                        Err(reconcile_error) => {
                            let message = format!(
                                "batch registration outcome is unknown: {error}; reconciliation failed: {reconcile_error}"
                            );
                            *tracker.terminal_failure.lock().await = Some(message.clone());
                            let _ = result_tx.send(Err(AstralError::Database(message.clone())));
                            return Err(message);
                        }
                    }
                }
            };

            let _ = result_tx.send(Ok(accepted));
            let worker_result = task.await;
            if worker_result.is_err() {
                // The worker wrapper usually finalizes its own failure. This
                // fallback keeps tracker-owned reconciliation for panics/errors.
                if let Err(error) = reconcile_card_bind_after_owner_exit_bounded(
                    &task_pool,
                    &registration_task_id,
                    "owned batch worker exited before durable completion was proven",
                )
                .await
                {
                    *tracker.terminal_failure.lock().await = Some(format!(
                        "batch worker failed and reconciliation failed: {error}"
                    ));
                }
            }
            worker_result
        };
        self.spawn_owned_reserved_with_card_bind(reservation, task_id, pool.clone(), worker)
            .await?;
        result_rx.await.map_err(|_| {
            AstralError::Internal(
                "tracker-owned batch registration ended before returning its result".into(),
            )
        })?
    }

    async fn spawn_owned_reserved_with_card_bind<F>(
        &self,
        reservation: BatchAdmissionPermit,
        task_id: String,
        pool: MySqlPool,
        task: F,
    ) -> Result<(), AstralError>
    where
        F: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut state = self.state.lock().await;
        self.prepare_spawn(&mut state).await?;
        if state.closing || self.closing.load(Ordering::Acquire) {
            return Err(AstralError::Internal(
                "async operation tracker is shutting down".into(),
            ));
        }
        let permit = reservation.into_task_permit();
        state.registered_card_binds.insert(task_id.clone(), pool);
        state.join_set.spawn(async move {
            let _permit = permit;
            (Some(task_id), task.await)
        });
        Ok(())
    }

    pub async fn shutdown_tasks(&self, timeout: Duration) -> Result<(), AstralError> {
        self.closing.store(true, Ordering::Release);
        self.admission.close();
        let close_result = tokio::time::timeout(timeout, async {
            let mut state = self.state.lock().await;
            state.closing = true;
            state.stop_requested.store(true, Ordering::Release);
        })
        .await;
        if close_result.is_err() {
            let failure = "async operation tracker state lock did not quiesce before shutdown";
            *self.terminal_failure.lock().await = Some(failure.to_owned());
            return Err(AstralError::Internal(failure.into()));
        }
        let admissions_drained = async {
            loop {
                let notified = self.admissions_drained.notified();
                if self.active_admissions.load(Ordering::Acquire) == 0 {
                    break;
                }
                notified.await;
            }
        };
        if tokio::time::timeout(timeout, admissions_drained)
            .await
            .is_err()
        {
            *self.terminal_failure.lock().await =
                Some("async operation admission did not quiesce before shutdown".into());
            return Err(AstralError::Internal(
                "async operation admission did not quiesce before shutdown".into(),
            ));
        }
        let state_lock = tokio::time::timeout(timeout, self.state.lock()).await;
        let mut state = match state_lock {
            Ok(state) => state,
            Err(_) => {
                let failure = "async operation tracker state lock did not reopen before drain";
                *self.terminal_failure.lock().await = Some(failure.to_owned());
                return Err(AstralError::Internal(failure.into()));
            }
        };
        let drain = async {
            let mut failures = Self::reap_finished(&mut state);
            while let Some(result) = state.join_set.join_next().await {
                match result {
                    Ok((task_id, Ok(()))) => {
                        if let Some(task_id) = task_id {
                            state.registered_card_binds.remove(&task_id);
                        }
                    }
                    Ok((_, Err(error))) => failures.push(error),
                    Err(error) => {
                        failures.push(format!("async operation task join failed: {error}"))
                    }
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(AstralError::Internal(failures.join("; ")))
            }
        };
        let drain_result = match tokio::time::timeout(timeout, drain).await {
            Ok(result) => result,
            Err(_) => {
                state.join_set.abort_all();
                let reap_after_abort = async {
                    while let Some(result) = state.join_set.join_next().await {
                        if let Ok((Some(task_id), Ok(()))) = result {
                            state.registered_card_binds.remove(&task_id);
                        }
                    }
                };
                if tokio::time::timeout(Duration::from_secs(1), reap_after_abort)
                    .await
                    .is_err()
                {
                    *self.terminal_failure.lock().await = Some(
                        "aborted async operation tasks did not finish within the reap bound; outcome unknown".into(),
                    );
                    return Err(AstralError::Internal(
                        "aborted async operation tasks did not finish within the reap bound; outcome unknown".into(),
                    ));
                }
                Err(AstralError::Internal(
                    "async operation drain timed out; unfinished durable items need reconciliation"
                        .into(),
                ))
            }
        };

        let reconcile = async {
            let entries: Vec<(String, MySqlPool)> = state
                .registered_card_binds
                .iter()
                .map(|(task_id, pool)| (task_id.clone(), pool.clone()))
                .collect();
            let mut failures = Vec::new();
            for (task_id, pool) in entries {
                match reconcile_card_bind_after_owner_exit_bounded(
                    &pool,
                    &task_id,
                    "owned batch worker exited before durable completion was proven",
                )
                .await
                {
                    Ok(true) => {
                        state.registered_card_binds.remove(&task_id);
                    }
                    Ok(false) => failures.push(format!(
                        "{task_id}: registration outcome remains unknown after bounded reconciliation"
                    )),
                    Err(error) => failures.push(format!("{task_id}: {error}")),
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(AstralError::Internal(failures.join("; ")))
            }
        };
        let reconcile_result = tokio::time::timeout(ABORTED_BATCH_FINALIZATION_TIMEOUT, reconcile)
            .await
            .unwrap_or_else(|_| {
                Err(AstralError::Internal(
                    "batch operation reconciliation timed out; durable outcomes remain unknown"
                        .into(),
                ))
            });

        let result = match (drain_result, reconcile_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(drain), Ok(())) => Err(drain),
            (Ok(()), Err(reconcile)) => Err(reconcile),
            (Err(drain), Err(reconcile)) => {
                Err(AstralError::Internal(format!("{drain}; {reconcile}")))
            }
        };
        if let Err(error) = &result {
            *self.terminal_failure.lock().await = Some(error.to_string());
        }
        result
    }
}

static TRACKER: once_cell::sync::Lazy<AsyncOperationTracker> =
    once_cell::sync::Lazy::new(AsyncOperationTracker::new);

pub fn tracker() -> &'static AsyncOperationTracker {
    &TRACKER
}

pub fn generate_task_id(prefix: &str) -> String {
    let uuid = uuid::Uuid::new_v4().simple().to_string();
    let task_id = format!("{prefix}:{uuid}");
    debug_assert!(task_id.len() <= MAX_TASK_ID_LENGTH);
    task_id
}
