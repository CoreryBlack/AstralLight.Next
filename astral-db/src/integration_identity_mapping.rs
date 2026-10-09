//! Default-off external subject → existing platform identity mapping storage.
//!
//! The mapping is an identity lookup only: this module never creates platform
//! users/cards, grants `user_card` authority, or merges by email. Callers own
//! authentication/authorization policy. Positive reads require the current
//! platform user and identity card to remain ACTIVE and the identity card to be
//! unexpired; all other states fail closed as `None`.

use sha2::{Digest, Sha256};
use sqlx::mysql::MySqlPool;
use sqlx::{MySql, Transaction};
use thiserror::Error;
use uuid::Uuid;

mod schema;
pub use schema::validate_integration_mapping_schema;

/// Maximum byte width accepted for an external application identifier.
pub const MAX_INTEGRATION_IDENTITY_APP_ID_BYTES: usize = 64;
/// Maximum byte width accepted for issuer and subject components.
///
/// The durable columns reserve 512 bytes for forward compatibility; the current
/// external SDK contract accepts visible ASCII identifiers up to this boundary.
pub const MAX_INTEGRATION_IDENTITY_COMPONENT_BYTES: usize = 256;
/// Maximum byte width of the audit/idempotency operation identity.
pub const MAX_INTEGRATION_IDENTITY_OPERATION_ID_BYTES: usize = 64;

const MAPPING_TABLE: &str = "integration_identity_mapping";
const OPERATION_TABLE: &str = "integration_identity_mapping_operation";
const MAPPING_IDENTITY_UNIQUE_INDEX: &str = "uq_iim_external_identity";
const MAPPING_USER_INDEX: &str = "idx_iim_user_id";
const MAPPING_CARD_INDEX: &str = "idx_iim_identity_card_id";
const MAPPING_USER_FK: &str = "fk_iim_platform_user";
const MAPPING_CARD_FK: &str = "fk_iim_identity_card";

const OPERATION_CLAIM_SQL: &str = "INSERT INTO integration_identity_mapping_operation \
    (operation_id, request_digest, actor_id, status, result_revision, claim_token) \
    VALUES (?, ?, ?, 'PENDING', NULL, ?) \
    ON DUPLICATE KEY UPDATE operation_id = VALUES(operation_id)";

const OPERATION_LOCK_SQL: &str =
    "SELECT request_digest, actor_id, status, result_revision, claim_token \
    FROM integration_identity_mapping_operation WHERE operation_id = ? FOR UPDATE";

const OPERATION_COMPLETE_SQL: &str = "UPDATE integration_identity_mapping_operation \
    SET status = 'COMPLETED', result_revision = ?, claim_token = NULL \
    WHERE operation_id = ? AND request_digest = ? AND actor_id = ? \
      AND status = 'PENDING' AND claim_token = ?";

const SOURCE_BINDING_FOR_UPDATE_SQL: &str = "SELECT pu.user_id, ic.card_id \
    FROM platform_user AS pu \
    INNER JOIN identity_card AS ic ON ic.user_id = pu.user_id \
    WHERE pu.user_id = ? AND ic.card_id = ? \
      AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
      AND ic.status = 'ACTIVE' \
      AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
    FOR UPDATE";

const ACTIVE_GLOBAL_ADMIN_FOR_UPDATE_SQL: &str = "SELECT pu.user_id \
    FROM platform_user AS pu \
    INNER JOIN identity_global_admin AS iga ON iga.user_id = pu.user_id \
    WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
      AND iga.status = 'ACTIVE' FOR UPDATE";

const MAPPING_INSERT_SQL: &str = "INSERT INTO integration_identity_mapping \
    (app_id, issuer, subject, user_id, identity_card_id, status, revision, \
     created_by, updated_by, operation_id) \
    VALUES (?, ?, ?, ?, ?, 'ACTIVE', 1, ?, ?, ?)";

const MAPPING_LOCK_SQL: &str = "SELECT mapping_id, user_id, identity_card_id, status, revision \
    FROM integration_identity_mapping \
    WHERE app_id = ? AND issuer = ? AND subject = ? FOR UPDATE";

const MAPPING_STATUS_UPDATE_SQL: &str = "UPDATE integration_identity_mapping \
    SET status = ?, revision = ?, updated_by = ?, operation_id = ?, updated_at = UTC_TIMESTAMP(6) \
    WHERE mapping_id = ? AND revision = ? AND status = ?";

/// Strict positive-read query. The external key predicates operate directly on
/// VARBINARY columns; no trim, case fold, collation conversion, or normalization
/// is applied to application, issuer, or subject bytes.
const MAPPING_READ_ACTIVE_SQL: &str = "SELECT m.app_id, m.issuer, m.subject, m.user_id, \
    m.identity_card_id, m.status, m.revision \
    FROM integration_identity_mapping AS m \
    INNER JOIN platform_user AS pu ON pu.user_id = m.user_id \
      AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
    INNER JOIN identity_card AS ic ON ic.card_id = m.identity_card_id \
      AND ic.user_id = m.user_id AND ic.status = 'ACTIVE' \
      AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
    WHERE m.app_id = ? AND m.issuer = ? AND m.subject = ? AND m.status = 'ACTIVE'";

const MAPPING_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
    (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
    VALUES (?, NULL, ?, 'integration_identity_mapping', 'SUCCESS', NULL, \
            'IDENTITY_INTEGRATION_MAPPING', ?, ?)";

const INTEGRATION_ADMISSION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
    (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
     tenant_id, domain_id, detail, created_at) \
    VALUES (?, ?, ?, ?, ?, ?, 'INTEGRATION_ADMISSION', ?, ?, ?, ?, UTC_TIMESTAMP())";

const OPERATION_DOMAIN: &[u8] = b"astral.integration-identity-mapping.v1\0";
const KEY_DIGEST_DOMAIN: &[u8] = b"astral.integration-identity-key.v1\0";

/// Exact external identity tuple. Valid values preserve byte identity; inputs
/// outside the SDK's bounded visible-ASCII contract are rejected, not normalized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntegrationIdentityKey {
    pub app_id: String,
    pub issuer: String,
    pub subject: String,
}

impl IntegrationIdentityKey {
    pub fn new(
        app_id: impl Into<String>,
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, IntegrationIdentityMappingError> {
        let key = Self {
            app_id: app_id.into(),
            issuer: issuer.into(),
            subject: subject.into(),
        };
        key.validate()?;
        Ok(key)
    }

    fn validate(&self) -> Result<(), IntegrationIdentityMappingError> {
        validate_app_id(&self.app_id)?;
        validate_opaque_component(
            "issuer",
            &self.issuer,
            MAX_INTEGRATION_IDENTITY_COMPONENT_BYTES,
        )?;
        validate_opaque_component(
            "subject",
            &self.subject,
            MAX_INTEGRATION_IDENTITY_COMPONENT_BYTES,
        )?;
        Ok(())
    }
}

/// Durable lifecycle state. Public reads return only [`Self::Active`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrationIdentityMappingStatus {
    Active,
    Disabled,
    Revoked,
}

impl IntegrationIdentityMappingStatus {
    const fn as_db_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Disabled => "DISABLED",
            Self::Revoked => "REVOKED",
        }
    }

    fn parse(value: &[u8]) -> Result<Self, IntegrationIdentityMappingError> {
        if value == b"ACTIVE" {
            Ok(Self::Active)
        } else if value == b"DISABLED" {
            Ok(Self::Disabled)
        } else if value == b"REVOKED" {
            Ok(Self::Revoked)
        } else {
            Err(IntegrationIdentityMappingError::CorruptRow(
                "unknown mapping status",
            ))
        }
    }
}

/// Active mapping plus its existing platform identity binding.
///
/// `Eq` is intentional so Identity can compare the initial lookup with its final
/// re-read before returning an admission decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegrationIdentityMapping {
    pub app_id: String,
    pub issuer: String,
    pub subject: String,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub status: IntegrationIdentityMappingStatus,
    pub revision: u64,
}

/// Platform admission audit record, distinct from business-operation commit audit.
/// The detail field should contain trace identifiers and content digests only; do
/// not include credentials, tokens, or unredacted integration secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationAdmissionAudit {
    pub user_id: i64,
    pub card_id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub resource: String,
    pub action: String,
    pub decision: String,
    pub reason: String,
    pub request_id: String,
    pub detail: String,
}

/// Create one permanent external identity binding to an existing active user/card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateIntegrationIdentityMapping {
    pub key: IntegrationIdentityKey,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub operation_id: String,
    pub actor_id: i64,
}

/// Disable or permanently revoke an existing mapping using an expected revision.
/// `Active` is rejected; a disabled mapping can only advance to `Revoked`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetIntegrationIdentityMappingStatus {
    pub key: IntegrationIdentityKey,
    pub expected_revision: u64,
    pub status: IntegrationIdentityMappingStatus,
    pub operation_id: String,
    pub actor_id: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrationIdentityMappingError {
    #[error("invalid integration identity mapping input: {field}: {reason}")]
    InvalidInput {
        field: &'static str,
        reason: &'static str,
    },
    #[error("integration identity mapping conflict: {0}")]
    Conflict(&'static str),
    #[error("integration identity mapping was not found")]
    NotFound,
    #[error("integration identity mapping source identity is unavailable")]
    SourceIdentityUnavailable,
    #[error("integration identity mapping schema contract failed: {0}")]
    SchemaMismatch(String),
    #[error("integration identity mapping row is corrupt: {0}")]
    CorruptRow(&'static str),
    #[error("integration identity mapping operation is in doubt: {0}")]
    InDoubtOperation(&'static str),
    #[error("database operation failed: {0}")]
    Database(String),
    #[error("database commit outcome is unknown: {0}")]
    UnknownCommit(String),
}

/// Create a mapping after revalidating and locking the existing active source
/// rows. The mapping, operation ledger, and mutation audit commit atomically.
pub async fn create_integration_identity_mapping(
    pool: &MySqlPool,
    command: CreateIntegrationIdentityMapping,
) -> Result<u64, IntegrationIdentityMappingError> {
    validate_create_command(&command)?;
    let digest = create_request_digest(&command);
    let claim_token = Uuid::new_v4().into_bytes();
    let source_guard = crate::memory_projection_hub::acquire_source_guard()
        .map_err(|error| IntegrationIdentityMappingError::Database(error.to_string()))?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| db_error("begin mapping create transaction", error))?;

    require_active_actor_in_tx(&mut tx, command.actor_id).await?;
    if let ClaimOutcome::Replay(revision) = claim_operation_in_tx(
        &mut tx,
        &command.operation_id,
        command.actor_id,
        &digest,
        &claim_token,
    )
    .await?
    {
        tx.rollback()
            .await
            .map_err(|error| db_error("rollback mapping create replay", error))?;
        return Ok(revision);
    }

    let source_binding: Option<(i64, i64)> = sqlx::query_as(SOURCE_BINDING_FOR_UPDATE_SQL)
        .bind(command.user_id)
        .bind(command.identity_card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| db_error("lock mapping source identity", error))?;
    if source_binding != Some((command.user_id, command.identity_card_id)) {
        return Err(IntegrationIdentityMappingError::SourceIdentityUnavailable);
    }

    let insert = sqlx::query(MAPPING_INSERT_SQL)
        .bind(command.key.app_id.as_bytes())
        .bind(command.key.issuer.as_bytes())
        .bind(command.key.subject.as_bytes())
        .bind(command.user_id)
        .bind(command.identity_card_id)
        .bind(command.actor_id)
        .bind(command.actor_id)
        .bind(command.operation_id.as_bytes())
        .execute(&mut *tx)
        .await;
    let mapping_id = match insert {
        Ok(result) => result.last_insert_id(),
        Err(error) if is_duplicate_key(&error) => {
            return Err(IntegrationIdentityMappingError::Conflict(
                "external identity key is already permanently bound",
            ));
        }
        Err(error) => return Err(db_error("insert integration identity mapping", error)),
    };

    append_mapping_audit_in_tx(
        &mut tx,
        MappingAudit {
            actor_id: command.actor_id,
            action: "integration_identity_mapping.create",
            operation_id: &command.operation_id,
            key: &command.key,
            revision: 1,
            status: IntegrationIdentityMappingStatus::Active,
            user_id: command.user_id,
            identity_card_id: command.identity_card_id,
            request_digest: &digest,
        },
    )
    .await?;
    complete_operation_in_tx(
        &mut tx,
        &command.operation_id,
        command.actor_id,
        &digest,
        &claim_token,
        1,
    )
    .await?;
    debug_assert!(mapping_id > 0);

    commit_source_transaction(
        tx,
        source_guard.as_ref(),
        "create integration identity mapping",
    )
    .await?;
    Ok(1)
}

/// Move a mapping only forward through ACTIVE → DISABLED → REVOKED (ACTIVE may
/// also be revoked directly). It can never be rebound or re-enabled.
pub async fn set_integration_identity_mapping_status(
    pool: &MySqlPool,
    command: SetIntegrationIdentityMappingStatus,
) -> Result<u64, IntegrationIdentityMappingError> {
    validate_status_command(&command)?;
    let digest = status_request_digest(&command);
    let claim_token = Uuid::new_v4().into_bytes();
    let source_guard = crate::memory_projection_hub::acquire_source_guard()
        .map_err(|error| IntegrationIdentityMappingError::Database(error.to_string()))?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| db_error("begin mapping status transaction", error))?;

    require_active_actor_in_tx(&mut tx, command.actor_id).await?;
    if let ClaimOutcome::Replay(revision) = claim_operation_in_tx(
        &mut tx,
        &command.operation_id,
        command.actor_id,
        &digest,
        &claim_token,
    )
    .await?
    {
        tx.rollback()
            .await
            .map_err(|error| db_error("rollback mapping status replay", error))?;
        return Ok(revision);
    }

    let current: Option<(u64, i64, i64, Vec<u8>, u64)> = sqlx::query_as(MAPPING_LOCK_SQL)
        .bind(command.key.app_id.as_bytes())
        .bind(command.key.issuer.as_bytes())
        .bind(command.key.subject.as_bytes())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| db_error("lock integration identity mapping", error))?;
    let Some((mapping_id, user_id, identity_card_id, current_status_raw, revision)) = current
    else {
        return Err(IntegrationIdentityMappingError::NotFound);
    };
    if revision != command.expected_revision {
        return Err(IntegrationIdentityMappingError::Conflict(
            "expected mapping revision does not match",
        ));
    }
    if revision == u64::MAX {
        return Err(IntegrationIdentityMappingError::Conflict(
            "mapping revision is exhausted",
        ));
    }
    let current_status = IntegrationIdentityMappingStatus::parse(&current_status_raw)?;
    if !valid_forward_transition(current_status, command.status) {
        return Err(IntegrationIdentityMappingError::Conflict(
            "mapping status transition is not allowed",
        ));
    }
    let next_revision = revision + 1;
    let update = sqlx::query(MAPPING_STATUS_UPDATE_SQL)
        .bind(command.status.as_db_str())
        .bind(next_revision)
        .bind(command.actor_id)
        .bind(command.operation_id.as_bytes())
        .bind(mapping_id)
        .bind(revision)
        .bind(current_status.as_db_str())
        .execute(&mut *tx)
        .await
        .map_err(|error| db_error("advance integration identity mapping", error))?;
    if update.rows_affected() != 1 {
        return Err(IntegrationIdentityMappingError::Conflict(
            "mapping revision compare-and-set failed",
        ));
    }

    append_mapping_audit_in_tx(
        &mut tx,
        MappingAudit {
            actor_id: command.actor_id,
            action: match command.status {
                IntegrationIdentityMappingStatus::Disabled => {
                    "integration_identity_mapping.disable"
                }
                IntegrationIdentityMappingStatus::Revoked => "integration_identity_mapping.revoke",
                IntegrationIdentityMappingStatus::Active => {
                    unreachable!("validated status command")
                }
            },
            operation_id: &command.operation_id,
            key: &command.key,
            revision: next_revision,
            status: command.status,
            user_id,
            identity_card_id,
            request_digest: &digest,
        },
    )
    .await?;
    complete_operation_in_tx(
        &mut tx,
        &command.operation_id,
        command.actor_id,
        &digest,
        &claim_token,
        next_revision,
    )
    .await?;

    commit_source_transaction(
        tx,
        source_guard.as_ref(),
        "change integration identity mapping status",
    )
    .await?;
    Ok(next_revision)
}

#[derive(sqlx::FromRow)]
struct ActiveMappingRow {
    app_id: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    user_id: i64,
    identity_card_id: i64,
    status: Vec<u8>,
    revision: u64,
}

#[derive(sqlx::FromRow)]
struct OperationRow {
    request_digest: Vec<u8>,
    actor_id: i64,
    status: Vec<u8>,
    result_revision: Option<u64>,
    claim_token: Option<Vec<u8>>,
}

struct MappingAudit<'a> {
    actor_id: i64,
    action: &'static str,
    operation_id: &'a str,
    key: &'a IntegrationIdentityKey,
    revision: u64,
    status: IntegrationIdentityMappingStatus,
    user_id: i64,
    identity_card_id: i64,
    request_digest: &'a [u8; 32],
}

/// Append an assessed or refused platform decision to the shared audit table.
/// This is audit-only: it does not acquire the source-writer guard and does not
/// imply a business source mutation or business-operation commit.
pub async fn record_integration_admission_audit(
    pool: &MySqlPool,
    audit: IntegrationAdmissionAudit,
) -> Result<(), IntegrationIdentityMappingError> {
    validate_admission_audit(&audit)?;
    sqlx::query(INTEGRATION_ADMISSION_AUDIT_INSERT_SQL)
        .bind(audit.user_id)
        .bind(audit.card_id)
        .bind(&audit.action)
        .bind(&audit.resource)
        .bind(&audit.decision)
        .bind(&audit.reason)
        .bind(&audit.request_id)
        .bind(audit.tenant_id)
        .bind(audit.domain_id)
        .bind(&audit.detail)
        .execute(pool)
        .await
        .map_err(|error| db_error("record integration admission audit", error))?;
    Ok(())
}

/// Read an active mapping only when its platform user and identity card are
/// currently consistent, active, and unexpired. This is a pure read and does
/// not acquire the source-writer guard; admission callers own any outer fence
/// and should perform their final re-read/compare before returning ALLOW.
pub async fn read_integration_identity_mapping(
    pool: &MySqlPool,
    key: &IntegrationIdentityKey,
) -> Result<Option<IntegrationIdentityMapping>, IntegrationIdentityMappingError> {
    key.validate()?;
    let row: Option<ActiveMappingRow> = sqlx::query_as(MAPPING_READ_ACTIVE_SQL)
        .bind(key.app_id.as_bytes())
        .bind(key.issuer.as_bytes())
        .bind(key.subject.as_bytes())
        .fetch_optional(pool)
        .await
        .map_err(|error| db_error("read active integration identity mapping", error))?;
    row.map(
        |ActiveMappingRow {
             app_id,
             issuer,
             subject,
             user_id,
             identity_card_id,
             status,
             revision,
         }| {
            if user_id <= 0 || identity_card_id <= 0 || revision == 0 {
                return Err(IntegrationIdentityMappingError::CorruptRow(
                    "non-positive identity or revision",
                ));
            }
            let status = IntegrationIdentityMappingStatus::parse(&status)?;
            if status != IntegrationIdentityMappingStatus::Active {
                return Err(IntegrationIdentityMappingError::CorruptRow(
                    "positive read returned a non-active mapping",
                ));
            }
            Ok(IntegrationIdentityMapping {
                app_id: decode_key_component(app_id, "app_id")?,
                issuer: decode_key_component(issuer, "issuer")?,
                subject: decode_key_component(subject, "subject")?,
                user_id,
                identity_card_id,
                status,
                revision,
            })
        },
    )
    .transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimOutcome {
    New,
    Replay(u64),
}

fn resolve_operation_claim_outcome(
    status: &[u8],
    stored_claim: Option<&[u8]>,
    result_revision: Option<u64>,
    claim_token: &[u8],
) -> Result<ClaimOutcome, IntegrationIdentityMappingError> {
    if status == b"COMPLETED" {
        if stored_claim.is_some() {
            return Err(IntegrationIdentityMappingError::InDoubtOperation(
                "completed operation retains a claim token",
            ));
        }
        return result_revision.map(ClaimOutcome::Replay).ok_or(
            IntegrationIdentityMappingError::InDoubtOperation(
                "completed operation has no result revision",
            ),
        );
    }
    if status == b"PENDING" {
        if stored_claim != Some(claim_token) {
            return Err(IntegrationIdentityMappingError::InDoubtOperation(
                "operation ledger contains a committed pending claim",
            ));
        }
        if result_revision.is_some() {
            return Err(IntegrationIdentityMappingError::InDoubtOperation(
                "new operation claim already has a result revision",
            ));
        }
        return Ok(ClaimOutcome::New);
    }
    Err(IntegrationIdentityMappingError::InDoubtOperation(
        "operation ledger has an unknown state",
    ))
}

async fn claim_operation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    actor_id: i64,
    request_digest: &[u8; 32],
    claim_token: &[u8; 16],
) -> Result<ClaimOutcome, IntegrationIdentityMappingError> {
    sqlx::query(OPERATION_CLAIM_SQL)
        .bind(operation_id.as_bytes())
        .bind(request_digest.as_slice())
        .bind(actor_id)
        .bind(claim_token.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(|error| db_error("claim integration mapping operation", error))?;
    let row: Option<OperationRow> = sqlx::query_as(OPERATION_LOCK_SQL)
        .bind(operation_id.as_bytes())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| db_error("lock integration mapping operation", error))?;
    let Some(OperationRow {
        request_digest: stored_digest,
        actor_id: stored_actor,
        status,
        result_revision,
        claim_token: stored_claim,
    }) = row
    else {
        return Err(IntegrationIdentityMappingError::InDoubtOperation(
            "operation claim disappeared inside its transaction",
        ));
    };
    if stored_digest.as_slice() != request_digest || stored_actor != actor_id {
        return Err(IntegrationIdentityMappingError::Conflict(
            "operation_id is already bound to different content or actor",
        ));
    }
    resolve_operation_claim_outcome(
        &status,
        stored_claim.as_deref(),
        result_revision,
        claim_token,
    )
}

async fn complete_operation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    actor_id: i64,
    request_digest: &[u8; 32],
    claim_token: &[u8; 16],
    result_revision: u64,
) -> Result<(), IntegrationIdentityMappingError> {
    let result = sqlx::query(OPERATION_COMPLETE_SQL)
        .bind(result_revision)
        .bind(operation_id.as_bytes())
        .bind(request_digest.as_slice())
        .bind(actor_id)
        .bind(claim_token.as_slice())
        .execute(&mut **tx)
        .await
        .map_err(|error| db_error("complete integration mapping operation", error))?;
    if result.rows_affected() != 1 {
        return Err(IntegrationIdentityMappingError::InDoubtOperation(
            "operation completion compare-and-set failed",
        ));
    }
    Ok(())
}

async fn append_mapping_audit_in_tx(
    tx: &mut Transaction<'_, MySql>,
    audit: MappingAudit<'_>,
) -> Result<(), IntegrationIdentityMappingError> {
    let MappingAudit {
        actor_id,
        action,
        operation_id,
        key,
        revision,
        status,
        user_id,
        identity_card_id,
        request_digest,
    } = audit;
    let detail = serde_json::json!({
        "keyDigest": hex::encode(key_digest(key)),
        "requestDigest": hex::encode(request_digest),
        "revision": revision,
        "status": status.as_db_str(),
        "userId": user_id,
        "identityCardId": identity_card_id,
    })
    .to_string();
    sqlx::query(MAPPING_AUDIT_INSERT_SQL)
        .bind(actor_id)
        .bind(action)
        .bind(operation_id)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| db_error("append integration mapping audit", error))?;
    Ok(())
}

async fn require_active_actor_in_tx(
    tx: &mut Transaction<'_, MySql>,
    actor_id: i64,
) -> Result<(), IntegrationIdentityMappingError> {
    let actor: Option<i64> = sqlx::query_scalar(ACTIVE_GLOBAL_ADMIN_FOR_UPDATE_SQL)
        .bind(actor_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| db_error("lock active mapping administrator", error))?;
    if actor != Some(actor_id) {
        return Err(IntegrationIdentityMappingError::SourceIdentityUnavailable);
    }
    Ok(())
}

async fn commit_source_transaction(
    tx: Transaction<'_, MySql>,
    source_guard: Option<&crate::memory_projection_hub::SourceTransactionGuard>,
    context: &'static str,
) -> Result<(), IntegrationIdentityMappingError> {
    if let Some(guard) = source_guard {
        guard.mark_commit_started();
    }
    match tx.commit().await {
        Ok(()) => {
            if let Some(guard) = source_guard {
                guard.mark_commit_proven();
            }
            Ok(())
        }
        Err(error) => {
            if let Some(guard) = source_guard {
                guard.mark_uncertain();
            }
            Err(IntegrationIdentityMappingError::UnknownCommit(format!(
                "{context}: {error}"
            )))
        }
    }
}

fn validate_create_command(
    command: &CreateIntegrationIdentityMapping,
) -> Result<(), IntegrationIdentityMappingError> {
    command.key.validate()?;
    validate_operation_id(&command.operation_id)?;
    validate_positive_id(command.user_id, "user_id")?;
    validate_positive_id(command.identity_card_id, "identity_card_id")?;
    validate_positive_id(command.actor_id, "actor_id")?;
    Ok(())
}

fn validate_status_command(
    command: &SetIntegrationIdentityMappingStatus,
) -> Result<(), IntegrationIdentityMappingError> {
    command.key.validate()?;
    validate_operation_id(&command.operation_id)?;
    validate_positive_id(command.actor_id, "actor_id")?;
    if command.expected_revision == 0 {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "expected_revision",
            reason: "must be greater than zero",
        });
    }
    if command.status == IntegrationIdentityMappingStatus::Active {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "status",
            reason: "management operations cannot reactivate a mapping",
        });
    }
    Ok(())
}

fn validate_app_id(value: &str) -> Result<(), IntegrationIdentityMappingError> {
    validate_component("app_id", value, MAX_INTEGRATION_IDENTITY_APP_ID_BYTES)?;
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase())
        || !value.bytes().skip(1).all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "app_id",
            reason: "must use lowercase ASCII identifier syntax",
        });
    }
    Ok(())
}

fn validate_opaque_component(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), IntegrationIdentityMappingError> {
    validate_component(field, value, maximum_bytes)?;
    if !value.is_ascii() || !value.bytes().all(|byte| (b'!'..=b'~').contains(&byte)) {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field,
            reason: "must use visible ASCII without whitespace",
        });
    }
    Ok(())
}

fn validate_component(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), IntegrationIdentityMappingError> {
    if value.is_empty() {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > maximum_bytes {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field,
            reason: "exceeds the UTF-8 byte limit",
        });
    }
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<(), IntegrationIdentityMappingError> {
    if value.is_empty() || value.len() > MAX_INTEGRATION_IDENTITY_OPERATION_ID_BYTES {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "operation_id",
            reason: "must contain 1 to 64 bytes",
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "operation_id",
            reason: "contains a character outside the stable operation-id alphabet",
        });
    }
    Ok(())
}

fn validate_positive_id(
    value: i64,
    field: &'static str,
) -> Result<(), IntegrationIdentityMappingError> {
    if value <= 0 {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field,
            reason: "must be positive",
        });
    }
    Ok(())
}

fn validate_admission_audit(
    audit: &IntegrationAdmissionAudit,
) -> Result<(), IntegrationIdentityMappingError> {
    for (value, field) in [
        (audit.user_id, "user_id"),
        (audit.card_id, "card_id"),
        (audit.tenant_id, "tenant_id"),
        (audit.domain_id, "domain_id"),
    ] {
        validate_positive_id(value, field)?;
    }
    validate_component("resource", &audit.resource, 256)?;
    validate_component("action", &audit.action, 64)?;
    validate_component("reason", &audit.reason, 256)?;
    validate_operation_id(&audit.request_id).map_err(|_| {
        IntegrationIdentityMappingError::InvalidInput {
            field: "request_id",
            reason: "must be a non-empty <=64 byte stable id",
        }
    })?;
    if !matches!(audit.decision.as_str(), "ALLOW" | "DENY" | "PENDING") {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "decision",
            reason: "must be ALLOW, DENY, or PENDING",
        });
    }
    if audit.detail.len() > astral_common::service::AUDIT_DETAIL_MAX_BYTES {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "detail",
            reason: "exceeds the shared audit detail byte limit",
        });
    }
    let value: serde_json::Value = serde_json::from_str(&audit.detail).map_err(|_| {
        IntegrationIdentityMappingError::InvalidInput {
            field: "detail",
            reason: "must be a bounded JSON object",
        }
    })?;
    let Some(fields) = value.as_object() else {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "detail",
            reason: "must be a JSON object",
        });
    };
    const ALLOWED: &[&str] = &[
        "appId",
        "requestDigest",
        "mappingRevision",
        "factsDigest",
        "operationId",
        "decisionDigest",
        "phase",
        "scope",
    ];
    if fields.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(IntegrationIdentityMappingError::InvalidInput {
            field: "detail",
            reason: "unknown audit detail field",
        });
    }
    Ok(())
}

fn valid_forward_transition(
    current: IntegrationIdentityMappingStatus,
    next: IntegrationIdentityMappingStatus,
) -> bool {
    matches!(
        (current, next),
        (
            IntegrationIdentityMappingStatus::Active,
            IntegrationIdentityMappingStatus::Disabled
        ) | (
            IntegrationIdentityMappingStatus::Active,
            IntegrationIdentityMappingStatus::Revoked
        ) | (
            IntegrationIdentityMappingStatus::Disabled,
            IntegrationIdentityMappingStatus::Revoked
        )
    )
}

fn create_request_digest(command: &CreateIntegrationIdentityMapping) -> [u8; 32] {
    let mut canonical = OPERATION_DOMAIN.to_vec();
    canonical.push(1); // CREATE
    append_key(&mut canonical, &command.key);
    canonical.extend_from_slice(&command.user_id.to_be_bytes());
    canonical.extend_from_slice(&command.identity_card_id.to_be_bytes());
    canonical.extend_from_slice(&command.actor_id.to_be_bytes());
    Sha256::digest(canonical).into()
}

fn status_request_digest(command: &SetIntegrationIdentityMappingStatus) -> [u8; 32] {
    let mut canonical = OPERATION_DOMAIN.to_vec();
    canonical.push(2); // STATUS
    append_key(&mut canonical, &command.key);
    canonical.extend_from_slice(&command.expected_revision.to_be_bytes());
    canonical.push(match command.status {
        IntegrationIdentityMappingStatus::Active => 0,
        IntegrationIdentityMappingStatus::Disabled => 1,
        IntegrationIdentityMappingStatus::Revoked => 2,
    });
    canonical.extend_from_slice(&command.actor_id.to_be_bytes());
    Sha256::digest(canonical).into()
}

fn append_key(canonical: &mut Vec<u8>, key: &IntegrationIdentityKey) {
    append_component(canonical, key.app_id.as_bytes());
    append_component(canonical, key.issuer.as_bytes());
    append_component(canonical, key.subject.as_bytes());
}

fn append_component(canonical: &mut Vec<u8>, value: &[u8]) {
    canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
    canonical.extend_from_slice(value);
}

fn key_digest(key: &IntegrationIdentityKey) -> [u8; 32] {
    let mut canonical = KEY_DIGEST_DOMAIN.to_vec();
    append_key(&mut canonical, key);
    Sha256::digest(canonical).into()
}

fn decode_key_component(
    value: Vec<u8>,
    field: &'static str,
) -> Result<String, IntegrationIdentityMappingError> {
    String::from_utf8(value).map_err(|_| {
        IntegrationIdentityMappingError::CorruptRow(match field {
            "app_id" => "app_id is not valid UTF-8",
            "issuer" => "issuer is not valid UTF-8",
            _ => "subject is not valid UTF-8",
        })
    })
}

fn is_duplicate_key(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "1062")
}

fn db_error(context: &'static str, error: sqlx::Error) -> IntegrationIdentityMappingError {
    IntegrationIdentityMappingError::Database(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests;
