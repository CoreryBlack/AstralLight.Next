//! Durable repository operations for terminal audit-message quarantine.
//!
//! The repository owns only the `audit_quarantine` table. It deliberately does
//! not acknowledge, publish, or otherwise operate on MQ deliveries.
//!
//! Metadata reads never expose `raw_payload` or a lease secret. A replay claim
//! is the explicit privileged boundary: it returns the raw record and the
//! one-time lease secret needed by a worker, while the database stores only the
//! secret hash and fencing generation.

use std::str::FromStr;

use sha2::{Digest, Sha256};
use sqlx::mysql::MySqlConnection;
use sqlx::MySqlPool;
use time::PrimitiveDateTime;
use uuid::Uuid;

use crate::DbError;

const STATUS_QUARANTINED: &str = "QUARANTINED";
const STATUS_REPLAY_REQUESTED: &str = "REPLAY_REQUESTED";
const STATUS_REPLAYING: &str = "REPLAYING";
const STATUS_REPLAY_CONFIRMED: &str = "REPLAY_CONFIRMED";

pub const MAX_SOURCE_QUEUE_LENGTH: usize = 128;
pub const MAX_MESSAGE_TYPE_LENGTH: usize = 64;
pub const MAX_MESSAGE_ID_LENGTH: usize = 255;
pub const MAX_SOURCE_EXCHANGE_LENGTH: usize = 128;
pub const MAX_SOURCE_ROUTING_KEY_LENGTH: usize = 255;
pub const MAX_FAILURE_REASON_LENGTH: usize = 255;
pub const MAX_LEASE_OWNER_LENGTH: usize = 128;
pub const MAX_OPERATION_ID_LENGTH: usize = 128;
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LIST_LIMIT: u32 = 500;
pub const MAX_LIST_OFFSET: u32 = 1_000_000;
pub const MAX_REPLAY_ATTEMPTS: u32 = 5;
pub const MAX_LEASE_SECONDS: i64 = 3_600;
#[cfg(test)]
const MAX_LEASE_GENERATION_SQL: &str = "18446744073709551615";

const RAW_SELECT_COLUMNS: &str = "id, identity_key, message_id, message_type, raw_payload, \
    source_queue, source_exchange, source_routing_key, retry_count, attempts, \
    replay_attempts, failure_reason, status, replay_lease_owner, \
    replay_lease_token_hash, replay_lease_generation, replay_lease_expires_at, \
    replay_operation_id_hash, replay_requested_by, replay_requested_at, \
    first_failed_at, last_failed_at, quarantined_at, replayed_at";
const METADATA_SELECT_COLUMNS: &str = "id, identity_key, message_id, message_type, \
    source_queue, source_exchange, source_routing_key, retry_count, attempts, \
    replay_attempts, failure_reason, status, replay_lease_owner, \
    replay_lease_generation, replay_lease_expires_at, replay_requested_by, \
    replay_requested_at, first_failed_at, last_failed_at, quarantined_at, replayed_at";

// Kept as constants so the state/CAS policy is reviewable without requiring a
// live MySQL instance. The VALUES() form is intentionally compatible with the
// MySQL versions supported by the migration contract.
const INSERT_OR_INCREMENT_SQL: &str = "INSERT INTO audit_quarantine \
    (identity_key, message_id, message_type, raw_payload, source_queue, \
     source_exchange, source_routing_key, retry_count, failure_reason, \
     first_failed_at, last_failed_at, quarantined_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
    ON DUPLICATE KEY UPDATE \
      message_id = VALUES(message_id), \
      message_type = VALUES(message_type), \
      raw_payload = VALUES(raw_payload), \
      source_queue = VALUES(source_queue), \
      source_exchange = VALUES(source_exchange), \
      source_routing_key = VALUES(source_routing_key), \
      retry_count = VALUES(retry_count), \
      attempts = attempts + 1, \
      failure_reason = VALUES(failure_reason), \
      status = 'QUARANTINED', \
      replay_lease_owner = NULL, \
      replay_lease_token_hash = NULL, \
      replay_lease_expires_at = NULL, \
      replay_operation_id_hash = NULL, \
      replay_requested_by = NULL, \
      replay_requested_at = NULL, \
      replayed_at = NULL, \
      first_failed_at = COALESCE(first_failed_at, UTC_TIMESTAMP()), \
      last_failed_at = UTC_TIMESTAMP(), \
      quarantined_at = UTC_TIMESTAMP()";

const REQUEST_REPLAY_SQL: &str = "UPDATE audit_quarantine \
    SET status = 'REPLAY_REQUESTED', \
        replay_operation_id_hash = ?, \
        replay_requested_by = ?, \
        replay_requested_at = UTC_TIMESTAMP() \
    WHERE id = ? \
      AND status = 'QUARANTINED' \
      AND replay_attempts < ?";

const BEGIN_REPLAY_SQL: &str = "UPDATE audit_quarantine \
    SET status = 'REPLAYING', \
        replay_attempts = replay_attempts + 1, \
        replay_lease_owner = ?, \
        replay_lease_token_hash = ?, \
        replay_lease_generation = replay_lease_generation + 1, \
        replay_lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        replayed_at = NULL \
    WHERE id = ? \
      AND replay_attempts < ? \
      AND replay_lease_generation < 18446744073709551615 \
      AND ((status = 'REPLAY_REQUESTED' \
            AND replay_operation_id_hash = ?) \
           OR (status = 'REPLAYING' \
               AND replay_operation_id_hash = ? \
               AND replay_lease_expires_at IS NOT NULL \
               AND replay_lease_expires_at <= UTC_TIMESTAMP()))";

const BEGIN_REQUESTED_REPLAY_SQL: &str = "UPDATE audit_quarantine \
    SET status = 'REPLAYING', \
        replay_attempts = replay_attempts + 1, \
        replay_lease_owner = ?, \
        replay_lease_token_hash = ?, \
        replay_lease_generation = replay_lease_generation + 1, \
        replay_lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        replayed_at = NULL \
    WHERE id = ? \
      AND status = 'REPLAY_REQUESTED' \
      AND replay_attempts < ? \
      AND replay_lease_generation < 18446744073709551615 \
      AND replay_operation_id_hash = ?";

const NEXT_REQUESTED_REPLAY_SQL: &str = "SELECT id, replay_operation_id_hash \
    FROM audit_quarantine \
    WHERE status = 'REPLAY_REQUESTED' \
      AND replay_attempts < ? \
      AND source_queue = ? \
      AND source_exchange = ? \
      AND source_routing_key = ? \
      AND message_type = ? \
      AND replay_operation_id_hash IS NOT NULL \
    ORDER BY replay_requested_at ASC, id ASC \
    LIMIT 1 \
    FOR UPDATE";

const NEXT_EXPIRED_REPLAYING_REPLAY_SQL: &str = "SELECT id, replay_operation_id_hash, \
        replay_lease_generation, replay_lease_owner, replay_lease_token_hash \
    FROM audit_quarantine \
    WHERE status = 'REPLAYING' \
      AND replay_attempts < ? \
      AND source_queue = ? \
      AND source_exchange = ? \
      AND source_routing_key = ? \
      AND message_type = ? \
      AND replay_operation_id_hash IS NOT NULL \
      AND replay_lease_generation > 0 \
      AND replay_lease_owner IS NOT NULL \
      AND replay_lease_token_hash IS NOT NULL \
      AND replay_lease_expires_at IS NOT NULL \
      AND replay_lease_expires_at <= UTC_TIMESTAMP() \
    ORDER BY replay_lease_expires_at ASC, id ASC \
    LIMIT 1 \
    FOR UPDATE";

const BEGIN_EXPIRED_REPLAYING_REPLAY_SQL: &str = "UPDATE audit_quarantine \
    SET status = 'REPLAYING', \
        replay_attempts = replay_attempts + 1, \
        replay_lease_owner = ?, \
        replay_lease_token_hash = ?, \
        replay_lease_generation = replay_lease_generation + 1, \
        replay_lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP()), \
        replayed_at = NULL \
    WHERE id = ? \
      AND status = 'REPLAYING' \
      AND replay_attempts < ? \
      AND replay_lease_generation < 18446744073709551615 \
      AND source_queue = ? \
      AND source_exchange = ? \
      AND source_routing_key = ? \
      AND message_type = ? \
      AND replay_operation_id_hash = ? \
      AND replay_lease_generation = ? \
      AND replay_lease_owner = ? \
      AND replay_lease_token_hash = ? \
      AND replay_lease_expires_at IS NOT NULL \
      AND replay_lease_expires_at <= UTC_TIMESTAMP()";

const CONFIRM_REPLAY_SQL: &str = "UPDATE audit_quarantine \
    SET status = 'REPLAY_CONFIRMED', \
        replayed_at = COALESCE(replayed_at, UTC_TIMESTAMP()) \
    WHERE id = ? \
      AND status = 'REPLAYING' \
      AND replay_lease_owner = ? \
      AND replay_lease_generation = ? \
      AND replay_operation_id_hash = ? \
      AND replay_lease_token_hash = ? \
      AND replay_lease_expires_at IS NOT NULL \
      AND replay_lease_expires_at > UTC_TIMESTAMP()";

const CONFIRM_IDEMPOTENT_SQL: &str = "SELECT id FROM audit_quarantine \
    WHERE id = ? \
      AND status = 'REPLAY_CONFIRMED' \
      AND replay_lease_owner = ? \
      AND replay_lease_generation = ? \
      AND replay_operation_id_hash = ? \
      AND replay_lease_token_hash = ?";

const FAIL_REPLAY_SQL: &str = "UPDATE audit_quarantine \
    SET status = 'QUARANTINED', \
        failure_reason = ?, \
        replay_lease_owner = NULL, \
        replay_lease_token_hash = NULL, \
        replay_lease_expires_at = NULL, \
        replay_operation_id_hash = NULL, \
        replay_requested_by = NULL, \
        replay_requested_at = NULL, \
        replayed_at = NULL, \
        last_failed_at = UTC_TIMESTAMP(), \
        quarantined_at = UTC_TIMESTAMP() \
    WHERE id = ? \
      AND status = 'REPLAYING' \
      AND replay_lease_owner = ? \
      AND replay_lease_generation = ? \
      AND replay_operation_id_hash = ? \
      AND replay_lease_token_hash = ? \
      AND replay_lease_expires_at IS NOT NULL \
      AND replay_lease_expires_at > UTC_TIMESTAMP()";

/// Supported durable states in `audit_quarantine.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditQuarantineStatus {
    Quarantined,
    ReplayRequested,
    Replaying,
    ReplayConfirmed,
}

impl AuditQuarantineStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quarantined => STATUS_QUARANTINED,
            Self::ReplayRequested => STATUS_REPLAY_REQUESTED,
            Self::Replaying => STATUS_REPLAYING,
            Self::ReplayConfirmed => STATUS_REPLAY_CONFIRMED,
        }
    }
}

impl AsRef<str> for AuditQuarantineStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for AuditQuarantineStatus {
    type Err = DbError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            STATUS_QUARANTINED => Ok(Self::Quarantined),
            STATUS_REPLAY_REQUESTED => Ok(Self::ReplayRequested),
            STATUS_REPLAYING => Ok(Self::Replaying),
            STATUS_REPLAY_CONFIRMED => Ok(Self::ReplayConfirmed),
            unknown => Err(invalid_status_error(unknown)),
        }
    }
}

impl TryFrom<&str> for AuditQuarantineStatus {
    type Error = DbError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

fn invalid_status_error(value: &str) -> DbError {
    // Keep the error machine-readable without allowing a malformed database
    // value to create an unbounded error message.
    let bounded = value.chars().take(64).collect::<String>();
    DbError::Mapping(format!("code=quarantine.invalid_status;status={bounded:?}"))
}

fn validation_error(code: &str) -> DbError {
    DbError::Mapping(format!("code=quarantine.{code}"))
}

fn validate_component(value: &str, code: &str, max_length: usize) -> Result<(), DbError> {
    if value.is_empty() || value.len() > max_length || value.contains('\0') {
        return Err(validation_error(code));
    }
    Ok(())
}

fn validate_id(id: i64) -> Result<(), DbError> {
    if id <= 0 {
        Err(validation_error("invalid_id"))
    } else {
        Ok(())
    }
}

fn validate_input(input: &AuditQuarantineInput) -> Result<(), DbError> {
    validate_component(
        &input.source_queue,
        "invalid_source_queue",
        MAX_SOURCE_QUEUE_LENGTH,
    )?;
    validate_component(
        &input.message_type,
        "invalid_message_type",
        MAX_MESSAGE_TYPE_LENGTH,
    )?;
    if let Some(message_id) = input.canonical_message_id.as_deref() {
        validate_component(message_id, "invalid_message_id", MAX_MESSAGE_ID_LENGTH)?;
    }
    validate_component(
        &input.source_exchange,
        "invalid_source_exchange",
        MAX_SOURCE_EXCHANGE_LENGTH,
    )?;
    validate_component(
        &input.source_routing_key,
        "invalid_source_routing_key",
        MAX_SOURCE_ROUTING_KEY_LENGTH,
    )?;
    validate_component(
        &input.failure_reason,
        "invalid_failure_reason",
        MAX_FAILURE_REASON_LENGTH,
    )?;
    if input.raw_payload.is_empty() || input.raw_payload.len() > MAX_PAYLOAD_BYTES {
        return Err(validation_error("invalid_payload_size"));
    }
    Ok(())
}

fn validate_paging(limit: u32, offset: u32) -> Result<(), DbError> {
    if limit == 0 || limit > MAX_LIST_LIMIT {
        return Err(validation_error("invalid_limit"));
    }
    if offset > MAX_LIST_OFFSET {
        return Err(validation_error("invalid_offset"));
    }
    Ok(())
}

fn validate_lease_owner(owner: &str) -> Result<(), DbError> {
    validate_component(owner, "invalid_lease_owner", MAX_LEASE_OWNER_LENGTH)
}

fn validate_operation_id(operation_id: &str) -> Result<(), DbError> {
    validate_component(
        operation_id,
        "invalid_operation_id",
        MAX_OPERATION_ID_LENGTH,
    )
}

fn validate_lease_seconds(lease_seconds: i64) -> Result<(), DbError> {
    if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(validation_error("invalid_lease_duration"));
    }
    Ok(())
}

fn validate_failure_reason(failure_reason: &str) -> Result<(), DbError> {
    validate_component(
        failure_reason,
        "invalid_failure_reason",
        MAX_FAILURE_REASON_LENGTH,
    )
}

fn sha256_bytes(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Input for terminal quarantine upsert.
///
/// `message_id` is not nullable in the SQL contract. When no canonical
/// message id is available, the repository stores the identity digest as its
/// stable textual surrogate while the identity key itself remains the raw
/// SHA-256 digest defined by [`stable_quarantine_identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuarantineInput {
    pub source_queue: String,
    pub message_type: String,
    pub canonical_message_id: Option<String>,
    pub raw_payload: Vec<u8>,
    pub source_exchange: String,
    pub source_routing_key: String,
    pub retry_count: u32,
    pub failure_reason: String,
}

/// Backwards-neutral descriptive alias for callers that prefer an insert name.
pub type AuditQuarantineInsertInput = AuditQuarantineInput;

/// Metadata safe for ordinary get/list paths. It intentionally has no raw
/// payload and no lease secret (or token hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuarantineMetadata {
    pub id: i64,
    pub identity_key: [u8; 32],
    pub message_id: String,
    pub message_type: String,
    pub source_queue: String,
    pub source_exchange: String,
    pub source_routing_key: String,
    pub retry_count: u32,
    pub attempts: u32,
    pub replay_attempts: u32,
    pub failure_reason: String,
    pub status: AuditQuarantineStatus,
    pub replay_lease_owner: Option<String>,
    pub replay_lease_generation: u64,
    pub replay_lease_expires_at: Option<PrimitiveDateTime>,
    pub replay_requested_by: Option<String>,
    pub replay_requested_at: Option<PrimitiveDateTime>,
    pub first_failed_at: PrimitiveDateTime,
    pub last_failed_at: PrimitiveDateTime,
    pub quarantined_at: PrimitiveDateTime,
    pub replayed_at: Option<PrimitiveDateTime>,
}

/// Compatibility name for callers that used the old row type. This is now the
/// metadata DTO; use [`get_quarantine_raw_by_id`] for an explicit raw read.
pub type AuditQuarantineRow = AuditQuarantineMetadata;

/// Explicit privileged record containing the failed message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuarantineRawRecord {
    pub metadata: AuditQuarantineMetadata,
    pub raw_payload: Vec<u8>,
}

/// Opaque operation identity returned to a worker claim.
///
/// The database stores only the hash of the operator-supplied operation id, so
/// a worker must carry this typed identity through confirm/fail rather than
/// attempting to reconstruct or log the original operation id.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayOperationIdentity([u8; 32]);

impl ReplayOperationIdentity {
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(operation_id: &str) -> Self {
        Self::from_operation_id(operation_id)
    }

    fn from_hash(hash: &[u8]) -> Result<Self, DbError> {
        let hash: [u8; 32] = hash.try_into().map_err(|_| {
            DbError::Mapping(format!(
                "code=quarantine.invalid_operation_id_hash;length={}",
                hash.len()
            ))
        })?;
        Ok(Self(hash))
    }

    fn from_operation_id(operation_id: &str) -> Self {
        Self(sha256_bytes(operation_id))
    }

    fn as_hash(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ReplayOperationIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReplayOperationIdentity(REDACTED)")
    }
}

/// One-time secret returned only by the explicit worker claim operation.
///
/// Its `Debug` implementation is redacted so accidental structured logging
/// cannot disclose the fencing secret. The database stores only its SHA-256
/// hash.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayLeaseToken(String);

impl ReplayLeaseToken {
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(token: &str) -> Self {
        Self(token.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ReplayLeaseToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReplayLeaseToken(REDACTED)")
    }
}

/// Privileged worker claim. The lease secret is separate from metadata and is
/// required, together with owner, operation identity and generation, for CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuarantineReplayClaim {
    pub raw_record: AuditQuarantineRawRecord,
    pub lease_owner: String,
    pub lease_generation: u64,
    pub lease_token: ReplayLeaseToken,
    pub lease_expires_at: PrimitiveDateTime,
    pub operation_identity: ReplayOperationIdentity,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditQuarantineDbRow {
    id: i64,
    identity_key: Vec<u8>,
    message_id: String,
    message_type: String,
    raw_payload: Vec<u8>,
    source_queue: String,
    source_exchange: String,
    source_routing_key: String,
    retry_count: u32,
    attempts: u32,
    replay_attempts: u32,
    failure_reason: String,
    status: String,
    replay_lease_owner: Option<String>,
    replay_lease_token_hash: Option<Vec<u8>>,
    replay_lease_generation: u64,
    replay_lease_expires_at: Option<PrimitiveDateTime>,
    replay_operation_id_hash: Option<Vec<u8>>,
    replay_requested_by: Option<String>,
    replay_requested_at: Option<PrimitiveDateTime>,
    first_failed_at: PrimitiveDateTime,
    last_failed_at: PrimitiveDateTime,
    quarantined_at: PrimitiveDateTime,
    replayed_at: Option<PrimitiveDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditQuarantineMetadataDbRow {
    id: i64,
    identity_key: Vec<u8>,
    message_id: String,
    message_type: String,
    source_queue: String,
    source_exchange: String,
    source_routing_key: String,
    retry_count: u32,
    attempts: u32,
    replay_attempts: u32,
    failure_reason: String,
    status: String,
    replay_lease_owner: Option<String>,
    replay_lease_generation: u64,
    replay_lease_expires_at: Option<PrimitiveDateTime>,
    replay_requested_by: Option<String>,
    replay_requested_at: Option<PrimitiveDateTime>,
    first_failed_at: PrimitiveDateTime,
    last_failed_at: PrimitiveDateTime,
    quarantined_at: PrimitiveDateTime,
    replayed_at: Option<PrimitiveDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
struct ExpiredReplayCandidate {
    id: i64,
    replay_operation_id_hash: Vec<u8>,
    replay_lease_generation: u64,
    replay_lease_owner: String,
    replay_lease_token_hash: Vec<u8>,
}

fn validate_optional_hash(value: Option<&[u8]>, field: &str) -> Result<(), DbError> {
    if value.is_some_and(|bytes| bytes.len() != 32) {
        return Err(DbError::Mapping(format!(
            "code=quarantine.invalid_hash;field={field}"
        )));
    }
    Ok(())
}

impl AuditQuarantineDbRow {
    fn into_raw_record(self) -> Result<AuditQuarantineRawRecord, DbError> {
        let identity_key: [u8; 32] = self.identity_key.try_into().map_err(|key: Vec<u8>| {
            DbError::Mapping(format!(
                "code=quarantine.invalid_identity_key;length={}",
                key.len()
            ))
        })?;
        validate_optional_hash(self.replay_lease_token_hash.as_deref(), "lease_token_hash")?;
        validate_optional_hash(
            self.replay_operation_id_hash.as_deref(),
            "operation_id_hash",
        )?;
        let status = AuditQuarantineStatus::from_str(&self.status)?;

        Ok(AuditQuarantineRawRecord {
            metadata: AuditQuarantineMetadata {
                id: self.id,
                identity_key,
                message_id: self.message_id,
                message_type: self.message_type,
                source_queue: self.source_queue,
                source_exchange: self.source_exchange,
                source_routing_key: self.source_routing_key,
                retry_count: self.retry_count,
                attempts: self.attempts,
                replay_attempts: self.replay_attempts,
                failure_reason: self.failure_reason,
                status,
                replay_lease_owner: self.replay_lease_owner,
                replay_lease_generation: self.replay_lease_generation,
                replay_lease_expires_at: self.replay_lease_expires_at,
                replay_requested_by: self.replay_requested_by,
                replay_requested_at: self.replay_requested_at,
                first_failed_at: self.first_failed_at,
                last_failed_at: self.last_failed_at,
                quarantined_at: self.quarantined_at,
                replayed_at: self.replayed_at,
            },
            raw_payload: self.raw_payload,
        })
    }
}

impl AuditQuarantineMetadataDbRow {
    fn into_metadata(self) -> Result<AuditQuarantineMetadata, DbError> {
        let identity_key: [u8; 32] = self.identity_key.try_into().map_err(|key: Vec<u8>| {
            DbError::Mapping(format!(
                "code=quarantine.invalid_identity_key;length={}",
                key.len()
            ))
        })?;
        let status = AuditQuarantineStatus::from_str(&self.status)?;
        Ok(AuditQuarantineMetadata {
            id: self.id,
            identity_key,
            message_id: self.message_id,
            message_type: self.message_type,
            source_queue: self.source_queue,
            source_exchange: self.source_exchange,
            source_routing_key: self.source_routing_key,
            retry_count: self.retry_count,
            attempts: self.attempts,
            replay_attempts: self.replay_attempts,
            failure_reason: self.failure_reason,
            status,
            replay_lease_owner: self.replay_lease_owner,
            replay_lease_generation: self.replay_lease_generation,
            replay_lease_expires_at: self.replay_lease_expires_at,
            replay_requested_by: self.replay_requested_by,
            replay_requested_at: self.replay_requested_at,
            first_failed_at: self.first_failed_at,
            last_failed_at: self.last_failed_at,
            quarantined_at: self.quarantined_at,
            replayed_at: self.replayed_at,
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

/// Compute the durable identity key for a terminal audit message.
///
/// With a canonical id, the exact byte stream is
/// `source_queue || NUL || message_type || NUL || canonical_message_id`.
/// Without one, the final component is the binary SHA-256 digest of the raw
/// payload. No textual placeholder is used, so a missing-id message cannot
/// collide with an actual canonical id equal to `"<missing>"` merely because
/// of a sentinel convention.
pub fn stable_quarantine_identity(
    source_queue: &str,
    message_type: &str,
    canonical_message_id: Option<&str>,
    raw_payload: &[u8],
) -> [u8; 32] {
    let raw_component = Sha256::digest(raw_payload);
    let final_component: &[u8] = match canonical_message_id {
        Some(message_id) => message_id.as_bytes(),
        None => raw_component.as_slice(),
    };
    let mut input =
        Vec::with_capacity(source_queue.len() + 1 + message_type.len() + 1 + final_component.len());
    input.extend_from_slice(source_queue.as_bytes());
    input.push(0);
    input.extend_from_slice(message_type.as_bytes());
    input.push(0);
    input.extend_from_slice(final_component);
    Sha256::digest(input).into()
}

fn input_identity(input: &AuditQuarantineInput) -> [u8; 32] {
    stable_quarantine_identity(
        &input.source_queue,
        &input.message_type,
        input.canonical_message_id.as_deref(),
        &input.raw_payload,
    )
}

async fn fetch_raw_by_id(
    connection: &mut MySqlConnection,
    id: i64,
) -> Result<Option<AuditQuarantineDbRow>, DbError> {
    let row = sqlx::query_as::<_, AuditQuarantineDbRow>(&format!(
        "SELECT {RAW_SELECT_COLUMNS} FROM audit_quarantine WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(connection)
    .await?;
    Ok(row)
}

async fn fetch_metadata_by_id(
    connection: &mut MySqlConnection,
    id: i64,
) -> Result<Option<AuditQuarantineMetadataDbRow>, DbError> {
    let row = sqlx::query_as::<_, AuditQuarantineMetadataDbRow>(&format!(
        "SELECT {METADATA_SELECT_COLUMNS} FROM audit_quarantine WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(connection)
    .await?;
    Ok(row)
}

async fn validate_known_status(pool: &MySqlPool, id: i64) -> Result<(), DbError> {
    let status: Option<(String,)> =
        sqlx::query_as("SELECT status FROM audit_quarantine WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    if let Some((status,)) = status {
        AuditQuarantineStatus::from_str(&status)?;
    }
    Ok(())
}

/// Insert a terminal failure, or atomically increment the existing identity's
/// attempt count and refresh its failure metadata. The lookup occurs in the
/// same transaction as the upsert, so the returned row is the committed view.
pub async fn insert_or_increment_terminal(
    pool: &MySqlPool,
    input: &AuditQuarantineInput,
) -> Result<AuditQuarantineRow, DbError> {
    validate_input(input)?;
    let identity_key = input_identity(input);
    let message_id = input
        .canonical_message_id
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| hex_encode(&identity_key));

    let mut transaction = pool.begin().await?;
    sqlx::query(INSERT_OR_INCREMENT_SQL)
        .bind(identity_key.as_slice())
        .bind(message_id)
        .bind(&input.message_type)
        .bind(&input.raw_payload)
        .bind(&input.source_queue)
        .bind(&input.source_exchange)
        .bind(&input.source_routing_key)
        .bind(input.retry_count)
        .bind(&input.failure_reason)
        .execute(&mut *transaction)
        .await?;

    let row = fetch_by_id_by_identity(&mut transaction, identity_key)
        .await?
        .ok_or_else(|| DbError::Mapping("code=quarantine.upsert_missing_row".into()))?;
    let metadata = row.into_metadata()?;
    transaction.commit().await?;
    Ok(metadata)
}

async fn fetch_by_id_by_identity(
    connection: &mut MySqlConnection,
    identity_key: [u8; 32],
) -> Result<Option<AuditQuarantineMetadataDbRow>, DbError> {
    let row = sqlx::query_as::<_, AuditQuarantineMetadataDbRow>(&format!(
        "SELECT {METADATA_SELECT_COLUMNS} FROM audit_quarantine WHERE identity_key = ?"
    ))
    .bind(identity_key.as_slice())
    .fetch_optional(connection)
    .await?;
    Ok(row)
}

/// Get one metadata DTO by its durable numeric id.
pub async fn get_quarantine_by_id(
    pool: &MySqlPool,
    id: i64,
) -> Result<Option<AuditQuarantineMetadata>, DbError> {
    get_quarantine_metadata_by_id(pool, id).await
}

/// Explicit metadata name for callers that want to make the privilege boundary
/// visible in their code.
pub async fn get_quarantine_metadata_by_id(
    pool: &MySqlPool,
    id: i64,
) -> Result<Option<AuditQuarantineMetadata>, DbError> {
    validate_id(id)?;
    let mut connection = pool.acquire().await?;
    fetch_metadata_by_id(&mut connection, id)
        .await?
        .map(AuditQuarantineMetadataDbRow::into_metadata)
        .transpose()
}

/// Get a raw record only through the explicit privileged repository method.
pub async fn get_quarantine_raw_by_id(
    pool: &MySqlPool,
    id: i64,
) -> Result<Option<AuditQuarantineRawRecord>, DbError> {
    validate_id(id)?;
    let mut connection = pool.acquire().await?;
    fetch_raw_by_id(&mut connection, id)
        .await?
        .map(AuditQuarantineDbRow::into_raw_record)
        .transpose()
}

/// Descriptive alias for callers using the table name in the method name.
pub async fn get_audit_quarantine_by_id(
    pool: &MySqlPool,
    id: i64,
) -> Result<Option<AuditQuarantineMetadata>, DbError> {
    get_quarantine_metadata_by_id(pool, id).await
}

/// List metadata DTOs by their controlled durable status.
pub async fn list_quarantine_by_status<S: AsRef<str>>(
    pool: &MySqlPool,
    status: S,
    limit: u32,
    offset: u32,
) -> Result<Vec<AuditQuarantineMetadata>, DbError> {
    let status = AuditQuarantineStatus::try_from(status.as_ref())?;
    validate_paging(limit, offset)?;
    let rows = sqlx::query_as::<_, AuditQuarantineMetadataDbRow>(&format!(
        "SELECT {METADATA_SELECT_COLUMNS} FROM audit_quarantine \
         WHERE status = ? ORDER BY quarantined_at DESC, id DESC LIMIT ? OFFSET ?"
    ))
    .bind(status.as_str())
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(AuditQuarantineMetadataDbRow::into_metadata)
        .collect()
}

/// Explicit metadata name for list callers.
pub async fn list_quarantine_metadata_by_status<S: AsRef<str>>(
    pool: &MySqlPool,
    status: S,
    limit: u32,
    offset: u32,
) -> Result<Vec<AuditQuarantineMetadata>, DbError> {
    list_quarantine_by_status(pool, status, limit, offset).await
}

/// Mark an operator-approved replay request. Worker claim is intentionally a
/// separate operation and cannot claim a plain `QUARANTINED` row.
pub async fn request_replay(
    pool: &MySqlPool,
    id: i64,
    operation_id: &str,
    requested_by: &str,
) -> Result<bool, DbError> {
    validate_id(id)?;
    validate_operation_id(operation_id)?;
    validate_lease_owner(requested_by)?;
    let operation_hash = sha256_bytes(operation_id);

    let mut transaction = pool.begin().await?;
    let Some(row) = fetch_raw_by_id(&mut transaction, id).await? else {
        transaction.commit().await?;
        return Ok(false);
    };
    let existing_operation_matches = row
        .replay_operation_id_hash
        .as_deref()
        .is_some_and(|hash| hash == operation_hash);
    let metadata = row.into_raw_record()?.metadata;

    let requested = match metadata.status {
        AuditQuarantineStatus::Quarantined => {
            if metadata.replay_attempts >= MAX_REPLAY_ATTEMPTS {
                false
            } else {
                sqlx::query(REQUEST_REPLAY_SQL)
                    .bind(operation_hash.as_slice())
                    .bind(requested_by)
                    .bind(id)
                    .bind(MAX_REPLAY_ATTEMPTS)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
                    == 1
            }
        }
        AuditQuarantineStatus::ReplayRequested => existing_operation_matches,
        AuditQuarantineStatus::Replaying | AuditQuarantineStatus::ReplayConfirmed => false,
    };
    transaction.commit().await?;
    Ok(requested)
}

/// Claim an operator-requested row with a server-generated fencing secret.
///
/// `operation_id` is the idempotency identity recorded by [`request_replay`],
/// not a caller-provided lease secret. The returned secret is held outside the
/// metadata DTO and is never persisted in plaintext.
pub async fn begin_replay(
    pool: &MySqlPool,
    id: i64,
    lease_owner: &str,
    operation_id: &str,
    lease_seconds: i64,
) -> Result<Option<AuditQuarantineReplayClaim>, DbError> {
    validate_id(id)?;
    validate_lease_owner(lease_owner)?;
    validate_operation_id(operation_id)?;
    validate_lease_seconds(lease_seconds)?;

    let operation_hash = sha256_bytes(operation_id);
    let token = ReplayLeaseToken(Uuid::new_v4().simple().to_string());
    let token_hash = sha256_bytes(token.as_str());

    let mut transaction = pool.begin().await?;
    let updated = sqlx::query(BEGIN_REPLAY_SQL)
        .bind(lease_owner)
        .bind(token_hash.as_slice())
        .bind(lease_seconds)
        .bind(id)
        .bind(MAX_REPLAY_ATTEMPTS)
        .bind(operation_hash.as_slice())
        .bind(operation_hash.as_slice())
        .execute(&mut *transaction)
        .await?;

    let Some(row) = fetch_raw_by_id(&mut transaction, id).await? else {
        transaction.commit().await?;
        return Ok(None);
    };
    let raw_record = row.into_raw_record()?;
    if updated.rows_affected() != 1 {
        let _ = raw_record.metadata.status;
        transaction.commit().await?;
        return Ok(None);
    }
    if raw_record.metadata.status != AuditQuarantineStatus::Replaying {
        transaction.commit().await?;
        return Ok(None);
    }
    let lease_generation = raw_record.metadata.replay_lease_generation;
    let lease_expires_at = raw_record
        .metadata
        .replay_lease_expires_at
        .ok_or_else(|| DbError::Mapping("code=quarantine.claim_missing_expiry".into()))?;
    transaction.commit().await?;

    Ok(Some(AuditQuarantineReplayClaim {
        raw_record,
        lease_owner: lease_owner.to_owned(),
        lease_generation,
        lease_token: token,
        lease_expires_at,
        operation_identity: ReplayOperationIdentity::from_operation_id(operation_id),
    }))
}

/// Claim the oldest exact TrustGraph audit replay request without requiring a
/// worker to recover the plaintext operation id. Only the operation hash is
/// selected from the database and carried in the typed claim.
pub async fn begin_next_requested_replay(
    pool: &MySqlPool,
    lease_owner: &str,
    source_queue: &str,
    source_exchange: &str,
    source_routing_key: &str,
    message_type: &str,
    lease_seconds: i64,
) -> Result<Option<AuditQuarantineReplayClaim>, DbError> {
    validate_lease_owner(lease_owner)?;
    validate_component(
        source_queue,
        "invalid_source_queue",
        MAX_SOURCE_QUEUE_LENGTH,
    )?;
    validate_component(
        source_exchange,
        "invalid_source_exchange",
        MAX_SOURCE_EXCHANGE_LENGTH,
    )?;
    validate_component(
        source_routing_key,
        "invalid_source_routing_key",
        MAX_SOURCE_ROUTING_KEY_LENGTH,
    )?;
    validate_component(
        message_type,
        "invalid_message_type",
        MAX_MESSAGE_TYPE_LENGTH,
    )?;
    validate_lease_seconds(lease_seconds)?;

    let token = ReplayLeaseToken(Uuid::new_v4().simple().to_string());
    let token_hash = sha256_bytes(token.as_str());
    let mut transaction = pool.begin().await?;
    let candidate: Option<(i64, Vec<u8>)> = sqlx::query_as(NEXT_REQUESTED_REPLAY_SQL)
        .bind(MAX_REPLAY_ATTEMPTS)
        .bind(source_queue)
        .bind(source_exchange)
        .bind(source_routing_key)
        .bind(message_type)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some((id, operation_hash)) = candidate else {
        transaction.commit().await?;
        return Ok(None);
    };
    let operation_identity = ReplayOperationIdentity::from_hash(&operation_hash)?;
    let updated = sqlx::query(BEGIN_REQUESTED_REPLAY_SQL)
        .bind(lease_owner)
        .bind(token_hash.as_slice())
        .bind(lease_seconds)
        .bind(id)
        .bind(MAX_REPLAY_ATTEMPTS)
        .bind(operation_identity.as_hash())
        .execute(&mut *transaction)
        .await?;
    if updated.rows_affected() != 1 {
        transaction.commit().await?;
        return Ok(None);
    }

    let Some(row) = fetch_raw_by_id(&mut transaction, id).await? else {
        transaction.commit().await?;
        return Ok(None);
    };
    let raw_record = row.into_raw_record()?;
    if raw_record.metadata.status != AuditQuarantineStatus::Replaying {
        transaction.commit().await?;
        return Ok(None);
    }
    let lease_generation = raw_record.metadata.replay_lease_generation;
    let lease_expires_at = raw_record
        .metadata
        .replay_lease_expires_at
        .ok_or_else(|| DbError::Mapping("code=quarantine.claim_missing_expiry".into()))?;
    transaction.commit().await?;

    Ok(Some(AuditQuarantineReplayClaim {
        raw_record,
        lease_owner: lease_owner.to_owned(),
        lease_generation,
        lease_token: token,
        lease_expires_at,
        operation_identity,
    }))
}

/// Claim the oldest expired TrustGraph replay lease without exposing the
/// plaintext operation id. Candidate selection and fencing update happen in
/// one transaction: `FOR UPDATE` serializes concurrent workers, while the
/// update repeats every old lease identity so a stale candidate cannot be
/// reclaimed after another worker has fenced it.
pub async fn begin_next_expired_replaying_replay(
    pool: &MySqlPool,
    lease_owner: &str,
    source_queue: &str,
    source_exchange: &str,
    source_routing_key: &str,
    message_type: &str,
    lease_seconds: i64,
) -> Result<Option<AuditQuarantineReplayClaim>, DbError> {
    validate_lease_owner(lease_owner)?;
    validate_component(
        source_queue,
        "invalid_source_queue",
        MAX_SOURCE_QUEUE_LENGTH,
    )?;
    validate_component(
        source_exchange,
        "invalid_source_exchange",
        MAX_SOURCE_EXCHANGE_LENGTH,
    )?;
    validate_component(
        source_routing_key,
        "invalid_source_routing_key",
        MAX_SOURCE_ROUTING_KEY_LENGTH,
    )?;
    validate_component(
        message_type,
        "invalid_message_type",
        MAX_MESSAGE_TYPE_LENGTH,
    )?;
    validate_lease_seconds(lease_seconds)?;

    let token = ReplayLeaseToken(Uuid::new_v4().simple().to_string());
    let token_hash = sha256_bytes(token.as_str());
    let mut transaction = pool.begin().await?;
    let candidate: Option<ExpiredReplayCandidate> =
        sqlx::query_as(NEXT_EXPIRED_REPLAYING_REPLAY_SQL)
            .bind(MAX_REPLAY_ATTEMPTS)
            .bind(source_queue)
            .bind(source_exchange)
            .bind(source_routing_key)
            .bind(message_type)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some(ExpiredReplayCandidate {
        id,
        replay_operation_id_hash: operation_hash,
        replay_lease_generation: lease_generation,
        replay_lease_owner: old_lease_owner,
        replay_lease_token_hash: old_token_hash,
    }) = candidate
    else {
        transaction.commit().await?;
        return Ok(None);
    };
    let operation_identity = ReplayOperationIdentity::from_hash(&operation_hash)?;
    validate_optional_hash(Some(&old_token_hash), "lease_token_hash")?;
    let updated = sqlx::query(BEGIN_EXPIRED_REPLAYING_REPLAY_SQL)
        .bind(lease_owner)
        .bind(token_hash.as_slice())
        .bind(lease_seconds)
        .bind(id)
        .bind(MAX_REPLAY_ATTEMPTS)
        .bind(source_queue)
        .bind(source_exchange)
        .bind(source_routing_key)
        .bind(message_type)
        .bind(operation_identity.as_hash())
        .bind(lease_generation)
        .bind(&old_lease_owner)
        .bind(&old_token_hash)
        .execute(&mut *transaction)
        .await?;
    if updated.rows_affected() != 1 {
        transaction.commit().await?;
        return Ok(None);
    }

    let Some(row) = fetch_raw_by_id(&mut transaction, id).await? else {
        transaction.commit().await?;
        return Ok(None);
    };
    let raw_record = row.into_raw_record()?;
    if raw_record.metadata.status != AuditQuarantineStatus::Replaying {
        transaction.commit().await?;
        return Ok(None);
    }
    let lease_generation = raw_record.metadata.replay_lease_generation;
    let lease_expires_at = raw_record
        .metadata
        .replay_lease_expires_at
        .ok_or_else(|| DbError::Mapping("code=quarantine.claim_missing_expiry".into()))?;
    transaction.commit().await?;

    Ok(Some(AuditQuarantineReplayClaim {
        raw_record,
        lease_owner: lease_owner.to_owned(),
        lease_generation,
        lease_token: token,
        lease_expires_at,
        operation_identity,
    }))
}

/// Return metadata for replay rows that reached the retry ceiling. The worker
/// uses this read only for structured observability; these rows remain in their
/// durable status and are never marked confirmed implicitly.
pub async fn list_exhausted_replays(
    pool: &MySqlPool,
    source_queue: &str,
    source_exchange: &str,
    source_routing_key: &str,
    message_type: &str,
    limit: u32,
) -> Result<Vec<AuditQuarantineMetadata>, DbError> {
    validate_component(
        source_queue,
        "invalid_source_queue",
        MAX_SOURCE_QUEUE_LENGTH,
    )?;
    validate_component(
        source_exchange,
        "invalid_source_exchange",
        MAX_SOURCE_EXCHANGE_LENGTH,
    )?;
    validate_component(
        source_routing_key,
        "invalid_source_routing_key",
        MAX_SOURCE_ROUTING_KEY_LENGTH,
    )?;
    validate_component(
        message_type,
        "invalid_message_type",
        MAX_MESSAGE_TYPE_LENGTH,
    )?;
    if limit == 0 || limit > MAX_LIST_LIMIT {
        return Err(validation_error("invalid_exhausted_replay_limit"));
    }

    let rows = sqlx::query_as::<_, AuditQuarantineMetadataDbRow>(&format!(
        "SELECT {METADATA_SELECT_COLUMNS} \
         FROM audit_quarantine \
         WHERE replay_attempts >= ? \
           AND status <> 'REPLAY_CONFIRMED' \
           AND source_queue = ? \
           AND source_exchange = ? \
           AND source_routing_key = ? \
           AND message_type = ? \
         ORDER BY quarantined_at ASC, id ASC LIMIT ?"
    ))
    .bind(MAX_REPLAY_ATTEMPTS)
    .bind(source_queue)
    .bind(source_exchange)
    .bind(source_routing_key)
    .bind(message_type)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(AuditQuarantineMetadataDbRow::into_metadata)
        .collect()
}

async fn confirm_replay_by_hash(
    pool: &MySqlPool,
    id: i64,
    lease_owner: &str,
    operation_hash: &[u8],
    lease_generation: u64,
    lease_token: &str,
) -> Result<bool, DbError> {
    if id <= 0
        || lease_owner.is_empty()
        || operation_hash.len() != 32
        || lease_generation == 0
        || lease_token.is_empty()
    {
        return Ok(false);
    }
    validate_lease_owner(lease_owner)?;
    let token_hash = sha256_bytes(lease_token);
    let mut transaction = pool.begin().await?;
    let updated = sqlx::query(CONFIRM_REPLAY_SQL)
        .bind(id)
        .bind(lease_owner)
        .bind(lease_generation)
        .bind(operation_hash)
        .bind(token_hash.as_slice())
        .execute(&mut *transaction)
        .await?;
    if updated.rows_affected() == 1 {
        transaction.commit().await?;
        return Ok(true);
    }
    let idempotent: Option<(i64,)> = sqlx::query_as(CONFIRM_IDEMPOTENT_SQL)
        .bind(id)
        .bind(lease_owner)
        .bind(lease_generation)
        .bind(operation_hash)
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
    if idempotent.is_some() {
        transaction.commit().await?;
        return Ok(true);
    }
    validate_known_status(pool, id).await?;
    transaction.commit().await?;
    Ok(false)
}

async fn fail_replay_by_hash(
    pool: &MySqlPool,
    id: i64,
    lease_owner: &str,
    operation_hash: &[u8],
    lease_generation: u64,
    lease_token: &str,
    failure_reason: &str,
) -> Result<bool, DbError> {
    if id <= 0
        || lease_owner.is_empty()
        || operation_hash.len() != 32
        || lease_generation == 0
        || lease_token.is_empty()
    {
        return Ok(false);
    }
    validate_lease_owner(lease_owner)?;
    validate_failure_reason(failure_reason)?;
    let token_hash = sha256_bytes(lease_token);
    let updated = sqlx::query(FAIL_REPLAY_SQL)
        .bind(failure_reason)
        .bind(id)
        .bind(lease_owner)
        .bind(lease_generation)
        .bind(operation_hash)
        .bind(token_hash.as_slice())
        .execute(pool)
        .await?;
    if updated.rows_affected() == 1 {
        return Ok(true);
    }
    validate_known_status(pool, id).await?;
    Ok(false)
}

/// Confirm a typed worker claim with all fencing identities intact.
pub async fn confirm_replay_claim(
    pool: &MySqlPool,
    claim: &AuditQuarantineReplayClaim,
) -> Result<bool, DbError> {
    confirm_replay_by_hash(
        pool,
        claim.raw_record.metadata.id,
        &claim.lease_owner,
        claim.operation_identity.as_hash(),
        claim.lease_generation,
        claim.lease_token.as_str(),
    )
    .await
}

/// Fail a typed worker claim with all fencing identities intact.
pub async fn fail_replay_claim(
    pool: &MySqlPool,
    claim: &AuditQuarantineReplayClaim,
    failure_reason: &str,
) -> Result<bool, DbError> {
    fail_replay_by_hash(
        pool,
        claim.raw_record.metadata.id,
        &claim.lease_owner,
        claim.operation_identity.as_hash(),
        claim.lease_generation,
        claim.lease_token.as_str(),
        failure_reason,
    )
    .await
}

/// Confirm replay with active owner, operation identity, generation and token.
/// A repeated confirmation is idempotent only when all of those identities
/// match the already-confirmed operation; any other non-empty token is false.
pub async fn confirm_replay(
    pool: &MySqlPool,
    id: i64,
    lease_owner: &str,
    operation_id: &str,
    lease_generation: u64,
    lease_token: &str,
) -> Result<bool, DbError> {
    if id <= 0
        || lease_owner.is_empty()
        || operation_id.is_empty()
        || lease_generation == 0
        || lease_token.is_empty()
    {
        return Ok(false);
    }
    validate_lease_owner(lease_owner)?;
    validate_operation_id(operation_id)?;
    let operation_hash = sha256_bytes(operation_id);
    let token_hash = sha256_bytes(lease_token);

    let mut transaction = pool.begin().await?;
    let updated = sqlx::query(CONFIRM_REPLAY_SQL)
        .bind(id)
        .bind(lease_owner)
        .bind(lease_generation)
        .bind(operation_hash.as_slice())
        .bind(token_hash.as_slice())
        .execute(&mut *transaction)
        .await?;
    if updated.rows_affected() == 1 {
        transaction.commit().await?;
        return Ok(true);
    }

    let idempotent: Option<(i64,)> = sqlx::query_as(CONFIRM_IDEMPOTENT_SQL)
        .bind(id)
        .bind(lease_owner)
        .bind(lease_generation)
        .bind(operation_hash.as_slice())
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
    if idempotent.is_some() {
        transaction.commit().await?;
        return Ok(true);
    }

    let status: Option<(String,)> =
        sqlx::query_as("SELECT status FROM audit_quarantine WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await?;
    if let Some((status,)) = status {
        AuditQuarantineStatus::from_str(&status)?;
    }
    transaction.commit().await?;
    Ok(false)
}

/// Fail replay with the active owner, operation identity, generation and token,
/// returning the row to `QUARANTINED` while retaining the failure reason.
pub async fn fail_replay(
    pool: &MySqlPool,
    id: i64,
    lease_owner: &str,
    operation_id: &str,
    lease_generation: u64,
    lease_token: &str,
    failure_reason: &str,
) -> Result<bool, DbError> {
    if id <= 0
        || lease_owner.is_empty()
        || operation_id.is_empty()
        || lease_generation == 0
        || lease_token.is_empty()
    {
        return Ok(false);
    }
    validate_lease_owner(lease_owner)?;
    validate_operation_id(operation_id)?;
    validate_failure_reason(failure_reason)?;
    let operation_hash = sha256_bytes(operation_id);
    let token_hash = sha256_bytes(lease_token);

    let updated = sqlx::query(FAIL_REPLAY_SQL)
        .bind(failure_reason)
        .bind(id)
        .bind(lease_owner)
        .bind(lease_generation)
        .bind(operation_hash.as_slice())
        .bind(token_hash.as_slice())
        .execute(pool)
        .await?;
    if updated.rows_affected() == 1 {
        return Ok(true);
    }
    validate_known_status(pool, id).await?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_uses_canonical_id_when_present() {
        let expected = Sha256::digest(b"audit\0permission\0message-1");
        assert_eq!(
            stable_quarantine_identity("audit", "permission", Some("message-1"), b"ignored"),
            <[u8; 32]>::from(expected)
        );
    }

    #[test]
    fn identity_hashes_raw_payload_without_a_sentinel() {
        let raw_hash = Sha256::digest(b"<missing>");
        let mut canonical = b"audit\0permission\0".to_vec();
        canonical.extend_from_slice(raw_hash.as_slice());
        let expected = Sha256::digest(canonical);
        let actual = stable_quarantine_identity("audit", "permission", None, b"<missing>");
        assert_eq!(actual, <[u8; 32]>::from(expected));
        assert_ne!(
            actual,
            stable_quarantine_identity("audit", "permission", Some("<missing>"), b"<missing>")
        );
    }

    #[test]
    fn unknown_status_is_a_structured_error_and_never_a_replay_state() {
        let error = AuditQuarantineStatus::from_str("CORRUPTED").expect_err("unknown state");
        assert!(error.to_string().contains("code=quarantine.invalid_status"));
        assert!(AuditQuarantineStatus::from_str("CORRUPTED").is_err());
    }

    #[test]
    fn input_and_paging_validation_rejects_oversized_values() {
        let mut input = AuditQuarantineInput {
            source_queue: "queue".into(),
            message_type: "type".into(),
            canonical_message_id: None,
            raw_payload: vec![1],
            source_exchange: "exchange".into(),
            source_routing_key: "routing".into(),
            retry_count: 0,
            failure_reason: "reason".into(),
        };
        assert!(validate_input(&input).is_ok());
        input.raw_payload = vec![0; MAX_PAYLOAD_BYTES + 1];
        assert!(validate_input(&input).is_err());
        assert!(validate_paging(MAX_LIST_LIMIT, MAX_LIST_OFFSET).is_ok());
        assert!(validate_paging(MAX_LIST_LIMIT + 1, 0).is_err());
        assert!(validate_paging(1, MAX_LIST_OFFSET + 1).is_err());
    }

    #[test]
    fn replay_sql_contains_request_separation_and_fencing_guards() {
        assert!(INSERT_OR_INCREMENT_SQL.contains("replay_lease_token_hash = NULL"));
        assert!(REQUEST_REPLAY_SQL.contains("status = 'REPLAY_REQUESTED'"));
        assert!(REQUEST_REPLAY_SQL.contains("replay_attempts < ?"));
        assert!(BEGIN_REPLAY_SQL.contains("status = 'REPLAY_REQUESTED'"));
        assert!(BEGIN_REPLAY_SQL.contains("replay_attempts < ?"));
        assert!(BEGIN_REPLAY_SQL.contains("replay_lease_generation = replay_lease_generation + 1"));
        assert!(BEGIN_REPLAY_SQL.contains(MAX_LEASE_GENERATION_SQL));
        assert!(BEGIN_REQUESTED_REPLAY_SQL.contains(MAX_LEASE_GENERATION_SQL));
        assert!(BEGIN_REQUESTED_REPLAY_SQL
            .contains("replay_lease_generation = replay_lease_generation + 1"));
        assert!(BEGIN_EXPIRED_REPLAYING_REPLAY_SQL.contains(MAX_LEASE_GENERATION_SQL));
        assert!(BEGIN_EXPIRED_REPLAYING_REPLAY_SQL
            .contains("replay_lease_generation = replay_lease_generation + 1"));
        assert!(BEGIN_REPLAY_SQL.contains("replay_lease_token_hash = ?"));
        assert!(BEGIN_REPLAY_SQL.contains("replay_lease_expires_at <= UTC_TIMESTAMP()"));
        assert!(NEXT_EXPIRED_REPLAYING_REPLAY_SQL.contains("FOR UPDATE"));
        assert!(NEXT_EXPIRED_REPLAYING_REPLAY_SQL
            .contains("replay_lease_expires_at <= UTC_TIMESTAMP()"));
        assert!(BEGIN_EXPIRED_REPLAYING_REPLAY_SQL.contains("replay_lease_generation = ?"));
        assert!(BEGIN_EXPIRED_REPLAYING_REPLAY_SQL.contains("replay_lease_token_hash = ?"));
        assert!(
            BEGIN_EXPIRED_REPLAYING_REPLAY_SQL.contains("replay_attempts = replay_attempts + 1")
        );
        assert!(CONFIRM_REPLAY_SQL.contains("replay_lease_owner = ?"));
        assert!(CONFIRM_REPLAY_SQL.contains("replay_lease_generation = ?"));
        assert!(CONFIRM_REPLAY_SQL.contains("replay_lease_token_hash = ?"));
        assert!(CONFIRM_REPLAY_SQL.contains("replay_lease_expires_at > UTC_TIMESTAMP()"));
        assert!(CONFIRM_IDEMPOTENT_SQL.contains("status = 'REPLAY_CONFIRMED'"));
        assert!(FAIL_REPLAY_SQL.contains("status = 'QUARANTINED'"));
        assert!(FAIL_REPLAY_SQL.contains("failure_reason = ?"));
    }

    #[test]
    fn status_values_match_migration_contract() {
        assert_eq!(AuditQuarantineStatus::Quarantined.as_str(), "QUARANTINED");
        assert_eq!(
            AuditQuarantineStatus::ReplayRequested.as_str(),
            "REPLAY_REQUESTED"
        );
        assert_eq!(AuditQuarantineStatus::Replaying.as_str(), "REPLAYING");
        assert_eq!(
            AuditQuarantineStatus::ReplayConfirmed.as_str(),
            "REPLAY_CONFIRMED"
        );
    }

    #[test]
    fn lease_token_debug_is_redacted() {
        let token = ReplayLeaseToken("secret-token".into());
        assert!(!format!("{token:?}").contains("secret-token"));
    }
}
