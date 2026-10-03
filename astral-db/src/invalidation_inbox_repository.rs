//! MySQL-backed durable per-node invalidation inbox.
//!
//! The Rabbit invalidation fanout transport gives every node its own durable
//! subscription queue. Before a broker delivery may be ACKed, the consumer
//! commits a row here; that row is the node-local durable receipt. Only after
//! the node's in-memory invalidation apply succeeds is the receipt marked
//! `APPLIED`.
//!
//! Receipt semantics (fail-closed):
//! - `PENDING`  — the node durably received the notification but has not
//!   proven the in-memory apply. A receipt left `PENDING` (for example after
//!   repeated apply failures) is a reconciliation flag, never a readiness
//!   proof.
//! - `APPLIED`  — the node durably received the notification **and** applied
//!   it to its local acceleration state. This proves invalidation freshness
//!   only; it never proves that a downstream authorization projection is
//!   READY. Authorization read gates stay `PENDING`/`DENY` until the
//!   projection path itself proves READY.
//!
//! Write ownership: this repository exclusively owns
//! `authorization_invalidation_inbox`. It deliberately shares no rows, keys,
//! or write paths with [`crate::LocalMessageRepository`] (`al_message_outbox`),
//! which remains the sole owner of the sender-side outbox state machine.

use sqlx::mysql::MySqlPool;
use sqlx::FromRow;
use time::PrimitiveDateTime;

const MAX_NODE_REGION_BYTES: usize = 64;
const MAX_NODE_ID_BYTES: usize = 128;
const MAX_MESSAGE_ID_BYTES: usize = 128;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_MESSAGE_TYPE_BYTES: usize = 64;
const MAX_ORIGIN_REGION_BYTES: usize = 64;
const MAX_ORDERING_KEY_BYTES: usize = 256;

/// Identity charset shared with the astral-mq `NodeIdentity` contract. The
/// rules are mirrored here (astral-db does not depend on astral-mq) so a
/// rejected identity fails closed at whichever boundary is reached first.
fn is_valid_identity_part(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_'
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationInboxCommit {
    /// First durable commit of this delivery on this node.
    InsertedPending,
    /// Redelivery of a receipt that is still `PENDING` (apply not proven).
    ExistingPending,
    /// Duplicate delivery of an already applied receipt.
    ExistingApplied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationInboxMarkApplied {
    /// The receipt transitioned `PENDING -> APPLIED` in this call.
    Applied,
    /// The receipt was already `APPLIED` (idempotent re-apply).
    AlreadyApplied,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidationInboxError {
    #[error("invalidation inbox validation failed: {0}")]
    Validation(String),
    #[error("invalidation inbox receipt conflicts with an existing message id")]
    PayloadConflict,
    #[error("invalidation inbox receipt is missing")]
    RowMissing,
    #[error("invalidation inbox database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone)]
pub struct InvalidationInboxInput<'a> {
    pub node_region: &'a str,
    pub node_id: &'a str,
    pub message_id: &'a str,
    pub operation_id: &'a str,
    pub message_type: &'a str,
    pub ordering_key: Option<&'a str>,
    pub tenant_id: Option<i64>,
    pub origin_region: &'a str,
    pub schema_version: i32,
    pub payload_json: &'a str,
    pub payload_sha256: &'a str,
    /// The sender envelope's `createdAt` (UTC), used for per-scope watermark
    /// gap detection. Parsed/normalized by the caller before this boundary.
    pub envelope_created_at: PrimitiveDateTime,
}

#[derive(Debug, Clone, FromRow)]
pub struct InvalidationInboxRow {
    pub node_region: String,
    pub node_id: String,
    pub message_id: String,
    pub operation_id: String,
    pub message_type: String,
    pub ordering_key: Option<String>,
    pub tenant_id: Option<i64>,
    pub origin_region: String,
    pub schema_version: i32,
    pub payload_json: String,
    pub payload_sha256: String,
    pub envelope_created_at: PrimitiveDateTime,
    pub status: String,
    pub applied_at: Option<PrimitiveDateTime>,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

#[derive(Clone)]
pub struct InvalidationInboxRepository {
    pool: MySqlPool,
}

impl InvalidationInboxRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Commit a delivery as this node's durable receipt. The insert is the
    /// durable proof that the node received the notification; it is
    /// idempotent under broker redelivery. A conflicting redelivery (same
    /// `(node_region, node_id, message_id)` with different content) fails
    /// closed with [`InvalidationInboxError::PayloadConflict`].
    pub async fn commit_delivery(
        &self,
        input: &InvalidationInboxInput<'_>,
    ) -> Result<InvalidationInboxCommit, InvalidationInboxError> {
        validate_input(input)?;
        let result = sqlx::query(
            "INSERT INTO authorization_invalidation_inbox \
             (node_region, node_id, message_id, operation_id, message_type, ordering_key, \
              tenant_id, origin_region, schema_version, payload_json, payload_sha256, \
              envelope_created_at, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING') \
             ON DUPLICATE KEY UPDATE node_region = node_region",
        )
        .bind(input.node_region)
        .bind(input.node_id)
        .bind(input.message_id)
        .bind(input.operation_id)
        .bind(input.message_type)
        .bind(input.ordering_key)
        .bind(input.tenant_id)
        .bind(input.origin_region)
        .bind(input.schema_version)
        .bind(input.payload_json)
        .bind(input.payload_sha256)
        .bind(input.envelope_created_at)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 1 {
            return Ok(InvalidationInboxCommit::InsertedPending);
        }
        let existing = self
            .receipt(input.node_region, input.node_id, input.message_id)
            .await?;
        match existing {
            Some(row)
                if row.payload_sha256 == input.payload_sha256
                    && row.operation_id == input.operation_id
                    && row.message_type == input.message_type
                    && row.ordering_key.as_deref() == input.ordering_key
                    && row.tenant_id == input.tenant_id
                    && row.origin_region == input.origin_region
                    && row.schema_version == input.schema_version
                    && row.payload_json == input.payload_json
                    && row.envelope_created_at == input.envelope_created_at =>
            {
                if row.status == "APPLIED" {
                    Ok(InvalidationInboxCommit::ExistingApplied)
                } else {
                    Ok(InvalidationInboxCommit::ExistingPending)
                }
            }
            Some(_) => Err(InvalidationInboxError::PayloadConflict),
            None => Err(InvalidationInboxError::Database(sqlx::Error::Protocol(
                "duplicate invalidation inbox receipt disappeared before readback".into(),
            ))),
        }
    }

    /// Mark a receipt `APPLIED` after the node's in-memory apply succeeded.
    /// The transition is guarded on `status = 'PENDING'` so a concurrent or
    /// repeated mark stays idempotent.
    pub async fn mark_applied(
        &self,
        node_region: &str,
        node_id: &str,
        message_id: &str,
    ) -> Result<InvalidationInboxMarkApplied, InvalidationInboxError> {
        validate_identity(node_region, node_id)?;
        if message_id.trim().is_empty() || message_id.len() > MAX_MESSAGE_ID_BYTES {
            return Err(InvalidationInboxError::Validation(
                "message_id is required and must be at most 128 bytes".into(),
            ));
        }
        let result = sqlx::query(
            "UPDATE authorization_invalidation_inbox \
             SET status = 'APPLIED', applied_at = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6) \
             WHERE node_region = ? AND node_id = ? AND message_id = ? AND status = 'PENDING'",
        )
        .bind(node_region)
        .bind(node_id)
        .bind(message_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 1 {
            return Ok(InvalidationInboxMarkApplied::Applied);
        }
        let existing = self.receipt(node_region, node_id, message_id).await?;
        match existing {
            Some(row) if row.status == "APPLIED" => {
                Ok(InvalidationInboxMarkApplied::AlreadyApplied)
            }
            Some(_) => Err(InvalidationInboxError::Validation(
                "invalidation inbox receipt is not in an applicable state".into(),
            )),
            None => Err(InvalidationInboxError::RowMissing),
        }
    }

    /// Load one receipt; `None` when this node never committed the message.
    pub async fn receipt(
        &self,
        node_region: &str,
        node_id: &str,
        message_id: &str,
    ) -> Result<Option<InvalidationInboxRow>, InvalidationInboxError> {
        Ok(sqlx::query_as::<_, InvalidationInboxRow>(
            "SELECT node_region, node_id, message_id, operation_id, message_type, ordering_key, \
                    tenant_id, origin_region, schema_version, payload_json, payload_sha256, \
                    envelope_created_at, status, applied_at, created_at, updated_at \
             FROM authorization_invalidation_inbox \
             WHERE node_region = ? AND node_id = ? AND message_id = ?",
        )
        .bind(node_region)
        .bind(node_id)
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Per-scope watermark gap probe: does this node still hold a `PENDING`
    /// receipt inside the ordering-key scope that strictly precedes
    /// `(envelope_created_at, message_id)`? A `true` answer means an
    /// out-of-order gap exists and scope reconciliation must be flagged. The
    /// probe never mutates state and never clears a proof.
    pub async fn has_pending_before(
        &self,
        node_region: &str,
        node_id: &str,
        ordering_key: &str,
        envelope_created_at: PrimitiveDateTime,
        message_id: &str,
    ) -> Result<bool, InvalidationInboxError> {
        validate_identity(node_region, node_id)?;
        if ordering_key.trim().is_empty() || ordering_key.len() > MAX_ORDERING_KEY_BYTES {
            return Err(InvalidationInboxError::Validation(
                "ordering_key is required and must be at most 256 bytes".into(),
            ));
        }
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM authorization_invalidation_inbox \
             WHERE node_region = ? AND node_id = ? AND ordering_key = ? AND status = 'PENDING' \
               AND (envelope_created_at < ? \
                    OR (envelope_created_at = ? AND message_id < ?))",
        )
        .bind(node_region)
        .bind(node_id)
        .bind(ordering_key)
        .bind(envelope_created_at)
        .bind(envelope_created_at)
        .bind(message_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 > 0)
    }
}

fn validate_identity(node_region: &str, node_id: &str) -> Result<(), InvalidationInboxError> {
    if !is_valid_identity_part(node_region) || node_region.len() > MAX_NODE_REGION_BYTES {
        return Err(InvalidationInboxError::Validation(
            "node_region must be a non-empty legal identity of at most 64 bytes".into(),
        ));
    }
    if !is_valid_identity_part(node_id) || node_id.len() > MAX_NODE_ID_BYTES {
        return Err(InvalidationInboxError::Validation(
            "node_id must be a non-empty legal identity of at most 128 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_input(input: &InvalidationInboxInput<'_>) -> Result<(), InvalidationInboxError> {
    validate_identity(input.node_region, input.node_id)?;
    for (name, value) in [
        ("message_id", input.message_id),
        ("operation_id", input.operation_id),
        ("message_type", input.message_type),
        ("origin_region", input.origin_region),
        ("payload_json", input.payload_json),
        ("payload_sha256", input.payload_sha256),
    ] {
        if value.trim().is_empty() {
            return Err(InvalidationInboxError::Validation(format!(
                "{name} is required"
            )));
        }
    }
    if input.message_id.len() > MAX_MESSAGE_ID_BYTES
        || input.operation_id.len() > MAX_OPERATION_ID_BYTES
        || input.message_type.len() > MAX_MESSAGE_TYPE_BYTES
        || input.origin_region.len() > MAX_ORIGIN_REGION_BYTES
    {
        return Err(InvalidationInboxError::Validation(
            "invalidation inbox metadata is too long".into(),
        ));
    }
    if input
        .ordering_key
        .is_some_and(|value| value.len() > MAX_ORDERING_KEY_BYTES)
    {
        return Err(InvalidationInboxError::Validation(
            "ordering_key is too long".into(),
        ));
    }
    if input.schema_version <= 0 {
        return Err(InvalidationInboxError::Validation(
            "schema_version must be positive".into(),
        ));
    }
    if input.tenant_id.is_some_and(|tenant_id| tenant_id <= 0) {
        return Err(InvalidationInboxError::Validation(
            "tenant_id must be positive when present".into(),
        ));
    }
    if input.payload_sha256.len() != 64
        || !input
            .payload_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(InvalidationInboxError::Validation(
            "payload_sha256 must be a 64-character hexadecimal digest".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(message_id: &str) -> InvalidationInboxInput<'_> {
        InvalidationInboxInput {
            node_region: "city-a",
            node_id: "node-1",
            message_id,
            operation_id: "operation-1",
            message_type: "EVIDENCE_INVALIDATED",
            ordering_key: Some("authorization:evidence:tenant/7/card/42"),
            tenant_id: Some(7),
            origin_region: "city-a",
            schema_version: 1,
            payload_json: "{}",
            payload_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            envelope_created_at: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2026, time::Month::October, 1).unwrap(),
                time::Time::MIDNIGHT,
            ),
        }
    }

    #[test]
    fn input_contract_rejects_missing_fields_and_bad_digest() {
        let mut bad = input("msg-1");
        bad.message_id = " ";
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message)) if message.contains("message_id")
        ));

        let mut bad = input("msg-1");
        bad.payload_sha256 = "not-a-digest";
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message))
                if message.contains("payload_sha256")
        ));

        let mut bad = input("msg-1");
        bad.tenant_id = Some(0);
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message)) if message.contains("tenant_id")
        ));

        let mut bad = input("msg-1");
        bad.schema_version = 0;
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message))
                if message.contains("schema_version")
        ));
    }

    #[test]
    fn identity_contract_mirrors_node_identity_rules() {
        let mut bad = input("msg-1");
        bad.node_region = "";
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message))
                if message.contains("node_region")
        ));

        let mut bad = input("msg-1");
        bad.node_id = "bad id with space";
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message)) if message.contains("node_id")
        ));

        let long_node = "n".repeat(129);
        let mut bad = input("msg-1");
        bad.node_id = &long_node;
        assert!(matches!(
            validate_input(&bad),
            Err(InvalidationInboxError::Validation(message)) if message.contains("node_id")
        ));

        let boundary_region = "r".repeat(64);
        let boundary_node = "n".repeat(128);
        let mut boundary = input("msg-1");
        boundary.node_region = &boundary_region;
        boundary.node_id = &boundary_node;
        assert!(validate_input(&boundary).is_ok());
    }

    #[test]
    fn identity_part_charset_is_strict() {
        assert!(is_valid_identity_part("city-a"));
        assert!(is_valid_identity_part("node_1.a"));
        assert!(!is_valid_identity_part(""));
        assert!(!is_valid_identity_part("city a"));
        assert!(!is_valid_identity_part("节点"));
    }
}
