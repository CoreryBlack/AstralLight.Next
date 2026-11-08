//! Durable recipient-specific legs for committed invalidation messages.
//!
//! This journal is independent from `al_message_outbox` settlement. One source
//! transaction stages the canonical outbox row and a frozen recipient roster;
//! each transport leg then advances under its own lease/generation fence.

use std::sync::Arc;

use astral_types::AuthorizationMessageMetadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

pub const INVALIDATION_DELIVERY_MAX_RECIPIENTS: usize = 64;
pub const INVALIDATION_DELIVERY_MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const INVALIDATION_DELIVERY_LEASE_SECONDS: i64 = 30;
pub const INVALIDATION_DELIVERY_MAX_ATTEMPTS: u32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationDeliveryTransport {
    SameDbMtls,
    CrossDbRabbit,
}

impl InvalidationDeliveryTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::SameDbMtls => "same_db_mtls",
            Self::CrossDbRabbit => "cross_db_rabbit",
        }
    }
}

/// Frozen startup recipient route. This value is trusted configuration, never
/// deserialized from an invalidation envelope or a request header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InvalidationDeliveryRecipient {
    pub region_id: String,
    pub node_id: String,
    pub database_id: String,
    pub transport: InvalidationDeliveryTransport,
    /// HTTPS endpoint for same-DB mTLS; absent for Rabbit legs.
    pub endpoint: Option<String>,
    /// SHA-256 of the peer certificate DER pinned by the frozen roster.
    pub peer_certificate_sha256: Option<String>,
}

impl InvalidationDeliveryRecipient {
    fn validate(&self, source_database_id: &str) -> Result<(), InvalidationDeliveryError> {
        validate_identity(&self.region_id, 64, "region_id")?;
        validate_identity(&self.node_id, 128, "node_id")?;
        validate_identity(&self.database_id, 128, "database_id")?;
        match self.transport {
            InvalidationDeliveryTransport::SameDbMtls => {
                if self.database_id != source_database_id {
                    return Err(InvalidationDeliveryError::InvalidRoster(
                        "same-db recipient database identity differs from source".into(),
                    ));
                }
                let endpoint = self.endpoint.as_deref().ok_or_else(|| {
                    InvalidationDeliveryError::InvalidRoster(
                        "same-db recipient HTTPS endpoint is required".into(),
                    )
                })?;
                let parsed = url::Url::parse(endpoint).map_err(|_| {
                    InvalidationDeliveryError::InvalidRoster(
                        "same-db recipient endpoint must be a valid HTTPS URL".into(),
                    )
                })?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || parsed.username() != ""
                    || parsed.password().is_some()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(InvalidationDeliveryError::InvalidRoster(
                        "same-db recipient endpoint must be HTTPS without credentials/query/fragment".into(),
                    ));
                }
                validate_digest(
                    self.peer_certificate_sha256.as_deref(),
                    "peer_certificate_sha256",
                )?;
            }
            InvalidationDeliveryTransport::CrossDbRabbit => {
                if self.database_id == source_database_id {
                    return Err(InvalidationDeliveryError::InvalidRoster(
                        "cross-db Rabbit recipient must use another database identity".into(),
                    ));
                }
                if self.endpoint.is_some() || self.peer_certificate_sha256.is_some() {
                    return Err(InvalidationDeliveryError::InvalidRoster(
                        "Rabbit recipient cannot carry a same-db endpoint or TLS pin".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Startup-frozen delivery inputs shared by every source writer in a process.
///
/// This is deliberately an immutable, owned value: producers receive a clone of
/// the same context and never read env/config globals while a source transaction
/// is open. The recipient order is canonicalized once here, so every journal
/// stage call receives the identical roster bytes and roster version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidationDeliveryContext {
    source_database_id: Arc<str>,
    roster_version: Arc<str>,
    recipients: Arc<[InvalidationDeliveryRecipient]>,
}

impl InvalidationDeliveryContext {
    pub fn try_new(
        source_database_id: impl Into<String>,
        roster_version: impl Into<String>,
        mut recipients: Vec<InvalidationDeliveryRecipient>,
    ) -> Result<Self, InvalidationDeliveryError> {
        let source_database_id = source_database_id.into();
        let roster_version = roster_version.into();
        validate_identity(&source_database_id, 128, "source_database_id")?;
        validate_identity(&roster_version, 64, "roster_version")?;
        if recipients.is_empty() || recipients.len() > INVALIDATION_DELIVERY_MAX_RECIPIENTS {
            return Err(InvalidationDeliveryError::InvalidRoster(
                "recipient count must be within 1..=64".into(),
            ));
        }
        recipients.sort_by(|a, b| {
            (
                a.database_id.as_str(),
                a.region_id.as_str(),
                a.node_id.as_str(),
            )
                .cmp(&(
                    b.database_id.as_str(),
                    b.region_id.as_str(),
                    b.node_id.as_str(),
                ))
        });
        let mut seen = std::collections::HashSet::with_capacity(recipients.len());
        for recipient in &recipients {
            recipient.validate(&source_database_id)?;
            if !seen.insert((
                recipient.database_id.clone(),
                recipient.region_id.clone(),
                recipient.node_id.clone(),
            )) {
                return Err(InvalidationDeliveryError::InvalidRoster(
                    "recipient roster contains duplicates".into(),
                ));
            }
        }
        Ok(Self {
            source_database_id: Arc::from(source_database_id),
            roster_version: Arc::from(roster_version),
            recipients: recipients.into(),
        })
    }

    pub fn source_database_id(&self) -> &str {
        &self.source_database_id
    }

    pub fn roster_version(&self) -> &str {
        &self.roster_version
    }

    pub fn recipients(&self) -> &[InvalidationDeliveryRecipient] {
        &self.recipients
    }
}

/// Canonical envelope shape mirrored at the DB boundary so staging can verify
/// exact row bindings and both hash domains without depending on `astral-mq`.
/// Typed invalidation payload validation remains the producer's MQ boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalInvalidationEnvelope {
    message_id: String,
    operation_id: String,
    message_type: String,
    schema_version: i32,
    tenant_id: Option<i64>,
    origin_region: String,
    target_region: Option<String>,
    ordering_key: Option<String>,
    trace_id: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    payload_sha256: String,
    #[serde(default)]
    authority_metadata: Option<AuthorizationMessageMetadata>,
    payload: Value,
}

impl CanonicalInvalidationEnvelope {
    fn authority_metadata_json(&self) -> Result<Option<String>, InvalidationDeliveryError> {
        let Some(metadata) = &self.authority_metadata else {
            return Ok(None);
        };
        metadata.validate().map_err(|_| {
            InvalidationDeliveryError::InvalidInput("authority metadata failed validation".into())
        })?;
        serde_json::to_string(metadata).map(Some).map_err(|_| {
            InvalidationDeliveryError::InvalidInput(
                "authority metadata serialization failed".into(),
            )
        })
    }

    fn validate(&self, canonical_bytes: &str) -> Result<(), InvalidationDeliveryError> {
        if !matches!(
            self.message_type.as_str(),
            "EVIDENCE_INVALIDATED" | "ELIGIBILITY_INVALIDATED" | "SESSION_REVOKED"
        ) || self.schema_version != astral_types::AUTHORIZATION_EDITION as i32
            || self.message_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
            || self.origin_region.trim().is_empty()
            || self.message_id.len() > 128
            || self.operation_id.len() > 128
            || self.message_type.len() > 64
            || self.origin_region.len() > 64
            || self
                .target_region
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 64)
            || self
                .ordering_key
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || self.tenant_id.is_some_and(|value| value <= 0)
        {
            return Err(InvalidationDeliveryError::InvalidInput(
                "canonical envelope is not a supported authorization invalidation".into(),
            ));
        }
        let payload_digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&self.payload).map_err(|_| {
                InvalidationDeliveryError::InvalidInput(
                    "invalidation payload serialization failed".into(),
                )
            })?)
        );
        if self.payload_sha256.to_ascii_lowercase() != payload_digest {
            return Err(InvalidationDeliveryError::Conflict);
        }
        let serialized = serde_json::to_string(self).map_err(|_| {
            InvalidationDeliveryError::InvalidInput(
                "canonical envelope serialization failed".into(),
            )
        })?;
        if serialized != canonical_bytes {
            return Err(InvalidationDeliveryError::Conflict);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidationDeliveryLeg {
    pub message_id: String,
    pub leg_id: String,
    pub recipient: InvalidationDeliveryRecipient,
    pub operation_id: String,
    pub message_type: String,
    pub schema_version: i32,
    pub origin_region: String,
    pub ordering_key: Option<String>,
    pub tenant_id: Option<i64>,
    pub authority_metadata_json: Option<String>,
    /// SHA-256 of the complete canonical envelope bytes (delivery identity).
    pub envelope_sha256: String,
    /// The envelope's `payloadSha256`, which is a different hash domain.
    pub payload_sha256: String,
    pub state: InvalidationDeliveryLegState,
    pub attempts: u32,
    pub generation: u64,
    pub lease_owner: Option<String>,
    pub lease_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationDeliveryLegState {
    Pending,
    Processing,
    SendConfirmed,
    PendingApply,
    InDoubt,
    Applied,
    Quarantined,
}

impl InvalidationDeliveryLegState {
    fn parse(value: &str) -> Result<Self, InvalidationDeliveryError> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "PROCESSING" => Ok(Self::Processing),
            "SEND_CONFIRMED" => Ok(Self::SendConfirmed),
            "PENDING_APPLY" => Ok(Self::PendingApply),
            "IN_DOUBT" => Ok(Self::InDoubt),
            "APPLIED" => Ok(Self::Applied),
            "QUARANTINED" => Ok(Self::Quarantined),
            _ => Err(InvalidationDeliveryError::CorruptState),
        }
    }
}

#[derive(Debug, Error)]
pub enum InvalidationDeliveryError {
    #[error("invalid invalidation delivery input: {0}")]
    InvalidInput(String),
    #[error("invalid invalidation recipient roster: {0}")]
    InvalidRoster(String),
    #[error("durable invalidation delivery row conflicts with an existing identity")]
    Conflict,
    #[error("durable invalidation delivery state is corrupt")]
    CorruptState,
    #[error("durable invalidation delivery lease was lost or is unknown")]
    LeaseLost,
    #[error("durable invalidation delivery database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Stage one immutable journal and its frozen recipient legs using the startup
/// context shared by all producers in this process. The context is the only
/// source of routing identity; callers must not read env/config while the
/// source transaction is open.
pub async fn stage_invalidation_delivery_with_context_in_tx(
    tx: &mut Transaction<'_, MySql>,
    context: &InvalidationDeliveryContext,
    message_id: &str,
) -> Result<(), InvalidationDeliveryError> {
    stage_invalidation_delivery_in_tx(
        tx,
        context.source_database_id(),
        context.roster_version(),
        context.recipients(),
        message_id,
    )
    .await
}

/// Validate and append an immutable source journal plus all recipient legs in
/// the caller's still-open source transaction. The bytes are copied from the
/// existing outbox row and are never reconstructed here.
pub async fn stage_invalidation_delivery_in_tx(
    tx: &mut Transaction<'_, MySql>,
    source_database_id: &str,
    roster_version: &str,
    recipients: &[InvalidationDeliveryRecipient],
    message_id: &str,
) -> Result<(), InvalidationDeliveryError> {
    validate_identity(source_database_id, 128, "source_database_id")?;
    validate_identity(roster_version, 64, "roster_version")?;
    if recipients.is_empty() || recipients.len() > INVALIDATION_DELIVERY_MAX_RECIPIENTS {
        return Err(InvalidationDeliveryError::InvalidRoster(
            "recipient count must be within 1..=64".into(),
        ));
    }
    if message_id.trim().is_empty() || message_id.len() > 128 {
        return Err(InvalidationDeliveryError::InvalidInput(
            "message_id must be non-empty and at most 128 bytes".into(),
        ));
    }
    let row = sqlx::query(
        "SELECT message_id, operation_id, message_type, queue_name, CAST(payload_json AS CHAR) AS payload_json, \
         headers_json, payload_sha256, origin_region, target_region, schema_version, ordering_key, tenant_id, authority_metadata_json \
         FROM al_message_outbox WHERE message_id = ? FOR UPDATE",
    )
    .bind(message_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| InvalidationDeliveryError::InvalidInput("canonical outbox row is missing".into()))?;
    let row_message_id: String = row.try_get("message_id")?;
    let operation_id: String = row.try_get("operation_id")?;
    let message_type: String = row.try_get("message_type")?;
    let queue_name: String = row.try_get("queue_name")?;
    let envelope_json: String = row.try_get("payload_json")?;
    let headers_json: Option<String> = row.try_get("headers_json")?;
    let payload_sha256: String = row.try_get("payload_sha256")?;
    let origin_region: String = row.try_get("origin_region")?;
    let authority_metadata_json: Option<String> = row.try_get("authority_metadata_json")?;
    let target_region: Option<String> = row.try_get("target_region")?;
    let schema_version: i32 = row.try_get("schema_version")?;
    let ordering_key: Option<String> = row.try_get("ordering_key")?;
    let tenant_id: Option<i64> = row.try_get("tenant_id")?;
    if row_message_id != message_id
        || queue_name != "astral.authorization.invalidation"
        || !matches!(
            message_type.as_str(),
            "EVIDENCE_INVALIDATED" | "ELIGIBILITY_INVALIDATED" | "SESSION_REVOKED"
        )
    {
        return Err(InvalidationDeliveryError::InvalidInput(
            "outbox identity or queue is not a typed invalidation".into(),
        ));
    }
    if envelope_json.len() > INVALIDATION_DELIVERY_MAX_ENVELOPE_BYTES {
        return Err(InvalidationDeliveryError::InvalidInput(
            "canonical invalidation envelope exceeds 1 MiB".into(),
        ));
    }
    let envelope: CanonicalInvalidationEnvelope =
        serde_json::from_str(&envelope_json).map_err(|_| {
            InvalidationDeliveryError::InvalidInput(
                "canonical envelope is invalid or has unknown fields".into(),
            )
        })?;
    envelope.validate(&envelope_json)?;
    let envelope_sha256 = format!("{:x}", Sha256::digest(envelope_json.as_bytes()));
    if envelope.message_id != message_id
        || envelope.operation_id != operation_id
        || envelope.message_type != message_type
        || !envelope
            .payload_sha256
            .eq_ignore_ascii_case(&payload_sha256)
        || envelope.origin_region != origin_region
        || envelope.target_region != target_region
        || envelope.schema_version != schema_version
        || envelope.ordering_key != ordering_key
        || envelope.tenant_id != tenant_id
        || envelope.authority_metadata_json()?.as_deref() != authority_metadata_json.as_deref()
    {
        return Err(InvalidationDeliveryError::Conflict);
    }
    if headers_json.is_some() {
        return Err(InvalidationDeliveryError::InvalidInput(
            "typed invalidation outbox headers are unsupported; envelope metadata must remain canonical".into(),
        ));
    }
    if payload_sha256.len() != 64 || !payload_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(InvalidationDeliveryError::Conflict);
    }
    let payload_sha256 = payload_sha256.to_ascii_lowercase();
    let envelope_payload_sha256 = envelope.payload_sha256.to_ascii_lowercase();
    if envelope_payload_sha256 != payload_sha256 {
        return Err(InvalidationDeliveryError::Conflict);
    }

    let mut roster = recipients.to_vec();
    roster.sort_by(|a, b| {
        (
            a.database_id.as_str(),
            a.region_id.as_str(),
            a.node_id.as_str(),
        )
            .cmp(&(
                b.database_id.as_str(),
                b.region_id.as_str(),
                b.node_id.as_str(),
            ))
    });
    let mut seen = std::collections::HashSet::with_capacity(roster.len());
    for recipient in &roster {
        recipient.validate(source_database_id)?;
        if !seen.insert((
            recipient.database_id.clone(),
            recipient.region_id.clone(),
            recipient.node_id.clone(),
        )) {
            return Err(InvalidationDeliveryError::InvalidRoster(
                "recipient roster contains duplicates".into(),
            ));
        }
    }
    let roster_json = serde_json::to_string(&roster).map_err(|_| {
        InvalidationDeliveryError::InvalidRoster("recipient roster serialization failed".into())
    })?;
    if roster_json.len() > 256 * 1024 {
        return Err(InvalidationDeliveryError::InvalidRoster(
            "recipient roster exceeds 256 KiB".into(),
        ));
    }
    let roster_sha256 = Sha256::digest(roster_json.as_bytes());
    sqlx::query(
        "INSERT INTO authorization_invalidation_delivery_journal \
         (message_id, operation_id, source_database_id, envelope_sha256, payload_sha256, envelope_json, message_type, schema_version, origin_region, target_region, ordering_key, tenant_id, authority_metadata_json, roster_version, recipient_roster_json, recipient_roster_sha256, status) \
         VALUES (?, ?, ?, UNHEX(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UNHEX(?), 'READY') \
         ON DUPLICATE KEY UPDATE message_id = message_id",
    )
    .bind(message_id)
    .bind(&operation_id)
    .bind(source_database_id)
    .bind(&envelope_sha256)
    .bind(&payload_sha256)
    .bind(&envelope_json)
    .bind(&message_type)
    .bind(schema_version)
    .bind(&origin_region)
    .bind(&target_region)
    .bind(&ordering_key)
    .bind(tenant_id)
    .bind(&authority_metadata_json)
    .bind(roster_version)
    .bind(&roster_json)
    .bind(hex::encode(roster_sha256))
    .execute(&mut **tx)
    .await?;
    let existing = sqlx::query(
        "SELECT operation_id, source_database_id, LOWER(HEX(envelope_sha256)) AS envelope_sha256, payload_sha256, \
         envelope_json, message_type, schema_version, origin_region, target_region, ordering_key, tenant_id, authority_metadata_json, roster_version, recipient_roster_json, LOWER(HEX(recipient_roster_sha256)) AS roster_sha256 \
         FROM authorization_invalidation_delivery_journal WHERE message_id = ? FOR UPDATE",
    )
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    let existing_operation: String = existing.try_get("operation_id")?;
    let existing_database: String = existing.try_get("source_database_id")?;
    let existing_digest: String = existing.try_get("envelope_sha256")?;
    let existing_payload_digest: String = existing.try_get("payload_sha256")?;
    let existing_envelope: String = existing.try_get("envelope_json")?;
    let existing_message_type: String = existing.try_get("message_type")?;
    let existing_schema_version: i32 = existing.try_get("schema_version")?;
    let existing_origin_region: String = existing.try_get("origin_region")?;
    let existing_target_region: Option<String> = existing.try_get("target_region")?;
    let existing_ordering_key: Option<String> = existing.try_get("ordering_key")?;
    let existing_tenant_id: Option<i64> = existing.try_get("tenant_id")?;
    let existing_authority_metadata_json: Option<String> =
        existing.try_get("authority_metadata_json")?;
    let existing_roster_version: String = existing.try_get("roster_version")?;
    let existing_roster: String = existing.try_get("recipient_roster_json")?;
    let existing_roster_digest: String = existing.try_get("roster_sha256")?;
    if existing_operation != operation_id
        || existing_database != source_database_id
        || existing_digest != envelope_sha256
        || existing_payload_digest != payload_sha256
        || existing_envelope != envelope_json
        || existing_message_type != message_type
        || existing_schema_version != schema_version
        || existing_origin_region != origin_region
        || existing_target_region != target_region
        || existing_ordering_key != ordering_key
        || existing_tenant_id != tenant_id
        || existing_authority_metadata_json != authority_metadata_json
        || existing_roster_version != roster_version
        || existing_roster != roster_json
        || existing_roster_digest != hex::encode(roster_sha256)
    {
        return Err(InvalidationDeliveryError::Conflict);
    }
    for recipient in roster {
        let leg_id = stable_leg_id(message_id, &recipient);
        let transport = recipient.transport.as_str();
        let endpoint = recipient.endpoint.as_deref();
        let certificate = recipient.peer_certificate_sha256.as_deref();
        sqlx::query(
            "INSERT INTO authorization_invalidation_delivery_leg \
             (message_id, leg_id, recipient_region, recipient_node, recipient_database_id, transport_kind, endpoint, peer_certificate_sha256, envelope_sha256, payload_sha256, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, UNHEX(?), ?, 'PENDING') \
             ON DUPLICATE KEY UPDATE message_id = message_id",
        )
        .bind(message_id).bind(&leg_id).bind(&recipient.region_id).bind(&recipient.node_id)
        .bind(&recipient.database_id).bind(transport).bind(endpoint).bind(certificate)
        .bind(&envelope_sha256).bind(&payload_sha256).execute(&mut **tx).await?;
        let leg = sqlx::query(
            "SELECT recipient_region, recipient_node, recipient_database_id, transport_kind, endpoint, peer_certificate_sha256, LOWER(HEX(envelope_sha256)) AS envelope_sha256, payload_sha256 \
             FROM authorization_invalidation_delivery_leg WHERE message_id = ? AND leg_id = ? FOR UPDATE",
        ).bind(message_id).bind(&leg_id).fetch_one(&mut **tx).await?;
        let same = leg.try_get::<String, _>("recipient_region")? == recipient.region_id
            && leg.try_get::<String, _>("recipient_node")? == recipient.node_id
            && leg.try_get::<String, _>("recipient_database_id")? == recipient.database_id
            && leg.try_get::<String, _>("transport_kind")? == transport
            && leg.try_get::<Option<String>, _>("endpoint")? == recipient.endpoint
            && leg.try_get::<Option<String>, _>("peer_certificate_sha256")?
                == recipient.peer_certificate_sha256
            && leg.try_get::<String, _>("envelope_sha256")? == envelope_sha256
            && leg.try_get::<String, _>("payload_sha256")? == payload_sha256;
        if !same {
            return Err(InvalidationDeliveryError::Conflict);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ClaimedInvalidationDeliveryLeg {
    pub leg: InvalidationDeliveryLeg,
    pub envelope_json: String,
    pub lease_token: String,
}

/// Receipt metadata returned by a receiver only after authenticating the peer
/// and durably committing the matching inbox row. The transport adapter must
/// derive target identity from its authenticated peer, never request fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedInvalidationReceipt {
    pub message_id: String,
    pub leg_id: String,
    pub target_database_id: String,
    pub target_region: String,
    pub target_node: String,
    pub envelope_sha256: String,
    pub payload_sha256: String,
    pub operation_id: String,
    pub message_type: String,
    pub schema_version: i32,
    pub origin_region: String,
    pub ordering_key: Option<String>,
    pub tenant_id: Option<i64>,
    pub authority_metadata_json: Option<String>,
    /// Receiver inbox proof only: PENDING means durably accepted; APPLIED means
    /// local invalidation application was separately proven.
    pub status: String,
}

#[derive(Clone)]
pub struct InvalidationDeliveryRepository {
    pool: MySqlPool,
}

impl InvalidationDeliveryRepository {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    /// Claim at most one PENDING leg. A stale PROCESSING lease is made IN_DOUBT,
    /// never reclaimed for blind resend.
    pub async fn claim_one(
        &self,
        owner: &str,
    ) -> Result<Option<ClaimedInvalidationDeliveryLeg>, InvalidationDeliveryError> {
        validate_identity(owner, 128, "owner")?;
        let mut tx = self.pool.begin().await?;
        let stale: Option<(String, String)> = sqlx::query_as(
            "SELECT message_id, leg_id FROM authorization_invalidation_delivery_leg \
             WHERE status = 'PROCESSING' AND lease_expires_at < UTC_TIMESTAMP(6) ORDER BY updated_at LIMIT 1 FOR UPDATE SKIP LOCKED",
        ).fetch_optional(&mut *tx).await?;
        if let Some((message_id, leg_id)) = stale {
            sqlx::query("UPDATE authorization_invalidation_delivery_leg SET status = 'IN_DOUBT', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP(6) WHERE message_id = ? AND leg_id = ? AND status = 'PROCESSING'")
                .bind(message_id).bind(leg_id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT l.message_id, l.leg_id, l.recipient_region, l.recipient_node, l.recipient_database_id, l.transport_kind, l.endpoint, l.peer_certificate_sha256, LOWER(HEX(l.envelope_sha256)) AS envelope_sha256, l.payload_sha256, l.status, l.attempts, l.generation, j.envelope_json, j.operation_id, j.message_type, j.schema_version, j.origin_region, j.ordering_key, j.tenant_id, j.authority_metadata_json \
             FROM authorization_invalidation_delivery_leg l JOIN authorization_invalidation_delivery_journal j USING (message_id) \
             WHERE l.status = 'PENDING' AND l.attempts < ? ORDER BY l.created_at, l.message_id, l.leg_id LIMIT 1 FOR UPDATE SKIP LOCKED",
        ).bind(INVALIDATION_DELIVERY_MAX_ATTEMPTS).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let message_id: String = row.try_get("message_id")?;
        let leg_id: String = row.try_get("leg_id")?;
        let old_attempts: i32 = row.try_get("attempts")?;
        let old_generation: i64 = row.try_get("generation")?;
        if old_attempts < 0 || old_generation < 0 {
            return Err(InvalidationDeliveryError::CorruptState);
        }
        let expected_attempts = old_attempts
            .checked_add(1)
            .ok_or(InvalidationDeliveryError::CorruptState)?;
        let expected_generation = old_generation
            .checked_add(1)
            .ok_or(InvalidationDeliveryError::CorruptState)?;
        let token = Uuid::new_v4().to_string();
        let update = sqlx::query(
            "UPDATE authorization_invalidation_delivery_leg SET status = 'PROCESSING', attempts = attempts + 1, generation = generation + 1, lease_owner = ?, lease_token = ?, lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), updated_at = UTC_TIMESTAMP(6) WHERE message_id = ? AND leg_id = ? AND status = 'PENDING' AND attempts = ? AND generation = ?",
        ).bind(owner).bind(&token).bind(INVALIDATION_DELIVERY_LEASE_SECONDS).bind(&message_id).bind(&leg_id).bind(old_attempts).bind(old_generation).execute(&mut *tx).await?;
        if update.rows_affected() != 1 {
            return Err(InvalidationDeliveryError::LeaseLost);
        }
        let claimed = sqlx::query(
            "SELECT l.message_id, l.leg_id, l.recipient_region, l.recipient_node, l.recipient_database_id, l.transport_kind, l.endpoint, l.peer_certificate_sha256, LOWER(HEX(l.envelope_sha256)) AS envelope_sha256, l.payload_sha256, l.status, l.attempts, l.generation, l.lease_owner, l.lease_token, j.envelope_json, j.operation_id, j.message_type, j.schema_version, j.origin_region, j.ordering_key, j.tenant_id, j.authority_metadata_json \
             FROM authorization_invalidation_delivery_leg l JOIN authorization_invalidation_delivery_journal j USING (message_id) \
             WHERE l.message_id = ? AND l.leg_id = ? FOR UPDATE",
        ).bind(&message_id).bind(&leg_id).fetch_one(&mut *tx).await?;
        let attempts: i32 = claimed.try_get("attempts")?;
        let generation: i64 = claimed.try_get("generation")?;
        if attempts != expected_attempts || generation != expected_generation {
            return Err(InvalidationDeliveryError::CorruptState);
        }
        let envelope_json: String = claimed.try_get("envelope_json")?;
        let lease_owner: String = claimed.try_get("lease_owner")?;
        let lease_token_readback: String = claimed.try_get("lease_token")?;
        if lease_owner != owner
            || lease_token_readback != token
            || claimed.try_get::<String, _>("status")? != "PROCESSING"
        {
            return Err(InvalidationDeliveryError::LeaseLost);
        }
        let leg = row_to_leg(&claimed, Some(owner.to_owned()), Some(token.clone()))?;
        if leg.attempts
            != u32::try_from(expected_attempts)
                .map_err(|_| InvalidationDeliveryError::CorruptState)?
            || leg.generation
                != u64::try_from(expected_generation)
                    .map_err(|_| InvalidationDeliveryError::CorruptState)?
        {
            return Err(InvalidationDeliveryError::CorruptState);
        }
        tx.commit().await?;
        Ok(Some(ClaimedInvalidationDeliveryLeg {
            leg,
            envelope_json,
            lease_token: token,
        }))
    }

    pub async fn settle_send(
        &self,
        claim: &ClaimedInvalidationDeliveryLeg,
        state: InvalidationDeliveryLegState,
    ) -> Result<(), InvalidationDeliveryError> {
        let target = match state {
            InvalidationDeliveryLegState::SendConfirmed => "SEND_CONFIRMED",
            InvalidationDeliveryLegState::PendingApply => "PENDING_APPLY",
            InvalidationDeliveryLegState::InDoubt => "IN_DOUBT",
            InvalidationDeliveryLegState::Quarantined => "QUARANTINED",
            _ => {
                return Err(InvalidationDeliveryError::InvalidInput(
                    "invalid transport settlement state".into(),
                ))
            }
        };
        validate_digest(Some(&claim.leg.envelope_sha256), "envelope_sha256")?;
        let generation = i64::try_from(claim.leg.generation)
            .map_err(|_| InvalidationDeliveryError::CorruptState)?;
        let result = sqlx::query(
            "UPDATE authorization_invalidation_delivery_leg SET status = ?, lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP(6) \
             WHERE message_id = ? AND leg_id = ? AND status = 'PROCESSING' AND generation = ? AND lease_owner = ? AND lease_token = ? \
               AND envelope_sha256 = UNHEX(?) AND lease_expires_at >= UTC_TIMESTAMP(6)",
        )
        .bind(target)
        .bind(&claim.leg.message_id)
        .bind(&claim.leg.leg_id)
        .bind(generation)
        .bind(claim.leg.lease_owner.as_deref().ok_or(InvalidationDeliveryError::LeaseLost)?)
        .bind(&claim.lease_token)
        .bind(&claim.leg.envelope_sha256)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(InvalidationDeliveryError::LeaseLost);
        }
        Ok(())
    }

    /// Persist an authenticated receiver receipt before it can influence the
    /// sender leg state. Exact identity, both hash domains and canonical message
    /// metadata are checked against the immutable source journal and frozen leg.
    pub async fn record_authenticated_receipt(
        &self,
        receipt: &AuthenticatedInvalidationReceipt,
    ) -> Result<(), InvalidationDeliveryError> {
        validate_identity(&receipt.target_database_id, 128, "target_database_id")?;
        validate_identity(&receipt.target_region, 64, "target_region")?;
        validate_identity(&receipt.target_node, 128, "target_node")?;
        validate_digest(Some(&receipt.envelope_sha256), "envelope_sha256")?;
        validate_digest(Some(&receipt.payload_sha256), "payload_sha256")?;
        if !matches!(receipt.status.as_str(), "PENDING" | "APPLIED") {
            return Err(InvalidationDeliveryError::InvalidInput(
                "receiver receipt status must be PENDING or APPLIED".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let exact = sqlx::query(
            "SELECT l.recipient_database_id, l.recipient_region, l.recipient_node, LOWER(HEX(l.envelope_sha256)) AS envelope_sha256, l.payload_sha256, j.operation_id, j.message_type, j.schema_version, j.origin_region, j.ordering_key, j.tenant_id, j.authority_metadata_json \
             FROM authorization_invalidation_delivery_leg l JOIN authorization_invalidation_delivery_journal j USING (message_id) \
             WHERE l.message_id = ? AND l.leg_id = ? FOR UPDATE",
        ).bind(&receipt.message_id).bind(&receipt.leg_id).fetch_optional(&mut *tx).await?
            .ok_or(InvalidationDeliveryError::Conflict)?;
        let matches = exact.try_get::<String, _>("recipient_database_id")?
            == receipt.target_database_id
            && exact.try_get::<String, _>("recipient_region")? == receipt.target_region
            && exact.try_get::<String, _>("recipient_node")? == receipt.target_node
            && exact.try_get::<String, _>("envelope_sha256")?
                == receipt.envelope_sha256.to_ascii_lowercase()
            && exact.try_get::<String, _>("payload_sha256")?
                == receipt.payload_sha256.to_ascii_lowercase()
            && exact.try_get::<String, _>("operation_id")? == receipt.operation_id
            && exact.try_get::<String, _>("message_type")? == receipt.message_type
            && exact.try_get::<i32, _>("schema_version")? == receipt.schema_version
            && exact.try_get::<String, _>("origin_region")? == receipt.origin_region
            && exact.try_get::<Option<String>, _>("ordering_key")? == receipt.ordering_key
            && exact.try_get::<Option<i64>, _>("tenant_id")? == receipt.tenant_id
            && exact.try_get::<Option<String>, _>("authority_metadata_json")?
                == receipt.authority_metadata_json;
        if !matches {
            return Err(InvalidationDeliveryError::Conflict);
        }
        sqlx::query(
            "INSERT INTO authorization_invalidation_delivery_receipt \
             (message_id, leg_id, target_database_id, target_region, target_node, envelope_sha256, payload_sha256, operation_id, message_type, schema_version, origin_region, ordering_key, tenant_id, authority_metadata_json, receipt_status) \
             VALUES (?, ?, ?, ?, ?, UNHEX(?), ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE receipt_status = CASE \
                 WHEN receipt_status = 'PENDING' AND VALUES(receipt_status) = 'APPLIED' THEN 'APPLIED' \
                 ELSE receipt_status END",
        )
        .bind(&receipt.message_id).bind(&receipt.leg_id).bind(&receipt.target_database_id)
        .bind(&receipt.target_region).bind(&receipt.target_node).bind(&receipt.envelope_sha256)
        .bind(receipt.payload_sha256.to_ascii_lowercase()).bind(&receipt.operation_id)
        .bind(&receipt.message_type).bind(receipt.schema_version).bind(&receipt.origin_region)
        .bind(&receipt.ordering_key).bind(receipt.tenant_id).bind(&receipt.authority_metadata_json)
        .bind(&receipt.status).execute(&mut *tx).await?;
        let stored = sqlx::query(
            "SELECT target_database_id, target_region, target_node, LOWER(HEX(envelope_sha256)) AS envelope_sha256, payload_sha256, operation_id, message_type, schema_version, origin_region, ordering_key, tenant_id, authority_metadata_json, receipt_status \
             FROM authorization_invalidation_delivery_receipt WHERE message_id = ? AND leg_id = ? FOR UPDATE",
        ).bind(&receipt.message_id).bind(&receipt.leg_id).fetch_one(&mut *tx).await?;
        let same = stored.try_get::<String, _>("target_database_id")? == receipt.target_database_id
            && stored.try_get::<String, _>("target_region")? == receipt.target_region
            && stored.try_get::<String, _>("target_node")? == receipt.target_node
            && stored.try_get::<String, _>("envelope_sha256")?
                == receipt.envelope_sha256.to_ascii_lowercase()
            && stored.try_get::<String, _>("payload_sha256")?
                == receipt.payload_sha256.to_ascii_lowercase()
            && stored.try_get::<String, _>("operation_id")? == receipt.operation_id
            && stored.try_get::<String, _>("message_type")? == receipt.message_type
            && stored.try_get::<i32, _>("schema_version")? == receipt.schema_version
            && stored.try_get::<String, _>("origin_region")? == receipt.origin_region
            && stored.try_get::<Option<String>, _>("ordering_key")? == receipt.ordering_key
            && stored.try_get::<Option<i64>, _>("tenant_id")? == receipt.tenant_id
            && stored.try_get::<Option<String>, _>("authority_metadata_json")?
                == receipt.authority_metadata_json
            && stored.try_get::<String, _>("receipt_status")? == receipt.status;
        if !same {
            return Err(InvalidationDeliveryError::Conflict);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Apply a previously persisted, exact APPLIED receipt to the source leg.
    /// The receiver identity comes from the frozen roster and is matched to both
    /// receipt row and full-envelope digest. The CAS prevents stale writes.
    pub async fn mark_applied_from_exact_receipt(
        &self,
        message_id: &str,
        leg_id: &str,
        envelope_sha256: &str,
        expected_generation: u64,
    ) -> Result<(), InvalidationDeliveryError> {
        validate_digest(Some(envelope_sha256), "envelope_sha256")?;
        let generation = i64::try_from(expected_generation)
            .map_err(|_| InvalidationDeliveryError::CorruptState)?;
        let result = sqlx::query(
            "UPDATE authorization_invalidation_delivery_leg l \
             JOIN authorization_invalidation_delivery_receipt r \
               ON r.message_id = l.message_id AND r.leg_id = l.leg_id \
              AND r.target_database_id = l.recipient_database_id AND r.target_region = l.recipient_region AND r.target_node = l.recipient_node \
              AND r.envelope_sha256 = l.envelope_sha256 AND r.payload_sha256 = l.payload_sha256 AND r.receipt_status = 'APPLIED' \
             JOIN authorization_invalidation_delivery_journal j ON j.message_id = l.message_id \
              AND r.operation_id = j.operation_id AND r.message_type = j.message_type AND r.schema_version = j.schema_version \
              AND r.origin_region = j.origin_region AND r.ordering_key <=> j.ordering_key AND r.tenant_id <=> j.tenant_id \
              AND r.authority_metadata_json <=> j.authority_metadata_json \
             SET l.status = 'APPLIED', l.lease_owner = NULL, l.lease_token = NULL, l.lease_expires_at = NULL, l.updated_at = UTC_TIMESTAMP(6) \
             WHERE l.message_id = ? AND l.leg_id = ? AND l.generation = ? AND l.status IN ('SEND_CONFIRMED', 'PENDING_APPLY', 'IN_DOUBT') \
               AND LOWER(HEX(l.envelope_sha256)) = ?",
        ).bind(message_id).bind(leg_id).bind(generation).bind(envelope_sha256.to_ascii_lowercase())
        .execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(InvalidationDeliveryError::LeaseLost);
        }
        Ok(())
    }
}

fn row_to_leg(
    row: &sqlx::mysql::MySqlRow,
    owner: Option<String>,
    token: Option<String>,
) -> Result<InvalidationDeliveryLeg, InvalidationDeliveryError> {
    let transport: String = row.try_get("transport_kind")?;
    let recipient = InvalidationDeliveryRecipient {
        region_id: row.try_get("recipient_region")?,
        node_id: row.try_get("recipient_node")?,
        database_id: row.try_get("recipient_database_id")?,
        transport: match transport.as_str() {
            "same_db_mtls" => InvalidationDeliveryTransport::SameDbMtls,
            "cross_db_rabbit" => InvalidationDeliveryTransport::CrossDbRabbit,
            _ => return Err(InvalidationDeliveryError::CorruptState),
        },
        endpoint: row.try_get("endpoint")?,
        peer_certificate_sha256: row.try_get("peer_certificate_sha256")?,
    };
    Ok(InvalidationDeliveryLeg {
        message_id: row.try_get("message_id")?,
        leg_id: row.try_get("leg_id")?,
        recipient,
        operation_id: row.try_get("operation_id")?,
        message_type: row.try_get("message_type")?,
        schema_version: row.try_get("schema_version")?,
        origin_region: row.try_get("origin_region")?,
        ordering_key: row.try_get("ordering_key")?,
        tenant_id: row.try_get("tenant_id")?,
        authority_metadata_json: row.try_get("authority_metadata_json")?,
        envelope_sha256: row.try_get("envelope_sha256")?,
        payload_sha256: row.try_get("payload_sha256")?,
        state: InvalidationDeliveryLegState::parse(&row.try_get::<String, _>("status")?)?,
        attempts: u32::try_from(row.try_get::<i32, _>("attempts")?)
            .map_err(|_| InvalidationDeliveryError::CorruptState)?,
        generation: u64::try_from(row.try_get::<i64, _>("generation")?)
            .map_err(|_| InvalidationDeliveryError::CorruptState)?,
        lease_owner: owner,
        lease_token: token,
    })
}

pub fn stable_leg_id(message_id: &str, recipient: &InvalidationDeliveryRecipient) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_INVALIDATION_DELIVERY_LEG_V1\0");
    for field in [
        message_id,
        recipient.transport.as_str(),
        &recipient.database_id,
        &recipient.region_id,
        &recipient.node_id,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn validate_identity(
    value: &str,
    max_bytes: usize,
    name: &'static str,
) -> Result<(), InvalidationDeliveryError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(InvalidationDeliveryError::InvalidInput(format!(
            "{name} is not a bounded canonical identity"
        )));
    }
    Ok(())
}

fn validate_digest(
    value: Option<&str>,
    name: &'static str,
) -> Result<(), InvalidationDeliveryError> {
    let value = value
        .ok_or_else(|| InvalidationDeliveryError::InvalidRoster(format!("{name} is required")))?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(InvalidationDeliveryError::InvalidRoster(format!(
            "{name} must be 64 hexadecimal characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(
        transport: InvalidationDeliveryTransport,
        database_id: &str,
    ) -> InvalidationDeliveryRecipient {
        InvalidationDeliveryRecipient {
            region_id: "region-a".into(),
            node_id: "node-a".into(),
            database_id: database_id.into(),
            transport,
            endpoint: (transport == InvalidationDeliveryTransport::SameDbMtls)
                .then(|| "https://peer.example:9443/internal/authorization-invalidations".into()),
            peer_certificate_sha256: (transport == InvalidationDeliveryTransport::SameDbMtls)
                .then(|| "a".repeat(64)),
        }
    }

    #[test]
    fn stable_leg_identity_binds_transport_and_peer_database() {
        let same = peer(InvalidationDeliveryTransport::SameDbMtls, "db-a");
        let same_again = peer(InvalidationDeliveryTransport::SameDbMtls, "db-a");
        let cross = peer(InvalidationDeliveryTransport::CrossDbRabbit, "db-b");
        assert_eq!(
            stable_leg_id("message", &same),
            stable_leg_id("message", &same_again)
        );
        assert_ne!(
            stable_leg_id("message", &same),
            stable_leg_id("message", &cross)
        );
    }

    #[test]
    fn recipient_routes_fail_closed_on_wrong_database_or_transport_material() {
        assert!(peer(InvalidationDeliveryTransport::SameDbMtls, "db-a")
            .validate("db-b")
            .is_err());
        assert!(peer(InvalidationDeliveryTransport::CrossDbRabbit, "db-a")
            .validate("db-a")
            .is_err());
        let mut bad = peer(InvalidationDeliveryTransport::SameDbMtls, "db-a");
        bad.endpoint = Some("http://peer.example/route".into());
        assert!(bad.validate("db-a").is_err());
        bad.endpoint = Some("https://peer.example/route".into());
        bad.peer_certificate_sha256 = Some("not-a-digest".into());
        assert!(bad.validate("db-a").is_err());
    }
}
