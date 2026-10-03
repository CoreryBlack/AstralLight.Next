//! Typed Rabbit fanout transport for authorization invalidation notifications.
//!
//! P3/P4 durable cross-node fanout. Topology (fanout exchange, per-node
//! durable subscription queues, per-node DLX queues) lives in
//! [`crate::config`]; this module owns the typed wire contract, the publish
//! outcome classification, the durable per-node inbox proof adapter, and the
//! real lapin implementations.
//!
//! Fail-closed rules encoded here:
//! - The wire body of an invalidation frame is the **canonical envelope
//!   JSON** produced by the durable outbox — publishers never rebuild
//!   `createdAt` or re-serialize business payloads.
//! - A publish outcome is broker admission only. It is never a remote
//!   business completion and never an authorization READY proof.
//! - Unknown transport results are typed [`InvalidationFanoutPublishOutcome::Unknown`]
//!   and must be reconciled through the durable outbox; callers must never
//!   blind-retry them.
//! - ACK on the consumer side happens only after the durable per-node inbox
//!   commit; broker success does not claim authorization READY. The receipt
//!   (`APPLIED`) proves only that this node applied the invalidation to its
//!   local acceleration state.
//! - Heartbeat frames record liveness only. They can never clear a durable
//!   proof, a watermark, or a suspect flag (suspect clearing is owned by the
//!   projection hub's own reconciliation).

use async_trait::async_trait;
use lapin::message::BasicReturnMessage;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions, BasicQosOptions,
};
use lapin::types::{FieldTable, ShortString};
use lapin::{BasicProperties, Channel, Confirmation, Connection};
use serde::{Deserialize, Serialize};
use time::PrimitiveDateTime;
use uuid::Uuid;

use crate::config::{
    declare_invalidation_fanout_topology, invalidation_fanout_queue_name, NodeIdentity,
    INVALIDATION_HEARTBEAT_MESSAGE_TYPE,
};
use crate::error::MqError;
use crate::invalidation::{
    InvalidationContractError, InvalidationEvent, ELIGIBILITY_INVALIDATED, EVIDENCE_INVALIDATED,
    INVALIDATION_SCHEMA_VERSION, SESSION_REVOKED,
};

/// Sentinel used by [`InvalidationInboxFailure::Storage`] formatting; kept as
/// a stable substring for classification tests.
pub const INBOX_STORAGE_ERROR_TAG: &str = "inbox_storage_error";

// ===== wire frames =====

/// Heartbeat scope metadata. Carries sender identity and sent time only —
/// never authorization data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeartbeatScope {
    pub node_region: String,
    pub node_id: String,
    pub sent_at: String,
}

impl HeartbeatScope {
    pub fn validate(&self) -> Result<(), InvalidationFanoutContractError> {
        NodeIdentity::try_from_parts(self.node_region.clone(), self.node_id.clone())
            .map_err(InvalidationFanoutContractError::InvalidHeartbeat)?;
        if time::OffsetDateTime::parse(
            &self.sent_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        {
            return Err(InvalidationFanoutContractError::InvalidHeartbeat(
                "heartbeat sentAt is not a valid RFC3339 timestamp".into(),
            ));
        }
        Ok(())
    }
}

/// One typed frame on the fanout channel. The wire body is always a complete
/// transport-neutral [`crate::envelope::MessageEnvelope`]; the discriminator
/// is the envelope's `messageType`.
///
/// - [`FanoutFrame::Invalidation`] — a full typed invalidation envelope
///   (`EVIDENCE_INVALIDATED` / `ELIGIBILITY_INVALIDATED` / `SESSION_REVOKED`),
///   revalidated against the typed scope contract on decode.
/// - [`FanoutFrame::Heartbeat`] — liveness scope metadata only.
#[derive(Debug, Clone, PartialEq)]
pub enum FanoutFrame {
    Invalidation(crate::envelope::MessageEnvelope),
    Heartbeat(crate::envelope::MessageEnvelope),
}

impl FanoutFrame {
    pub fn envelope(&self) -> &crate::envelope::MessageEnvelope {
        match self {
            Self::Invalidation(envelope) | Self::Heartbeat(envelope) => envelope,
        }
    }

    /// Serialize the frame body. Invalidation frames should normally be
    /// published through [`CommittedInvalidationEnvelope::canonical_bytes`]
    /// to preserve the durable outbox bytes verbatim; this method exists for
    /// heartbeat frames and mock transports.
    pub fn encode(&self) -> Result<Vec<u8>, InvalidationFanoutContractError> {
        serde_json::to_vec(self.envelope())
            .map_err(|error| InvalidationFanoutContractError::Serialization(error.to_string()))
    }

    /// Decode and fully revalidate a wire body. Unknown message types,
    /// digest mismatches, and typed-scope violations fail closed.
    pub fn decode(body: &[u8]) -> Result<Self, InvalidationFanoutContractError> {
        let envelope: crate::envelope::MessageEnvelope = serde_json::from_slice(body)
            .map_err(|error| InvalidationFanoutContractError::InvalidFrame(error.to_string()))?;
        envelope
            .validate()
            .map_err(InvalidationFanoutContractError::InvalidFrame)?;
        match envelope.message_type.as_str() {
            INVALIDATION_HEARTBEAT_MESSAGE_TYPE => {
                let scope: HeartbeatScope = serde_json::from_value(envelope.payload.clone())
                    .map_err(|error| {
                        InvalidationFanoutContractError::InvalidFrame(format!(
                            "heartbeat payload rejected: {error}"
                        ))
                    })?;
                scope.validate()?;
                Ok(Self::Heartbeat(envelope))
            }
            EVIDENCE_INVALIDATED | ELIGIBILITY_INVALIDATED | SESSION_REVOKED => {
                InvalidationEvent::from_envelope(&envelope)
                    .map_err(InvalidationFanoutContractError::Contract)?;
                Ok(Self::Invalidation(envelope))
            }
            other => Err(InvalidationFanoutContractError::UnsupportedMessageType(
                other.to_owned(),
            )),
        }
    }

    /// Build a heartbeat frame body for `identity`. Message and operation ids
    /// are fresh per heartbeat: heartbeats are liveness signals, not
    /// deduplicated effects, and are never tracked by a durable outbox.
    pub fn encode_heartbeat(
        identity: &NodeIdentity,
        sent_at: impl Into<String>,
    ) -> Result<Vec<u8>, InvalidationFanoutContractError> {
        let scope = HeartbeatScope {
            node_region: identity.region().to_owned(),
            node_id: identity.node().to_owned(),
            sent_at: sent_at.into(),
        };
        scope.validate()?;
        let payload = serde_json::to_value(&scope)
            .map_err(|error| InvalidationFanoutContractError::Serialization(error.to_string()))?;
        let envelope = crate::envelope::MessageEnvelope::new(
            format!("heartbeat-{}", Uuid::new_v4()),
            format!("heartbeat-{}", identity.region()),
            INVALIDATION_HEARTBEAT_MESSAGE_TYPE,
            INVALIDATION_SCHEMA_VERSION,
            identity.region(),
            payload,
        )
        .map_err(InvalidationFanoutContractError::InvalidFrame)?;
        envelope
            .validate()
            .map_err(InvalidationFanoutContractError::InvalidFrame)?;
        serde_json::to_vec(&envelope)
            .map_err(|error| InvalidationFanoutContractError::Serialization(error.to_string()))
    }
}

// ===== canonical publish request (durable outbox -> fanout) =====

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidationFanoutContractError {
    #[error("durable row is not an authorization invalidation row: queue={queue_name}")]
    NotInvalidationRow { queue_name: String },
    #[error("durable row status {status} is not claimable for fanout publish")]
    UnclaimableStatus { status: String },
    #[error("invalid fanout frame: {0}")]
    InvalidFrame(String),
    #[error("invalid heartbeat scope: {0}")]
    InvalidHeartbeat(String),
    #[error("unsupported fanout message type `{0}`")]
    UnsupportedMessageType(String),
    #[error("durable row and envelope diverge: {0}")]
    EnvelopeMismatch(String),
    #[error("invalidation contract error: {0}")]
    Contract(#[from] InvalidationContractError),
    #[error("fanout frame serialization failed: {0}")]
    Serialization(String),
}

/// A publish request derived from a **preexisting durable outbox row**.
///
/// Construction revalidates the row against the typed invalidation contract
/// and keeps the row's `payload_json` bytes verbatim: the wire body is the
/// same canonical envelope that the source transaction committed, including
/// the original `createdAt`. Nothing here rebuilds envelope identity.
#[derive(Debug, Clone)]
pub struct CommittedInvalidationEnvelope {
    envelope: crate::envelope::MessageEnvelope,
    canonical_bytes: Vec<u8>,
}

impl CommittedInvalidationEnvelope {
    pub fn from_durable_row(
        row: &astral_db::LocalMessageRow,
    ) -> Result<Self, InvalidationFanoutContractError> {
        if row.queue_name != crate::invalidation::INVALIDATION_QUEUE {
            return Err(InvalidationFanoutContractError::NotInvalidationRow {
                queue_name: row.queue_name.clone(),
            });
        }
        if row.status != "PENDING" && row.status != "PROCESSING" {
            return Err(InvalidationFanoutContractError::UnclaimableStatus {
                status: row.status.clone(),
            });
        }
        let envelope: crate::envelope::MessageEnvelope = serde_json::from_str(&row.payload_json)
            .map_err(|error| InvalidationFanoutContractError::InvalidFrame(error.to_string()))?;
        envelope
            .validate()
            .map_err(InvalidationFanoutContractError::InvalidFrame)?;

        // Option equality preserves None == None: a field absent on both
        // sides matches, a field present only on one side diverges.
        let mismatched_field = [
            ("messageId", envelope.message_id != row.message_id),
            ("operationId", envelope.operation_id != row.operation_id),
            ("messageType", envelope.message_type != row.message_type),
            ("tenantId", envelope.tenant_id != row.tenant_id),
            ("originRegion", envelope.origin_region != row.origin_region),
            ("targetRegion", envelope.target_region != row.target_region),
            (
                "schemaVersion",
                envelope.schema_version != row.schema_version,
            ),
            ("orderingKey", envelope.ordering_key != row.ordering_key),
            (
                "payloadSha256",
                envelope.payload_sha256 != row.payload_sha256,
            ),
        ]
        .into_iter()
        .find(|(_, mismatched)| *mismatched)
        .map(|(field, _)| field);
        if let Some(field) = mismatched_field {
            return Err(InvalidationFanoutContractError::EnvelopeMismatch(format!(
                "{field} does not match the durable row"
            )));
        }

        InvalidationEvent::from_envelope(&envelope)?;
        let canonical_bytes = row.payload_json.clone().into_bytes();
        Ok(Self {
            envelope,
            canonical_bytes,
        })
    }

    pub fn envelope(&self) -> &crate::envelope::MessageEnvelope {
        &self.envelope
    }

    /// The exact bytes stored in the durable outbox row. `createdAt` and all
    /// envelope identity fields are preserved byte-for-byte.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn message_id(&self) -> &str {
        &self.envelope.message_id
    }
}

// ===== typed publish outcomes =====

/// Typed result of one fanout publish. Admission (`Admitted`) means the
/// broker confirmed a persistent, mandatory publish into the fanout exchange
/// — nothing more. It is not a remote business completion, not a per-node
/// apply proof, and not an authorization READY proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationFanoutPublishOutcome {
    /// Broker confirmed the persistent publish (publisher confirm ACK, no
    /// mandatory return). Broker admission only.
    Admitted,
    /// The broker returned the message as unroutable (no queue bound to the
    /// fanout exchange). Explicit, safe-to-retry failure.
    ReturnedUnroutable { reply_code: u16, reply_text: String },
    /// The broker negatively acknowledged the publish. Explicit,
    /// safe-to-retry failure (the broker did not accept the message).
    Rejected { reason: String },
    /// Publisher confirms are not enabled on the channel. Configuration
    /// error; the publish must not be treated as admitted.
    ConfirmsNotEnabled,
    /// The outcome cannot be proven (transport error, confirm wait error, or
    /// confirm wait timeout). Reconcile through the durable outbox state
    /// machine — never blind-retry.
    Unknown { reason: String },
}

impl InvalidationFanoutPublishOutcome {
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted)
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    pub fn is_known_failure(&self) -> bool {
        matches!(
            self,
            Self::ReturnedUnroutable { .. } | Self::Rejected { .. } | Self::ConfirmsNotEnabled
        )
    }
}

impl std::fmt::Display for InvalidationFanoutPublishOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admitted => write!(formatter, "Admitted"),
            Self::ReturnedUnroutable {
                reply_code,
                reply_text,
            } => write!(
                formatter,
                "ReturnedUnroutable(reply_code={reply_code}, reply_text={reply_text})"
            ),
            Self::Rejected { reason } => write!(formatter, "Rejected({reason})"),
            Self::ConfirmsNotEnabled => write!(formatter, "ConfirmsNotEnabled"),
            Self::Unknown { reason } => write!(formatter, "Unknown({reason})"),
        }
    }
}

/// Pure classifier: map one lapin confirmation onto the typed outcome.
/// Used by the lapin transport and exercised directly by classification tests.
pub fn classify_confirmation(confirmation: Confirmation) -> InvalidationFanoutPublishOutcome {
    match confirmation {
        Confirmation::Ack(None) => InvalidationFanoutPublishOutcome::Admitted,
        Confirmation::Ack(Some(returned)) => classify_returned(&returned, "ack_returned"),
        Confirmation::Nack(returned) => returned
            .map(|returned| classify_returned(&returned, "nack_returned"))
            .unwrap_or_else(|| InvalidationFanoutPublishOutcome::Rejected {
                reason: "publisher negatively acknowledged".to_owned(),
            }),
        Confirmation::NotRequested => InvalidationFanoutPublishOutcome::ConfirmsNotEnabled,
    }
}

fn classify_returned(
    returned: &BasicReturnMessage,
    origin: &'static str,
) -> InvalidationFanoutPublishOutcome {
    // Only broker metadata crosses this boundary; the frame body itself is
    // never copied into the outcome.
    InvalidationFanoutPublishOutcome::ReturnedUnroutable {
        reply_code: returned.reply_code,
        reply_text: format!("{origin}:{}", returned.reply_text),
    }
}

/// Pure classifier: transport errors are always `Unknown` — the frame may or
/// may not have reached the broker, so the durable outbox must reconcile.
pub fn classify_transport_error(error: &lapin::Error) -> InvalidationFanoutPublishOutcome {
    InvalidationFanoutPublishOutcome::Unknown {
        reason: format!("transport error: {error}"),
    }
}

// ===== publish transport =====

/// The publisher-side transport. Implementations publish **raw canonical
/// bytes** with mandatory + persistent delivery and classify the broker
/// answer into [`InvalidationFanoutPublishOutcome`].
#[async_trait]
pub trait InvalidationFanoutTransport: Send + Sync {
    async fn publish_canonical(
        &self,
        body: &[u8],
        message_id: &str,
    ) -> InvalidationFanoutPublishOutcome;

    /// Publish a committed invalidation envelope (canonical bytes preserved).
    async fn publish_committed_invalidation(
        &self,
        request: &CommittedInvalidationEnvelope,
    ) -> InvalidationFanoutPublishOutcome {
        self.publish_canonical(request.canonical_bytes(), request.message_id())
            .await
    }

    /// Publish a liveness heartbeat frame. Heartbeats are admission-only;
    /// failures are logged by the relay and never retried blindly.
    async fn publish_heartbeat(
        &self,
        identity: &NodeIdentity,
        sent_at: String,
    ) -> InvalidationFanoutPublishOutcome {
        match FanoutFrame::encode_heartbeat(identity, sent_at) {
            Ok(body) => {
                self.publish_canonical(&body, &format!("heartbeat-{}", identity.node()))
                    .await
            }
            Err(error) => InvalidationFanoutPublishOutcome::Rejected {
                reason: error.to_string(),
            },
        }
    }
}

/// Real lapin fanout publisher. The channel must have publisher confirms
/// enabled; the constructor enables and verifies them, refusing to build a
/// publisher that could silently return `NotRequested`.
#[derive(Clone)]
pub struct LapinFanoutPublisher {
    channel: Channel,
}

impl LapinFanoutPublisher {
    pub async fn new(channel: Channel) -> Result<Self, MqError> {
        crate::producer::Producer::enable_confirms(&channel).await?;
        Ok(Self { channel })
    }

    fn properties(&self, message_id: &str) -> BasicProperties {
        BasicProperties::default()
            .with_delivery_mode(2)
            .with_content_type("application/json".into())
            .with_message_id(ShortString::from(message_id))
    }
}

#[async_trait]
impl InvalidationFanoutTransport for LapinFanoutPublisher {
    async fn publish_canonical(
        &self,
        body: &[u8],
        message_id: &str,
    ) -> InvalidationFanoutPublishOutcome {
        let confirm = self
            .channel
            .basic_publish(
                ShortString::from(crate::config::EXCHANGE_AUTHORIZATION_INVALIDATION_FANOUT),
                ShortString::from(""),
                BasicPublishOptions {
                    mandatory: true,
                    ..BasicPublishOptions::default()
                },
                body,
                self.properties(message_id),
            )
            .await;
        match confirm {
            Ok(confirm) => match confirm.await {
                Ok(confirmation) => classify_confirmation(confirmation),
                Err(error) => classify_transport_error(&error),
            },
            Err(error) => classify_transport_error(&error),
        }
    }
}

// ===== consume transport =====

/// Settlement hooks for one delivery, transport agnostic.
#[async_trait]
pub trait FanoutDeliverySettlement: Send + Sync {
    async fn ack(&self) -> Result<(), String>;
    /// Negative acknowledgement with requeue: the delivery returns to the
    /// node's queue without any durable state change.
    async fn nack_requeue(&self) -> Result<(), String>;
    /// Negative acknowledgement without requeue: the delivery is handed to
    /// the node's DLX queue (quarantine park). The durable inbox receipt, if
    /// committed, stays `PENDING`.
    async fn nack_dead_letter(&self) -> Result<(), String>;
}

/// One delivered fanout frame plus its settlement hooks.
pub struct FanoutDelivery {
    pub payload: Vec<u8>,
    pub settlement: Box<dyn FanoutDeliverySettlement>,
}

/// Pull-side transport for one subscribed node session. `None` ends the
/// session (channel/connection closed); the worker then marks the channel
/// suspect and reconnects.
#[async_trait]
pub trait FanoutDeliverySource: Send {
    async fn next_delivery(&mut self) -> Option<Result<FanoutDelivery, String>>;
}

/// Real lapin consumer session for one node. Declares the per-node topology
/// (idempotent) and subscribes to the node's own durable queue.
pub struct LapinInboxSession {
    consumer: lapin::Consumer,
    #[allow(dead_code)]
    channel: Channel,
}

impl LapinInboxSession {
    /// Establish one consume session. Topology declaration is re-run on every
    /// (re)connect; all statements are creator-guarded.
    pub async fn connect(
        connection: &Connection,
        identity: &NodeIdentity,
        prefetch: u16,
    ) -> Result<Self, MqError> {
        let channel = connection
            .create_channel()
            .await
            .map_err(|error| MqError::Channel(format!("fanout inbox channel failed: {error}")))?;
        declare_invalidation_fanout_topology(&channel, identity)
            .await
            .map_err(|error| {
                MqError::Channel(format!("fanout topology declare failed: {error}"))
            })?;
        channel
            .basic_qos(prefetch, BasicQosOptions { global: false })
            .await
            .map_err(|error| MqError::Channel(format!("fanout inbox qos failed: {error}")))?;
        let consumer = channel
            .basic_consume(
                ShortString::from(invalidation_fanout_queue_name(identity)),
                ShortString::from(format!(
                    "invalidation-fanout-{}-{}",
                    identity.region(),
                    identity.node()
                )),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|error| MqError::Consume(format!("fanout inbox subscribe failed: {error}")))?;
        Ok(Self { consumer, channel })
    }
}

#[async_trait]
impl FanoutDeliverySource for LapinInboxSession {
    async fn next_delivery(&mut self) -> Option<Result<FanoutDelivery, String>> {
        use futures_util::StreamExt;
        match self.consumer.next().await {
            Some(Ok(delivery)) => Some(Ok(FanoutDelivery {
                payload: delivery.data.clone(),
                settlement: Box::new(LapinDeliverySettlement {
                    acker: delivery.acker.clone(),
                }),
            })),
            Some(Err(error)) => Some(Err(error.to_string())),
            None => None,
        }
    }
}

struct LapinDeliverySettlement {
    acker: lapin::Acker,
}

#[async_trait]
impl FanoutDeliverySettlement for LapinDeliverySettlement {
    async fn ack(&self) -> Result<(), String> {
        self.acker
            .ack(BasicAckOptions::default())
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn nack_requeue(&self) -> Result<(), String> {
        self.acker
            .nack(BasicNackOptions {
                requeue: true,
                ..BasicNackOptions::default()
            })
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn nack_dead_letter(&self) -> Result<(), String> {
        self.acker
            .nack(BasicNackOptions {
                requeue: false,
                ..BasicNackOptions::default()
            })
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

// ===== durable per-node inbox proof adapter =====

/// The record committed as this node's durable receipt before any ACK.
#[derive(Debug, Clone)]
pub struct InvalidationInboxRecord {
    pub node_region: String,
    pub node_id: String,
    pub envelope: crate::envelope::MessageEnvelope,
}

impl InvalidationInboxRecord {
    pub(crate) fn payload_json(&self) -> Result<String, String> {
        self.envelope.envelope_json()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxCommitOutcome {
    /// First durable commit of this delivery on this node.
    InsertedPending,
    /// Redelivery of a receipt still `PENDING` (apply not yet proven).
    ExistingPending,
    /// Duplicate delivery of an already applied receipt.
    ExistingApplied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxMarkApplied {
    Applied,
    AlreadyApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidationInboxFailure {
    /// Same node/message id committed with different content. Terminal
    /// contract violation — never retried, never overwritten.
    #[error("inbox receipt payload conflict")]
    PayloadConflict,
    /// Storage unavailable or transition lost. Treated as requeue-able.
    #[error("inbox storage failure: {0}")]
    Storage(String),
}

/// Durable per-node inbox proof adapter. Implementations own exactly one
/// node's receipt rows; the MySql implementation is backed by
/// `astral_db::InvalidationInboxRepository` and shares no write ownership
/// with `al_message_outbox`.
#[async_trait]
pub trait InvalidationInboxAdapter: Send + Sync {
    /// Commit the delivery durably. Must complete before any ACK.
    async fn commit_delivery(
        &self,
        record: &InvalidationInboxRecord,
    ) -> Result<InboxCommitOutcome, InvalidationInboxFailure>;

    /// Mark the receipt applied after the in-memory apply succeeded.
    async fn mark_applied(
        &self,
        identity: &NodeIdentity,
        message_id: &str,
    ) -> Result<InboxMarkApplied, InvalidationInboxFailure>;

    /// Per-scope gap probe: does a `PENDING` receipt exist in this exact
    /// ordering-key scope strictly before `(envelope created_at, message_id)`?
    /// Never mutates state, never clears a proof.
    async fn has_pending_before(
        &self,
        identity: &NodeIdentity,
        ordering_key: &str,
        envelope_created_at: &str,
        message_id: &str,
    ) -> Result<bool, InvalidationInboxFailure>;
}

/// MySql implementation of the durable per-node inbox proof adapter.
#[derive(Clone)]
pub struct MySqlInvalidationInbox {
    repository: astral_db::InvalidationInboxRepository,
}

impl MySqlInvalidationInbox {
    pub fn new(pool: sqlx::MySqlPool) -> Self {
        Self {
            repository: astral_db::InvalidationInboxRepository::new(pool),
        }
    }
}

fn parse_envelope_created_at(
    created_at: &str,
) -> Result<PrimitiveDateTime, InvalidationInboxFailure> {
    let parsed =
        time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339)
            .map_err(|error| {
                InvalidationInboxFailure::Storage(format!(
                    "envelope createdAt is not RFC3339: {error}"
                ))
            })?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    Ok(PrimitiveDateTime::new(utc.date(), utc.time()))
}

#[async_trait]
impl InvalidationInboxAdapter for MySqlInvalidationInbox {
    async fn commit_delivery(
        &self,
        record: &InvalidationInboxRecord,
    ) -> Result<InboxCommitOutcome, InvalidationInboxFailure> {
        let payload_json = record
            .payload_json()
            .map_err(InvalidationInboxFailure::Storage)?;
        let input = astral_db::InvalidationInboxInput {
            node_region: &record.node_region,
            node_id: &record.node_id,
            message_id: &record.envelope.message_id,
            operation_id: &record.envelope.operation_id,
            message_type: &record.envelope.message_type,
            ordering_key: record.envelope.ordering_key.as_deref(),
            tenant_id: record.envelope.tenant_id,
            origin_region: &record.envelope.origin_region,
            schema_version: record.envelope.schema_version,
            payload_json: &payload_json,
            payload_sha256: &record.envelope.payload_sha256,
            envelope_created_at: parse_envelope_created_at(&record.envelope.created_at)?,
        };
        self.repository
            .commit_delivery(&input)
            .await
            .map(|committed| match committed {
                astral_db::InvalidationInboxCommit::InsertedPending => {
                    InboxCommitOutcome::InsertedPending
                }
                astral_db::InvalidationInboxCommit::ExistingPending => {
                    InboxCommitOutcome::ExistingPending
                }
                astral_db::InvalidationInboxCommit::ExistingApplied => {
                    InboxCommitOutcome::ExistingApplied
                }
            })
            .map_err(|error| match error {
                astral_db::InvalidationInboxError::PayloadConflict => {
                    InvalidationInboxFailure::PayloadConflict
                }
                other => {
                    InvalidationInboxFailure::Storage(format!("{INBOX_STORAGE_ERROR_TAG}: {other}"))
                }
            })
    }

    async fn mark_applied(
        &self,
        identity: &NodeIdentity,
        message_id: &str,
    ) -> Result<InboxMarkApplied, InvalidationInboxFailure> {
        self.repository
            .mark_applied(identity.region(), identity.node(), message_id)
            .await
            .map(|marked| match marked {
                astral_db::InvalidationInboxMarkApplied::Applied => InboxMarkApplied::Applied,
                astral_db::InvalidationInboxMarkApplied::AlreadyApplied => {
                    InboxMarkApplied::AlreadyApplied
                }
            })
            .map_err(|error| match error {
                astral_db::InvalidationInboxError::PayloadConflict => {
                    InvalidationInboxFailure::PayloadConflict
                }
                other => {
                    InvalidationInboxFailure::Storage(format!("{INBOX_STORAGE_ERROR_TAG}: {other}"))
                }
            })
    }

    async fn has_pending_before(
        &self,
        identity: &NodeIdentity,
        ordering_key: &str,
        envelope_created_at: &str,
        message_id: &str,
    ) -> Result<bool, InvalidationInboxFailure> {
        let created_at = parse_envelope_created_at(envelope_created_at)?;
        self.repository
            .has_pending_before(
                identity.region(),
                identity.node(),
                ordering_key,
                created_at,
                message_id,
            )
            .await
            .map_err(|error| {
                InvalidationInboxFailure::Storage(format!("{INBOX_STORAGE_ERROR_TAG}: {error}"))
            })
    }
}

// ===== apply callback + listener =====

/// The consumer-side apply callback. Implementations apply the typed
/// invalidation to the node's local acceleration state (memory hub fences,
/// L1 eligibility cache, session registry) and re-read authoritative data
/// through the strict reader. An `Err` keeps the durable receipt `PENDING`.
#[async_trait]
pub trait InvalidationApply: Send + Sync {
    async fn apply(
        &self,
        envelope: &crate::envelope::MessageEnvelope,
        event: &InvalidationEvent,
    ) -> Result<(), String>;
}

/// Per-scope reconciliation report. Scope-exact: everything is bound to one
/// ordering key (which encodes tenant + aggregate type + aggregate id +
/// card), one message id, and one payload hash. Never compare across
/// aggregate domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeGapReport {
    pub ordering_key: String,
    pub observed_created_at: String,
    pub observed_message_id: String,
    pub observed_payload_sha256: String,
    /// A `PENDING` receipt exists earlier in this exact scope.
    pub has_pending_earlier: bool,
    /// The watermark moved backwards inside this scope.
    pub scope_regressed: bool,
}

/// Listener hooks for health wiring. Contract:
/// - `on_channel_suspect` is the only hook allowed to raise the suspect
///   state (which triggers the strict fail-closed read path).
/// - `on_heartbeat_alive` may only record liveness (monotonic). It must
///   never clear a suspect flag, a durable receipt, or a watermark.
/// - `on_scope_gap` reports an exact per-scope reconciliation need. Scope
///   gaps are suspect-grade signals: implementations must surface them to
///   the strict fail-closed read path (or an equivalent reconciliation
///   flag) until the gap is resolved; they must never be swallowed.
#[async_trait]
pub trait InvalidationFanoutListener: Send + Sync {
    async fn on_channel_suspect(&self, identity: &NodeIdentity, reason: &str);
    async fn on_heartbeat_alive(&self, identity: &NodeIdentity, heartbeat: &HeartbeatScope);
    async fn on_scope_gap(&self, identity: &NodeIdentity, report: &ScopeGapReport);
}

/// No-op listener for tests and for assemblies that only need the transport.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopListener;

#[async_trait]
impl InvalidationFanoutListener for NoopListener {
    async fn on_channel_suspect(&self, _identity: &NodeIdentity, _reason: &str) {}
    async fn on_heartbeat_alive(&self, _identity: &NodeIdentity, _heartbeat: &HeartbeatScope) {}
    async fn on_scope_gap(&self, _identity: &NodeIdentity, _report: &ScopeGapReport) {}
}

// ===== per-node, per-scope watermark =====

/// In-memory per-node watermark tracker. Keyed by the exact ordering key
/// (scope), comparing only `(envelope created_at, message_id)` inside that
/// scope — never across scopes or aggregate domains.
#[derive(Debug, Default)]
pub struct ScopeWatermarkTracker {
    last_applied: std::collections::HashMap<String, (String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkAdvance {
    /// The scope watermark moved forward.
    Advanced,
    /// The observed message is not ahead of the watermark for this scope.
    /// Freshness application is still safe (generations fence the apply),
    /// but the scope is flagged for reconciliation.
    ScopeRegressed {
        previous: (String, String),
        observed: (String, String),
    },
}

impl ScopeWatermarkTracker {
    pub fn advance(
        &mut self,
        ordering_key: &str,
        envelope_created_at: &str,
        message_id: &str,
    ) -> WatermarkAdvance {
        let observed = (envelope_created_at.to_owned(), message_id.to_owned());
        match self.last_applied.get(ordering_key) {
            None => {
                self.last_applied.insert(ordering_key.to_owned(), observed);
                WatermarkAdvance::Advanced
            }
            Some(previous) => {
                if observed > *previous {
                    self.last_applied
                        .insert(ordering_key.to_owned(), observed.clone());
                    WatermarkAdvance::Advanced
                } else {
                    WatermarkAdvance::ScopeRegressed {
                        previous: previous.clone(),
                        observed,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::payload_digest;
    use serde_json::json;

    fn evidence_envelope() -> crate::envelope::MessageEnvelope {
        crate::invalidation::InvalidationEvent::EvidenceInvalidated(
            crate::invalidation::EvidenceInvalidated {
                tenant_id: 7,
                card_id: Some(42),
                aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
                aggregate_id: 42,
                published_generation: 10,
                source_generation: 10,
                revoke_fence: 0,
            },
        )
        .to_envelope("event-1", "operation-1", "city-a")
        .unwrap()
    }

    fn heartbeat_envelope() -> crate::envelope::MessageEnvelope {
        let scope = HeartbeatScope {
            node_region: "city-a".into(),
            node_id: "node-1".into(),
            sent_at: "2026-10-01T00:00:00Z".into(),
        };
        let payload = serde_json::to_value(&scope).unwrap();
        let envelope = crate::envelope::MessageEnvelope::new(
            "heartbeat-1",
            "heartbeat-op",
            INVALIDATION_HEARTBEAT_MESSAGE_TYPE,
            INVALIDATION_SCHEMA_VERSION,
            "city-a",
            payload,
        )
        .unwrap();
        envelope.validate().unwrap();
        envelope
    }

    #[test]
    fn invalidation_frame_round_trips_and_revalidates_scope() {
        let envelope = evidence_envelope();
        let body = FanoutFrame::Invalidation(envelope.clone())
            .encode()
            .unwrap();
        let frame = FanoutFrame::decode(&body).unwrap();
        assert_eq!(frame, FanoutFrame::Invalidation(envelope));
    }

    #[test]
    fn heartbeat_frame_round_trips_and_validates_scope() {
        let envelope = heartbeat_envelope();
        let body = FanoutFrame::Heartbeat(envelope.clone()).encode().unwrap();
        let frame = FanoutFrame::decode(&body).unwrap();
        assert_eq!(frame, FanoutFrame::Heartbeat(envelope));
    }

    #[test]
    fn frame_decode_fails_closed_on_digest_and_type_violations() {
        let mut tampered = evidence_envelope();
        tampered.payload = json!({"tenantId": 7, "unexpected": true});
        tampered.payload_sha256 = payload_digest(&tampered.payload).unwrap();
        // Type stays EVIDENCE_INVALIDATED but the payload no longer matches
        // the typed contract: decode must reject it.
        let body = serde_json::to_vec(&tampered).unwrap();
        assert!(matches!(
            FanoutFrame::decode(&body),
            Err(InvalidationFanoutContractError::Contract(_))
        ));

        let mut unknown = evidence_envelope();
        unknown.message_type = "AUTHORIZATION_READY_BROADCAST".into();
        let body = serde_json::to_vec(&unknown).unwrap();
        assert!(matches!(
            FanoutFrame::decode(&body),
            Err(InvalidationFanoutContractError::UnsupportedMessageType(message))
                if message.contains("AUTHORIZATION_READY_BROADCAST")
        ));

        let mut bad_heartbeat = heartbeat_envelope();
        bad_heartbeat.payload =
            json!({"nodeRegion": "city-a", "nodeId": "node-1", "sentAt": "not-a-time"});
        bad_heartbeat.payload_sha256 = payload_digest(&bad_heartbeat.payload).unwrap();
        let body = serde_json::to_vec(&bad_heartbeat).unwrap();
        assert!(matches!(
            FanoutFrame::decode(&body),
            Err(InvalidationFanoutContractError::InvalidHeartbeat(reason))
                if reason.contains("sentAt")
        ));

        assert!(FanoutFrame::decode(b"not json").is_err());
    }

    #[test]
    fn heartbeat_scope_rejects_illegal_identity_and_timestamp() {
        let bad_identity = HeartbeatScope {
            node_region: "city a".into(),
            node_id: "node-1".into(),
            sent_at: "2026-10-01T00:00:00Z".into(),
        };
        assert!(matches!(
            bad_identity.validate(),
            Err(InvalidationFanoutContractError::InvalidHeartbeat(_))
        ));

        let bad_time = HeartbeatScope {
            node_region: "city-a".into(),
            node_id: "node-1".into(),
            sent_at: "yesterday".into(),
        };
        assert!(matches!(
            bad_time.validate(),
            Err(InvalidationFanoutContractError::InvalidHeartbeat(reason))
                if reason.contains("sentAt")
        ));

        let good = HeartbeatScope {
            node_region: "city-a".into(),
            node_id: "node-1".into(),
            sent_at: "2026-10-01T00:00:00Z".into(),
        };
        assert!(good.validate().is_ok());
    }

    #[test]
    fn committed_envelope_preserves_canonical_bytes_and_created_at() {
        let envelope = evidence_envelope();
        let payload_json = envelope.envelope_json().unwrap();
        let row = astral_db::LocalMessageRow {
            message_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            message_type: envelope.message_type.clone(),
            queue_name: crate::invalidation::INVALIDATION_QUEUE.to_owned(),
            ordering_key: envelope.ordering_key.clone(),
            tenant_id: envelope.tenant_id,
            origin_region: envelope.origin_region.clone(),
            target_region: envelope.target_region.clone(),
            schema_version: envelope.schema_version,
            payload_json: payload_json.clone(),
            headers_json: None,
            payload_sha256: envelope.payload_sha256.clone(),
            status: "PENDING".into(),
            attempts: 0,
            next_attempt_at: None,
            lease_owner: Some("relay:token".into()),
            lease_expires_at: None,
            processed_at: None,
            last_error: None,
            created_at: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2026, time::Month::October, 1).unwrap(),
                time::Time::MIDNIGHT,
            ),
            updated_at: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2026, time::Month::October, 1).unwrap(),
                time::Time::MIDNIGHT,
            ),
        };

        let request = CommittedInvalidationEnvelope::from_durable_row(&row).unwrap();
        assert_eq!(request.canonical_bytes(), payload_json.as_bytes());
        assert_eq!(request.envelope().created_at, envelope.created_at);
        assert_eq!(request.message_id(), "event-1");
    }

    #[test]
    fn committed_envelope_rejects_foreign_rows_and_divergence() {
        let envelope = evidence_envelope();
        let payload_json = envelope.envelope_json().unwrap();
        let mut row = astral_db::LocalMessageRow {
            message_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            message_type: envelope.message_type.clone(),
            queue_name: "astral.audit.log".into(),
            ordering_key: envelope.ordering_key.clone(),
            tenant_id: envelope.tenant_id,
            origin_region: envelope.origin_region.clone(),
            target_region: envelope.target_region.clone(),
            schema_version: envelope.schema_version,
            payload_json: payload_json.clone(),
            headers_json: None,
            payload_sha256: envelope.payload_sha256.clone(),
            status: "PENDING".into(),
            attempts: 0,
            next_attempt_at: None,
            lease_owner: None,
            lease_expires_at: None,
            processed_at: None,
            last_error: None,
            created_at: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2026, time::Month::October, 1).unwrap(),
                time::Time::MIDNIGHT,
            ),
            updated_at: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2026, time::Month::October, 1).unwrap(),
                time::Time::MIDNIGHT,
            ),
        };
        assert!(matches!(
            CommittedInvalidationEnvelope::from_durable_row(&row),
            Err(InvalidationFanoutContractError::NotInvalidationRow { .. })
        ));

        row.queue_name = crate::invalidation::INVALIDATION_QUEUE.to_owned();
        row.status = "PROCESSED".into();
        assert!(matches!(
            CommittedInvalidationEnvelope::from_durable_row(&row),
            Err(InvalidationFanoutContractError::UnclaimableStatus { status }) if status == "PROCESSED"
        ));

        row.status = "PROCESSING".into();
        row.payload_sha256 = "0".repeat(64);
        assert!(matches!(
            CommittedInvalidationEnvelope::from_durable_row(&row),
            Err(InvalidationFanoutContractError::EnvelopeMismatch(reason))
                if reason.contains("payloadSha256")
        ));

        row.payload_sha256 = envelope.payload_sha256.clone();
        row.payload_json = row.payload_json.replace("\"createdAt\"", "\"createdAtX\"");
        assert!(
            CommittedInvalidationEnvelope::from_durable_row(&row).is_err(),
            "a row whose payload no longer parses as a valid envelope must be rejected"
        );
    }

    #[test]
    fn publish_outcome_classification_covers_every_confirmation_variant() {
        assert_eq!(
            classify_confirmation(Confirmation::Ack(None)),
            InvalidationFanoutPublishOutcome::Admitted
        );
        assert!(classify_confirmation(Confirmation::Ack(None)).is_admitted());

        let make_returned = |reply_text: &str| {
            let delivery = lapin::message::Delivery::mock(
                1,
                ShortString::from(crate::config::EXCHANGE_AUTHORIZATION_INVALIDATION_FANOUT),
                ShortString::from(""),
                false,
                b"frame-body".to_vec(),
            );
            BasicReturnMessage {
                delivery,
                reply_code: 312,
                reply_text: ShortString::from(reply_text),
            }
        };
        let unroutable = classify_confirmation(Confirmation::Ack(Some(make_returned("NO_ROUTE"))));
        assert_eq!(
            unroutable,
            InvalidationFanoutPublishOutcome::ReturnedUnroutable {
                reply_code: 312,
                reply_text: "ack_returned:NO_ROUTE".into(),
            }
        );
        let nack_returned =
            classify_confirmation(Confirmation::Nack(Some(make_returned("NO_ROUTE"))));
        assert_eq!(
            nack_returned,
            InvalidationFanoutPublishOutcome::ReturnedUnroutable {
                reply_code: 312,
                reply_text: "nack_returned:NO_ROUTE".into(),
            }
        );

        assert_eq!(
            classify_confirmation(Confirmation::Nack(None)),
            InvalidationFanoutPublishOutcome::Rejected {
                reason: "publisher negatively acknowledged".into(),
            }
        );
        assert_eq!(
            classify_confirmation(Confirmation::NotRequested),
            InvalidationFanoutPublishOutcome::ConfirmsNotEnabled
        );

        let unknown = classify_transport_error(&lapin::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "connection lost",
        )));
        assert!(unknown.is_unknown());
        assert!(!unknown.is_admitted());
        assert!(!unknown.is_known_failure());
        assert!(InvalidationFanoutPublishOutcome::ConfirmsNotEnabled.is_known_failure());
    }

    #[test]
    fn watermark_tracks_scopes_independently() {
        let mut tracker = ScopeWatermarkTracker::default();
        let key_a = "authorization:evidence:tenant/7/aggregate/USER_CARD/42/card/42";
        let key_b = "authorization:eligibility/card/42";

        assert_eq!(
            tracker.advance(key_a, "2026-10-01T00:00:01Z", "event-2"),
            WatermarkAdvance::Advanced
        );
        // A different scope never regresses another scope.
        assert_eq!(
            tracker.advance(key_b, "2026-10-01T00:00:00Z", "event-1"),
            WatermarkAdvance::Advanced
        );
        // Same scope, later timestamp advances.
        assert_eq!(
            tracker.advance(key_a, "2026-10-01T00:00:02Z", "event-3"),
            WatermarkAdvance::Advanced
        );
        // Same scope, earlier timestamp regresses (flagged, not stored).
        assert_eq!(
            tracker.advance(key_a, "2026-10-01T00:00:00Z", "event-0"),
            WatermarkAdvance::ScopeRegressed {
                previous: ("2026-10-01T00:00:02Z".into(), "event-3".into()),
                observed: ("2026-10-01T00:00:00Z".into(), "event-0".into()),
            }
        );
        // Same timestamp resolves by message id.
        assert_eq!(
            tracker.advance(key_a, "2026-10-01T00:00:02Z", "event-4"),
            WatermarkAdvance::Advanced
        );
        assert_eq!(
            tracker.advance(key_a, "2026-10-01T00:00:02Z", "event-4"),
            WatermarkAdvance::ScopeRegressed {
                previous: ("2026-10-01T00:00:02Z".into(), "event-4".into()),
                observed: ("2026-10-01T00:00:02Z".into(), "event-4".into()),
            }
        );
    }
}
