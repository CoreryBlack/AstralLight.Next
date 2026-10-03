//! Cross-city runtime wiring (P4 production entry point, DEFAULT-OFF).
//!
//! This module is the ONLY sanctioned runtime caller of the cross-city
//! coordinator library: it turns the explicit environment decision into a
//! real, bounded, RAII-managed runtime built from PRODUCTION adapters — a
//! real AMQP (lapin) transport with publisher confirms, and durable
//! outbox/inbox handling BEFORE any broker acknowledgement. It is a library
//! entry point, NOT a server: the outer runtime calls
//! [`start_cross_city_runtime`] EXACTLY ONCE and holds the returned
//! [`CrossCityRuntimeHandle`] (RAII) until shutdown. Nothing here touches
//! HTTP routing, `AppState`, PolicyEngine, Identity, Gateway, or the outer
//! runtime module; no mock/in-memory transport stands in for the broker path.
//!
//! # Default-off and zero-I/O guarantee
//!
//! The start decision comes from [`resolve_cross_city_start_from_env`]:
//! `ASTRAL_CROSS_CITY_ENABLED` is ABSENT or false by default, and a disabled
//! decision returns a DORMANT handle before ANY I/O — no database read, no
//! AMQP connection, no spawned task. Enabling with MISSING configuration
//! (any required variable absent/empty, unparsable or out-of-bounds values)
//! is a typed REFUSAL, never a silent default.
//!
//! # Startup admission (durable, one-shot, refuses missing registries)
//!
//! An enabled start reads the durable registries ONCE and refuses to come up
//! when the explicit fixed providers are missing: an empty node-key registry
//! or an authoritative city-scope registry without a single authoritative
//! row is missing configuration. The wiring NEVER registers keys or scopes
//! by itself and NEVER creates a new authorization — registration is an
//! explicit administrative source mutation through the astral-db primitives.
//!
//! # Transport truth (no fakes, durable before ACK)
//!
//! - OUTBOUND relay: durably claims a bounded batch (lease), publishes over
//!   the real lapin channel with PUBLISHER CONFIRMS, and marks the row
//!   `SUCCEEDED` only after the broker confirm. A known failure enters the
//!   attempt budget (`fail`), an UNKNOWN outcome enters `PUBLISH_IN_DOUBT`
//!   (never SUCCEEDED, never silently retried). The send runs OUTSIDE any
//!   transaction; every state change is its own short transaction.
//! - INBOUND: the durable inbox record commits BEFORE handling. Only the
//!   current delivery's message id can be claimed; the body stays with that
//!   delivery. Handling and its durable settlement must commit before ACK.
//!   Retryable refusals are requeued; QUARANTINED/IN_DOUBT receipts are parked
//!   durably and acknowledged without claiming business completion. An
//!   idempotent REDELIVERY of a message whose durable row already reached a
//!   state the worker path cannot advance is acknowledged with an audit event.
//! - REMOTE COMMITS ARE NEVER FAKED: a `COMMIT_CONFIRMED` body is admitted
//!   only through the coordinator's signed-receipt path (Ed25519-authenticated
//!   evidence + explicit authoritative city scope + full version binding
//!   against the locked parent), and activation mints ONLY from the durable
//!   two-city commit receipts. Remote database replication is not simulated,
//!   guessed, or inferred from message liveness. Every recorded vote attempts
//!   the evidence-derived agreement seal (idempotent; typed refusal until
//!   quorum is derivable), and an activation mint whose storage outcome is
//!   UNKNOWN collapses the operation into `IN_DOUBT` — the fail-closed
//!   recovery edge, never a guess and never a silent retry.
//!
//! # Budgets (no unbounded polling)
//!
//! Every loop is tick- or delivery-driven with a bounded batch, a bounded
//! prefetch, a bounded lease, and a shutdown watch. The outer runtime observes
//! required worker exits during serving; bounded shutdown aborts stragglers.
//!
//! # Wire envelope
//!
//! AMQP bodies are `[u32 BE envelope length][envelope JSON][payload bytes]`.
//! The envelope pins `version`, `operation_id`, `phase`, `source_city_id`,
//! `destination_city_id`; the receiver re-derives the message identity (the
//! same canonical derivation as the durable outbox/inbox rows) and refuses
//! any disagreement BEFORE recording anything.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions, BasicQosOptions,
    ConfirmSelectOptions, ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
};
use lapin::types::{FieldTable, LongString};
use lapin::BasicProperties;
use lapin::Confirmation;
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use astral_db::{
    claim_inbox_message_in_tx, claim_next_outbox_in_tx, fail_inbox_in_tx, fail_outbox_in_tx,
    load_cross_city_authority_scope_registry, load_cross_city_node_key_snapshot,
    mark_inbox_process_in_doubt_in_tx, mark_inbox_processed_in_tx,
    mark_outbox_publish_in_doubt_in_tx, mark_outbox_succeeded_in_tx, record_inbox_in_tx,
    CrossCityAuthorityScopeEntry, CrossCityCommitReceiptMeta, CrossCityInboxInsertOutcome,
    CrossCityInboxLeaseGrant, CrossCityInboxRecordInsert, CrossCityOutboxLeaseGrant,
    CrossCityTransportFailureOutcome, CrossCityTransportLeaseProof,
};
use astral_types::{
    CrossCityDeliveryStatus, CrossCityMessageIdentity, CrossCityMessagePhase,
    CrossCityOperationState, ZeroDecisionEvidence,
};

use super::cross_city_coordinator::{
    CrossCityAgreementSealOutcome, CrossCityCoordinator, CrossCityCoordinatorAuditEvent,
    CrossCityCoordinatorAuditSink, CrossCityCoordinatorError, CrossCityMessageTransport,
    CrossCityOutboundMessage, CrossCityTransportDispatchError, CrossCityVoteAdmission,
};

// ---------------------------------------------------------------------------
// Environment contract (fail-closed; absent = disabled)
// ---------------------------------------------------------------------------

/// Master switch; ABSENT or `false`/`0`/`off`/`no` (case-insensitive) means
/// disabled. There is NO implicit enablement.
pub const CROSS_CITY_ENABLED_ENV: &str = "ASTRAL_CROSS_CITY_ENABLED";
/// This deployment's city id (home city; outbox `source_city_id`).
pub const CROSS_CITY_HOME_CITY_ENV: &str = "ASTRAL_CROSS_CITY_HOME_CITY_ID";
/// This deployment's node id (lease-owner namespace only; never an
/// authorization identity — node identities live in the durable registry).
pub const CROSS_CITY_NODE_ID_ENV: &str = "ASTRAL_CROSS_CITY_NODE_ID";
/// Monotonic coordinator epoch fence (positive integer).
pub const CROSS_CITY_COORDINATOR_EPOCH_ENV: &str = "ASTRAL_CROSS_CITY_COORDINATOR_EPOCH";
/// AMQP URL of the cross-city broker (secret: env-only, never logged).
pub const CROSS_CITY_AMQP_URL_ENV: &str = "ASTRAL_CROSS_CITY_AMQP_URL";
/// Explicit peer city ids (comma-separated; NO discovery, NO defaults).
pub const CROSS_CITY_PEER_CITIES_ENV: &str = "ASTRAL_CROSS_CITY_PEER_CITIES";
/// Outbox relay batch bound (optional; default [`DEFAULT_RELAY_BATCH`]).
pub const CROSS_CITY_RELAY_BATCH_ENV: &str = "ASTRAL_CROSS_CITY_RELAY_BATCH";
/// Relay tick interval in milliseconds (optional; default
/// [`DEFAULT_RELAY_TICK_MS`]).
pub const CROSS_CITY_RELAY_TICK_MS_ENV: &str = "ASTRAL_CROSS_CITY_RELAY_TICK_MS";
/// Inbound prefetch bound (optional; default [`DEFAULT_INBOX_BATCH`]).
pub const CROSS_CITY_INBOX_BATCH_ENV: &str = "ASTRAL_CROSS_CITY_INBOX_BATCH";
/// Transport lease seconds for the durable outbox/inbox claim (optional;
/// default [`LEASE_SECONDS_DEFAULT`]). A distinct variable on purpose: the
/// relay tick and the lease budget are independent bounds and must never be
/// derived from each other.
pub const CROSS_CITY_TRANSPORT_LEASE_SECONDS_ENV: &str =
    "ASTRAL_CROSS_CITY_TRANSPORT_LEASE_SECONDS";

/// AMQP exchange all cross-city messages pass through (direct routing).
pub const CROSS_CITY_EXCHANGE: &str = "authorization.cross_city.v1";
/// Durable dead-letter exchange for unroutable/poisoned cross-city deliveries.
pub const CROSS_CITY_DLX_EXCHANGE: &str = "authorization.cross_city.v1.dlx";
/// Durable queue prefix; the suffix is the destination city id.
pub const CROSS_CITY_QUEUE_PREFIX: &str = "authorization.cross_city.v1.queue";

/// Compile-time marker: the wiring starts NOTHING by default.
pub const CROSS_CITY_WIRING_DEFAULT_ENABLED: bool = false;

const DEFAULT_RELAY_BATCH: usize = 8;
const DEFAULT_RELAY_TICK_MS: u64 = 250;
/// Floor for the relay tick: a tick below this would poll the durable outbox
/// claim at an unbounded rate (bounded-budget hygiene for the DB).
const MIN_RELAY_TICK_MS: u64 = 10;
const DEFAULT_INBOX_BATCH: usize = 16;
const MAX_BATCH_BOUND: usize = 64;
const LEASE_SECONDS_DEFAULT: i64 = 30;
const MIN_LEASE_SECONDS: i64 = 5;
const MAX_LEASE_SECONDS: i64 = 300;
const MAX_CITY_ID_LENGTH: usize = 191;
const WIRE_ENVELOPE_VERSION: u8 = 1;
const CROSS_CITY_PUBLISH_DEADLINE: Duration = Duration::from_secs(2);
const CROSS_CITY_HANDLE_DEADLINE: Duration = Duration::from_secs(3);
const CROSS_CITY_REQUEUE_PAUSE: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// Start decision and errors
// ---------------------------------------------------------------------------

/// The resolved start decision: disabled (zero-I/O) or complete configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCityStartDecision {
    /// Flag absent/false: startup is a dormant no-op with zero I/O.
    Disabled,
    /// Explicit, complete, validated enablement configuration.
    Enabled(Box<CrossCityRuntimeConfig>),
}

/// Validated enablement configuration (never constructed by a default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityRuntimeConfig {
    pub home_city_id: String,
    pub node_id: String,
    pub coordinator_epoch: u64,
    /// Cross-city AMQP URL; secret material — never logged, never embedded
    /// into an error message.
    pub amqp_url: String,
    pub peer_city_ids: Vec<String>,
    pub relay_batch: usize,
    pub relay_tick_ms: u64,
    pub inbox_batch: usize,
    pub transport_lease_seconds: i64,
}

/// Typed startup failures. None ever leaves a partial runtime running.
#[derive(Debug, Error)]
pub enum CrossCityRuntimeStartError {
    /// Enabling configuration is missing or malformed (fail-closed refusal).
    #[error("cross-city runtime configuration refused: {0}")]
    ConfigRefused(&'static str),
    /// A cross-city repository refused the startup admission read.
    #[error(transparent)]
    Repository(#[from] astral_db::CrossCityRepositoryError),
    /// The runtime repository refused the startup admission read.
    #[error(transparent)]
    RuntimeRepository(#[from] astral_db::CrossCityRuntimeRepositoryError),
    /// The coordinator construction refused the configuration.
    #[error(transparent)]
    Coordinator(#[from] CrossCityCoordinatorError),
    /// The broker connection/topology setup failed (no durable state was
    /// written by the start itself; no handle is returned).
    #[error("cross-city AMQP startup failed: {0}")]
    Amqp(#[from] lapin::Error),
    /// A worker task terminated abnormally (panic or cancellation) instead of
    /// returning its outcome. Never swallowed: shutdown reports it.
    #[error("cross-city worker join failed: {0}")]
    WorkerJoin(#[from] tokio::task::JoinError),
    #[error("cross-city transport storage failed: {0}")]
    TransportRepository(#[from] astral_db::CrossCityTransportRepositoryError),
    #[error("cross-city storage outcome unknown: {0}")]
    StorageOutcomeUnknown(#[from] sqlx::Error),
    #[error("cross-city worker stopped: {0}")]
    WorkerStopped(&'static str),
}

fn required_env(variable: &str, label: &'static str) -> Result<String, CrossCityRuntimeStartError> {
    let value = std::env::var(variable).unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CrossCityRuntimeStartError::ConfigRefused(label));
    }
    Ok(trimmed.to_owned())
}

fn parse_city_list(raw: &str) -> Result<Vec<String>, CrossCityRuntimeStartError> {
    let mut cities = Vec::new();
    for part in raw.split(',') {
        let city = part.trim();
        if city.is_empty() || city.len() > MAX_CITY_ID_LENGTH {
            return Err(CrossCityRuntimeStartError::ConfigRefused(
                "peer_city_malformed",
            ));
        }
        cities.push(city.to_owned());
    }
    if cities.is_empty() || cities.len() > 8 {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "peer_city_count_refused",
        ));
    }
    Ok(cities)
}

fn parse_bounded_usize(
    raw: &str,
    default_value: usize,
    label: &'static str,
) -> Result<usize, CrossCityRuntimeStartError> {
    if raw.trim().is_empty() {
        return Ok(default_value);
    }
    let parsed: usize = raw
        .trim()
        .parse()
        .map_err(|_| CrossCityRuntimeStartError::ConfigRefused(label))?;
    if parsed == 0 || parsed > MAX_BATCH_BOUND {
        return Err(CrossCityRuntimeStartError::ConfigRefused(label));
    }
    Ok(parsed)
}

fn parse_lease_seconds(raw: &str) -> Result<i64, CrossCityRuntimeStartError> {
    if raw.trim().is_empty() {
        return Ok(LEASE_SECONDS_DEFAULT);
    }
    let parsed: i64 = raw
        .trim()
        .parse()
        .map_err(|_| CrossCityRuntimeStartError::ConfigRefused("lease_seconds_unparsable"))?;
    if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&parsed) {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "lease_seconds_out_of_bounds",
        ));
    }
    Ok(parsed)
}

/// Strict relay tick parsing: absent/empty takes the default; every present
/// value must parse, be non-zero, and stay at or above [`MIN_RELAY_TICK_MS`].
/// An unparsable value is a typed REFUSAL, never a silent default.
fn parse_relay_tick_ms(raw: &str) -> Result<u64, CrossCityRuntimeStartError> {
    if raw.trim().is_empty() {
        return Ok(DEFAULT_RELAY_TICK_MS);
    }
    let parsed: u64 = raw
        .trim()
        .parse()
        .map_err(|_| CrossCityRuntimeStartError::ConfigRefused("relay_tick_unparsable"))?;
    if parsed == 0 {
        return Err(CrossCityRuntimeStartError::ConfigRefused("relay_tick_zero"));
    }
    if parsed < MIN_RELAY_TICK_MS {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "relay_tick_below_floor",
        ));
    }
    Ok(parsed)
}

/// Resolve the start decision from the process environment. PURE (no I/O).
/// A disabled flag yields [`CrossCityStartDecision::Disabled`]; a partial
/// enablement is a typed refusal, never a partial start.
pub fn resolve_cross_city_start_from_env(
) -> Result<CrossCityStartDecision, CrossCityRuntimeStartError> {
    let flag = std::env::var(CROSS_CITY_ENABLED_ENV).unwrap_or_default();
    match flag.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "off" | "no" => Ok(CrossCityStartDecision::Disabled),
        "1" | "true" | "on" | "yes" => {
            let home_city_id = required_env(CROSS_CITY_HOME_CITY_ENV, "home_city_id_missing")?;
            let node_id = required_env(CROSS_CITY_NODE_ID_ENV, "node_id_missing")?;
            let amqp_url = required_env(CROSS_CITY_AMQP_URL_ENV, "amqp_url_missing")?;
            let coordinator_epoch: u64 = required_env(
                CROSS_CITY_COORDINATOR_EPOCH_ENV,
                "coordinator_epoch_missing",
            )?
            .parse()
            .map_err(|_| {
                CrossCityRuntimeStartError::ConfigRefused("coordinator_epoch_unparsable")
            })?;
            if coordinator_epoch == 0 {
                return Err(CrossCityRuntimeStartError::ConfigRefused(
                    "coordinator_epoch_zero",
                ));
            }
            let peers_raw = required_env(CROSS_CITY_PEER_CITIES_ENV, "peer_cities_missing")?;
            let peer_city_ids = parse_city_list(&peers_raw)?;
            if peer_city_ids.contains(&home_city_id) {
                return Err(CrossCityRuntimeStartError::ConfigRefused(
                    "peer_list_contains_home",
                ));
            }
            let relay_batch = parse_bounded_usize(
                &std::env::var(CROSS_CITY_RELAY_BATCH_ENV).unwrap_or_default(),
                DEFAULT_RELAY_BATCH,
                "relay_batch_refused",
            )?;
            let relay_tick_ms: u64 = parse_relay_tick_ms(
                &std::env::var(CROSS_CITY_RELAY_TICK_MS_ENV).unwrap_or_default(),
            )?;
            let inbox_batch = parse_bounded_usize(
                &std::env::var(CROSS_CITY_INBOX_BATCH_ENV).unwrap_or_default(),
                DEFAULT_INBOX_BATCH,
                "inbox_batch_refused",
            )?;
            let transport_lease_seconds = parse_lease_seconds(
                &std::env::var(CROSS_CITY_TRANSPORT_LEASE_SECONDS_ENV).unwrap_or_default(),
            )?;
            Ok(CrossCityStartDecision::Enabled(Box::new(
                CrossCityRuntimeConfig {
                    home_city_id,
                    node_id,
                    coordinator_epoch,
                    amqp_url,
                    peer_city_ids,
                    relay_batch,
                    relay_tick_ms,
                    inbox_batch,
                    transport_lease_seconds,
                },
            )))
        }
        _ => Err(CrossCityRuntimeStartError::ConfigRefused(
            "enabled_flag_invalid",
        )),
    }
}

/// The durable queue name (and direct routing key) of one city.
pub fn cross_city_queue_name(city_id: &str) -> Result<String, CrossCityRuntimeStartError> {
    if city_id.is_empty()
        || city_id.len() > MAX_CITY_ID_LENGTH
        || city_id
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "queue_city_malformed",
        ));
    }
    Ok(format!("{CROSS_CITY_QUEUE_PREFIX}.{city_id}"))
}

fn cross_city_queue_arguments(queue: &str) -> FieldTable {
    let mut arguments = FieldTable::default();
    arguments.insert(
        "x-dead-letter-exchange".into(),
        LongString::from(CROSS_CITY_DLX_EXCHANGE).into(),
    );
    arguments.insert(
        "x-dead-letter-routing-key".into(),
        LongString::from(format!("{queue}.dlq")).into(),
    );
    arguments
}

fn classify_cross_city_confirmation(
    confirmation: Confirmation,
) -> Result<(), CrossCityTransportDispatchError> {
    match confirmation {
        Confirmation::Ack(None) => Ok(()),
        Confirmation::Ack(Some(_)) | Confirmation::Nack(Some(_)) => {
            Err(CrossCityTransportDispatchError {
                code: "CROSS_CITY_AMQP_UNROUTABLE",
            })
        }
        Confirmation::Nack(None) => Err(CrossCityTransportDispatchError {
            code: "CROSS_CITY_AMQP_CONFIRM_NACKED",
        }),
        Confirmation::NotRequested => Err(CrossCityTransportDispatchError {
            code: "CROSS_CITY_AMQP_CONFIRM_NOT_REQUESTED",
        }),
    }
}

// ---------------------------------------------------------------------------
// Production adapters (real broker; no mocks)
// ---------------------------------------------------------------------------

/// REAL AMQP transport (lapin): a confirm-selected publisher channel; the
/// destination city's durable queue receives the exact wire bytes.
#[derive(Clone)]
pub struct CrossCityAmqpTransport {
    publisher: lapin::Channel,
}

impl CrossCityAmqpTransport {
    async fn connect(url: &str) -> Result<Self, CrossCityRuntimeStartError> {
        let connection =
            lapin::Connection::connect(url, lapin::ConnectionProperties::default()).await?;
        let publisher = connection.create_channel().await?;
        for exchange in [CROSS_CITY_EXCHANGE, CROSS_CITY_DLX_EXCHANGE] {
            publisher
                .exchange_declare(
                    exchange.into(),
                    lapin::ExchangeKind::Direct,
                    ExchangeDeclareOptions {
                        durable: true,
                        ..ExchangeDeclareOptions::default()
                    },
                    FieldTable::default(),
                )
                .await?;
        }
        publisher
            .confirm_select(ConfirmSelectOptions::default())
            .await?;
        Ok(Self { publisher })
    }

    /// Declare the durable home queue and bind it to the exchange (routing
    /// key = queue name). Returns the queue name for the consumer.
    async fn declare_home_queue(
        &self,
        home_city_id: &str,
    ) -> Result<String, CrossCityRuntimeStartError> {
        let queue = cross_city_queue_name(home_city_id)?;
        let dead_letter_queue = format!("{queue}.dlq");
        self.publisher
            .queue_declare(
                dead_letter_queue.clone().into(),
                QueueDeclareOptions {
                    durable: true,
                    ..QueueDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await?;
        self.publisher
            .queue_bind(
                dead_letter_queue.clone().into(),
                CROSS_CITY_DLX_EXCHANGE.into(),
                dead_letter_queue.into(),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
        self.publisher
            .queue_declare(
                queue.clone().into(),
                QueueDeclareOptions {
                    durable: true,
                    ..QueueDeclareOptions::default()
                },
                cross_city_queue_arguments(&queue),
            )
            .await?;
        self.publisher
            .queue_bind(
                queue.clone().into(),
                CROSS_CITY_EXCHANGE.into(),
                queue.clone().into(),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
        Ok(queue)
    }
}

#[async_trait]
impl CrossCityMessageTransport for CrossCityAmqpTransport {
    async fn send(
        &self,
        message: &CrossCityOutboundMessage,
    ) -> Result<(), CrossCityTransportDispatchError> {
        let routing_key = cross_city_queue_name(&message.destination_city_id).map_err(|_| {
            CrossCityTransportDispatchError {
                code: "CROSS_CITY_QUEUE_NAME_REFUSED",
            }
        })?;
        let publish = async {
            self.publisher
                .basic_publish(
                    CROSS_CITY_EXCHANGE.into(),
                    routing_key.into(),
                    BasicPublishOptions {
                        mandatory: true,
                        ..BasicPublishOptions::default()
                    },
                    message.payload.as_slice(),
                    BasicProperties::default()
                        .with_delivery_mode(2)
                        .with_message_id(message.message_id.as_str().into()),
                )
                .await
                .map_err(|_| CrossCityTransportDispatchError {
                    code: "CROSS_CITY_AMQP_PUBLISH_UNKNOWN",
                })?
                .await
                .map_err(|_| CrossCityTransportDispatchError {
                    code: "CROSS_CITY_AMQP_CONFIRM_FAILED",
                })
        };
        let confirmed = tokio::time::timeout(CROSS_CITY_PUBLISH_DEADLINE, publish)
            .await
            .map_err(|_| CrossCityTransportDispatchError {
                code: "CROSS_CITY_AMQP_CONFIRM_TIMEOUT",
            })??;
        classify_cross_city_confirmation(confirmed)
    }
}

/// Bounded observation sink (ring buffer + tracing). The DURABLE audit trail
/// of the cross-city subsystem is the set of durable rows themselves — votes
/// with their replay reservations, commit receipts, activation-mint records —
/// each carrying the stable operation/message ids; this sink only makes the
/// correlated events observable.
#[derive(Default)]
pub struct CrossCityObservabilityAuditSink {
    recent: std::sync::Mutex<VecDeque<CrossCityCoordinatorAuditEvent>>,
}

impl CrossCityObservabilityAuditSink {
    const CAPACITY: usize = 256;

    /// Bounded snapshot of the most recent events.
    pub fn snapshot(&self) -> Vec<CrossCityCoordinatorAuditEvent> {
        self.recent
            .lock()
            .expect("audit ring lock")
            .iter()
            .cloned()
            .collect()
    }
}

#[async_trait]
impl CrossCityCoordinatorAuditSink for CrossCityObservabilityAuditSink {
    async fn record(&self, event: CrossCityCoordinatorAuditEvent) {
        tracing::info!(
            target: "cross_city_runtime",
            event_code = event.event_code,
            operation_id = event.operation_id.as_deref().unwrap_or("-"),
            message_id = event.message_id.as_deref().unwrap_or("-"),
            city_id = event.city_id.as_deref().unwrap_or("-"),
            detail = %event.detail,
            "cross-city audit"
        );
        let mut ring = self.recent.lock().expect("audit ring lock");
        if ring.len() >= Self::CAPACITY {
            ring.pop_front();
        }
        ring.push_back(event);
    }
}

// ---------------------------------------------------------------------------
// Wire envelope (identity re-derived and verified on receive)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CrossCityWireEnvelope {
    version: u8,
    operation_id: String,
    phase: String,
    source_city_id: String,
    destination_city_id: String,
}

#[derive(Debug, Clone, PartialEq)]
struct DecodedWire {
    identity: CrossCityMessageIdentity,
    payload: Vec<u8>,
}

fn seal_outbound_wire(grant: &CrossCityOutboxLeaseGrant) -> Vec<u8> {
    let envelope = CrossCityWireEnvelope {
        version: WIRE_ENVELOPE_VERSION,
        operation_id: grant.identity.operation_id.clone(),
        phase: grant.identity.phase.as_str().to_owned(),
        source_city_id: grant.identity.source_city_id.clone(),
        destination_city_id: grant.identity.destination_city_id.clone(),
    };
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap_or_default();
    let mut wire = Vec::with_capacity(4 + envelope_bytes.len() + grant.payload.len());
    wire.extend_from_slice(&(envelope_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&envelope_bytes);
    wire.extend_from_slice(&grant.payload);
    wire
}

fn split_inbound_wire(
    raw: &[u8],
    expected_destination: &str,
) -> Result<DecodedWire, CrossCityRuntimeStartError> {
    if raw.len() < 4 {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "wire_envelope_too_short",
        ));
    }
    let envelope_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if envelope_len == 0 || envelope_len > raw.len().saturating_sub(4) {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "wire_envelope_length_invalid",
        ));
    }
    let envelope: CrossCityWireEnvelope = serde_json::from_slice(&raw[4..4 + envelope_len])
        .map_err(|_| CrossCityRuntimeStartError::ConfigRefused("wire_envelope_unparsable"))?;
    if envelope.version != WIRE_ENVELOPE_VERSION {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "wire_envelope_version_unknown",
        ));
    }
    if envelope.destination_city_id != expected_destination {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "wire_destination_not_home",
        ));
    }
    let phase = CrossCityMessagePhase::parse_str(&envelope.phase)
        .map_err(|_| CrossCityRuntimeStartError::ConfigRefused("wire_phase_unknown"))?;
    let identity = CrossCityMessageIdentity::new(
        &envelope.operation_id,
        phase,
        &envelope.source_city_id,
        &envelope.destination_city_id,
    )
    .map_err(|_| CrossCityRuntimeStartError::ConfigRefused("wire_identity_refused"))?;
    Ok(DecodedWire {
        identity,
        payload: raw[4 + envelope_len..].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Runtime handle (RAII) and the single start entry point
// ---------------------------------------------------------------------------

/// RAII handle of the started runtime. Dropping it signals shutdown to every
/// worker; [`CrossCityRuntimeHandle::shutdown`] joins with a bounded
/// timeout. The outer runtime holds this until shutdown.
#[derive(Debug)]
pub struct CrossCityRuntimeHandle {
    active: bool,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<Result<&'static str, CrossCityRuntimeStartError>>>,
}

/// Bounded shutdown report. Deadline expiry aborts unfinished workers; their
/// durable outcomes remain unknown until reconciled.
#[derive(Debug)]
pub struct CrossCityRuntimeShutdownReport {
    pub completed_within_bound: bool,
    pub outcomes: Vec<Result<&'static str, CrossCityRuntimeStartError>>,
}

impl CrossCityRuntimeHandle {
    fn dormant() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            active: false,
            shutdown,
            tasks: Vec::new(),
        }
    }

    /// Whether any worker was started (false when the flag was off).
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Wait until a required worker stops while the runtime is serving.
    pub async fn wait_for_failure(&mut self) -> CrossCityRuntimeStartError {
        if !self.active {
            return std::future::pending().await;
        }
        if self.tasks.is_empty() {
            return CrossCityRuntimeStartError::WorkerStopped("required_workers_missing");
        }
        let (outcome, index, _) = futures_util::future::select_all(&mut self.tasks).await;
        drop(self.tasks.remove(index));
        let _ = self.shutdown.send(true);
        match outcome {
            Ok(Ok(reason)) => CrossCityRuntimeStartError::WorkerStopped(reason),
            Ok(Err(error)) => error,
            Err(error) => error.into(),
        }
    }

    /// Signal shutdown and join within the caller's budget. Unfinished workers
    /// are aborted; neither cancellation nor a timeout proves durable rollback.
    pub async fn shutdown(mut self, bound: Duration) -> CrossCityRuntimeShutdownReport {
        let _ = self.shutdown.send(true);
        let mut tasks = std::mem::take(&mut self.tasks);
        let joined = tokio::time::timeout(bound, async {
            let mut outcomes = Vec::with_capacity(tasks.len());
            for task in &mut tasks {
                outcomes.push(task.await);
            }
            outcomes
        })
        .await;
        match joined {
            Ok(joined) => CrossCityRuntimeShutdownReport {
                completed_within_bound: true,
                outcomes: joined
                    .into_iter()
                    .map(|outcome| outcome.unwrap_or_else(|error| Err(error.into())))
                    .collect(),
            },
            Err(_) => {
                for task in &tasks {
                    task.abort();
                }
                CrossCityRuntimeShutdownReport {
                    completed_within_bound: false,
                    outcomes: Vec::new(),
                }
            }
        }
    }
}

impl Drop for CrossCityRuntimeHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Start (or refuse to start) the cross-city runtime. A disabled decision
/// returns a DORMANT handle with ZERO I/O; an enabled decision performs the
/// one-shot durable startup admission (both registries present) BEFORE the
/// broker connection, then spawns the bounded workers. Call ONCE per
/// process; the caller holds the handle (RAII) until shutdown.
pub async fn start_cross_city_runtime(
    pool: MySqlPool,
    decision: CrossCityStartDecision,
) -> Result<CrossCityRuntimeHandle, CrossCityRuntimeStartError> {
    let Some(config) = (match &decision {
        CrossCityStartDecision::Disabled => None,
        CrossCityStartDecision::Enabled(config) => Some(config.as_ref().clone()),
    }) else {
        // Default-off: NOTHING is read, connected, or spawned.
        return Ok(CrossCityRuntimeHandle::dormant());
    };

    // ── One-shot durable startup admission (fail-closed, no side effects) ──
    let node_keys = load_cross_city_node_key_snapshot(&pool).await?;
    if node_keys.usable_count() == 0 {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "node_key_registry_missing",
        ));
    }
    let scopes: Vec<CrossCityAuthorityScopeEntry> =
        load_cross_city_authority_scope_registry(&pool).await?;
    if !scopes.iter().any(|scope| scope.authoritative) {
        return Err(CrossCityRuntimeStartError::ConfigRefused(
            "authority_scope_registry_missing",
        ));
    }

    // ── Real broker topology (lapin, durable, confirm-selected) ────────────
    let transport = CrossCityAmqpTransport::connect(&config.amqp_url).await?;
    let home_queue = transport.declare_home_queue(&config.home_city_id).await?;
    let consumer_channel = transport.publisher.clone();
    consumer_channel
        .basic_qos(config.inbox_batch as u16, BasicQosOptions::default())
        .await?;
    let consumer = consumer_channel
        .basic_consume(
            home_queue.into(),
            "cross_city_inbound_v1".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    // ── Coordinator assembly (explicit fixed providers) ─────────────────────
    let audit = Arc::new(CrossCityObservabilityAuditSink::default());
    let coordinator = Arc::new(CrossCityCoordinator::try_new(
        pool.clone(),
        &config.home_city_id,
        config.coordinator_epoch,
        Arc::new(node_keys),
        Arc::new(transport.clone()),
        audit.clone(),
    )?);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let lease_owner = format!(
        "cross-city-runtime:{}:{}",
        config.node_id,
        uuid::Uuid::new_v4().simple()
    );

    let relay_handle = tokio::spawn(outbox_relay_worker(
        pool.clone(),
        transport,
        audit.clone(),
        OutboxWorkerConfig {
            lease_owner: format!("{lease_owner}:outbox"),
            lease_seconds: config.transport_lease_seconds,
            batch: config.relay_batch,
            tick: Duration::from_millis(config.relay_tick_ms),
        },
        shutdown_rx.clone(),
    ));
    let inbound_handle = tokio::spawn(inbound_worker(
        pool.clone(),
        consumer,
        coordinator,
        audit,
        InboundWorkerConfig {
            home_city_id: config.home_city_id.clone(),
            lease_owner: format!("{lease_owner}:inbox"),
            lease_seconds: config.transport_lease_seconds,
        },
        shutdown_rx.clone(),
    ));

    Ok(CrossCityRuntimeHandle {
        active: true,
        shutdown: shutdown_tx,
        tasks: vec![relay_handle, inbound_handle],
    })
}

// ---------------------------------------------------------------------------
// Workers (tick/delivery driven, batch-bounded, shutdown-aware)
// ---------------------------------------------------------------------------

type WorkerOutcome = Result<&'static str, CrossCityRuntimeStartError>;

#[derive(Debug)]
struct OutboxWorkerConfig {
    lease_owner: String,
    lease_seconds: i64,
    batch: usize,
    tick: Duration,
}

#[derive(Debug)]
struct InboundWorkerConfig {
    home_city_id: String,
    lease_owner: String,
    lease_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboxHandlingOutcome {
    Processed,
    Refused(&'static str),
    Unknown(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboxSettlement {
    Ack,
    Retry,
}

fn refusal_settlement(outcome: CrossCityTransportFailureOutcome) -> InboxSettlement {
    match outcome {
        CrossCityTransportFailureOutcome::RetryScheduled { .. } => InboxSettlement::Retry,
        CrossCityTransportFailureOutcome::Quarantined { .. } => InboxSettlement::Ack,
    }
}

#[async_trait]
trait InboxStateTransaction: Send {
    type Proof: Sync;

    async fn persist(
        &mut self,
        proof: &Self::Proof,
        outcome: InboxHandlingOutcome,
    ) -> Result<InboxSettlement, CrossCityRuntimeStartError>;

    async fn commit(self) -> Result<(), CrossCityRuntimeStartError>;
}

#[async_trait]
impl InboxStateTransaction for sqlx::Transaction<'_, sqlx::MySql> {
    type Proof = CrossCityTransportLeaseProof;

    async fn persist(
        &mut self,
        proof: &Self::Proof,
        outcome: InboxHandlingOutcome,
    ) -> Result<InboxSettlement, CrossCityRuntimeStartError> {
        match outcome {
            InboxHandlingOutcome::Processed => {
                mark_inbox_processed_in_tx(self, proof).await?;
                Ok(InboxSettlement::Ack)
            }
            InboxHandlingOutcome::Refused(reason) => Ok(refusal_settlement(
                fail_inbox_in_tx(self, proof, reason).await?,
            )),
            InboxHandlingOutcome::Unknown(reason) => {
                mark_inbox_process_in_doubt_in_tx(self, proof, reason).await?;
                Ok(InboxSettlement::Ack)
            }
        }
    }

    async fn commit(self) -> Result<(), CrossCityRuntimeStartError> {
        sqlx::Transaction::commit(self).await?;
        Ok(())
    }
}

async fn commit_inbox_handling<T: InboxStateTransaction>(
    mut transaction: T,
    proof: &T::Proof,
    outcome: InboxHandlingOutcome,
) -> Result<InboxSettlement, CrossCityRuntimeStartError> {
    let settlement = transaction.persist(proof, outcome).await?;
    transaction.commit().await?;
    Ok(settlement)
}

fn inbound_storage_is_unknown(error: &CrossCityCoordinatorError) -> bool {
    use astral_db::{CrossCityRepositoryError, CrossCityRuntimeRepositoryError};
    matches!(
        error,
        CrossCityCoordinatorError::UnknownStorage(_)
            | CrossCityCoordinatorError::Repository(CrossCityRepositoryError::Query(_))
            | CrossCityCoordinatorError::RuntimeRepository(CrossCityRuntimeRepositoryError::Query(
                _
            ))
            | CrossCityCoordinatorError::RuntimeRepository(
                CrossCityRuntimeRepositoryError::Repository(CrossCityRepositoryError::Query(_))
            )
            | CrossCityCoordinatorError::TransportRepository(
                astral_db::CrossCityTransportRepositoryError::Query(_)
            )
            | CrossCityCoordinatorError::ConfigRefused("vote_commit_unknown")
    )
}

fn dispatch_is_known_failure(error: &CrossCityTransportDispatchError) -> bool {
    matches!(
        error.code,
        "CROSS_CITY_QUEUE_NAME_REFUSED"
            | "CROSS_CITY_AMQP_UNROUTABLE"
            | "CROSS_CITY_AMQP_CONFIRM_NACKED"
    )
}

/// OUTBOUND: claim (durable lease) → REAL publish (broker confirm) → durable
/// terminal mark in its OWN transaction. Known failure → attempt budget;
/// unknown outcome → PUBLISH_IN_DOUBT. Nothing is ever marked SUCCEEDED
/// before the broker confirm, and no network call runs inside a transaction.
async fn outbox_relay_worker(
    pool: MySqlPool,
    transport: CrossCityAmqpTransport,
    audit: Arc<CrossCityObservabilityAuditSink>,
    worker: OutboxWorkerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> WorkerOutcome {
    let mut interval = tokio::time::interval(worker.tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok("outbox_relay_stopped"),
            _ = interval.tick() => {
                for _ in 0..worker.batch {
                    let grant = {
                        let mut tx = pool.begin().await?;
                        let claimed = claim_next_outbox_in_tx(
                            &mut tx,
                            &worker.lease_owner,
                            worker.lease_seconds,
                        )
                        .await?;
                        tx.commit().await?;
                        claimed
                    };
                    let Some(grant) = grant else { break };

                    // 2. Lease proof for the terminal mark.
                    let proof = CrossCityTransportLeaseProof {
                        message_id: grant.message_id.clone(),
                        lease_owner: grant.lease_owner.clone(),
                        lease_token: grant.lease_token.clone(),
                    };

                    // 3. REAL send with publisher confirm (outside any tx).
                    let wire = seal_outbound_wire(&grant);
                    let message = CrossCityOutboundMessage {
                        message_id: grant.message_id.clone(),
                        operation_id: grant.identity.operation_id.clone(),
                        phase: grant.identity.phase,
                        source_city_id: grant.identity.source_city_id.clone(),
                        destination_city_id: grant.identity.destination_city_id.clone(),
                        payload: wire,
                    };
                    let dispatch = transport.send(&message).await;

                    // 4. Durable outcome (own short tx; never SUCCEEDED
                    //    before the broker confirm).
                    match dispatch {
                        Ok(()) => {
                            let mut tx = pool.begin().await?;
                            mark_outbox_succeeded_in_tx(&mut tx, &proof).await?;
                            tx.commit().await?;
                            audit
                                .record(CrossCityCoordinatorAuditEvent::new(
                                    "cross_city_message_sent",
                                    Some(grant.identity.operation_id.clone()),
                                    Some(grant.message_id.clone()),
                                    Some(grant.identity.destination_city_id.clone()),
                                    grant.identity.phase.as_str(),
                                ))
                                .await;
                        }
                        Err(dispatch_error) => {
                            let mut tx = pool.begin().await?;
                            if dispatch_is_known_failure(&dispatch_error) {
                                fail_outbox_in_tx(&mut tx, &proof, dispatch_error.code).await?;
                            } else {
                                mark_outbox_publish_in_doubt_in_tx(
                                    &mut tx,
                                    &proof,
                                    dispatch_error.code,
                                )
                                .await?;
                            }
                            tx.commit().await?;
                            audit
                                .record(CrossCityCoordinatorAuditEvent::new(
                                    "cross_city_relay_dispatch_refused",
                                    Some(grant.identity.operation_id.clone()),
                                    Some(grant.message_id.clone()),
                                    Some(grant.identity.destination_city_id.clone()),
                                    dispatch_error.code,
                                ))
                                .await;
                        }
                    }
                }
            }
        }
    }
}

/// INBOUND: record commit → exact delivery claim commit → coordinator handling
/// outside the transaction → durable settlement commit → ACK or requeue.
async fn inbound_worker(
    pool: MySqlPool,
    mut consumer: lapin::Consumer,
    coordinator: Arc<CrossCityCoordinator>,
    audit: Arc<CrossCityObservabilityAuditSink>,
    worker: InboundWorkerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> WorkerOutcome {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok("inbound_worker_stopped"),
            delivered = consumer.next() => {
                let delivered = delivered.ok_or(
                    CrossCityRuntimeStartError::WorkerStopped("consumer_closed"),
                )?;
                let delivery = delivered.map_err(CrossCityRuntimeStartError::Amqp)?;
                let raw = delivery.data.as_slice();

                // 1. Identity re-derivation BEFORE any durable write.
                let decoded = match split_inbound_wire(raw, &worker.home_city_id) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        audit
                            .record(CrossCityCoordinatorAuditEvent::new(
                                "cross_city_inbound_undecodable",
                                None,
                                None,
                                Some(worker.home_city_id.clone()),
                                "wire_envelope_refused",
                            ))
                            .await;
                        delivery
                            .nack(BasicNackOptions { requeue: false, ..Default::default() })
                            .await?;
                        continue;
                    }
                };

                // 2. Durable inbox BEFORE ack (idempotent by message id).
                let insert = CrossCityInboxRecordInsert {
                    message_id: decoded.identity.message_id.clone(),
                    operation_id: decoded.identity.operation_id.clone(),
                    phase: decoded.identity.phase,
                    source_city_id: decoded.identity.source_city_id.clone(),
                    destination_city_id: decoded.identity.destination_city_id.clone(),
                    payload: raw.to_vec(),
                };
                let mut tx = pool.begin().await?;
                let recorded_outcome = record_inbox_in_tx(&mut tx, &insert).await?;
                tx.commit().await?;

                // Idempotent replay of a PRIOR delivery: when the durable row
                // already reached a state the worker path can NEVER advance
                // (SUCCEEDED is terminal; QUARANTINED/IN_DOUBT are held for
                // the operator/reconcile paths by the closed state machine),
                // broker redelivery cannot help — acknowledge with an honest
                // audit event. The durable row (digest + last_error) remains
                // the evidence; nothing is re-processed and nothing is
                // fabricated. PENDING/LEASED rows fall through to the claim
                // loop below.
                if let CrossCityInboxInsertOutcome::IdempotentExisting(existing) = recorded_outcome {
                    if matches!(
                        existing.status,
                        CrossCityDeliveryStatus::Succeeded
                            | CrossCityDeliveryStatus::Quarantined
                            | CrossCityDeliveryStatus::InDoubt
                    ) {
                        audit
                            .record(CrossCityCoordinatorAuditEvent::new(
                                "cross_city_inbound_redelivery_closed",
                                Some(decoded.identity.operation_id.clone()),
                                Some(decoded.identity.message_id.clone()),
                                Some(decoded.identity.source_city_id.clone()),
                                existing.status.as_str(),
                            ))
                            .await;
                        delivery.ack(BasicAckOptions::default()).await?;
                        continue;
                    }
                }

                let claim = {
                    let mut tx = pool.begin().await?;
                    let claimed = claim_inbox_message_in_tx(
                        &mut tx,
                        &decoded.identity.message_id,
                        &worker.lease_owner,
                        worker.lease_seconds,
                    )
                    .await?;
                    tx.commit().await?;
                    claimed
                };
                let Some(claim) = claim else {
                    tokio::time::sleep(CROSS_CITY_REQUEUE_PAUSE).await;
                    delivery
                        .nack(BasicNackOptions { requeue: true, ..Default::default() })
                        .await?;
                    continue;
                };
                let proof = CrossCityTransportLeaseProof {
                    message_id: claim.message_id.clone(),
                    lease_owner: claim.lease_owner.clone(),
                    lease_token: claim.lease_token.clone(),
                };
                let handled = tokio::time::timeout(
                    CROSS_CITY_HANDLE_DEADLINE,
                    handle_inbound_message(&coordinator, &audit, &claim, Some(&decoded.payload)),
                )
                .await;
                let (outcome, detail) = match handled {
                    Ok(Ok(detail)) => (InboxHandlingOutcome::Processed, detail),
                    Ok(Err(error)) if inbound_storage_is_unknown(&error) => {
                        (InboxHandlingOutcome::Unknown(error.code()), error.code())
                    }
                    Ok(Err(error)) => (InboxHandlingOutcome::Refused(error.code()), error.code()),
                    Err(_) => (
                        InboxHandlingOutcome::Unknown("CROSS_CITY_HANDLE_TIMEOUT"),
                        "CROSS_CITY_HANDLE_TIMEOUT",
                    ),
                };
                let settlement = commit_inbox_handling(pool.begin().await?, &proof, outcome).await?;
                audit
                    .record(CrossCityCoordinatorAuditEvent::new(
                        "cross_city_inbound_settled",
                        Some(claim.operation_id.clone()),
                        Some(claim.message_id.clone()),
                        Some(claim.source_city_id.clone()),
                        detail,
                    ))
                    .await;
                match settlement {
                    InboxSettlement::Ack => {
                        delivery.ack(BasicAckOptions::default()).await?;
                    }
                    InboxSettlement::Retry => {
                        tokio::time::sleep(CROSS_CITY_REQUEUE_PAUSE).await;
                        delivery
                            .nack(BasicNackOptions { requeue: true, ..Default::default() })
                            .await?;
                    }
                }
            }
        }
    }
}

/// Dispatch the claimed delivery through the coordinator. No recovery path
/// invents a missing body or treats transport liveness as signed evidence.
async fn handle_inbound_message(
    coordinator: &CrossCityCoordinator,
    audit: &Arc<CrossCityObservabilityAuditSink>,
    claim: &CrossCityInboxLeaseGrant,
    body: Option<&[u8]>,
) -> Result<&'static str, CrossCityCoordinatorError> {
    match claim.phase {
        CrossCityMessagePhase::Vote => {
            let evidence: ZeroDecisionEvidence = serde_json::from_slice(body.ok_or(
                CrossCityCoordinatorError::ConfigRefused("vote_body_unavailable"),
            )?)
            .map_err(|_| CrossCityCoordinatorError::ConfigRefused("vote_body_unparsable"))?;
            let admission = coordinator
                .admit_vote(&claim.operation_id, &evidence, wall_unix_seconds())
                .await;
            if admission.is_recorded() {
                // The agreement seal is the guarded next step of EVERY
                // recorded vote: derived ONLY from the durable,
                // reservation-proven votes, idempotent once sealed, and a
                // typed refusal until both cities' Allow votes are derivable
                // (the vote stays durably recorded either way).
                match coordinator
                    .seal_agreement(&claim.operation_id, wall_unix_seconds())
                    .await
                {
                    Ok(CrossCityAgreementSealOutcome::Sealed { agreement_digest }) => {
                        audit
                            .record(CrossCityCoordinatorAuditEvent::new(
                                "cross_city_agreement_sealed",
                                Some(claim.operation_id.clone()),
                                None,
                                Some(claim.source_city_id.clone()),
                                &format!("agreement_digest={agreement_digest}"),
                            ))
                            .await;
                    }
                    Ok(CrossCityAgreementSealOutcome::AlreadySealed) => {}
                    Err(seal_error) => {
                        audit
                            .record(CrossCityCoordinatorAuditEvent::new(
                                "cross_city_agreement_seal_refused",
                                Some(claim.operation_id.clone()),
                                None,
                                Some(claim.source_city_id.clone()),
                                seal_error.code(),
                            ))
                            .await;
                        if inbound_storage_is_unknown(&seal_error) {
                            return Err(seal_error);
                        }
                    }
                }
                Ok("VOTE_RECORDED")
            } else {
                match admission {
                    CrossCityVoteAdmission::Unknown => Err(
                        CrossCityCoordinatorError::ConfigRefused("vote_commit_unknown"),
                    ),
                    CrossCityVoteAdmission::Refused(error) => Err(error),
                    CrossCityVoteAdmission::Quarantined(error) => Err(error.into()),
                    CrossCityVoteAdmission::GateBlocked => {
                        Err(CrossCityCoordinatorError::GateBlocked)
                    }
                    CrossCityVoteAdmission::Recorded(_) => unreachable!(),
                }
            }
        }
        CrossCityMessagePhase::CommitConfirmed => {
            #[derive(serde::Deserialize)]
            struct CommitBody {
                evidence: ZeroDecisionEvidence,
                target_generation: u64,
                revoke_fence: u64,
                coordinator_epoch: u64,
            }
            let body: CommitBody = serde_json::from_slice(body.ok_or(
                CrossCityCoordinatorError::ConfigRefused("commit_body_unavailable"),
            )?)
            .map_err(|_| CrossCityCoordinatorError::ConfigRefused("commit_body_unparsable"))?;
            let meta = CrossCityCommitReceiptMeta {
                target_generation: body.target_generation,
                revoke_fence: body.revoke_fence,
                coordinator_epoch: body.coordinator_epoch,
            };
            coordinator
                .record_commit_receipt(
                    &claim.operation_id,
                    &body.evidence,
                    &meta,
                    wall_unix_seconds(),
                )
                .await?;
            // ONE bounded activation attempt per confirmed receipt: the mint
            // itself REFUSES unless BOTH cities' durable commit receipts are
            // complete — no confirm, cache, or boolean can substitute.
            match coordinator
                .activate_operation(&claim.operation_id, wall_unix_seconds())
                .await
            {
                Ok(_) => {}
                Err(error) if inbound_storage_is_unknown(&error) => {
                    let doubt = coordinator
                        .mark_unknown_outcome_in_doubt(
                            &claim.operation_id,
                            CrossCityOperationState::Activating,
                            "activation_mint_storage_unknown",
                            wall_unix_seconds(),
                        )
                        .await;
                    let detail = match doubt {
                        Ok(state) => state.as_str().to_owned(),
                        Err(ref failure) => failure.code().to_owned(),
                    };
                    audit
                        .record(CrossCityCoordinatorAuditEvent::new(
                            "cross_city_operation_unknown_collapsed_in_doubt",
                            Some(claim.operation_id.clone()),
                            None,
                            Some(claim.source_city_id.clone()),
                            &detail,
                        ))
                        .await;
                    return Err(error);
                }
                Err(refusal) => {
                    // Not yet mintable (e.g. only one city's receipt is
                    // durably recorded): the receipts stay durable and the
                    // NEXT confirmed receipt retries this bounded mint.
                    audit
                        .record(CrossCityCoordinatorAuditEvent::new(
                            "cross_city_activation_mint_refused",
                            Some(claim.operation_id.clone()),
                            None,
                            Some(claim.source_city_id.clone()),
                            refusal.code(),
                        ))
                        .await;
                }
            }
            Ok("COMMIT_RECEIPT_RECORDED")
        }
        // PREPARE / ACTIVATE / RECONCILE are coordination evidence only: the
        // durable record IS the complete honest handling available without
        // forging a source mutation (the apply belongs to the separately
        // reviewed source-mutation slice).
        CrossCityMessagePhase::Prepare
        | CrossCityMessagePhase::Activate
        | CrossCityMessagePhase::Reconcile => Ok("COORDINATION_EVIDENCE_RECORDED"),
    }
}

fn wall_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests (pure: no DB connection, no network, no MQ, no spawned worker unless
// the RAII lifecycle test itself spawns and joins one)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Pure config parsing ---------------------------------------------------

    #[test]
    fn relay_tick_parsing_is_strict_and_bounded() {
        // absent/empty → default.
        assert_eq!(parse_relay_tick_ms("").unwrap(), DEFAULT_RELAY_TICK_MS);
        assert_eq!(parse_relay_tick_ms("  ").unwrap(), DEFAULT_RELAY_TICK_MS);
        assert_eq!(parse_relay_tick_ms("500").unwrap(), 500);
        // Present values must parse (never silently default).
        assert!(matches!(
            parse_relay_tick_ms("abc"),
            Err(CrossCityRuntimeStartError::ConfigRefused(
                "relay_tick_unparsable"
            ))
        ));
        assert!(matches!(
            parse_relay_tick_ms("0"),
            Err(CrossCityRuntimeStartError::ConfigRefused("relay_tick_zero"))
        ));
        assert!(matches!(
            parse_relay_tick_ms("9"),
            Err(CrossCityRuntimeStartError::ConfigRefused(
                "relay_tick_below_floor"
            ))
        ));
        assert_eq!(parse_relay_tick_ms("10").unwrap(), 10);
    }

    #[test]
    fn lease_seconds_are_independent_of_the_relay_tick() {
        assert_eq!(parse_lease_seconds("").unwrap(), LEASE_SECONDS_DEFAULT);
        assert!(matches!(
            parse_lease_seconds("4"),
            Err(CrossCityRuntimeStartError::ConfigRefused(
                "lease_seconds_out_of_bounds"
            ))
        ));
        assert!(matches!(
            parse_lease_seconds("301"),
            Err(CrossCityRuntimeStartError::ConfigRefused(
                "lease_seconds_out_of_bounds"
            ))
        ));
        assert_eq!(parse_lease_seconds("30").unwrap(), 30);
    }

    #[test]
    fn queue_names_are_prefixed_durable_and_validated() {
        assert_eq!(
            cross_city_queue_name("city-alpha").unwrap(),
            "authorization.cross_city.v1.queue.city-alpha"
        );
        for malformed in ["", " city", "city\n", &"x".repeat(192)] {
            assert!(cross_city_queue_name(malformed).is_err());
        }
    }

    // -- Wire envelope ----------------------------------------------------------

    fn compose_wire(
        version: u8,
        operation_id: &str,
        phase: &str,
        source_city_id: &str,
        destination_city_id: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        let envelope = CrossCityWireEnvelope {
            version,
            operation_id: operation_id.to_owned(),
            phase: phase.to_owned(),
            source_city_id: source_city_id.to_owned(),
            destination_city_id: destination_city_id.to_owned(),
        };
        let envelope_bytes = serde_json::to_vec(&envelope).expect("envelope serializes");
        let mut wire = Vec::with_capacity(4 + envelope_bytes.len() + payload.len());
        wire.extend_from_slice(&(envelope_bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(&envelope_bytes);
        wire.extend_from_slice(payload);
        wire
    }

    #[test]
    fn inbound_wire_round_trips_identity_and_payload_exactly() {
        let wire = compose_wire(
            WIRE_ENVELOPE_VERSION,
            "550e8400-e29b-41d4-a716-446655440000",
            "VOTE",
            "city-alpha",
            "city-beta",
            b"vote-body-bytes",
        );
        let decoded =
            split_inbound_wire(&wire, "city-beta").expect("home-destination wire decodes");
        assert_eq!(
            decoded.identity.operation_id,
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(decoded.identity.phase, CrossCityMessagePhase::Vote);
        assert_eq!(decoded.identity.source_city_id, "city-alpha");
        assert_eq!(decoded.identity.destination_city_id, "city-beta");
        assert_eq!(decoded.payload, b"vote-body-bytes");
    }

    #[test]
    fn inbound_wire_refuses_every_malformed_shape_before_any_durable_step() {
        let home = "city-beta";
        // Too short / empty envelope / envelope longer than the wire.
        assert!(split_inbound_wire(&[0, 0], home).is_err());
        assert!(split_inbound_wire(&[0, 0, 0, 0], home).is_err());
        assert!(split_inbound_wire(&[0, 0, 0, 9, b'{', b'}'], home).is_err());
        // Unparsable envelope JSON.
        assert!(split_inbound_wire(&[0, 0, 0, 1, b'{'], home).is_err());
        // Unknown envelope version.
        let wrong_version = compose_wire(
            WIRE_ENVELOPE_VERSION + 1,
            "550e8400-e29b-41d4-a716-446655440000",
            "VOTE",
            "city-alpha",
            home,
            b"x",
        );
        assert!(split_inbound_wire(&wrong_version, home).is_err());
        // Destination is not home.
        let foreign = compose_wire(
            WIRE_ENVELOPE_VERSION,
            "550e8400-e29b-41d4-a716-446655440000",
            "VOTE",
            "city-alpha",
            "city-gamma",
            b"x",
        );
        assert!(split_inbound_wire(&foreign, home).is_err());
        // Unknown / case-drifted phase (strict parse; no case folding).
        for phase in ["VOTING", "vote", "VOTE "] {
            let drifted = compose_wire(
                WIRE_ENVELOPE_VERSION,
                "550e8400-e29b-41d4-a716-446655440000",
                phase,
                "city-alpha",
                home,
                b"x",
            );
            assert!(split_inbound_wire(&drifted, home).is_err(), "phase={phase}");
        }
    }

    // -- Start decision from env (serialized; process-global env) ---------------

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const ALL_CROSS_CITY_ENV_VARS: [&str; 10] = [
        CROSS_CITY_ENABLED_ENV,
        CROSS_CITY_HOME_CITY_ENV,
        CROSS_CITY_NODE_ID_ENV,
        CROSS_CITY_COORDINATOR_EPOCH_ENV,
        CROSS_CITY_AMQP_URL_ENV,
        CROSS_CITY_PEER_CITIES_ENV,
        CROSS_CITY_RELAY_BATCH_ENV,
        CROSS_CITY_RELAY_TICK_MS_ENV,
        CROSS_CITY_INBOX_BATCH_ENV,
        CROSS_CITY_TRANSPORT_LEASE_SECONDS_ENV,
    ];

    fn with_cross_city_env(run: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().expect("env test lock");
        for variable in ALL_CROSS_CITY_ENV_VARS {
            std::env::remove_var(variable);
        }
        run();
        for variable in ALL_CROSS_CITY_ENV_VARS {
            std::env::remove_var(variable);
        }
    }

    fn set_full_valid_enablement() {
        std::env::set_var(CROSS_CITY_ENABLED_ENV, "true");
        std::env::set_var(CROSS_CITY_HOME_CITY_ENV, "city-alpha");
        std::env::set_var(CROSS_CITY_NODE_ID_ENV, "node-01");
        std::env::set_var(CROSS_CITY_COORDINATOR_EPOCH_ENV, "1");
        std::env::set_var(CROSS_CITY_AMQP_URL_ENV, "amqp://127.0.0.1:1/%2F");
        std::env::set_var(CROSS_CITY_PEER_CITIES_ENV, "city-beta");
    }

    #[test]
    fn start_decision_is_disabled_by_default_and_by_explicit_false_values() {
        with_cross_city_env(|| {
            assert_eq!(
                resolve_cross_city_start_from_env().unwrap(),
                CrossCityStartDecision::Disabled,
                "absent flag must be Disabled with zero I/O"
            );
            for off in ["false", "0", "off", "no", "FALSE", "Off"] {
                std::env::set_var(CROSS_CITY_ENABLED_ENV, off);
                assert_eq!(
                    resolve_cross_city_start_from_env().unwrap(),
                    CrossCityStartDecision::Disabled,
                    "flag={off} must stay disabled"
                );
            }
        });
    }

    #[test]
    fn start_decision_refuses_invalid_flag_and_every_missing_piece() {
        with_cross_city_env(|| {
            std::env::set_var(CROSS_CITY_ENABLED_ENV, "maybe");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "enabled_flag_invalid"
                ))
            ));

            std::env::set_var(CROSS_CITY_ENABLED_ENV, "true");
            // Every required variable is refused by label when missing.
            let complete = [
                (CROSS_CITY_HOME_CITY_ENV, "city-alpha"),
                (CROSS_CITY_NODE_ID_ENV, "node-01"),
                (CROSS_CITY_COORDINATOR_EPOCH_ENV, "1"),
                (CROSS_CITY_AMQP_URL_ENV, "amqp://127.0.0.1:1/%2F"),
                (CROSS_CITY_PEER_CITIES_ENV, "city-beta"),
            ];
            for (missing, _) in complete {
                for (name, value) in complete {
                    if name != missing {
                        std::env::set_var(name, value);
                    } else {
                        std::env::remove_var(name);
                    }
                }
                let error = resolve_cross_city_start_from_env().expect_err("must refuse");
                assert!(
                    matches!(error, CrossCityRuntimeStartError::ConfigRefused(_)),
                    "missing {missing} must be a typed refusal"
                );
            }
        });
    }

    #[test]
    fn enabled_decision_parses_bounds_and_defaults_exactly_once() {
        with_cross_city_env(|| {
            set_full_valid_enablement();
            let decision = resolve_cross_city_start_from_env().expect("valid enablement");
            let CrossCityStartDecision::Enabled(config) = decision else {
                panic!("enabled flag must resolve to Enabled");
            };
            assert_eq!(config.home_city_id, "city-alpha");
            assert_eq!(config.coordinator_epoch, 1);
            assert_eq!(config.peer_city_ids, vec!["city-beta".to_owned()]);
            assert_eq!(config.relay_batch, DEFAULT_RELAY_BATCH);
            assert_eq!(config.relay_tick_ms, DEFAULT_RELAY_TICK_MS);
            assert_eq!(config.inbox_batch, DEFAULT_INBOX_BATCH);
            assert_eq!(config.transport_lease_seconds, LEASE_SECONDS_DEFAULT);
        });
    }

    #[test]
    fn relay_tick_is_never_misread_as_the_transport_lease() {
        with_cross_city_env(|| {
            set_full_valid_enablement();
            // A 1000 ms tick used to be fed into the lease parser (which
            // refuses >300) and broke startup; the lease now has its OWN
            // variable and the tick stays independent.
            std::env::set_var(CROSS_CITY_RELAY_TICK_MS_ENV, "1000");
            let decision = resolve_cross_city_start_from_env()
                .expect("a 1000ms tick must not be misread as lease seconds");
            let CrossCityStartDecision::Enabled(config) = decision else {
                panic!("enabled flag must resolve to Enabled");
            };
            assert_eq!(config.relay_tick_ms, 1000);
            assert_eq!(config.transport_lease_seconds, LEASE_SECONDS_DEFAULT);
        });
    }

    #[test]
    fn enabled_decision_refuses_malformed_values_and_peer_home_collision() {
        with_cross_city_env(|| {
            set_full_valid_enablement();
            std::env::set_var(CROSS_CITY_COORDINATOR_EPOCH_ENV, "abc");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "coordinator_epoch_unparsable"
                ))
            ));

            std::env::set_var(CROSS_CITY_COORDINATOR_EPOCH_ENV, "0");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "coordinator_epoch_zero"
                ))
            ));

            std::env::set_var(CROSS_CITY_COORDINATOR_EPOCH_ENV, "1");
            std::env::set_var(CROSS_CITY_RELAY_TICK_MS_ENV, "9");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "relay_tick_below_floor"
                ))
            ));
            std::env::set_var(CROSS_CITY_RELAY_TICK_MS_ENV, "1_000");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "relay_tick_unparsable"
                ))
            ));
            std::env::set_var(CROSS_CITY_RELAY_TICK_MS_ENV, "500");

            std::env::set_var(CROSS_CITY_TRANSPORT_LEASE_SECONDS_ENV, "4");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "lease_seconds_out_of_bounds"
                ))
            ));
            std::env::set_var(CROSS_CITY_TRANSPORT_LEASE_SECONDS_ENV, "30");

            std::env::set_var(CROSS_CITY_PEER_CITIES_ENV, "city-alpha");
            assert!(matches!(
                resolve_cross_city_start_from_env(),
                Err(CrossCityRuntimeStartError::ConfigRefused(
                    "peer_list_contains_home"
                ))
            ));
        });
    }

    // -- RAII handle lifecycle ---------------------------------------------------

    #[tokio::test]
    async fn dormant_handle_is_inactive_and_shuts_down_without_any_worker() {
        let handle = CrossCityRuntimeHandle::dormant();
        assert!(!handle.is_active());
        let report = handle.shutdown(Duration::ZERO).await;
        assert!(report.completed_within_bound);
        assert!(report.outcomes.is_empty());
    }

    #[tokio::test]
    async fn active_handle_signals_workers_and_reports_their_terminal_outcomes() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(async move {
            let mut stopped = false;
            while !stopped {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        stopped = *shutdown_rx.borrow_and_update();
                    }
                }
            }
            Ok::<&'static str, CrossCityRuntimeStartError>("outbox_relay_stopped")
        });
        let handle = CrossCityRuntimeHandle {
            active: true,
            shutdown: shutdown_tx,
            tasks: vec![worker],
        };
        assert!(handle.is_active());
        let report = handle.shutdown(Duration::from_secs(5)).await;
        assert!(report.completed_within_bound);
        assert_eq!(report.outcomes.len(), 1);
        assert!(
            matches!(report.outcomes[0], Ok("outbox_relay_stopped")),
            "worker terminal outcome must be reported"
        );
    }

    #[tokio::test]
    async fn active_handle_reports_a_worker_error_instead_of_silently_swallowing_it() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let worker = tokio::spawn(async move {
            let mut stopped = false;
            while !stopped {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        stopped = *shutdown_rx.borrow_and_update();
                    }
                }
            }
            Err::<&'static str, CrossCityRuntimeStartError>(
                CrossCityRuntimeStartError::ConfigRefused("worker_failed_synthetic"),
            )
        });
        let handle = CrossCityRuntimeHandle {
            active: true,
            shutdown: shutdown_tx,
            tasks: vec![worker],
        };
        let report = handle.shutdown(Duration::from_secs(5)).await;
        assert!(report.completed_within_bound);
        assert!(matches!(
            report.outcomes[0],
            Err(CrossCityRuntimeStartError::ConfigRefused(
                "worker_failed_synthetic"
            ))
        ));
    }

    #[derive(Clone, Copy)]
    enum TransactionFault {
        None,
        Persist,
        Commit,
    }

    struct FaultTransaction {
        fault: TransactionFault,
        settlement: InboxSettlement,
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl InboxStateTransaction for FaultTransaction {
        type Proof = ();

        async fn persist(
            &mut self,
            _proof: &Self::Proof,
            _outcome: InboxHandlingOutcome,
        ) -> Result<InboxSettlement, CrossCityRuntimeStartError> {
            self.calls.lock().unwrap().push("persist");
            if matches!(self.fault, TransactionFault::Persist) {
                return Err(CrossCityRuntimeStartError::ConfigRefused("persist_failed"));
            }
            Ok(self.settlement)
        }

        async fn commit(self) -> Result<(), CrossCityRuntimeStartError> {
            self.calls.lock().unwrap().push("commit");
            if matches!(self.fault, TransactionFault::Commit) {
                return Err(sqlx::Error::RowNotFound.into());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn inbox_persist_failure_never_commits_or_returns_a_settlement() {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let transaction = FaultTransaction {
            fault: TransactionFault::Persist,
            settlement: InboxSettlement::Ack,
            calls: calls.clone(),
        };
        let result = commit_inbox_handling(transaction, &(), InboxHandlingOutcome::Processed).await;
        assert!(matches!(
            result,
            Err(CrossCityRuntimeStartError::ConfigRefused("persist_failed"))
        ));
        assert_eq!(*calls.lock().unwrap(), vec!["persist"]);
    }

    #[tokio::test]
    async fn inbox_commit_unknown_never_returns_ack_or_retry() {
        for settlement in [InboxSettlement::Ack, InboxSettlement::Retry] {
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let transaction = FaultTransaction {
                fault: TransactionFault::Commit,
                settlement,
                calls: calls.clone(),
            };
            let result = commit_inbox_handling(
                transaction,
                &(),
                InboxHandlingOutcome::Unknown("handling_unknown"),
            )
            .await;
            assert!(matches!(
                result,
                Err(CrossCityRuntimeStartError::StorageOutcomeUnknown(_))
            ));
            assert_eq!(*calls.lock().unwrap(), vec!["persist", "commit"]);
        }
    }

    #[tokio::test]
    async fn inbox_settlement_is_available_only_after_commit_for_every_outcome() {
        for (outcome, settlement) in [
            (InboxHandlingOutcome::Processed, InboxSettlement::Ack),
            (
                InboxHandlingOutcome::Unknown("unknown"),
                InboxSettlement::Ack,
            ),
            (
                InboxHandlingOutcome::Refused("quarantined"),
                InboxSettlement::Ack,
            ),
            (
                InboxHandlingOutcome::Refused("retryable"),
                InboxSettlement::Retry,
            ),
        ] {
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let transaction = FaultTransaction {
                fault: TransactionFault::None,
                settlement,
                calls: calls.clone(),
            };
            assert_eq!(
                commit_inbox_handling(transaction, &(), outcome)
                    .await
                    .unwrap(),
                settlement
            );
            assert_eq!(*calls.lock().unwrap(), vec!["persist", "commit"]);
        }
    }

    #[test]
    fn retryable_refusal_cannot_be_acknowledged() {
        assert_eq!(
            refusal_settlement(CrossCityTransportFailureOutcome::RetryScheduled {
                attempts: 1,
                backoff_seconds: 2,
            }),
            InboxSettlement::Retry
        );
        assert_eq!(
            refusal_settlement(CrossCityTransportFailureOutcome::Quarantined { attempts: 8 }),
            InboxSettlement::Ack
        );
    }

    #[test]
    fn publisher_confirmation_refuses_returned_messages_and_unknown_results() {
        let returned = || lapin::message::BasicReturnMessage {
            delivery: lapin::message::Delivery::mock(
                1,
                CROSS_CITY_EXCHANGE.into(),
                "city-beta".into(),
                false,
                b"body".to_vec(),
            ),
            reply_code: 312,
            reply_text: "NO_ROUTE".into(),
        };
        assert!(classify_cross_city_confirmation(Confirmation::Ack(None)).is_ok());
        for confirmation in [
            Confirmation::Ack(Some(returned())),
            Confirmation::Nack(Some(returned())),
        ] {
            let error = classify_cross_city_confirmation(confirmation).unwrap_err();
            assert_eq!(error.code, "CROSS_CITY_AMQP_UNROUTABLE");
            assert!(dispatch_is_known_failure(&error));
        }
        let nack = classify_cross_city_confirmation(Confirmation::Nack(None)).unwrap_err();
        assert!(dispatch_is_known_failure(&nack));
        let no_confirm = classify_cross_city_confirmation(Confirmation::NotRequested).unwrap_err();
        assert!(!dispatch_is_known_failure(&no_confirm));
        for code in [
            "CROSS_CITY_AMQP_PUBLISH_UNKNOWN",
            "CROSS_CITY_AMQP_CONFIRM_FAILED",
            "CROSS_CITY_AMQP_CONFIRM_TIMEOUT",
        ] {
            assert!(!dispatch_is_known_failure(
                &CrossCityTransportDispatchError { code }
            ));
        }
    }

    #[test]
    fn home_queue_dead_letters_use_durable_named_routing() {
        let queue = cross_city_queue_name("city-alpha").unwrap();
        let arguments = cross_city_queue_arguments(&queue);
        assert_eq!(
            arguments.inner().get("x-dead-letter-exchange"),
            Some(&LongString::from(CROSS_CITY_DLX_EXCHANGE).into())
        );
        assert_eq!(
            arguments.inner().get("x-dead-letter-routing-key"),
            Some(&LongString::from(format!("{queue}.dlq")).into())
        );
    }

    #[test]
    fn nested_storage_errors_remain_unknown_not_retryable_refusals() {
        let errors = [
            CrossCityCoordinatorError::UnknownStorage(sqlx::Error::RowNotFound),
            CrossCityCoordinatorError::Repository(astral_db::CrossCityRepositoryError::Query(
                sqlx::Error::RowNotFound,
            )),
            CrossCityCoordinatorError::RuntimeRepository(
                astral_db::CrossCityRuntimeRepositoryError::Query(sqlx::Error::RowNotFound),
            ),
            CrossCityCoordinatorError::TransportRepository(
                astral_db::CrossCityTransportRepositoryError::Query(sqlx::Error::RowNotFound),
            ),
            CrossCityCoordinatorError::ConfigRefused("vote_commit_unknown"),
        ];
        for error in errors {
            assert!(inbound_storage_is_unknown(&error));
        }
        assert!(!inbound_storage_is_unknown(
            &CrossCityCoordinatorError::ConfigRefused("vote_body_unparsable")
        ));
    }

    #[tokio::test]
    async fn worker_failure_is_observed_before_shutdown_and_signals_siblings() {
        let (shutdown, mut sibling) = watch::channel(false);
        let worker = tokio::spawn(async {
            Err(CrossCityRuntimeStartError::WorkerStopped("consumer_closed"))
        });
        let mut handle = CrossCityRuntimeHandle {
            active: true,
            shutdown,
            tasks: vec![worker],
        };
        let error = tokio::time::timeout(Duration::from_secs(1), handle.wait_for_failure())
            .await
            .unwrap();
        assert!(matches!(
            error,
            CrossCityRuntimeStartError::WorkerStopped("consumer_closed")
        ));
        sibling.changed().await.unwrap();
        assert!(*sibling.borrow());
        assert!(handle.tasks.is_empty());
    }

    #[tokio::test]
    async fn unexpected_worker_success_is_also_a_runtime_failure() {
        let (shutdown, _) = watch::channel(false);
        let worker = tokio::spawn(async { Ok("unexpected_exit") });
        let mut handle = CrossCityRuntimeHandle {
            active: true,
            shutdown,
            tasks: vec![worker],
        };
        assert!(matches!(
            handle.wait_for_failure().await,
            CrossCityRuntimeStartError::WorkerStopped("unexpected_exit")
        ));
    }

    #[tokio::test]
    async fn shutdown_deadline_aborts_a_worker_instead_of_detaching_it() {
        struct CancellationProof(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for CancellationProof {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let (shutdown, _) = watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async {
            let _proof = CancellationProof(Some(stopped_tx));
            started_tx.send(()).unwrap();
            std::future::pending::<WorkerOutcome>().await
        });
        started_rx.await.unwrap();
        let handle = CrossCityRuntimeHandle {
            active: true,
            shutdown,
            tasks: vec![worker],
        };
        let report = handle.shutdown(Duration::from_millis(20)).await;
        assert!(!report.completed_within_bound);
        tokio::time::timeout(Duration::from_secs(1), stopped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn runtime_source_preserves_commit_gates_and_transport_options() {
        let source = production_source();
        let inbound = source
            .split_once("async fn inbound_worker(")
            .unwrap()
            .1
            .split_once("async fn handle_inbound_message(")
            .unwrap()
            .0;
        assert!(inbound.contains("claim_inbox_message_in_tx("));
        assert!(!inbound.contains("claim_inbox_in_tx("));
        assert!(!inbound.contains("let _ = delivery"));
        let settlement = inbound.find("commit_inbox_handling(").unwrap();
        let ack = inbound[settlement..].find("delivery.ack(").unwrap();
        assert!(ack > 0);
        assert!(source.contains("mandatory: true"));
        assert!(source.contains("durable: true"));
        assert!(source.contains(".with_delivery_mode(2)"));
        assert!(source.contains("cross_city_queue_arguments(&queue)"));
        assert!(source.contains("CROSS_CITY_PUBLISH_DEADLINE, publish"));
    }

    // -- Source-shape guards (this file's own production slice) -------------------

    fn production_source() -> &'static str {
        const TEST_MODULE_MARKER: &str = concat!("#[", "cfg(test)]");
        let source = include_str!("cross_city_runtime_wiring.rs");
        source
            .split_once(TEST_MODULE_MARKER)
            .map(|(production, _)| production)
            .expect("test-module marker present")
    }

    #[test]
    fn source_shape_runtime_wiring_contract() {
        let production = production_source();
        // The transport lease comes from its OWN env variable — never derived
        // from the relay tick (the two bounds are independent budgets).
        assert!(production.contains("CROSS_CITY_TRANSPORT_LEASE_SECONDS_ENV"));
        assert!(
            !production.contains(".unwrap_or(DEFAULT_RELAY_TICK_MS)"),
            "relay tick must never silently default on unparsable input"
        );
        // Every guarded coordinator step has its runtime caller in the inbound
        // path: vote admission, agreement seal, commit receipt, activation
        // mint, and the IN_DOUBT collapse of unknown storage outcomes.
        assert!(production.contains(".admit_vote("));
        assert!(production.contains(".seal_agreement("));
        assert!(production.contains(".record_commit_receipt("));
        assert!(production.contains(".mark_unknown_outcome_in_doubt("));
        assert_eq!(
            production.matches(".activate_operation(").count(),
            1,
            "the activation mint is attempted from exactly one place: after a \
             durable commit receipt, never from transport events"
        );
        let receipt = production
            .find(".record_commit_receipt(")
            .expect("commit receipt caller present");
        let activation = production
            .find(".activate_operation(")
            .expect("activation caller present");
        assert!(
            receipt < activation,
            "activation must follow the durable commit receipt, never precede it"
        );
        // Idempotent redelivery of closed rows is acknowledged honestly.
        assert!(production.contains("cross_city_inbound_redelivery_closed"));
        // Default-off marker stays false at compile time.
        const { assert!(!CROSS_CITY_WIRING_DEFAULT_ENABLED) };
    }
}
