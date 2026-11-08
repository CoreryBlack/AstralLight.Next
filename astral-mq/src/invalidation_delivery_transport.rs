//! Recipient-specific invalidation delivery transports and worker.
//!
//! This module is separate from the legacy fanout relay. The journal worker
//! claims `authorization_invalidation_delivery_leg` rows, so broker admission
//! never completes the source outbox and never proves remote apply.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use astral_db::invalidation_delivery as delivery;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions, BasicQosOptions,
    ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable, LongString, LongUInt, ShortString};
use lapin::{BasicProperties, Channel, Confirmation, ExchangeKind};
use reqwest::tls::TlsInfo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsAcceptor;

use crate::config::{dlx_routing_key, NodeIdentity, EXCHANGE_DLX};
use crate::error::MqError;
use crate::invalidation_fanout::{
    InvalidationApply, InvalidationInboxAdapter, MySqlInvalidationInbox,
};

const RECIPIENT_EXCHANGE: &str = "astral.auth.invalidation.recipient";
const RECIPIENT_RECEIPT_EXCHANGE: &str = "astral.auth.invalidation.receipt";
const RECIPIENT_QUEUE_PREFIX: &str = "astral.authorization.invalidation.recipient.";
const RECEIPT_QUEUE_PREFIX: &str = "astral.authorization.invalidation.receipt.";
const RECIPIENT_ROUTE_PREFIX: &str = "recipient.";
const RECEIPT_ROUTE_PREFIX: &str = "receipt.";
const RECEIPT_MAX_BYTES: usize = 64 * 1024;
const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const RABBIT_RECEIPT_TIMEOUT: Duration = Duration::from_secs(15);
const MTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MTLS_CONNECTION_LIFETIME: Duration = Duration::from_secs(60);
const MTLS_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSPORT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

mod lifecycle;
use lifecycle::{
    abort_and_reap_transport_join, drain_mtls_connections, retain_transport_join,
    run_owned_transport_task, wait_for_transport_join, MtlsConnectionsGuard,
};
pub use lifecycle::{InvalidationTransportLifecycle, InvalidationTransportLifecycleState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub database_id: String,
    pub region_id: String,
    pub node_id: String,
    pub certificate_sha256: String,
}

#[derive(Debug, Clone)]
pub struct MtlsReceiverConfig {
    pub bind_address: String,
    pub server_certificate_pem_path: String,
    pub server_private_key_pem_path: String,
    pub client_ca_pem_path: String,
    pub identity: NodeIdentity,
    pub database_id: String,
    pub allowed_peers: HashMap<String, AuthenticatedPeer>,
    pub max_connections: usize,
}

impl MtlsReceiverConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.bind_address.trim().is_empty() {
            return Err("mTLS receiver bind address is required".into());
        }
        if self.database_id.trim().is_empty() {
            return Err("mTLS receiver database identity is required".into());
        }
        if self.allowed_peers.is_empty() {
            return Err("mTLS receiver peer allowlist is required".into());
        }
        if self.max_connections == 0 || self.max_connections > 4096 {
            return Err("mTLS receiver max connections must be within 1..=4096".into());
        }
        for (fingerprint, peer) in &self.allowed_peers {
            if !is_sha256_fingerprint(fingerprint)
                || peer.certificate_sha256 != *fingerprint
                || peer.database_id.trim().is_empty()
                || peer.region_id.trim().is_empty()
                || peer.node_id.trim().is_empty()
            {
                return Err("mTLS receiver peer allowlist contains invalid identity".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvalidationReceiptWire {
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
    pub status: String,
}

impl InvalidationReceiptWire {
    fn into_db(self) -> delivery::AuthenticatedInvalidationReceipt {
        delivery::AuthenticatedInvalidationReceipt {
            message_id: self.message_id,
            leg_id: self.leg_id,
            target_database_id: self.target_database_id,
            target_region: self.target_region,
            target_node: self.target_node,
            envelope_sha256: self.envelope_sha256,
            payload_sha256: self.payload_sha256,
            operation_id: self.operation_id,
            message_type: self.message_type,
            schema_version: self.schema_version,
            origin_region: self.origin_region,
            ordering_key: self.ordering_key,
            tenant_id: self.tenant_id,
            authority_metadata_json: self.authority_metadata_json,
            status: self.status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientTransportOutcome {
    SendConfirmed,
    ReceiptPending(InvalidationReceiptWire),
    AppliedReceipt(InvalidationReceiptWire),
    Rejected { reason: String },
    Unknown { reason: String },
}

#[async_trait]
pub trait RecipientLegTransport: Send + Sync {
    async fn send(
        &self,
        leg: &delivery::InvalidationDeliveryLeg,
        envelope_json: &str,
    ) -> RecipientTransportOutcome;
}

#[derive(Debug)]
enum BoundedBodyError {
    TooLarge,
    Read(reqwest::Error),
}

async fn read_bounded_response_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BoundedBodyError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(BoundedBodyError::Read)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(BoundedBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_receipt_for_leg(
    receipt: &InvalidationReceiptWire,
    leg: &delivery::InvalidationDeliveryLeg,
) -> Result<(), String> {
    let exact = receipt.message_id == leg.message_id
        && receipt.leg_id == leg.leg_id
        && receipt.target_database_id == leg.recipient.database_id
        && receipt.target_region == leg.recipient.region_id
        && receipt.target_node == leg.recipient.node_id
        && receipt
            .envelope_sha256
            .eq_ignore_ascii_case(&leg.envelope_sha256)
        && receipt
            .payload_sha256
            .eq_ignore_ascii_case(&leg.payload_sha256)
        && receipt.operation_id == leg.operation_id
        && receipt.message_type == leg.message_type
        && receipt.schema_version == leg.schema_version
        && receipt.origin_region == leg.origin_region
        && receipt.ordering_key == leg.ordering_key
        && receipt.tenant_id == leg.tenant_id
        && receipt.authority_metadata_json == leg.authority_metadata_json;
    if exact {
        Ok(())
    } else {
        Err("authenticated receipt metadata does not match immutable leg".into())
    }
}

#[derive(Clone)]
pub struct RecipientTransportDispatcher {
    mtls: Option<Arc<MtlsRecipientSender>>,
    rabbit: Arc<RabbitRecipientTransport>,
}

impl RecipientTransportDispatcher {
    pub fn new(mtls: Option<MtlsRecipientSender>, rabbit: RabbitRecipientTransport) -> Self {
        Self {
            mtls: mtls.map(Arc::new),
            rabbit: Arc::new(rabbit),
        }
    }
}

#[async_trait]
impl RecipientLegTransport for RecipientTransportDispatcher {
    async fn send(
        &self,
        leg: &delivery::InvalidationDeliveryLeg,
        envelope_json: &str,
    ) -> RecipientTransportOutcome {
        match leg.recipient.transport {
            delivery::InvalidationDeliveryTransport::SameDbMtls => {
                let Some(mtls) = self.mtls.as_ref() else {
                    return RecipientTransportOutcome::Rejected {
                        reason: "mTLS recipient transport is not configured".into(),
                    };
                };
                mtls.send(leg, envelope_json).await
            }
            delivery::InvalidationDeliveryTransport::CrossDbRabbit => {
                self.rabbit.send(leg, envelope_json).await
            }
        }
    }
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn certificate_sha256(der: &[u8]) -> String {
    format!("{:x}", Sha256::digest(der))
}

fn recipient_identity_digest(database_id: &str, identity: &NodeIdentity) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_INVALIDATION_RECIPIENT_ROUTE_V1\0");
    for field in [database_id, identity.region(), identity.node()] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn recipient_route_key(database_id: &str, identity: &NodeIdentity) -> String {
    format!(
        "{}{}",
        RECIPIENT_ROUTE_PREFIX,
        recipient_identity_digest(database_id, identity)
    )
}

fn recipient_queue_name(database_id: &str, identity: &NodeIdentity) -> String {
    format!(
        "{}{}",
        RECIPIENT_QUEUE_PREFIX,
        recipient_identity_digest(database_id, identity)
    )
}

fn receipt_route_key(source_database_id: &str, leg_id: &str) -> String {
    format!(
        "{}{}",
        RECEIPT_ROUTE_PREFIX,
        digest_identity_fields(
            "ASTRAL_INVALIDATION_RECEIPT_ROUTE_V1",
            &[source_database_id, leg_id],
        ),
    )
}

fn receipt_queue_name(source_database_id: &str, leg_id: &str) -> String {
    format!(
        "{}{}",
        RECEIPT_QUEUE_PREFIX,
        digest_identity_fields(
            "ASTRAL_INVALIDATION_RECEIPT_QUEUE_V1",
            &[source_database_id, leg_id],
        ),
    )
}

fn digest_identity_fields(domain: &str, fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    for field in fields {
        digest.update(field.len().to_be_bytes());
        digest.update(field.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn recipient_queue_arguments(database_id: &str, identity: &NodeIdentity) -> FieldTable {
    let queue = recipient_queue_name(database_id, identity);
    let mut arguments = FieldTable::default();
    arguments.insert(
        "x-dead-letter-exchange".into(),
        LongString::from(EXCHANGE_DLX).into(),
    );
    arguments.insert(
        "x-dead-letter-routing-key".into(),
        LongString::from(dlx_routing_key(&queue)).into(),
    );
    arguments.insert(
        "x-message-ttl".into(),
        LongUInt::from(crate::config::MESSAGE_TTL_MS).into(),
    );
    arguments
}

pub async fn declare_recipient_rabbit_route(
    channel: &Channel,
    database_id: &str,
    identity: &NodeIdentity,
) -> Result<(), MqError> {
    declare_recipient_request_topology(channel, database_id, identity).await
}

fn receipt_queue_arguments(source_database_id: &str, leg_id: &str) -> FieldTable {
    let queue = receipt_queue_name(source_database_id, leg_id);
    let mut arguments = FieldTable::default();
    arguments.insert(
        "x-dead-letter-exchange".into(),
        LongString::from(EXCHANGE_DLX).into(),
    );
    arguments.insert(
        "x-dead-letter-routing-key".into(),
        LongString::from(dlx_routing_key(&queue)).into(),
    );
    arguments.insert(
        "x-message-ttl".into(),
        LongUInt::from(crate::config::MESSAGE_TTL_MS).into(),
    );
    arguments
}

async fn declare_receipt_topology(
    channel: &Channel,
    source_database_id: &str,
    leg_id: &str,
) -> Result<String, MqError> {
    channel
        .exchange_declare(
            ShortString::from(RECIPIENT_RECEIPT_EXCHANGE),
            ExchangeKind::Direct,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|error| MqError::Channel(format!("receipt exchange declare failed: {error}")))?;
    let queue = receipt_queue_name(source_database_id, leg_id);
    channel
        .queue_declare(
            ShortString::from(queue.as_str()),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            receipt_queue_arguments(source_database_id, leg_id),
        )
        .await
        .map_err(|error| MqError::Channel(format!("receipt queue declare failed: {error}")))?;
    channel
        .queue_bind(
            ShortString::from(queue.as_str()),
            ShortString::from(RECIPIENT_RECEIPT_EXCHANGE),
            ShortString::from(receipt_route_key(source_database_id, leg_id)),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|error| MqError::Channel(format!("receipt queue bind failed: {error}")))?;
    Ok(queue)
}

async fn declare_recipient_request_topology(
    channel: &Channel,
    database_id: &str,
    identity: &NodeIdentity,
) -> Result<(), MqError> {
    channel
        .exchange_declare(
            ShortString::from(RECIPIENT_EXCHANGE),
            ExchangeKind::Direct,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|error| MqError::Channel(format!("recipient exchange declare failed: {error}")))?;
    let queue = recipient_queue_name(database_id, identity);
    channel
        .queue_declare(
            ShortString::from(queue.as_str()),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            recipient_queue_arguments(database_id, identity),
        )
        .await
        .map_err(|error| MqError::Channel(format!("recipient queue declare failed: {error}")))?;
    channel
        .queue_bind(
            ShortString::from(queue.as_str()),
            ShortString::from(RECIPIENT_EXCHANGE),
            ShortString::from(recipient_route_key(database_id, identity)),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|error| MqError::Channel(format!("recipient queue bind failed: {error}")))?;
    let dlx = dlx_routing_key(&queue);
    channel
        .queue_declare(
            ShortString::from(dlx.as_str()),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|error| {
            MqError::Channel(format!("recipient DLX queue declare failed: {error}"))
        })?;
    channel
        .queue_bind(
            ShortString::from(dlx.as_str()),
            ShortString::from(EXCHANGE_DLX),
            ShortString::from(dlx.as_str()),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|error| MqError::Channel(format!("recipient DLX queue bind failed: {error}")))?;
    Ok(())
}

#[derive(Clone)]
pub struct RabbitRecipientTransport {
    channel: Channel,
    source_database_id: Arc<str>,
    repository: delivery::InvalidationDeliveryRepository,
}

impl RabbitRecipientTransport {
    pub async fn new(
        channel: Channel,
        source_database_id: impl Into<String>,
        repository: delivery::InvalidationDeliveryRepository,
    ) -> Result<Self, MqError> {
        let source_database_id = source_database_id.into();
        if source_database_id.trim().is_empty() {
            return Err(MqError::Channel(
                "Rabbit recipient source database identity is required".into(),
            ));
        }
        crate::producer::Producer::enable_confirms(&channel).await?;
        channel
            .exchange_declare(
                ShortString::from(RECIPIENT_RECEIPT_EXCHANGE),
                ExchangeKind::Direct,
                ExchangeDeclareOptions {
                    durable: true,
                    ..ExchangeDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|error| {
                MqError::Channel(format!("receipt exchange declare failed: {error}"))
            })?;
        Ok(Self {
            channel,
            source_database_id: Arc::from(source_database_id),
            repository,
        })
    }

    async fn wait_for_receipt(
        &self,
        leg: &delivery::InvalidationDeliveryLeg,
        queue: &str,
        mut consumer: lapin::Consumer,
    ) -> RecipientTransportOutcome {
        let delivery = match timeout(RABBIT_RECEIPT_TIMEOUT, consumer.next()).await {
            Ok(Some(Ok(delivery))) => delivery,
            Ok(Some(Err(error))) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("Rabbit receipt consumer: {error}"),
                }
            }
            Ok(None) => {
                return RecipientTransportOutcome::Unknown {
                    reason: "Rabbit receipt consumer closed".into(),
                }
            }
            Err(_) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("Rabbit receipt timeout for queue {queue}"),
                }
            }
        };
        if delivery.data.len() > RECEIPT_MAX_BYTES {
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            return RecipientTransportOutcome::Rejected {
                reason: "Rabbit receipt exceeds bounded response size".into(),
            };
        }
        let correlation = delivery
            .properties
            .correlation_id()
            .as_ref()
            .map(ToString::to_string);
        if correlation.as_deref() != Some(leg.leg_id.as_str()) {
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            return RecipientTransportOutcome::Rejected {
                reason: "Rabbit receipt correlation does not match claimed leg".into(),
            };
        }
        let receipt = match serde_json::from_slice::<InvalidationReceiptWire>(&delivery.data) {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                return RecipientTransportOutcome::Rejected {
                    reason: format!("Rabbit receipt JSON: {error}"),
                };
            }
        };
        if let Err(reason) = validate_receipt_for_leg(&receipt, leg) {
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            return RecipientTransportOutcome::Rejected { reason };
        }
        let status = receipt.status.as_str();
        if status != "PENDING" && status != "APPLIED" {
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            return RecipientTransportOutcome::Rejected {
                reason: "Rabbit receipt status is neither PENDING nor APPLIED".into(),
            };
        }
        if let Err(error) = self
            .repository
            .record_authenticated_receipt(&receipt.clone().into_db())
            .await
        {
            return RecipientTransportOutcome::Unknown {
                reason: format!("persist Rabbit receipt before ACK: {error}"),
            };
        }
        if let Err(error) = delivery.acker.ack(BasicAckOptions::default()).await {
            return RecipientTransportOutcome::Unknown {
                reason: format!("ACK Rabbit receipt: {error}"),
            };
        }
        if status == "APPLIED" {
            RecipientTransportOutcome::AppliedReceipt(receipt)
        } else {
            RecipientTransportOutcome::ReceiptPending(receipt)
        }
    }
}

#[async_trait]
impl RecipientLegTransport for RabbitRecipientTransport {
    async fn send(
        &self,
        leg: &delivery::InvalidationDeliveryLeg,
        envelope_json: &str,
    ) -> RecipientTransportOutcome {
        if leg.recipient.transport != delivery::InvalidationDeliveryTransport::CrossDbRabbit {
            return RecipientTransportOutcome::Rejected {
                reason: "Rabbit transport received a non-Rabbit leg".into(),
            };
        }
        let identity = match NodeIdentity::try_from_parts(
            leg.recipient.region_id.clone(),
            leg.recipient.node_id.clone(),
        ) {
            Ok(identity) => identity,
            Err(error) => return RecipientTransportOutcome::Rejected { reason: error },
        };
        if let Err(error) =
            declare_recipient_request_topology(&self.channel, &leg.recipient.database_id, &identity)
                .await
        {
            return RecipientTransportOutcome::Unknown {
                reason: format!("declare Rabbit recipient route: {error}"),
            };
        }
        let queue = match declare_receipt_topology(
            &self.channel,
            self.source_database_id.as_ref(),
            &leg.leg_id,
        )
        .await
        {
            Ok(queue) => queue,
            Err(error) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("declare Rabbit receipt route: {error}"),
                }
            }
        };
        let consumer = match self
            .channel
            .basic_consume(
                ShortString::from(queue.as_str()),
                ShortString::from(format!("invalidation-receipt-{}", leg.leg_id)),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
        {
            Ok(consumer) => consumer,
            Err(error) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("consume Rabbit receipt: {error}"),
                }
            }
        };
        let mut headers = FieldTable::default();
        headers.insert(
            "x-astral-source-database-id".into(),
            AMQPValue::LongString(self.source_database_id.to_string().into()),
        );
        headers.insert(
            "x-astral-leg-id".into(),
            AMQPValue::LongString(leg.leg_id.clone().into()),
        );
        let confirmation = self
            .channel
            .basic_publish(
                ShortString::from(RECIPIENT_EXCHANGE),
                ShortString::from(recipient_route_key(&leg.recipient.database_id, &identity)),
                BasicPublishOptions {
                    mandatory: true,
                    ..BasicPublishOptions::default()
                },
                envelope_json.as_bytes(),
                BasicProperties::default()
                    .with_delivery_mode(2)
                    .with_content_type("application/json".into())
                    .with_message_id(ShortString::from(leg.message_id.as_str()))
                    .with_correlation_id(ShortString::from(leg.leg_id.as_str()))
                    .with_reply_to(ShortString::from(queue.as_str()))
                    .with_headers(headers),
            )
            .await;
        let confirmation = match confirmation {
            Ok(confirmation) => confirmation,
            Err(error) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("recipient Rabbit publish: {error}"),
                }
            }
        };
        match confirmation.await {
            Ok(Confirmation::Ack(None)) => self.wait_for_receipt(leg, &queue, consumer).await,
            Ok(Confirmation::Ack(Some(returned))) => RecipientTransportOutcome::Rejected {
                reason: format!("recipient Rabbit unroutable {}", returned.reply_text),
            },
            Ok(Confirmation::Nack(returned)) => RecipientTransportOutcome::Rejected {
                reason: returned
                    .map(|value| value.reply_text.to_string())
                    .unwrap_or_else(|| "recipient Rabbit negative acknowledgement".into()),
            },
            Ok(Confirmation::NotRequested) => RecipientTransportOutcome::Rejected {
                reason: "recipient Rabbit publisher confirms are disabled".into(),
            },
            Err(error) => RecipientTransportOutcome::Unknown {
                reason: format!("recipient Rabbit confirmation: {error}"),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RabbitRecipientReceiverConfig {
    pub database_id: String,
    pub identity: NodeIdentity,
    pub allowed_source_database_ids: HashSet<String>,
    pub prefetch: u16,
}

impl RabbitRecipientReceiverConfig {
    fn validate(&self) -> Result<(), String> {
        if self.database_id.trim().is_empty()
            || self.database_id.len() > 128
            || !self
                .database_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err("Rabbit recipient receiver database identity is invalid".into());
        }
        if self.allowed_source_database_ids.is_empty()
            || self.allowed_source_database_ids.iter().any(|value| {
                value.trim().is_empty()
                    || value.len() > 128
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            })
        {
            return Err("Rabbit recipient receiver source allowlist is invalid".into());
        }
        if self.prefetch == 0 {
            return Err("Rabbit recipient receiver prefetch must be positive".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RabbitRecipientReceiverState {
    inbox: MySqlInvalidationInbox,
    apply: Arc<dyn InvalidationApply>,
    config: Arc<RabbitRecipientReceiverConfig>,
    channel: Channel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RabbitDeliveryAction {
    Ack,
    DeadLetter,
}

fn rabbit_header_string(delivery: &lapin::message::Delivery, name: &str) -> Option<String> {
    let headers = delivery.properties.headers().as_ref()?;
    match headers.inner().get(name)? {
        AMQPValue::LongString(value) => Some(value.to_string()),
        AMQPValue::ShortString(value) => Some(value.to_string()),
        _ => None,
    }
}

fn rabbit_delivery_identity(
    delivery: &lapin::message::Delivery,
) -> Result<(String, String, String, String), String> {
    let source_database_id = rabbit_header_string(delivery, "x-astral-source-database-id")
        .ok_or_else(|| "Rabbit invalidation source database header is required".to_owned())?;
    let leg_id = rabbit_header_string(delivery, "x-astral-leg-id")
        .or_else(|| {
            delivery
                .properties
                .correlation_id()
                .as_ref()
                .map(ToString::to_string)
        })
        .ok_or_else(|| "Rabbit invalidation leg identity is required".to_owned())?;
    let message_id = delivery
        .properties
        .message_id()
        .as_ref()
        .map(ToString::to_string)
        .ok_or_else(|| "Rabbit invalidation message identity is required".to_owned())?;
    let reply_to = delivery
        .properties
        .reply_to()
        .as_ref()
        .map(ToString::to_string)
        .ok_or_else(|| "Rabbit invalidation reply route is required".to_owned())?;
    Ok((source_database_id, leg_id, message_id, reply_to))
}

async fn publish_rabbit_receipt(
    channel: &Channel,
    source_database_id: &str,
    receipt: &InvalidationReceiptWire,
) -> Result<(), String> {
    let body = serde_json::to_vec(receipt).map_err(|error| error.to_string())?;
    if body.len() > RECEIPT_MAX_BYTES {
        return Err("Rabbit APPLIED receipt exceeds bounded size".into());
    }
    let confirmation = channel
        .basic_publish(
            ShortString::from(RECIPIENT_RECEIPT_EXCHANGE),
            ShortString::from(receipt_route_key(source_database_id, &receipt.leg_id)),
            BasicPublishOptions {
                mandatory: true,
                ..BasicPublishOptions::default()
            },
            &body,
            BasicProperties::default()
                .with_delivery_mode(2)
                .with_content_type("application/json".into())
                .with_message_id(ShortString::from(receipt.message_id.as_str()))
                .with_correlation_id(ShortString::from(receipt.leg_id.as_str())),
        )
        .await
        .map_err(|error| format!("publish Rabbit APPLIED receipt: {error}"))?;
    match confirmation
        .await
        .map_err(|error| format!("confirm Rabbit APPLIED receipt: {error}"))?
    {
        Confirmation::Ack(None) => Ok(()),
        Confirmation::Ack(Some(returned)) => Err(format!(
            "Rabbit APPLIED receipt unroutable: {}",
            returned.reply_text
        )),
        Confirmation::Nack(returned) => Err(format!(
            "Rabbit APPLIED receipt negatively acknowledged: {}",
            returned
                .map(|value| value.reply_text.to_string())
                .unwrap_or_else(|| "no broker reason".into())
        )),
        Confirmation::NotRequested => {
            Err("Rabbit APPLIED receipt publisher confirms are disabled".into())
        }
    }
}

async fn process_rabbit_delivery(
    state: &RabbitRecipientReceiverState,
    delivery: &lapin::message::Delivery,
) -> RabbitDeliveryAction {
    if delivery.data.len() > REQUEST_MAX_BYTES {
        tracing::error!("Rabbit invalidation body exceeds bounded size");
        return RabbitDeliveryAction::DeadLetter;
    }
    let (source_database_id, leg_id, message_id, reply_to) =
        match rabbit_delivery_identity(delivery) {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(error = %error, "Rabbit invalidation identity rejected");
                return RabbitDeliveryAction::DeadLetter;
            }
        };
    if !state
        .config
        .allowed_source_database_ids
        .contains(&source_database_id)
    {
        tracing::error!(source_database_id = %source_database_id, "Rabbit invalidation source is not allowlisted");
        return RabbitDeliveryAction::DeadLetter;
    }
    if reply_to != receipt_queue_name(&source_database_id, &leg_id) {
        tracing::error!(
            "Rabbit invalidation reply route does not match deterministic source route"
        );
        return RabbitDeliveryAction::DeadLetter;
    }
    let envelope = match serde_json::from_slice::<crate::envelope::MessageEnvelope>(&delivery.data)
    {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::error!(error = %error, "Rabbit invalidation envelope JSON rejected");
            return RabbitDeliveryAction::DeadLetter;
        }
    };
    let canonical_body = match envelope.envelope_json() {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "Rabbit invalidation canonical serialization failed");
            return RabbitDeliveryAction::DeadLetter;
        }
    };
    if envelope.validate().is_err() || canonical_body.as_bytes() != delivery.data.as_slice() {
        tracing::error!("Rabbit invalidation envelope is not canonical");
        return RabbitDeliveryAction::DeadLetter;
    }
    if envelope.message_id != message_id || envelope.message_id.trim().is_empty() {
        tracing::error!("Rabbit invalidation message identity conflicts with envelope");
        return RabbitDeliveryAction::DeadLetter;
    }
    let expected_leg = delivery::stable_leg_id(
        &envelope.message_id,
        &delivery::InvalidationDeliveryRecipient {
            region_id: state.config.identity.region().to_owned(),
            node_id: state.config.identity.node().to_owned(),
            database_id: state.config.database_id.clone(),
            transport: delivery::InvalidationDeliveryTransport::CrossDbRabbit,
            endpoint: None,
            peer_certificate_sha256: None,
        },
    );
    if leg_id != expected_leg
        || delivery
            .properties
            .correlation_id()
            .as_ref()
            .is_some_and(|value| value.as_str() != leg_id)
    {
        tracing::error!("Rabbit invalidation leg identity conflicts with frozen recipient");
        return RabbitDeliveryAction::DeadLetter;
    }
    let event = match crate::invalidation::InvalidationEvent::from_envelope(&envelope) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(error = %error, "Rabbit invalidation typed contract rejected");
            return RabbitDeliveryAction::DeadLetter;
        }
    };
    let record = crate::invalidation_fanout::InvalidationInboxRecord {
        node_region: state.config.identity.region().to_owned(),
        node_id: state.config.identity.node().to_owned(),
        envelope: envelope.clone(),
    };
    let committed = match state.inbox.commit_delivery(&record).await {
        Ok(committed) => committed,
        Err(error) => {
            tracing::error!(error = %error, "Rabbit invalidation inbox commit failed");
            return RabbitDeliveryAction::DeadLetter;
        }
    };
    if !matches!(
        committed,
        crate::invalidation_fanout::InboxCommitOutcome::ExistingApplied
    ) {
        if let Err(error) = state.apply.apply(&envelope, &event).await {
            tracing::error!(error = %error, "Rabbit invalidation apply failed; inbox remains pending");
            return RabbitDeliveryAction::DeadLetter;
        }
        if let Err(error) = state
            .inbox
            .mark_applied(&state.config.identity, &envelope.message_id)
            .await
        {
            tracing::error!(error = %error, "Rabbit invalidation inbox mark-applied failed");
            return RabbitDeliveryAction::DeadLetter;
        }
    }
    let canonical_body = match envelope.envelope_json() {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "Rabbit invalidation canonical serialization failed");
            return RabbitDeliveryAction::DeadLetter;
        }
    };
    let authority_metadata_json = match envelope.authority_metadata_json() {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error = %error, "Rabbit invalidation authority metadata serialization failed");
            return RabbitDeliveryAction::DeadLetter;
        }
    };
    let receipt = InvalidationReceiptWire {
        message_id: envelope.message_id.clone(),
        leg_id,
        target_database_id: state.config.database_id.clone(),
        target_region: state.config.identity.region().to_owned(),
        target_node: state.config.identity.node().to_owned(),
        envelope_sha256: format!("{:x}", Sha256::digest(canonical_body.as_bytes())),
        payload_sha256: envelope.payload_sha256.clone(),
        operation_id: envelope.operation_id.clone(),
        message_type: envelope.message_type.clone(),
        schema_version: envelope.schema_version,
        origin_region: envelope.origin_region.clone(),
        ordering_key: envelope.ordering_key.clone(),
        tenant_id: envelope.tenant_id,
        authority_metadata_json,
        status: "APPLIED".into(),
    };
    if let Err(error) = publish_rabbit_receipt(&state.channel, &source_database_id, &receipt).await
    {
        tracing::error!(error = %error, "Rabbit APPLIED receipt publication is unknown; request is dead-lettered");
        return RabbitDeliveryAction::DeadLetter;
    }
    RabbitDeliveryAction::Ack
}

#[derive(Debug)]
pub struct RabbitRecipientReceiverHandle {
    shutdown: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
    lifecycle: InvalidationTransportLifecycle,
}

impl RabbitRecipientReceiverHandle {
    pub fn signal_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn shutdown_and_join(&mut self) -> Result<(), String> {
        self.signal_shutdown();
        wait_for_transport_join(&mut self.join, "Rabbit recipient receiver").await
    }

    async fn abort_and_reap(
        &mut self,
        lifecycle: &InvalidationTransportLifecycle,
        deadline: Instant,
    ) -> String {
        abort_and_reap_transport_join(
            &mut self.join,
            "Rabbit recipient receiver",
            deadline,
            lifecycle,
        )
        .await
    }
}

impl Drop for RabbitRecipientReceiverHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            retain_transport_join(&self.lifecycle, "Rabbit recipient receiver drop", join);
        }
    }
}

pub async fn start_rabbit_recipient_receiver(
    channel: Channel,
    config: RabbitRecipientReceiverConfig,
    pool: sqlx::MySqlPool,
    apply: Arc<dyn InvalidationApply>,
    lifecycle: InvalidationTransportLifecycle,
) -> Result<RabbitRecipientReceiverHandle, String> {
    config.validate()?;
    crate::producer::Producer::enable_confirms(&channel)
        .await
        .map_err(|error| format!("enable Rabbit receipt confirms: {error}"))?;
    declare_recipient_request_topology(&channel, &config.database_id, &config.identity)
        .await
        .map_err(|error| format!("declare Rabbit recipient receiver route: {error}"))?;
    channel
        .exchange_declare(
            ShortString::from(RECIPIENT_RECEIPT_EXCHANGE),
            ExchangeKind::Direct,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|error| format!("declare Rabbit receipt exchange: {error}"))?;
    channel
        .basic_qos(config.prefetch, BasicQosOptions { global: false })
        .await
        .map_err(|error| format!("configure Rabbit recipient prefetch: {error}"))?;
    let queue = recipient_queue_name(&config.database_id, &config.identity);
    let mut consumer = channel
        .basic_consume(
            ShortString::from(queue.as_str()),
            ShortString::from(format!(
                "invalidation-recipient-{}-{}",
                config.identity.region(),
                config.identity.node()
            )),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|error| format!("consume Rabbit recipient queue: {error}"))?;
    let state = RabbitRecipientReceiverState {
        inbox: MySqlInvalidationInbox::new(pool),
        apply,
        config: Arc::new(config),
        channel,
    };
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let lifecycle_for_task = lifecycle.clone();
    let join = tokio::spawn(async move {
        let owner_lifecycle = lifecycle_for_task.clone();
        run_owned_transport_task(lifecycle_for_task, "rabbit-receiver", async move {
            owner_lifecycle.mark_ready("rabbit-receiver");
            loop {
                let delivery = tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return Ok(());
                        }
                        continue;
                    }
                    delivery = consumer.next() => delivery,
                };
                let Some(delivery) = delivery else {
                    return Err("Rabbit recipient consumer stream closed".into());
                };
                let delivery = match delivery {
                    Ok(delivery) => delivery,
                    Err(error) => {
                        tracing::error!(error = %error, "Rabbit recipient consumer stream failed");
                        return Err(format!("Rabbit recipient consumer stream failed: {error}"));
                    }
                };
                match process_rabbit_delivery(&state, &delivery).await {
                    RabbitDeliveryAction::Ack => {
                        if let Err(error) = delivery.acker.ack(BasicAckOptions::default()).await {
                            tracing::error!(error = %error, "Rabbit recipient request ACK failed");
                            return Err(format!("Rabbit recipient request ACK failed: {error}"));
                        }
                    }
                    RabbitDeliveryAction::DeadLetter => {
                        if let Err(error) = delivery
                            .acker
                            .nack(BasicNackOptions {
                                requeue: false,
                                ..BasicNackOptions::default()
                            })
                            .await
                        {
                            tracing::error!(error = %error, "Rabbit recipient request dead-letter failed");
                            return Err(format!("Rabbit recipient request dead-letter failed: {error}"));
                        }
                    }
                }
            }
        }).await;
    });
    Ok(RabbitRecipientReceiverHandle {
        shutdown,
        join: Some(join),
        lifecycle,
    })
}

#[derive(Clone)]
pub struct MtlsRecipientSender {
    client: reqwest::Client,
}

impl MtlsRecipientSender {
    pub fn from_pem_paths(
        client_identity_pem_path: impl AsRef<Path>,
        server_ca_pem_path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let identity_pem = std::fs::read(client_identity_pem_path.as_ref())
            .map_err(|error| format!("read mTLS client identity: {error}"))?;
        let ca_pem = std::fs::read(server_ca_pem_path.as_ref())
            .map_err(|error| format!("read mTLS server CA: {error}"))?;
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|error| format!("parse mTLS client identity: {error}"))?;
        let ca = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|error| format!("parse mTLS server CA: {error}"))?;
        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca)
            .tls_info(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| format!("build mTLS client: {error}"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl RecipientLegTransport for MtlsRecipientSender {
    async fn send(
        &self,
        leg: &delivery::InvalidationDeliveryLeg,
        envelope_json: &str,
    ) -> RecipientTransportOutcome {
        let Some(endpoint) = leg.recipient.endpoint.as_deref() else {
            return RecipientTransportOutcome::Rejected {
                reason: "same-db mTLS leg has no endpoint".into(),
            };
        };
        let expected_pin = leg
            .recipient
            .peer_certificate_sha256
            .as_deref()
            .unwrap_or_default();
        let response = match timeout(
            Duration::from_secs(10),
            self.client
                .post(endpoint)
                .header("content-type", "application/json")
                .header("x-astral-message-id", leg.message_id.as_str())
                .header("x-astral-leg-id", leg.leg_id.as_str())
                .body(envelope_json.to_owned())
                .send(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("mTLS recipient request: {error}"),
                }
            }
            Err(_) => {
                return RecipientTransportOutcome::Unknown {
                    reason: "mTLS recipient request timeout".into(),
                }
            }
        };
        let Some(tls_info) = response.extensions().get::<TlsInfo>() else {
            return RecipientTransportOutcome::Rejected {
                reason: "mTLS response has no peer TLS certificate".into(),
            };
        };
        let Some(peer_der) = tls_info.peer_certificate() else {
            return RecipientTransportOutcome::Rejected {
                reason: "mTLS response peer certificate is absent".into(),
            };
        };
        if certificate_sha256(peer_der) != expected_pin.to_ascii_lowercase() {
            return RecipientTransportOutcome::Rejected {
                reason: "mTLS response peer certificate pin mismatch".into(),
            };
        }
        let status = response.status();
        let body = read_bounded_response_body(response, RECEIPT_MAX_BYTES).await;
        let body = match body {
            Ok(body) => body,
            Err(BoundedBodyError::TooLarge) => {
                return RecipientTransportOutcome::Rejected {
                    reason: "mTLS receipt exceeds bounded response size".into(),
                }
            }
            Err(BoundedBodyError::Read(error)) => {
                return RecipientTransportOutcome::Unknown {
                    reason: format!("mTLS receipt body: {error}"),
                }
            }
        };
        if !status.is_success() {
            return RecipientTransportOutcome::Rejected {
                reason: format!("mTLS receiver returned HTTP {status}"),
            };
        }
        match serde_json::from_slice::<InvalidationReceiptWire>(&body) {
            Ok(receipt) => match validate_receipt_for_leg(&receipt, leg) {
                Ok(()) if receipt.status == "APPLIED" => {
                    RecipientTransportOutcome::AppliedReceipt(receipt)
                }
                Ok(()) => RecipientTransportOutcome::Unknown {
                    reason: "mTLS receiver receipt is not APPLIED".into(),
                },
                Err(reason) => RecipientTransportOutcome::Rejected { reason },
            },
            Err(error) => RecipientTransportOutcome::Rejected {
                reason: format!("mTLS receipt JSON: {error}"),
            },
        }
    }
}

#[derive(Debug)]
pub struct RecipientLegWorkerHandle {
    shutdown: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
    lifecycle: InvalidationTransportLifecycle,
}

impl RecipientLegWorkerHandle {
    pub fn signal_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn shutdown_and_join(&mut self) -> Result<(), String> {
        self.signal_shutdown();
        wait_for_transport_join(&mut self.join, "recipient leg worker").await
    }

    async fn abort_and_reap(
        &mut self,
        lifecycle: &InvalidationTransportLifecycle,
        deadline: Instant,
    ) -> String {
        abort_and_reap_transport_join(&mut self.join, "recipient leg worker", deadline, lifecycle)
            .await
    }
}

impl Drop for RecipientLegWorkerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            retain_transport_join(&self.lifecycle, "recipient leg worker drop", join);
        }
    }
}

pub fn spawn_recipient_leg_worker<T>(
    repository: delivery::InvalidationDeliveryRepository,
    transport: T,
    owner: String,
    poll_interval: Duration,
    lifecycle: InvalidationTransportLifecycle,
) -> Result<RecipientLegWorkerHandle, String>
where
    T: RecipientLegTransport + 'static,
{
    if owner.trim().is_empty() || poll_interval.is_zero() {
        return Err("recipient leg worker owner and poll interval are required".into());
    }
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let transport = Arc::new(transport);
    let lifecycle_for_task = lifecycle.clone();
    let join = tokio::spawn(async move {
        let owner_lifecycle = lifecycle_for_task.clone();
        run_owned_transport_task(lifecycle_for_task, "leg-worker", async move {
            owner_lifecycle.mark_ready("leg-worker");
            loop {
                if *shutdown_rx.borrow_and_update() {
                    return Ok(());
                }
            let claim = match repository.claim_one(&owner).await {
                Ok(claim) => claim,
                Err(error) => {
                    tracing::error!(owner = %owner, error = %error, "recipient leg claim failed");
                    if !sleep_or_stop(&mut shutdown_rx, poll_interval).await {
                        return Ok(());
                    }
                    continue;
                }
            };
            let Some(claim) = claim else {
                if !sleep_or_stop(&mut shutdown_rx, poll_interval).await {
                    return Ok(());
                }
                continue;
            };
            let outcome = transport.send(&claim.leg, &claim.envelope_json).await;
            let result = match outcome {
                RecipientTransportOutcome::SendConfirmed => repository
                    .settle_send(
                        &claim,
                        delivery::InvalidationDeliveryLegState::SendConfirmed,
                    )
                    .await,
                RecipientTransportOutcome::ReceiptPending(_receipt) => repository
                    .settle_send(
                        &claim,
                        delivery::InvalidationDeliveryLegState::PendingApply,
                    )
                    .await,
                RecipientTransportOutcome::AppliedReceipt(receipt) => {
                    let db_receipt = receipt.into_db();
                    match repository
                        .record_authenticated_receipt(&db_receipt)
                        .await
                    {
                        Ok(()) => match repository
                            .settle_send(
                                &claim,
                                delivery::InvalidationDeliveryLegState::PendingApply,
                            )
                            .await
                        {
                            Ok(()) => repository
                                .mark_applied_from_exact_receipt(
                                    &claim.leg.message_id,
                                    &claim.leg.leg_id,
                                    &claim.leg.envelope_sha256,
                                    claim.leg.generation,
                                )
                                .await,
                            Err(error) => Err(error),
                        },
                        Err(error) => Err(error),
                    }
                }
                RecipientTransportOutcome::Rejected { reason } => repository
                    .settle_send(
                        &claim,
                        delivery::InvalidationDeliveryLegState::Quarantined,
                    )
                    .await
                    .map_err(|error| {
                        delivery::InvalidationDeliveryError::InvalidInput(format!(
                            "{reason}; settlement: {error}"
                        ))
                    }),
                RecipientTransportOutcome::Unknown { reason } => repository
                    .settle_send(
                        &claim,
                        delivery::InvalidationDeliveryLegState::InDoubt,
                    )
                    .await
                    .map_err(|error| {
                        delivery::InvalidationDeliveryError::InvalidInput(format!(
                            "{reason}; settlement: {error}"
                        ))
                    }),
            };
            if let Err(error) = result {
                tracing::error!(
                    owner = %owner,
                    message_id = %claim.leg.message_id,
                    leg_id = %claim.leg.leg_id,
                    error = %error,
                    "recipient leg settlement failed; outcome is not replayed in this run"
                );
                }
            }
        }).await;
    });
    Ok(RecipientLegWorkerHandle {
        shutdown,
        join: Some(join),
        lifecycle,
    })
}

async fn sleep_or_stop(shutdown: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
        _ = tokio::time::sleep(duration) => !*shutdown.borrow(),
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    rustls_pemfile::certs(&mut BufReader::new(
        File::open(path)
            .map_err(|error| format!("open certificate {}: {error}", path.display()))?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| format!("parse certificates: {error}"))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    rustls_pemfile::private_key(&mut BufReader::new(
        File::open(path)
            .map_err(|error| format!("open private key {}: {error}", path.display()))?,
    ))
    .map_err(|error| format!("parse private key: {error}"))?
    .ok_or_else(|| "private key PEM contains no key".into())
}

fn build_receiver_acceptor(config: &MtlsReceiverConfig) -> Result<TlsAcceptor, String> {
    let certs = load_certs(Path::new(&config.server_certificate_pem_path))?;
    let key = load_key(Path::new(&config.server_private_key_pem_path))?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(Path::new(&config.client_ca_pem_path))? {
        roots
            .add(cert)
            .map_err(|error| format!("add client CA: {error}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| format!("build client verifier: {error}"))?;
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS protocol versions: {error}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| format!("server certificate/key: {error}"))?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

#[derive(Clone)]
struct ReceiverState {
    inbox: MySqlInvalidationInbox,
    apply: Arc<dyn InvalidationApply>,
    config: Arc<MtlsReceiverConfig>,
}

async fn receive_invalidation(
    state: Arc<ReceiverState>,
    peer_fingerprint: String,
    request: Request<Body>,
) -> Response {
    if !state.config.allowed_peers.contains_key(&peer_fingerprint) {
        return (
            StatusCode::UNAUTHORIZED,
            "peer certificate is not allowlisted",
        )
            .into_response();
    }
    let leg_id = request
        .headers()
        .get("x-astral-leg-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let message_header = request
        .headers()
        .get("x-astral-message-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = match axum::body::to_bytes(request.into_body(), REQUEST_MAX_BYTES).await {
        Ok(body) => body,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let envelope = match serde_json::from_slice::<crate::envelope::MessageEnvelope>(&body) {
        Ok(envelope) => envelope,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    if envelope.validate().is_err() {
        return (StatusCode::BAD_REQUEST, "invalid canonical envelope").into_response();
    }
    let canonical_body = match envelope.envelope_json() {
        Ok(canonical_body) => canonical_body,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if canonical_body.as_bytes() != body.as_ref()
        || (!message_header.is_empty() && message_header != envelope.message_id)
    {
        return (StatusCode::BAD_REQUEST, "envelope bytes are not canonical").into_response();
    }
    let expected_leg = delivery::stable_leg_id(
        &envelope.message_id,
        &delivery::InvalidationDeliveryRecipient {
            region_id: state.config.identity.region().to_owned(),
            node_id: state.config.identity.node().to_owned(),
            database_id: state.config.database_id.clone(),
            transport: delivery::InvalidationDeliveryTransport::SameDbMtls,
            endpoint: None,
            peer_certificate_sha256: None,
        },
    );
    if leg_id != expected_leg {
        return (StatusCode::CONFLICT, "leg identity mismatch").into_response();
    }
    let event = match crate::invalidation::InvalidationEvent::from_envelope(&envelope) {
        Ok(event) => event,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    let record = crate::invalidation_fanout::InvalidationInboxRecord {
        node_region: state.config.identity.region().to_owned(),
        node_id: state.config.identity.node().to_owned(),
        envelope: envelope.clone(),
    };
    let commit = match state.inbox.commit_delivery(&record).await {
        Ok(commit) => commit,
        Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    };
    if !matches!(
        commit,
        crate::invalidation_fanout::InboxCommitOutcome::ExistingApplied
    ) {
        if let Err(error) = state.apply.apply(&envelope, &event).await {
            return (StatusCode::SERVICE_UNAVAILABLE, error).into_response();
        }
        if let Err(error) = state
            .inbox
            .mark_applied(
                &NodeIdentity::try_from_parts(
                    state.config.identity.region().to_owned(),
                    state.config.identity.node().to_owned(),
                )
                .expect("validated receiver identity"),
                &envelope.message_id,
            )
            .await
        {
            return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
        }
    }
    let authority_metadata_json = match envelope.authority_metadata_json() {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let receipt = InvalidationReceiptWire {
        message_id: envelope.message_id,
        leg_id: expected_leg,
        target_database_id: state.config.database_id.clone(),
        target_region: state.config.identity.region().to_owned(),
        target_node: state.config.identity.node().to_owned(),
        envelope_sha256: format!("{:x}", Sha256::digest(canonical_body.as_bytes())),
        payload_sha256: envelope.payload_sha256.clone(),
        operation_id: envelope.operation_id.clone(),
        message_type: envelope.message_type.clone(),
        schema_version: envelope.schema_version,
        origin_region: envelope.origin_region.clone(),
        ordering_key: envelope.ordering_key.clone(),
        tenant_id: envelope.tenant_id,
        authority_metadata_json,
        status: "APPLIED".into(),
    };
    (StatusCode::OK, Json(receipt)).into_response()
}

pub struct MtlsInvalidationReceiverHandle {
    shutdown: watch::Sender<bool>,
    join: Option<JoinHandle<()>>,
    lifecycle: InvalidationTransportLifecycle,
}

impl MtlsInvalidationReceiverHandle {
    pub fn signal_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn shutdown_and_join(&mut self) -> Result<(), String> {
        self.signal_shutdown();
        wait_for_transport_join(&mut self.join, "mTLS receiver").await
    }

    async fn abort_and_reap(
        &mut self,
        lifecycle: &InvalidationTransportLifecycle,
        deadline: Instant,
    ) -> String {
        abort_and_reap_transport_join(&mut self.join, "mTLS receiver", deadline, lifecycle).await
    }
}

impl Drop for MtlsInvalidationReceiverHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.take() {
            retain_transport_join(&self.lifecycle, "mTLS receiver drop", join);
        }
    }
}

pub async fn start_mtls_invalidation_receiver(
    config: MtlsReceiverConfig,
    pool: sqlx::MySqlPool,
    apply: Arc<dyn InvalidationApply>,
    lifecycle: InvalidationTransportLifecycle,
) -> Result<MtlsInvalidationReceiverHandle, String> {
    config.validate()?;
    let acceptor = build_receiver_acceptor(&config)?;
    let listener = TcpListener::bind(&config.bind_address)
        .await
        .map_err(|error| format!("bind mTLS invalidation receiver: {error}"))?;
    let state = Arc::new(ReceiverState {
        inbox: MySqlInvalidationInbox::new(pool),
        apply,
        config: Arc::new(config),
    });
    let connection_limit = Arc::new(Semaphore::new(state.config.max_connections));
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let lifecycle_for_task = lifecycle.clone();
    let join = tokio::spawn(async move {
        let owner_lifecycle = lifecycle_for_task.clone();
        run_owned_transport_task(lifecycle_for_task, "mtls-receiver", async move {
            let mut connections_guard = MtlsConnectionsGuard::new(owner_lifecycle.clone());
            let mut accept_failure = None;
            owner_lifecycle.mark_ready("mtls-receiver");
            'accept: loop {
                let accepted = tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break 'accept;
                        }
                        continue;
                    }
                    accepted = listener.accept() => accepted,
                };
                let (stream, _peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        accept_failure =
                            Some(format!("mTLS invalidation receiver accept failed: {error}"));
                        break;
                    }
                };
                let permit = match Arc::clone(&connection_limit).acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        accept_failure =
                            Some("mTLS invalidation receiver connection limit closed".to_owned());
                        break 'accept;
                    }
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state);
                connections_guard.spawn(async move {
                    let _permit = permit;
                    let Ok(tls) = timeout(MTLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                        .await
                        .map_err(|_| ())
                        .and_then(|value| value.map_err(|_| ()))
                    else {
                        return;
                    };
                    let Some(certificate) = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                    else {
                        return;
                    };
                    let fingerprint = certificate_sha256(certificate.as_ref());
                    if !state.config.allowed_peers.contains_key(&fingerprint) {
                        return;
                    }
                    let service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let state = Arc::clone(&state);
                            let fingerprint = fingerprint.clone();
                            async move {
                                let (parts, incoming) = request.into_parts();
                                let request = Request::from_parts(parts, Body::new(incoming));
                                let path_ok = request.uri().path()
                                    == "/internal/authorization-invalidations"
                                    && request.method() == hyper::Method::POST;
                                if !path_ok {
                                    return Ok::<_, Infallible>(
                                        (StatusCode::NOT_FOUND, "not found").into_response(),
                                    );
                                }
                                Ok::<_, Infallible>(
                                    receive_invalidation(state, fingerprint, request).await,
                                )
                            }
                        },
                    );
                    let connection_builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let serving = connection_builder
                        .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(tls), service);
                    let _ = timeout(MTLS_CONNECTION_LIFETIME, serving).await;
                });
                while let Some(joined) = connections_guard.try_join_next() {
                    if let Err(error) = joined {
                        if !error.is_cancelled() {
                            accept_failure =
                                Some(format!("mTLS invalidation connection task failed: {error}"));
                            break 'accept;
                        }
                    }
                }
            }
            let drain_result =
                drain_mtls_connections(&mut connections_guard, MTLS_CONNECTION_DRAIN_TIMEOUT).await;
            if drain_result.is_ok() {
                let _connections = connections_guard.finish();
            }
            match (accept_failure, drain_result) {
                (Some(error), Ok(())) => Err(error),
                (Some(error), Err(drain_error)) => Err(format!("{error}; {drain_error}")),
                (None, result) => result,
            }
        })
        .await;
    });
    Ok(MtlsInvalidationReceiverHandle {
        shutdown,
        join: Some(join),
        lifecycle,
    })
}

pub struct OwnedInvalidationTransportHandles {
    pub leg_worker: Option<RecipientLegWorkerHandle>,
    pub mtls_receiver: Option<MtlsInvalidationReceiverHandle>,
    pub rabbit_receiver: Option<RabbitRecipientReceiverHandle>,
    lifecycle: InvalidationTransportLifecycle,
}

impl OwnedInvalidationTransportHandles {
    pub fn empty() -> Self {
        Self {
            leg_worker: None,
            mtls_receiver: None,
            rabbit_receiver: None,
            lifecycle: InvalidationTransportLifecycle::new(0),
        }
    }

    pub fn lifecycle(&self) -> InvalidationTransportLifecycle {
        self.lifecycle.clone()
    }

    pub async fn wait_until_ready(&self, budget: Duration) -> Result<(), String> {
        self.lifecycle.wait_until_ready(budget).await
    }

    pub async fn wait_for_failure(&self) -> String {
        self.lifecycle.wait_for_failure().await
    }

    pub async fn shutdown(self, budget: Duration) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        let lifecycle = self.lifecycle.clone();
        lifecycle.set_shutdown_deadline(deadline);
        lifecycle.begin_shutdown();
        if let Some(receiver) = self.mtls_receiver.as_ref() {
            receiver.signal_shutdown();
        }
        if let Some(receiver) = self.rabbit_receiver.as_ref() {
            receiver.signal_shutdown();
        }
        if let Some(worker) = self.leg_worker.as_ref() {
            worker.signal_shutdown();
        }
        let mut failures = Vec::new();
        let mut receiver = self.mtls_receiver;
        if let Some(receiver_handle) = receiver.as_mut() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, receiver_handle.shutdown_and_join()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error),
                Err(_) => {
                    failures.push("mTLS receiver shutdown timed out".into());
                    failures.push(receiver_handle.abort_and_reap(&lifecycle, deadline).await);
                }
            }
        }
        let mut rabbit_receiver = self.rabbit_receiver;
        if let Some(receiver_handle) = rabbit_receiver.as_mut() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, receiver_handle.shutdown_and_join()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error),
                Err(_) => {
                    failures.push("Rabbit recipient receiver shutdown timed out".into());
                    failures.push(receiver_handle.abort_and_reap(&lifecycle, deadline).await);
                }
            }
        }
        let mut leg_worker = self.leg_worker;
        if let Some(worker_handle) = leg_worker.as_mut() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, worker_handle.shutdown_and_join()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(error),
                Err(_) => {
                    failures.push("recipient leg worker shutdown timed out".into());
                    failures.push(worker_handle.abort_and_reap(&lifecycle, deadline).await);
                }
            }
        }
        if let Err(error) = lifecycle.wait_for_reapers(deadline).await {
            failures.push(error);
        }
        if failures.is_empty() {
            lifecycle.mark_shutdown_complete()
        } else {
            let error = failures.join("; ");
            lifecycle.mark_shutdown_failed(error.clone());
            Err(error)
        }
    }
}

pub struct InvalidationTransportStartSpec<'a> {
    pub config: &'a astral_common::config::AppConfig,
    pub delivery: &'a delivery::InvalidationDeliveryContext,
    pub pool: sqlx::MySqlPool,
    pub rabbit_connection: Arc<lapin::Connection>,
    pub owner: String,
    pub poll_interval: Duration,
    pub apply: Arc<dyn InvalidationApply>,
}

fn bounded_shutdown_error(startup_error: String, cleanup_error: Option<String>) -> String {
    match cleanup_error {
        Some(cleanup_error) => format!("{startup_error}; startup cleanup: {cleanup_error}"),
        None => startup_error,
    }
}

async fn shutdown_started_transport(handles: OwnedInvalidationTransportHandles) -> Option<String> {
    handles.shutdown(Duration::from_secs(5)).await.err()
}

pub async fn start_invalidation_transport(
    spec: InvalidationTransportStartSpec<'_>,
) -> Result<OwnedInvalidationTransportHandles, String> {
    if spec.owner.trim().is_empty() || spec.poll_interval.is_zero() {
        return Err("invalidation transport owner and poll interval are required".into());
    }
    let config = &spec.config.invalidation_delivery;
    if !config.enabled {
        return Err("invalidation delivery is disabled".into());
    }
    if spec.delivery.source_database_id() != config.source_database_id
        || spec.delivery.roster_version() != config.roster_version
    {
        return Err("frozen delivery context does not match AppConfig startup values".into());
    }
    if config.mtls_receiver_database_id != spec.delivery.source_database_id()
        || config.mtls_receiver_region_id != spec.config.region_id
        || config.mtls_receiver_node_id != spec.config.node_id
    {
        return Err("invalidation receiver identity does not match root startup identity".into());
    }
    let rabbit_allowed_source_database_ids =
        serde_json::from_str::<Vec<String>>(&config.rabbit_allowed_source_database_ids_json)
            .map_err(|error| format!("Rabbit source allowlist JSON: {error}"))?;
    if rabbit_allowed_source_database_ids.is_empty()
        || rabbit_allowed_source_database_ids.len() > 64
    {
        return Err("Rabbit recipient source allowlist must contain 1..=64 entries".into());
    }
    let mut seen_source_database_ids =
        HashSet::with_capacity(rabbit_allowed_source_database_ids.len());
    let rabbit_allowed_source_database_ids = rabbit_allowed_source_database_ids
        .into_iter()
        .map(|value| value.trim().to_owned())
        .collect::<Vec<_>>();
    if rabbit_allowed_source_database_ids.iter().any(|value| {
        value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || !seen_source_database_ids.insert(value.clone())
    }) {
        return Err(
            "Rabbit recipient source allowlist contains invalid or duplicate database identity"
                .into(),
        );
    }
    let rabbit_allowed_source_database_ids = rabbit_allowed_source_database_ids
        .into_iter()
        .collect::<HashSet<_>>();
    let rabbit_channel = spec
        .rabbit_connection
        .create_channel()
        .await
        .map_err(|error| format!("create invalidation Rabbit channel: {error}"))?;
    let repository = delivery::InvalidationDeliveryRepository::new(spec.pool.clone());
    let rabbit_transport = RabbitRecipientTransport::new(
        rabbit_channel.clone(),
        spec.delivery.source_database_id().to_owned(),
        repository.clone(),
    )
    .await
    .map_err(|error| format!("construct Rabbit recipient transport: {error}"))?;
    let mtls_sender = match (
        config.mtls_client_identity_pem_path.as_deref(),
        config.mtls_server_ca_pem_path.as_deref(),
    ) {
        (Some(identity_pem), Some(server_ca)) => Some(MtlsRecipientSender::from_pem_paths(
            identity_pem,
            server_ca,
        )?),
        (None, None) => None,
        _ => return Err("mTLS client identity and server CA must be configured together".into()),
    };
    let needs_mtls = spec.delivery.recipients().iter().any(|recipient| {
        matches!(
            recipient.transport,
            delivery::InvalidationDeliveryTransport::SameDbMtls
        )
    });
    if needs_mtls && mtls_sender.is_none() {
        return Err("same-db recipient exists but mTLS sender is not configured".into());
    }
    let rabbit_receiver_config = RabbitRecipientReceiverConfig {
        database_id: config.mtls_receiver_database_id.clone(),
        identity: NodeIdentity::try_from_parts(
            config.mtls_receiver_region_id.clone(),
            config.mtls_receiver_node_id.clone(),
        )?,
        allowed_source_database_ids: rabbit_allowed_source_database_ids,
        prefetch: config.mtls_receiver_max_connections.min(u16::MAX as usize) as u16,
    };
    let mtls_receiver_config = if config.mtls_receiver_bind_address.is_some() {
        Some(mtls_receiver_config_from_app_config(spec.config)?)
    } else {
        None
    };
    let dispatcher = RecipientTransportDispatcher::new(mtls_sender, rabbit_transport);
    let expected_owners = 2 + usize::from(mtls_receiver_config.is_some());
    let lifecycle = InvalidationTransportLifecycle::new(expected_owners);
    let leg_worker = spawn_recipient_leg_worker(
        repository,
        dispatcher,
        spec.owner,
        spec.poll_interval,
        lifecycle.clone(),
    )?;
    let mut handles = OwnedInvalidationTransportHandles {
        leg_worker: Some(leg_worker),
        mtls_receiver: None,
        rabbit_receiver: None,
        lifecycle: lifecycle.clone(),
    };
    let rabbit_receiver = match start_rabbit_recipient_receiver(
        rabbit_channel.clone(),
        rabbit_receiver_config,
        spec.pool.clone(),
        Arc::clone(&spec.apply),
        lifecycle.clone(),
    )
    .await
    {
        Ok(receiver) => receiver,
        Err(error) => {
            let cleanup = shutdown_started_transport(handles).await;
            return Err(bounded_shutdown_error(
                format!("start Rabbit recipient receiver: {error}"),
                cleanup,
            ));
        }
    };
    handles.rabbit_receiver = Some(rabbit_receiver);
    if let Some(receiver_config) = mtls_receiver_config {
        match start_mtls_invalidation_receiver(
            receiver_config,
            spec.pool,
            Arc::clone(&spec.apply),
            lifecycle.clone(),
        )
        .await
        {
            Ok(receiver) => handles.mtls_receiver = Some(receiver),
            Err(error) => {
                let cleanup = shutdown_started_transport(handles).await;
                return Err(bounded_shutdown_error(
                    format!("start mTLS invalidation receiver: {error}"),
                    cleanup,
                ));
            }
        }
    }
    match lifecycle.wait_until_ready(TRANSPORT_STARTUP_TIMEOUT).await {
        Ok(()) => Ok(handles),
        Err(error) => {
            let cleanup = shutdown_started_transport(handles).await;
            Err(bounded_shutdown_error(error, cleanup))
        }
    }
}

fn mtls_receiver_config_from_app_config(
    config: &astral_common::config::AppConfig,
) -> Result<MtlsReceiverConfig, String> {
    let delivery = &config.invalidation_delivery;
    let bind_address = delivery
        .mtls_receiver_bind_address
        .clone()
        .ok_or_else(|| "mTLS receiver bind address is required".to_owned())?;
    let server_certificate_pem_path = delivery
        .mtls_receiver_server_cert_pem_path
        .clone()
        .ok_or_else(|| "mTLS receiver server certificate is required".to_owned())?;
    let server_private_key_pem_path = delivery
        .mtls_receiver_server_key_pem_path
        .clone()
        .ok_or_else(|| "mTLS receiver server private key is required".to_owned())?;
    let client_ca_pem_path = delivery
        .mtls_receiver_client_ca_pem_path
        .clone()
        .ok_or_else(|| "mTLS receiver client CA is required".to_owned())?;
    let identity = NodeIdentity::try_from_parts(
        delivery.mtls_receiver_region_id.clone(),
        delivery.mtls_receiver_node_id.clone(),
    )?;
    let peers = serde_json::from_str::<Vec<astral_common::config::InvalidationReceiverPeerConfig>>(
        &delivery.mtls_receiver_allowed_peer_fingerprints_json,
    )
    .map_err(|error| format!("mTLS receiver peer allowlist JSON: {error}"))?;
    let allowed_peers = peers
        .into_iter()
        .map(|peer| {
            let identity =
                NodeIdentity::try_from_parts(peer.region_id.clone(), peer.node_id.clone())?;
            Ok::<_, String>((
                peer.certificate_sha256.clone(),
                AuthenticatedPeer {
                    database_id: peer.database_id,
                    region_id: identity.region().to_owned(),
                    node_id: identity.node().to_owned(),
                    certificate_sha256: peer.certificate_sha256,
                },
            ))
        })
        .collect::<Result<HashMap<_, _>, String>>()?;
    Ok(MtlsReceiverConfig {
        bind_address,
        server_certificate_pem_path,
        server_private_key_pem_path,
        client_ca_pem_path,
        identity,
        database_id: delivery.mtls_receiver_database_id.clone(),
        allowed_peers,
        max_connections: delivery.mtls_receiver_max_connections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn wait_for_transport_join_reuses_handle_after_timeout() {
        let (release_tx, release_rx) = oneshot::channel();
        let mut join = Some(tokio::spawn(async move {
            let _ = release_rx.await;
        }));
        let first = tokio::time::timeout(
            Duration::from_millis(1),
            wait_for_transport_join(&mut join, "test owner"),
        )
        .await;
        assert!(first.is_err());
        assert!(join.is_some());
        release_tx.send(()).unwrap();
        wait_for_transport_join(&mut join, "test owner")
            .await
            .unwrap();
        assert!(join.is_none());
    }

    #[tokio::test]
    async fn abort_reap_reports_timeout_and_removes_join_handle() {
        let mut join = Some(tokio::spawn(std::future::pending::<()>()));
        let lifecycle = InvalidationTransportLifecycle::new(0);
        let error = abort_and_reap_transport_join(
            &mut join,
            "test owner",
            Instant::now() + Duration::from_secs(1),
            &lifecycle,
        );
        let error = error.await;
        assert!(error.contains("aborted and reaped"));
        assert!(join.is_none());
    }
    #[test]
    fn certificate_pin_is_der_digest_not_ca_identity() {
        let first = certificate_sha256(b"leaf-a");
        let second = certificate_sha256(b"leaf-b");
        assert_ne!(first, second);
        assert!(is_sha256_fingerprint(&first));
    }

    #[test]
    fn recipient_route_is_node_specific() {
        let a = NodeIdentity::try_from_parts("r", "a").unwrap();
        let b = NodeIdentity::try_from_parts("r", "b").unwrap();
        assert_ne!(recipient_route_key("db", &a), recipient_route_key("db", &b));
        assert_ne!(
            recipient_route_key("db-a", &a),
            recipient_route_key("db-b", &a)
        );
    }

    #[tokio::test]
    async fn lifecycle_ready_waits_for_owner_initialization() {
        let lifecycle = InvalidationTransportLifecycle::new(1);
        let owner = lifecycle.clone();
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(run_owned_transport_task(
            lifecycle.clone(),
            "test-owner",
            async move {
                release_rx.await.map_err(|error| error.to_string())?;
                owner.mark_ready("test-owner");
                std::future::pending::<Result<(), String>>().await
            },
        ));
        let timeout_error = lifecycle
            .wait_until_ready(Duration::from_millis(5))
            .await
            .unwrap_err();
        assert!(timeout_error.contains("readiness timed out"));
        release_tx.send(()).unwrap();
        lifecycle
            .wait_until_ready(Duration::from_secs(1))
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn lifecycle_waiters_observe_ready_and_failure_without_lost_wake() {
        let lifecycle = InvalidationTransportLifecycle::new(1);
        let ready = lifecycle.clone();
        let owner = ready.clone();
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(run_owned_transport_task(
            ready.clone(),
            "test-owner",
            async move {
                owner.mark_ready("test-owner");
                release_rx.await.map_err(|error| error.to_string())?;
                Ok(())
            },
        ));
        ready
            .wait_until_ready(Duration::from_secs(1))
            .await
            .unwrap();
        release_tx.send(()).unwrap();
        let reason = tokio::time::timeout(Duration::from_secs(1), ready.wait_for_failure())
            .await
            .unwrap();
        assert!(reason.contains("stopped before shutdown"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn lifecycle_supervisor_fail_closes_error_and_panic() {
        async fn run_case<F>(task: F)
        where
            F: std::future::Future<Output = Result<(), String>> + Send + 'static,
        {
            let lifecycle = InvalidationTransportLifecycle::new(1);
            let join = tokio::spawn(run_owned_transport_task(
                lifecycle.clone(),
                "test-owner",
                task,
            ));
            let reason = tokio::time::timeout(Duration::from_secs(1), lifecycle.wait_for_failure())
                .await
                .unwrap();
            assert!(reason.contains("test-owner"));
            join.await.unwrap();
            assert!(matches!(
                lifecycle.state(),
                InvalidationTransportLifecycleState::Failed(_)
            ));
        }

        run_case(async { Err::<(), String>("injected error".into()) }).await;
        run_case(async {
            std::panic::resume_unwind(Box::new("injected panic"));
        })
        .await;
    }

    #[tokio::test]
    async fn lifecycle_supervisor_marks_cancelled_owner_failed() {
        let lifecycle = InvalidationTransportLifecycle::new(1);
        let owner = lifecycle.clone();
        let join = tokio::spawn(run_owned_transport_task(
            lifecycle.clone(),
            "test-owner",
            async move {
                owner.mark_ready("test-owner");
                std::future::pending::<Result<(), String>>().await
            },
        ));
        lifecycle
            .wait_until_ready(Duration::from_secs(1))
            .await
            .unwrap();
        join.abort();
        let join_error = join.await.unwrap_err();
        assert!(join_error.is_cancelled());
        let reason = tokio::time::timeout(Duration::from_secs(1), lifecycle.wait_for_failure())
            .await
            .unwrap();
        assert!(reason.contains("cancelled"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_transport_owners_share_one_shutdown_budget() {
        fn blocked_owner() -> (JoinHandle<()>, mpsc::Sender<()>) {
            let (started, running) = mpsc::channel();
            let (release, wait) = mpsc::channel();
            let join = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                wait.recv().unwrap();
            });
            running.recv_timeout(Duration::from_secs(1)).unwrap();
            (join, release)
        }
        let lifecycle = InvalidationTransportLifecycle::new(3);
        let (mtls, release_mtls) = blocked_owner();
        let (rabbit, release_rabbit) = blocked_owner();
        let (worker, release_worker) = blocked_owner();
        let (shutdown, _) = watch::channel(false);
        let handles = OwnedInvalidationTransportHandles {
            mtls_receiver: Some(MtlsInvalidationReceiverHandle {
                shutdown: shutdown.clone(),
                join: Some(mtls),
                lifecycle: lifecycle.clone(),
            }),
            rabbit_receiver: Some(RabbitRecipientReceiverHandle {
                shutdown: shutdown.clone(),
                join: Some(rabbit),
                lifecycle: lifecycle.clone(),
            }),
            leg_worker: Some(RecipientLegWorkerHandle {
                shutdown,
                join: Some(worker),
                lifecycle: lifecycle.clone(),
            }),
            lifecycle: lifecycle.clone(),
        };
        let start = Instant::now();
        let result = handles.shutdown(Duration::from_millis(20)).await;
        let elapsed = start.elapsed();
        release_mtls.send(()).unwrap();
        release_rabbit.send(()).unwrap();
        release_worker.send(()).unwrap();
        lifecycle
            .wait_for_reapers(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(result.unwrap_err().contains("unknown"));
        assert!(elapsed < Duration::from_millis(250), "elapsed: {elapsed:?}");
        assert!(matches!(
            lifecycle.state(),
            InvalidationTransportLifecycleState::Failed(_)
        ));
    }
}
