//! Production delivery subsystem: real transports with typed truth.
//!
//! This module is the single shared delivery owner for every caller in the
//! workspace (monitor alert dispatch, monitor notification test endpoint,
//! identity password reset, verification OTP). It provides:
//!
//! - [`state`]: typed delivery truth — provider acknowledgements cap at
//!   `ACCEPTED`; `DELIVERED` requires explicit receipt proof; `IN_DOUBT`
//!   blocks retries until explicit reconciliation.
//! - [`intent`]: bounded message composition (CRLF-injection safe).
//! - [`lease`]: CAS/generation attempt decisions (pure logic).
//! - [`store`]: durable intent port + in-memory reference store.
//! - [`store_sqlx`]: MySQL-backed store over `al_delivery_intent`.
//! - [`channel_config`]: channel JSON resolution with env-ref-only secrets.
//! - [`credential`]: protected env-ref secret resolution.
//! - [`endpoint`]: SSRF/allowlist/TLS endpoint policy + guarded DNS.
//! - [`email`]: real SMTP client (STARTTLS enforced, downgrade refused).
//! - [`http`]: real HTTPS relay/webhook transport (redirection off).
//! - [`owner`]: the [`owner::DeliveryOwner`] composition root.

pub mod channel_config;
pub mod credential;
pub mod email;
pub mod endpoint;
pub mod http;
pub mod intent;
pub mod lease;
pub mod owner;
pub mod state;
pub mod store;
pub mod store_sqlx;

pub use channel_config::{resolve_channel, ResolvedChannel};
pub use intent::{ChannelKind, DeliveryMessage, PayloadClass};
pub use lease::{AttemptLease, NextAction, WorkerIdentity};
pub use owner::{
    dispatch_channel_test, reconcile_in_doubt, ChannelTransport, DeliveryLimits, DeliveryOwner,
    OwnerAttemptLease,
};
pub use state::{DeliveryError, DeliveryState, DeliveryTruth};
pub use store::{DeliveryStore, InMemoryDeliveryStore, IntentRecord};
pub use store_sqlx::SqlxDeliveryIntentRepository;
