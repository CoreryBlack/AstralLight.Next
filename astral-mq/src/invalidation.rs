//! Typed invalidation contracts shared by the local bus and the Rabbit adapter.
//!
//! P3 starts with a transport-neutral contract. The event carries only
//! freshness/revocation metadata; consumers must re-read authoritative data
//! through the strict reader instead of treating this payload as authorization
//! data. Durable fanout, watermarks, and reconciliation are separate stages.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use astral_types::PublishedEvidenceAggregate;

use crate::envelope::MessageEnvelope;

pub const INVALIDATION_SCHEMA_VERSION: i32 = 1;
pub const INVALIDATION_QUEUE: &str = "astral.authorization.invalidation";
pub const INVALIDATION_ROUTING_KEY: &str = "authorization.invalidation";
pub const EVIDENCE_INVALIDATED: &str = "EVIDENCE_INVALIDATED";
pub const ELIGIBILITY_INVALIDATED: &str = "ELIGIBILITY_INVALIDATED";
pub const SESSION_REVOKED: &str = "SESSION_REVOKED";

/// Per-event bound for revoked JTIs; also the shard size of the bounded
/// stable SESSION_REVOKED sharding. Crate-visible so the revocation consumer
/// pins its snapshot capacity arithmetic to the same constant.
pub(crate) const MAX_REVOKED_JTIS: usize = 1024;
const MAX_JTI_BYTES: usize = 128;
const MAX_ORDERING_KEY_BYTES: usize = 192;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InvalidationContractError {
    #[error("invalidation field `{0}` must be positive")]
    NonPositiveField(&'static str),
    #[error("invalidation field `{0}` exceeds the supported bound")]
    FieldTooLarge(&'static str),
    #[error("evidence invalidation aggregate scope is inconsistent: {0}")]
    InvalidAggregateScope(String),
    #[error("evidence invalidation revoke fence exceeds source generation")]
    RevokeFenceExceedsSourceGeneration,
    #[error("session revocation must provide at least one revoked JTI")]
    EmptySessionRevocation,
    #[error("session revocation contains a blank JTI")]
    BlankJti,
    #[error("session revocation contains a duplicate JTI")]
    DuplicateJti,
    #[error("invalid invalidation envelope: {0}")]
    InvalidEnvelope(String),
    #[error("unsupported invalidation message type `{0}`")]
    UnsupportedMessageType(String),
    #[error("invalid invalidation payload: {0}")]
    InvalidPayload(String),
    #[error("invalidation payload serialization failed: {0}")]
    Serialization(String),
}

/// An authorization publication has become unsafe to use for this scope.
/// `published_generation` belongs to the published aggregate named by this
/// event. `source_generation` and `revoke_fence` are the CARD-parent lineage
/// proof carried by the ledger mutation; for `USER_CARD` the identities
/// coincide, while RULE_SET/APPROVAL/DELEGATION contributions inherit the
/// CARD source values. Consumers may match the full tuple only within the
/// event's pending scope and must never compare counters across aggregate
/// domains or use one aggregate's completion proof for another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceInvalidated {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: PublishedEvidenceAggregate,
    pub aggregate_id: i64,
    pub published_generation: u64,
    pub source_generation: u64,
    /// Zero is a valid initial revoke-fence value for a proven publication.
    pub revoke_fence: u64,
}

impl EvidenceInvalidated {
    fn validate(&self) -> Result<(), InvalidationContractError> {
        validate_positive(self.tenant_id, "tenant_id")?;
        if let Some(card_id) = self.card_id {
            validate_positive(card_id, "card_id")?;
        }
        validate_positive(self.aggregate_id, "aggregate_id")?;
        validate_positive(self.published_generation, "published_generation")?;
        validate_positive(self.source_generation, "source_generation")?;
        if self.revoke_fence > self.source_generation {
            return Err(InvalidationContractError::RevokeFenceExceedsSourceGeneration);
        }

        if self.card_id.is_some_and(|card_id| {
            self.aggregate_type == PublishedEvidenceAggregate::UserCard
                && card_id != self.aggregate_id
        }) {
            return Err(InvalidationContractError::InvalidAggregateScope(
                "USER_CARD aggregate_id must equal card_id when card scope is present".into(),
            ));
        }
        Ok(())
    }
}

/// A card's eligibility-derived cache/head is no longer safe to use.
/// The current eligibility key is globally card-scoped, so this contract does
/// not invent a tenant filter that the authoritative path does not possess.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EligibilityInvalidated {
    pub card_id: i64,
}

impl EligibilityInvalidated {
    fn validate(&self) -> Result<(), InvalidationContractError> {
        validate_positive(self.card_id, "card_id")
    }
}

/// A user's selected session JTIs have been revoked.
///
/// A user-wide `min_valid_epoch` is intentionally absent: the durable model
/// currently fences `session_epoch` per session, not with one user-level
/// watermark. Until that durable watermark exists, a JTI snapshot is the only
/// selector this event may claim as sufficient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRevoked {
    pub user_id: i64,
    pub revoked_jtis: Vec<String>,
}

impl SessionRevoked {
    fn validate(&self) -> Result<(), InvalidationContractError> {
        validate_positive(self.user_id, "user_id")?;
        if self.revoked_jtis.len() > MAX_REVOKED_JTIS {
            return Err(InvalidationContractError::FieldTooLarge("revoked_jtis"));
        }
        if self.revoked_jtis.is_empty() {
            return Err(InvalidationContractError::EmptySessionRevocation);
        }

        let mut seen = HashSet::with_capacity(self.revoked_jtis.len());
        for jti in &self.revoked_jtis {
            if jti.trim().is_empty() {
                return Err(InvalidationContractError::BlankJti);
            }
            if jti.len() > MAX_JTI_BYTES {
                return Err(InvalidationContractError::FieldTooLarge("jti"));
            }
            if !seen.insert(jti) {
                return Err(InvalidationContractError::DuplicateJti);
            }
        }
        Ok(())
    }
}

/// P3's closed set of freshness/revocation notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationEvent {
    EvidenceInvalidated(EvidenceInvalidated),
    EligibilityInvalidated(EligibilityInvalidated),
    SessionRevoked(SessionRevoked),
}

impl InvalidationEvent {
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::EvidenceInvalidated(_) => EVIDENCE_INVALIDATED,
            Self::EligibilityInvalidated(_) => ELIGIBILITY_INVALIDATED,
            Self::SessionRevoked(_) => SESSION_REVOKED,
        }
    }

    /// Tenant metadata belongs in the common envelope where it exists in the
    /// contract. Session and eligibility IDs are globally scoped in this first
    /// contract revision and therefore do not invent a tenant fallback.
    pub fn tenant_id(&self) -> Option<i64> {
        match self {
            Self::EvidenceInvalidated(value) => Some(value.tenant_id),
            Self::EligibilityInvalidated(_) | Self::SessionRevoked(_) => None,
        }
    }

    /// The ordering key is stable and scope-local. It is not a proof of
    /// durability; consumers still need a watermark/reconciliation layer.
    pub fn ordering_key(&self) -> String {
        match self {
            Self::EvidenceInvalidated(value) => format!(
                "authorization:evidence:tenant/{}/aggregate/{}/{}/card/{}",
                value.tenant_id,
                value.aggregate_type,
                value.aggregate_id,
                value
                    .card_id
                    .map_or_else(|| "all".to_owned(), |card_id| card_id.to_string())
            ),
            Self::EligibilityInvalidated(value) => {
                format!("authorization:eligibility/card/{}", value.card_id)
            }
            Self::SessionRevoked(value) => {
                format!("identity:session/user/{}", value.user_id)
            }
        }
    }

    pub fn validate(&self) -> Result<(), InvalidationContractError> {
        match self {
            Self::EvidenceInvalidated(value) => value.validate(),
            Self::EligibilityInvalidated(value) => value.validate(),
            Self::SessionRevoked(value) => value.validate(),
        }?;
        if self.ordering_key().len() > MAX_ORDERING_KEY_BYTES {
            return Err(InvalidationContractError::FieldTooLarge("ordering_key"));
        }
        Ok(())
    }

    fn payload(&self) -> Result<serde_json::Value, InvalidationContractError> {
        match self {
            Self::EvidenceInvalidated(value) => serde_json::to_value(value),
            Self::EligibilityInvalidated(value) => serde_json::to_value(value),
            Self::SessionRevoked(value) => serde_json::to_value(value),
        }
        .map_err(|error| InvalidationContractError::Serialization(error.to_string()))
    }

    /// Build a transport-neutral envelope without inventing message or
    /// operation IDs. Callers must provide stable IDs from the source mutation.
    pub fn to_envelope(
        &self,
        message_id: impl Into<String>,
        operation_id: impl Into<String>,
        origin_region: impl Into<String>,
    ) -> Result<MessageEnvelope, InvalidationContractError> {
        self.validate()?;
        let message_id = message_id.into();
        let operation_id = operation_id.into();
        let origin_region = origin_region.into();
        let mut envelope = MessageEnvelope::new(
            message_id,
            operation_id,
            self.message_type(),
            INVALIDATION_SCHEMA_VERSION,
            origin_region,
            self.payload()?,
        )
        .map_err(InvalidationContractError::InvalidEnvelope)?;
        envelope.tenant_id = self.tenant_id();
        envelope.ordering_key = Some(self.ordering_key());
        envelope
            .validate()
            .map_err(InvalidationContractError::InvalidEnvelope)?;
        Ok(envelope)
    }

    /// Decode and revalidate an envelope before dispatching it to a consumer.
    /// All envelope metadata that participates in scope routing is checked
    /// against the typed payload; mismatches fail closed.
    pub fn from_envelope(envelope: &MessageEnvelope) -> Result<Self, InvalidationContractError> {
        envelope
            .validate()
            .map_err(InvalidationContractError::InvalidEnvelope)?;
        if envelope.schema_version != INVALIDATION_SCHEMA_VERSION {
            return Err(InvalidationContractError::InvalidEnvelope(format!(
                "unsupported schemaVersion {}",
                envelope.schema_version
            )));
        }

        let event = match envelope.message_type.as_str() {
            EVIDENCE_INVALIDATED => Self::EvidenceInvalidated(
                serde_json::from_value(envelope.payload.clone()).map_err(|error| {
                    InvalidationContractError::InvalidPayload(error.to_string())
                })?,
            ),
            ELIGIBILITY_INVALIDATED => Self::EligibilityInvalidated(
                serde_json::from_value(envelope.payload.clone()).map_err(|error| {
                    InvalidationContractError::InvalidPayload(error.to_string())
                })?,
            ),
            SESSION_REVOKED => {
                Self::SessionRevoked(serde_json::from_value(envelope.payload.clone()).map_err(
                    |error| InvalidationContractError::InvalidPayload(error.to_string()),
                )?)
            }
            other => {
                return Err(InvalidationContractError::UnsupportedMessageType(
                    other.to_owned(),
                ))
            }
        };
        event.validate()?;

        if envelope.tenant_id != event.tenant_id() {
            return Err(InvalidationContractError::InvalidEnvelope(
                "tenantId does not match the typed invalidation scope".into(),
            ));
        }
        let expected_ordering_key = event.ordering_key();
        if envelope.ordering_key.as_deref() != Some(expected_ordering_key.as_str()) {
            return Err(InvalidationContractError::InvalidEnvelope(
                "orderingKey does not match the typed invalidation scope".into(),
            ));
        }
        Ok(event)
    }
}

fn validate_positive<T>(value: T, field: &'static str) -> Result<(), InvalidationContractError>
where
    T: PartialOrd + Default,
{
    if value <= T::default() {
        return Err(InvalidationContractError::NonPositiveField(field));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidationAppendError {
    #[error("invalid invalidation contract: {0}")]
    Contract(#[from] InvalidationContractError),
    #[error("invalid invalidation outbox append: {0}")]
    Database(#[from] astral_db::LocalMessageError),
}

/// Append an invalidation envelope to the caller's existing source
/// transaction. The function never commits, publishes to a broker, or touches
/// Redis; the caller owns the transaction boundary and must send any fanout
/// only after a proven commit.
pub async fn append_invalidation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    event: &InvalidationEvent,
    message_id: &str,
    operation_id: &str,
    origin_region: &str,
) -> Result<astral_db::LocalMessageAppend, InvalidationAppendError> {
    let envelope = event.to_envelope(message_id, operation_id, origin_region)?;
    let payload_json = envelope
        .envelope_json()
        .map_err(InvalidationContractError::Serialization)?;
    let input = astral_db::LocalMessageInput {
        message_id: &envelope.message_id,
        operation_id: &envelope.operation_id,
        message_type: event.message_type(),
        queue_name: INVALIDATION_QUEUE,
        ordering_key: envelope.ordering_key.as_deref(),
        tenant_id: envelope.tenant_id,
        origin_region: &envelope.origin_region,
        target_region: envelope.target_region.as_deref(),
        schema_version: envelope.schema_version,
        payload_json: &payload_json,
        headers_json: None,
        payload_sha256: &envelope.payload_sha256,
    };
    Ok(astral_db::append_in_tx(tx, &input).await?)
}

// ─────────────────────────────────────────────────────────────────────────────
// SESSION_REVOKED bounded stable sharding (producer-side durable intent)
// ─────────────────────────────────────────────────────────────────────────────
//
// The auth session revocation command captures the user's full ACTIVE JTI
// snapshot in its source transaction. That snapshot is unbounded, while this
// typed contract caps one SESSION_REVOKED event at [`MAX_REVOKED_JTIS`]
// entries. Massive revocations therefore split into a deterministic shard
// plan: every shard is a contract-valid SESSION_REVOKED event with a stable
// shard message id derived from the source operation id, and every shard is
// durably appended to the caller's source transaction (no MQ/network inside
// the transaction). Delivery stays with the existing post-commit relay/fanout
// infrastructure; an unknown delivery outcome is never replayed blindly (the
// relay quarantines or marks IN_DOUBT, and re-appends of the same operation
// resolve to the identical committed bytes or fail closed).

/// One bounded, stably identified SESSION_REVOKED shard of a larger snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRevocationShardPlan {
    /// 1-based shard position; stable for the lifetime of the operation.
    pub shard_index: usize,
    /// Total shard count derived from the canonical snapshot size.
    pub shard_total: usize,
    /// Stable outbox identity, deterministic per `(base_operation_id,
    /// shard_index)` and bounded by the outbox message-id column. Bases within
    /// the suffix budget keep the historical `{base_operation_id}#s/{index}`
    /// form; longer bases use the compact derived form `sh#{sha256}`. The id
    /// never encodes shard content, so a same-operation re-plan that changes
    /// shard bodies still reuses the identical message id and the durable
    /// outbox bodyhash conflict stays fail closed.
    pub message_id: String,
    /// The source mutation's stable operation id, unchanged across shards so
    /// the whole fanout remains correlatable to one revocation operation.
    pub operation_id: String,
    /// The contract-valid typed event carried by this shard.
    pub event: InvalidationEvent,
}

/// Outbox `message_id` column bound (`al_message_outbox.message_id`); also
/// the `al_message_outbox.operation_id` contract bound for the base id.
const SHARD_MESSAGE_ID_BOUND: usize = 128;
/// Stable shard suffix; `#` never appears in UUID operation ids, keeping the
/// base id recoverable and the shard namespace collision-free.
const SHARD_MESSAGE_SUFFIX: &str = "#s/";
/// Digits reserved for the 1-based shard index (`u32` range, 10 digits). The
/// base operation id must leave this suffix budget free so composing the
/// shard id can never overflow the outbox column for a legal base id.
const SHARD_INDEX_DIGITS_RESERVED: usize = 10;
/// Legacy suffix-fit budget: `128 - "#s/" - 10 index digits`. Base ids at or
/// below this bound keep the historical `{base}#s/{index}` shard id byte for
/// byte; longer bases (up to [`SESSION_REVOCATION_BASE_OPERATION_ID_BOUND`])
/// switch to the compact derived form instead of narrowing the accepted
/// operation-id contract.
pub const SESSION_REVOCATION_SHARD_BASE_OPERATION_ID_BOUND: usize =
    SHARD_MESSAGE_ID_BOUND - SHARD_MESSAGE_SUFFIX.len() - SHARD_INDEX_DIGITS_RESERVED;
/// Accepted base operation-id bound: the `al_message_outbox.operation_id`
/// column contract (128). Every operation id valid for the durable outbox is
/// planable; the shard message id cannot overflow the message-id column
/// because long bases use the derived compact form.
pub const SESSION_REVOCATION_BASE_OPERATION_ID_BOUND: usize = SHARD_MESSAGE_ID_BOUND;
/// Prefix of the derived compact shard id form: `sh#` + 64 lowercase hex
/// digest chars = 67 bytes, well inside the outbox message-id column. The
/// derived form never contains `#s/` (the marker every suffix-composed shard
/// id carries), so the two id namespaces are provably disjoint.
const SHARD_DERIVED_ID_PREFIX: &str = "sh#";
/// Domain-separation tag for the derived shard id digest. Hashing the domain
/// tag, the base id byte length (length framing defeats prefix ambiguity),
/// the base id bytes and the shard index keeps the id a pure deterministic
/// function of `(base, shard_index)` — never of the snapshot content — so a
/// same-operation re-plan that changes shard bodies still collides on the
/// same message id and the durable bodyhash conflict stays fail closed.
const SHARD_DERIVED_ID_DOMAIN: &[u8] = b"astral-mq:session-revocation-shard-message-id:v1";

/// Compact derived shard message id for base operation ids that cannot carry
/// the legacy suffix without overflowing the outbox message-id column.
///
/// The digest is domain-separated over [`SHARD_DERIVED_ID_DOMAIN`], the base
/// id byte length, the base id bytes and the 1-based shard index, so the
/// result is deterministic per `(base, shard_index)`, distinct per shard, and
/// distinct across bases (up to a SHA-256 collision).
fn derived_shard_message_id(base_operation_id: &str, shard_index: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SHARD_DERIVED_ID_DOMAIN);
    hasher.update([0u8]);
    hasher.update((base_operation_id.len() as u64).to_be_bytes());
    hasher.update(base_operation_id.as_bytes());
    hasher.update((shard_index as u64).to_be_bytes());
    let digest = hasher.finalize();
    format!("{SHARD_DERIVED_ID_PREFIX}{digest:x}")
}

/// Pure canonical shard planner for a SESSION_REVOKED JTI snapshot.
///
/// - Empty input yields zero shards: nothing was revoked, so nothing may be
///   notified (the typed contract itself rejects an empty snapshot).
/// - The snapshot is treated as a set: duplicates collapse and entries are
///   ordered lexicographically, so the same JTI set always produces the exact
///   same shards regardless of source row order or repeated input ("重复稳定").
/// - Shard count is `ceil(n / MAX_REVOKED_JTIS)`; every shard is validated
///   against the typed contract, so oversized/blank JTIs and invalid ids fail
///   closed before any durable append is attempted.
/// - The base operation id follows the durable outbox contract: blank ids
///   fail, ids up to [`SESSION_REVOCATION_BASE_OPERATION_ID_BOUND`] (128
///   bytes) are accepted, and every previously valid id (up to the legacy
///   [`SESSION_REVOCATION_SHARD_BASE_OPERATION_ID_BOUND`] suffix budget)
///   keeps its exact historical `{base}#s/{index}` shard id. Longer bases
///   derive a domain-separated SHA-256 compact shard id instead; the
///   envelope `operationId` always stays the original, untouched base id.
pub fn plan_session_revocation_shards(
    user_id: i64,
    revoked_jtis: &[String],
    base_operation_id: &str,
) -> Result<Vec<SessionRevocationShardPlan>, InvalidationContractError> {
    validate_positive(user_id, "user_id")?;
    if base_operation_id.trim().is_empty() {
        return Err(InvalidationContractError::InvalidEnvelope(
            "session revocation shards require a stable base operation id".into(),
        ));
    }
    if base_operation_id.len() > SESSION_REVOCATION_BASE_OPERATION_ID_BOUND {
        return Err(InvalidationContractError::FieldTooLarge(
            "base_operation_id (exceeds the outbox operation-id bound)",
        ));
    }
    // Canonical set encoding: dedupe + lexicographic order keeps shard
    // membership and ordering stable across producer retries and source row
    // order differences.
    let mut canonical: Vec<&str> = revoked_jtis.iter().map(String::as_str).collect();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.is_empty() {
        return Ok(Vec::new());
    }

    let shard_total = canonical.len().div_ceil(MAX_REVOKED_JTIS);
    let mut plans = Vec::with_capacity(shard_total);
    for (offset, chunk) in canonical.chunks(MAX_REVOKED_JTIS).enumerate() {
        let shard_index = offset + 1;
        // Bases within the legacy suffix budget keep the historical composed
        // id byte for byte (backward compatibility with already-durable rows);
        // longer — still contract-valid — bases use the compact derived form
        // so the message-id column bound can never overflow.
        let message_id =
            if base_operation_id.len() <= SESSION_REVOCATION_SHARD_BASE_OPERATION_ID_BOUND {
                format!("{base_operation_id}{SHARD_MESSAGE_SUFFIX}{shard_index}")
            } else {
                derived_shard_message_id(base_operation_id, shard_index)
            };
        let event = InvalidationEvent::SessionRevoked(SessionRevoked {
            user_id,
            revoked_jtis: chunk.iter().map(|jti| (*jti).to_owned()).collect(),
        });
        // Fail closed on contract violations (blank/oversized JTI, duplicate,
        // bound overflow) before the caller enters any durable append.
        event.validate()?;
        plans.push(SessionRevocationShardPlan {
            shard_index,
            shard_total,
            operation_id: base_operation_id.to_owned(),
            message_id,
            event,
        });
    }
    Ok(plans)
}

/// Process-wide frozen origin region for durable invalidation appends made
/// from inside astral-mq (the auth session revocation command consumer).
///
/// This is the shared freeze install point for every runtime that hosts the
/// revocation consumer (composite TrustGraph runtime and the standalone
/// Identity runtime): the deployment region comes from the startup-validated
/// `AppConfig.region_id` — never from a second env parser — so the envelope
/// origin cannot drift from the configured process identity. First value wins
/// for the process lifetime; a same-value re-install is idempotent, a
/// conflicting value fails closed.
pub fn install_origin_region(region: impl Into<String>) -> Result<(), String> {
    let region = region.into();
    if region.trim().is_empty() {
        return Err("invalidation origin region must not be blank".into());
    }
    if let Some(existing) = ORIGIN_REGION.get() {
        return if existing == &region {
            Ok(())
        } else {
            Err("invalidation origin region conflicts with the installed process identity".into())
        };
    }
    ORIGIN_REGION
        .set(region)
        .map_err(|_| "invalidation origin region was already installed".to_owned())
}

/// Frozen origin region read side; fail-closed when never installed. A missing
/// install must refuse the durable append instead of inventing a scope.
pub fn origin_region() -> Result<String, InvalidationContractError> {
    ORIGIN_REGION.get().cloned().ok_or_else(|| {
        InvalidationContractError::InvalidEnvelope(
            "invalidation origin region is not installed; refusing durable append".into(),
        )
    })
}

static ORIGIN_REGION: OnceLock<String> = OnceLock::new();

/// Append the bounded stable SESSION_REVOKED shard rows to the caller's
/// existing source transaction.
///
/// The function never commits, publishes to a broker, or touches any network:
/// it only writes durable `al_message_outbox` rows through
/// [`append_invalidation_in_tx`] (same invalidation queue, same per-user
/// ordering scope) and returns the exact envelopes it appended, in shard
/// order. The caller owns the transaction boundary and MUST dispatch the
/// returned envelopes only after a proven commit (direct local delivery is
/// the normal path; the durable rows remain the recovery journal for the
/// relay/fanout workers, and unknown outcomes are reconciled there — never
/// replayed here). Returns the appended envelopes (empty for an empty
/// snapshot: nothing was revoked, so nothing is notified).
pub async fn append_session_revocation_shards_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    user_id: i64,
    revoked_jtis: &[String],
    base_operation_id: &str,
) -> Result<Vec<MessageEnvelope>, InvalidationAppendError> {
    let origin_region = origin_region()?;
    let shards = plan_session_revocation_shards(user_id, revoked_jtis, base_operation_id)?;
    let mut envelopes = Vec::with_capacity(shards.len());
    for shard in &shards {
        // Rebuild-free envelope reuse is not possible here because
        // `to_envelope` stamps `createdAt`; build once per shard and derive
        // both the durable row and the post-commit direct delivery from the
        // identical instance, so delivery bytes equal committed bytes.
        let envelope =
            shard
                .event
                .to_envelope(&shard.message_id, &shard.operation_id, &origin_region)?;
        let payload_json = envelope
            .envelope_json()
            .map_err(InvalidationContractError::Serialization)?;
        let input = astral_db::LocalMessageInput {
            message_id: &envelope.message_id,
            operation_id: &envelope.operation_id,
            message_type: shard.event.message_type(),
            queue_name: INVALIDATION_QUEUE,
            ordering_key: envelope.ordering_key.as_deref(),
            tenant_id: envelope.tenant_id,
            origin_region: &envelope.origin_region,
            target_region: envelope.target_region.as_deref(),
            schema_version: envelope.schema_version,
            payload_json: &payload_json,
            headers_json: None,
            payload_sha256: &envelope.payload_sha256,
        };
        astral_db::append_in_tx(tx, &input).await?;
        envelopes.push(envelope);
    }
    Ok(envelopes)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::envelope::payload_digest;

    fn evidence() -> InvalidationEvent {
        InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 42,
            published_generation: 10,
            source_generation: 10,
            revoke_fence: 0,
        })
    }

    fn session() -> InvalidationEvent {
        InvalidationEvent::SessionRevoked(SessionRevoked {
            user_id: 9,
            revoked_jtis: vec!["jti-1".into()],
        })
    }

    #[test]
    fn evidence_envelope_round_trips_with_scope_metadata() {
        let event = evidence();
        let envelope = event
            .to_envelope("event-1", "operation-1", "city-a")
            .expect("valid invalidation envelope");

        assert_eq!(envelope.message_type, EVIDENCE_INVALIDATED);
        assert_eq!(envelope.schema_version, INVALIDATION_SCHEMA_VERSION);
        assert_eq!(envelope.tenant_id, Some(7));
        assert_eq!(envelope.ordering_key, Some(event.ordering_key()));
        assert_eq!(InvalidationEvent::from_envelope(&envelope), Ok(event));
    }

    #[test]
    fn envelope_rejects_scope_metadata_tampering() {
        let event = evidence();
        let mut envelope = event
            .to_envelope("event-1", "operation-1", "city-a")
            .expect("valid invalidation envelope");
        envelope.tenant_id = Some(8);
        assert!(matches!(
            InvalidationEvent::from_envelope(&envelope),
            Err(InvalidationContractError::InvalidEnvelope(message))
                if message.contains("tenantId")
        ));

        let mut envelope = event
            .to_envelope("event-1", "operation-1", "city-a")
            .expect("valid invalidation envelope");
        envelope.ordering_key = Some("authorization:evidence:tenant/7/card/all".into());
        assert!(matches!(
            InvalidationEvent::from_envelope(&envelope),
            Err(InvalidationContractError::InvalidEnvelope(message))
                if message.contains("orderingKey")
        ));
    }

    #[test]
    fn evidence_scope_contains_aggregate_identity_and_zero_fence_is_valid() {
        let tenant_wide = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: None,
            aggregate_type: PublishedEvidenceAggregate::RuleSet,
            aggregate_id: 6001,
            published_generation: 11,
            source_generation: 11,
            revoke_fence: 0,
        });
        assert_ne!(tenant_wide.ordering_key(), evidence().ordering_key());
        assert!(tenant_wide
            .ordering_key()
            .contains("aggregate/RULE_SET/6001"));
        tenant_wide
            .validate()
            .expect("tenant-wide evidence is valid");
    }

    #[test]
    fn evidence_rejects_cross_domain_scope_and_accepts_independent_generations() {
        let invalid_scope = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 43,
            published_generation: 10,
            source_generation: 10,
            revoke_fence: 0,
        });
        assert!(matches!(
            invalid_scope.validate(),
            Err(InvalidationContractError::InvalidAggregateScope(_))
        ));

        let invalid_fence = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 42,
            published_generation: 10,
            source_generation: 10,
            revoke_fence: 11,
        });
        assert_eq!(
            invalid_fence.validate(),
            Err(InvalidationContractError::RevokeFenceExceedsSourceGeneration)
        );

        let independent_generations = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 42,
            published_generation: 11,
            source_generation: 10,
            revoke_fence: 0,
        });
        assert!(independent_generations.validate().is_ok());
    }

    #[test]
    fn session_revocation_requires_a_non_empty_unique_jti_snapshot() {
        let empty = InvalidationEvent::SessionRevoked(SessionRevoked {
            user_id: 9,
            revoked_jtis: Vec::new(),
        });
        assert_eq!(
            empty.validate(),
            Err(InvalidationContractError::EmptySessionRevocation)
        );

        let duplicate = InvalidationEvent::SessionRevoked(SessionRevoked {
            user_id: 9,
            revoked_jtis: vec!["jti-1".into(), "jti-1".into()],
        });
        assert_eq!(
            duplicate.validate(),
            Err(InvalidationContractError::DuplicateJti)
        );
    }

    #[test]
    fn invalidation_ids_and_generation_fail_closed() {
        let invalid = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 0,
            card_id: Some(42),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 42,
            published_generation: 10,
            source_generation: 10,
            revoke_fence: 0,
        });
        assert_eq!(
            invalid.validate(),
            Err(InvalidationContractError::NonPositiveField("tenant_id"))
        );

        let invalid =
            InvalidationEvent::EligibilityInvalidated(EligibilityInvalidated { card_id: 0 });
        assert_eq!(
            invalid.validate(),
            Err(InvalidationContractError::NonPositiveField("card_id"))
        );

        let invalid = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 42,
            published_generation: 0,
            source_generation: 1,
            revoke_fence: 0,
        });
        assert_eq!(
            invalid.validate(),
            Err(InvalidationContractError::NonPositiveField(
                "published_generation"
            ))
        );
    }

    #[test]
    fn stable_ids_and_strict_payload_validation_fail_closed() {
        let event = session();
        assert!(matches!(
            event.to_envelope("", "operation-1", "city-a"),
            Err(InvalidationContractError::InvalidEnvelope(message))
                if message.contains("messageId")
        ));

        let mut envelope = event
            .to_envelope("event-1", "operation-1", "city-a")
            .expect("valid invalidation envelope");
        envelope.payload = json!({
            "userId": 9,
            "revokedJtis": [],
            "unexpected": true
        });
        envelope.payload_sha256 = payload_digest(&envelope.payload).expect("payload digest");
        assert!(matches!(
            InvalidationEvent::from_envelope(&envelope),
            Err(InvalidationContractError::InvalidPayload(_))
        ));
    }

    #[test]
    fn fixed_queue_contract_is_not_caller_selectable() {
        assert_eq!(INVALIDATION_QUEUE, "astral.authorization.invalidation");
        assert_eq!(INVALIDATION_ROUTING_KEY, "authorization.invalidation");
    }

    #[test]
    fn eligibility_and_session_ordering_keys_are_global_scope_keys() {
        let eligibility =
            InvalidationEvent::EligibilityInvalidated(EligibilityInvalidated { card_id: 9 });
        assert_eq!(
            eligibility.ordering_key(),
            "authorization:eligibility/card/9"
        );
        assert_eq!(session().ordering_key(), "identity:session/user/9");
    }

    // ===== SESSION_REVOKED bounded stable sharding =====

    fn jtis(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("jti-{index:06}")).collect()
    }

    fn shard_jtis(plans: &[SessionRevocationShardPlan]) -> Vec<String> {
        plans
            .iter()
            .flat_map(|plan| match &plan.event {
                InvalidationEvent::SessionRevoked(value) => value.revoked_jtis.clone(),
                other => panic!("unexpected invalidation event in shard plan: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn empty_snapshot_plans_zero_shards_and_notifies_nothing() {
        let plans = plan_session_revocation_shards(9, &[], "op-1").expect("empty snapshot");
        assert!(plans.is_empty());
    }

    #[test]
    fn single_and_exact_bound_snapshots_plan_one_bounded_shard() {
        for count in [1usize, MAX_REVOKED_JTIS] {
            let plans = plan_session_revocation_shards(9, &jtis(count), "op-1")
                .expect("snapshot within the per-event bound");
            assert_eq!(plans.len(), 1, "count={count}");
            assert_eq!(plans[0].shard_total, 1);
            assert_eq!(plans[0].shard_index, 1);
            let event_jtis = match &plans[0].event {
                InvalidationEvent::SessionRevoked(value) => &value.revoked_jtis,
                other => panic!("unexpected invalidation event: {other:?}"),
            };
            assert_eq!(event_jtis.len(), count);
            assert!(event_jtis.len() <= MAX_REVOKED_JTIS);
            plans[0].event.validate().expect("contract-valid shard");
        }
    }

    #[test]
    fn over_bound_snapshots_split_into_bounded_shards_without_tail_loss() {
        // 1025 = exactly one over the bound: two shards, tail of one.
        let plans =
            plan_session_revocation_shards(9, &jtis(1025), "op-1").expect("just over the bound");
        assert_eq!(plans.len(), 2);
        assert_eq!(shard_jtis(&plans).len(), 1025);

        // Large non-multiple set: 5000 -> 4 full shards + a 904-entry tail.
        let large = jtis(5000);
        let plans = plan_session_revocation_shards(9, &large, "op-1").expect("large snapshot");
        assert_eq!(plans.len(), 5);
        let lengths: Vec<usize> = plans
            .iter()
            .map(|plan| match &plan.event {
                InvalidationEvent::SessionRevoked(value) => value.revoked_jtis.len(),
                other => panic!("unexpected invalidation event: {other:?}"),
            })
            .collect();
        assert_eq!(
            lengths,
            vec![
                MAX_REVOKED_JTIS,
                MAX_REVOKED_JTIS,
                MAX_REVOKED_JTIS,
                MAX_REVOKED_JTIS,
                5000 - 4 * MAX_REVOKED_JTIS
            ]
        );
        for plan in &plans {
            assert_eq!(plan.shard_total, 5);
            assert!(
                plan.event.validate().is_ok(),
                "every shard stays within the typed bound"
            );
        }
    }

    #[test]
    fn shard_union_is_complete_unique_and_canonical() {
        let mut input = jtis(3000);
        // Duplicates must collapse, never duplicate across shards.
        input.extend_from_slice(&jtis(500));
        let plans = plan_session_revocation_shards(9, &input, "op-1").expect("plan");
        let union = shard_jtis(&plans);
        let mut sorted_union = union.clone();
        sorted_union.sort();
        sorted_union.dedup();
        assert_eq!(union.len(), sorted_union.len(), "no duplicate in any shard");

        let mut expected = jtis(3000);
        expected.extend_from_slice(&jtis(500));
        expected.sort();
        expected.dedup();
        assert_eq!(
            sorted_union, expected,
            "complete, no omission, canonical order"
        );
    }

    #[test]
    fn shard_plan_is_byte_stable_under_input_order_and_duplicates() {
        let mut shuffled = jtis(2500);
        shuffled.reverse();
        shuffled.rotate_left(777);
        shuffled.extend_from_slice(&jtis(2500));

        let baseline = plan_session_revocation_shards(9, &jtis(2500), "op-1").expect("baseline");
        let shuffled_plan = plan_session_revocation_shards(9, &shuffled, "op-1").expect("shuffled");
        assert_eq!(
            baseline, shuffled_plan,
            "same set must yield identical shards"
        );

        let again = plan_session_revocation_shards(9, &jtis(2500), "op-1").expect("repeat");
        assert_eq!(baseline, again, "repeated invocation must be byte-stable");
    }

    #[test]
    fn shard_ids_are_stable_one_based_and_operation_correlated() {
        let plans = plan_session_revocation_shards(9, &jtis(2048), "6f0a2b1c-uuid").expect("plan");
        assert_eq!(plans.len(), 2);
        for (offset, plan) in plans.iter().enumerate() {
            assert_eq!(plan.message_id, format!("6f0a2b1c-uuid#s/{}", offset + 1));
            assert_eq!(plan.operation_id, "6f0a2b1c-uuid");
            assert_eq!(plan.shard_index, offset + 1);
            assert_eq!(plan.shard_total, 2);
        }
    }

    #[test]
    fn shard_planning_fails_closed_on_invalid_scope_or_ids() {
        // Non-positive user scope.
        assert!(matches!(
            plan_session_revocation_shards(0, &jtis(1), "op-1"),
            Err(InvalidationContractError::NonPositiveField("user_id"))
        ));
        // Blank base operation id.
        assert!(matches!(
            plan_session_revocation_shards(9, &jtis(1), "   "),
            Err(InvalidationContractError::InvalidEnvelope(_))
        ));
        // Base id beyond the 128-byte outbox operation-id contract fails
        // closed instead of being naively concatenated into an unappendable
        // shard id.
        let over_bound_base = "a".repeat(SESSION_REVOCATION_BASE_OPERATION_ID_BOUND + 1);
        assert_eq!(over_bound_base.len(), 129);
        assert!(matches!(
            plan_session_revocation_shards(9, &jtis(1), &over_bound_base),
            Err(InvalidationContractError::FieldTooLarge(
                "base_operation_id (exceeds the outbox operation-id bound)"
            ))
        ));
        // Exactly at the legacy suffix budget keeps the composed suffix form.
        let at_budget_base = "a".repeat(SESSION_REVOCATION_SHARD_BASE_OPERATION_ID_BOUND);
        let plans =
            plan_session_revocation_shards(9, &jtis(1), &at_budget_base).expect("budgeted base");
        assert_eq!(
            plans[0].message_id,
            format!("{at_budget_base}#s/1"),
            "legacy suffix ids stay byte-identical"
        );
        // Contract-invalid JTI entries fail before any durable append.
        assert!(matches!(
            plan_session_revocation_shards(9, &["  ".to_owned()], "op-1"),
            Err(InvalidationContractError::BlankJti)
        ));
        let oversized = vec!["j".repeat(MAX_JTI_BYTES + 1)];
        assert!(matches!(
            plan_session_revocation_shards(9, &oversized, "op-1"),
            Err(InvalidationContractError::FieldTooLarge("jti"))
        ));
    }

    #[test]
    fn shard_ids_preserve_full_operation_id_contract_across_115_116_128_129() {
        // 115 bytes: the last base that keeps the historical suffix form.
        let base_115 = "a".repeat(115);
        let plans = plan_session_revocation_shards(9, &jtis(1), &base_115).expect("legacy fit");
        assert_eq!(plans[0].message_id, format!("{base_115}#s/1"));
        assert_eq!(plans[0].operation_id, base_115);
        assert!(plans[0].message_id.len() <= SHARD_MESSAGE_ID_BOUND);

        // 116 bytes: one past the suffix budget — previously rejected, now
        // valid through the compact derived form.
        let base_116 = "a".repeat(116);
        let plans = plan_session_revocation_shards(9, &jtis(1), &base_116).expect("derived form");
        assert_eq!(
            plans[0].operation_id, base_116,
            "operation id stays untouched"
        );
        assert_eq!(
            plans[0].message_id.len(),
            SHARD_DERIVED_ID_PREFIX.len() + 64
        );
        assert!(plans[0].message_id.starts_with(SHARD_DERIVED_ID_PREFIX));
        assert!(!plans[0].message_id.contains(SHARD_MESSAGE_SUFFIX));

        // 128 bytes: the full outbox operation-id contract stays planable.
        let base_128 = "a".repeat(SHARD_MESSAGE_ID_BOUND);
        let plans = plan_session_revocation_shards(9, &jtis(1), &base_128).expect("contract bound");
        assert_eq!(plans[0].operation_id, base_128);
        assert!(plans[0].message_id.len() <= SHARD_MESSAGE_ID_BOUND);
        assert!(!plans[0].message_id.contains(SHARD_MESSAGE_SUFFIX));
        // The untouched 128-byte operation id and the compact id both compose
        // a contract-valid envelope.
        let envelope = plans[0]
            .event
            .to_envelope(&plans[0].message_id, &plans[0].operation_id, "city-a")
            .expect("envelope holds the untouched operation id");
        assert_eq!(envelope.operation_id, base_128);
        assert_eq!(envelope.message_id, plans[0].message_id);

        // 129 bytes: one past the outbox operation-id contract fails closed.
        let base_129 = "a".repeat(129);
        assert!(matches!(
            plan_session_revocation_shards(9, &jtis(1), &base_129),
            Err(InvalidationContractError::FieldTooLarge(
                "base_operation_id (exceeds the outbox operation-id bound)"
            ))
        ));
    }

    #[test]
    fn derived_shard_ids_are_deterministic_bounded_and_distinct_by_base_or_shard() {
        let long_base = "a".repeat(SESSION_REVOCATION_SHARD_BASE_OPERATION_ID_BOUND + 1);

        // Deterministic per (base, shard index): repeated invocations agree.
        let first = plan_session_revocation_shards(9, &jtis(1), &long_base).expect("plan");
        let again = plan_session_revocation_shards(9, &jtis(1), &long_base).expect("plan");
        assert_eq!(first[0].message_id, again[0].message_id);

        // Distinct per shard of the same operation.
        let two_shards = plan_session_revocation_shards(9, &jtis(MAX_REVOKED_JTIS + 1), &long_base)
            .expect("two shards");
        assert_eq!(two_shards.len(), 2);
        assert_ne!(two_shards[0].message_id, two_shards[1].message_id);

        // Distinct across bases (digest separation).
        let other_base = format!("{long_base}b");
        let other = plan_session_revocation_shards(9, &jtis(1), &other_base).expect("plan");
        assert_ne!(first[0].message_id, other[0].message_id);

        // The derived namespace never collides with the suffix namespace: a
        // derived id contains no "#s/", and every suffix-composed id does.
        for plan in [first, again, two_shards, other].into_iter().flatten() {
            assert!(plan.message_id.starts_with(SHARD_DERIVED_ID_PREFIX));
            assert!(!plan.message_id.contains(SHARD_MESSAGE_SUFFIX));
            assert!(plan.message_id.len() <= SHARD_MESSAGE_ID_BOUND);
        }
    }

    #[test]
    fn unicode_bases_follow_the_byte_length_contract() {
        // "好" is 3 UTF-8 bytes: byte length, not char count, is the contract.
        let base_115_bytes = format!("{}a", "好".repeat(38));
        assert_eq!(base_115_bytes.len(), 115);
        let base_116_bytes = format!("{}ab", "好".repeat(38));
        assert_eq!(base_116_bytes.len(), 116);
        let base_128_bytes = format!("{}ab", "好".repeat(42));
        assert_eq!(base_128_bytes.len(), 128);
        let base_129_bytes = "好".repeat(43);
        assert_eq!(base_129_bytes.len(), 129);
        assert!(base_129_bytes.chars().count() < SHARD_MESSAGE_ID_BOUND);

        // Within the suffix budget the composed form survives multibyte bases.
        let plans = plan_session_revocation_shards(9, &jtis(1), &base_115_bytes).expect("byte fit");
        assert_eq!(plans[0].message_id, format!("{base_115_bytes}#s/1"));

        // Past the suffix budget the derived form keeps multibyte bases valid.
        for base in [&base_116_bytes, &base_128_bytes] {
            let plans = plan_session_revocation_shards(9, &jtis(1), base)
                .unwrap_or_else(|error| panic!("byte-bounded base must plan: {error}"));
            assert_eq!(plans[0].operation_id, *base);
            assert!(plans[0].message_id.starts_with(SHARD_DERIVED_ID_PREFIX));
            assert!(plans[0].message_id.len() <= SHARD_MESSAGE_ID_BOUND);
        }

        // 129 bytes fails even though the char count is far below 128.
        assert!(matches!(
            plan_session_revocation_shards(9, &jtis(1), &base_129_bytes),
            Err(InvalidationContractError::FieldTooLarge(
                "base_operation_id (exceeds the outbox operation-id bound)"
            ))
        ));
    }

    #[test]
    fn same_base_changed_body_keeps_identical_shard_id_for_bodyhash_conflict() {
        // The shard id is a pure function of (base, shard index): it never
        // encodes the snapshot content, so a same-operation re-plan with a
        // changed body still resolves to the identical committed message id
        // and the durable outbox bodyhash conflict stays fail closed (adding
        // content to the id would silently bypass that protection).
        for base in [
            "op-1".to_owned(),
            "a".repeat(SESSION_REVOCATION_BASE_OPERATION_ID_BOUND),
        ] {
            let original = plan_session_revocation_shards(9, &jtis(1), &base).expect("plan");
            let changed = plan_session_revocation_shards(9, &["revoked-jti-x".to_owned()], &base)
                .expect("plan");
            assert_eq!(original[0].message_id, changed[0].message_id);
            assert_eq!(original[0].operation_id, changed[0].operation_id);
            // The bodies genuinely differ, so the durable layer would see the
            // same message id with a different payload digest.
            assert_ne!(original[0].event, changed[0].event);
        }
    }

    #[test]
    fn origin_region_install_point_is_frozen_and_conflict_free() {
        // First install wins for the process lifetime; the same value is an
        // idempotent re-install, a different value fails closed. (This test
        // owns the process-wide singleton: no other test may pre-seed it.)
        install_origin_region("city-test").expect("first install");
        install_origin_region("city-test").expect("idempotent same-value install");
        assert_eq!(origin_region().expect("installed"), "city-test");
        assert!(install_origin_region("city-other").is_err());
        assert!(install_origin_region("  ").is_err());
        assert_eq!(origin_region().expect("still installed"), "city-test");
    }
}
