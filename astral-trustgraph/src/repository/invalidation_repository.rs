//! Durable authorization invalidation append helpers.
//!
//! These helpers run inside the caller-owned source transaction
//! (`AuthorizationSourceTransaction`). They only build the typed envelope once,
//! append the very same envelope to `al_message_outbox`, and register it as a
//! post-commit receipt on the transaction; commit and the direct LocalBus
//! fanout remain owned by `authorization_source_transaction`.

use astral_db::{lock_current_pointer_in_tx, ProjectionAggregateIdentity};
use astral_types::{AstralError, PublishedEvidenceAggregate};

use crate::repository::authorization_source_transaction::{
    AuthorizationSourceTransaction, InvalidationReceipt,
};

pub(crate) fn install_origin_region(region: impl Into<String>) -> Result<(), AstralError> {
    astral_mq::invalidation::install_origin_region(region).map_err(AstralError::Config)
}

/// 进程级 origin region 只读访问：ELIGIBILITY durable invalidation intent 与
/// evidence invalidation 共用 astral-mq 的唯一进程身份单例。
pub(crate) fn origin_region() -> Result<String, AstralError> {
    astral_mq::invalidation::origin_region().map_err(|error| AstralError::Config(error.to_string()))
}

#[derive(Debug, Clone)]
pub(crate) struct EvidenceInvalidationAppend {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: PublishedEvidenceAggregate,
    pub aggregate_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub source_generation: u64,
    pub revoke_fence: u64,
}

impl EvidenceInvalidationAppend {
    pub(crate) fn origin_region(&self) -> Result<String, AstralError> {
        origin_region()
    }
}

/// Append one evidence invalidation for a published aggregate when a proven
/// current pointer exists. The pointer is locked in the same transaction, so
/// `published_generation` is never guessed from a source or per-grant version.
/// A missing pointer means no published evidence exists yet and therefore does
/// not require an invalidation notification (and no receipt).
///
/// The envelope is built exactly once, in-transaction, from stable ids and the
/// frozen origin region; the identical instance is durably appended to the
/// outbox and carried as a receipt. After a proven commit the receipt is
/// published on the LocalBus without any database read or envelope rebuild;
/// the durable row stays the recovery path for the relay.
pub(crate) async fn append_evidence_invalidation_if_published(
    tx: &mut AuthorizationSourceTransaction,
    request: &EvidenceInvalidationAppend,
) -> Result<(), AstralError> {
    if request.event_id.trim().is_empty() || request.operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "evidence invalidation requires stable event and operation ids".into(),
        ));
    }
    let origin_region = request.origin_region()?;
    let identity = ProjectionAggregateIdentity::new(
        request.tenant_id,
        request.aggregate_type.as_str(),
        request.aggregate_id,
    )
    .map_err(|error| AstralError::Validation(error.to_string()))?;
    let Some(pointer) = lock_current_pointer_in_tx(tx, &identity)
        .await
        .map_err(|error| AstralError::Database(error.to_string()))?
    else {
        return Ok(());
    };
    if !pointer.revoke_fence_proven {
        return Err(AstralError::Database(
            "published evidence pointer lacks revoke-fence proof".into(),
        ));
    }
    let event = astral_mq::InvalidationEvent::EvidenceInvalidated(astral_mq::EvidenceInvalidated {
        tenant_id: request.tenant_id,
        card_id: request.card_id,
        aggregate_type: request.aggregate_type,
        aggregate_id: request.aggregate_id,
        published_generation: pointer.current_generation,
        source_generation: request.source_generation,
        revoke_fence: request.revoke_fence,
    });
    // 构造一次：同一个 envelope 实例既落 durable outbox，也留在事务 receipts。
    let envelope = event
        .to_envelope(&request.event_id, &request.operation_id, &origin_region)
        .map_err(|error| AstralError::Validation(error.to_string()))?;
    let payload_json = envelope.envelope_json().map_err(AstralError::Internal)?;
    let input = astral_db::LocalMessageInput {
        message_id: &envelope.message_id,
        operation_id: &envelope.operation_id,
        message_type: event.message_type(),
        queue_name: astral_mq::invalidation::INVALIDATION_QUEUE,
        ordering_key: envelope.ordering_key.as_deref(),
        tenant_id: envelope.tenant_id,
        origin_region: &envelope.origin_region,
        target_region: envelope.target_region.as_deref(),
        schema_version: envelope.schema_version,
        payload_json: &payload_json,
        headers_json: None,
        payload_sha256: &envelope.payload_sha256,
    };
    astral_db::append_in_tx(tx, &input)
        .await
        .map_err(|error| AstralError::Database(error.to_string()))?;
    tx.record_invalidation_receipt(InvalidationReceipt {
        event_id: envelope.message_id.clone(),
        operation_id: envelope.operation_id.clone(),
        envelope,
    });
    Ok(())
}
