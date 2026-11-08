//! Borrowed, source-transaction-bound CardCreate RuleSet evidence capture.
//!
//! This child is the only constructor of the Identity CardCreate RuleSet binding
//! receipt. It records the complete typed RuleSet image before the source mutation,
//! then reads every after/projection/ref/audit/ADD fact from the same transaction.
//! Callers cannot provide images, ids, deltas, or receipt fields.

use serde_json::{Map, Value};
use sqlx::{MySql, Transaction};

use astral_types::AstralError;

const RULE_SET_AGGREGATE: &str = "RULE_SET";
const CARD_AGGREGATE: &str = "CARD";
const CARD_CREATED: &str = "CARD_CREATED";
const RULE_SET_UPDATE: &str = "RULE_SET_UPDATE";
const BIND_CARD: &str = "BIND_CARD";
const MAX_AUDITS: i64 = 8;
const MAX_DELTAS: i64 = 1024;

struct AggregateParts<'a> {
    root: &'a Map<String, Value>,
    entries: &'a [Value],
    bindings: &'a [Value],
}

/// Only durable identities needed to locate and validate one source binding.
/// The image, reference id, audit, projection, and delta values are never accepted
/// from the caller.
#[derive(Debug, Clone)]
pub struct CardCreateRuleSetCaptureSpec {
    pub card_id: i64,
    pub user_id: i64,
    pub tenant_id: i64,
    pub domain_id: Option<i64>,
    pub operation_id: String,
    pub rule_set_id: i64,
}

/// A capture structurally owns the mutable source transaction borrow until it is
/// sealed. This prevents finishing a capture against another transaction.
pub struct CardCreateRuleSetCapture<'tx, 'conn> {
    tx: Option<&'tx mut Transaction<'conn, MySql>>,
    spec: CardCreateRuleSetCaptureSpec,
    lookup: String,
    before_image: String,
}

/// Opaque durable CardCreate RuleSet receipt. It has no public fields and no
/// deserialization path; only `finish_in_tx` can construct it.
#[derive(Debug, Clone)]
pub struct CardCreateRuleSetReceipt {
    evidence: Value,
}

impl CardCreateRuleSetReceipt {
    pub fn rule_set_id(&self) -> i64 {
        self.evidence
            .get("ruleSetId")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }

    pub fn source_evidence(&self) -> &Value {
        &self.evidence
    }
}

impl<'tx, 'conn> CardCreateRuleSetCapture<'tx, 'conn> {
    /// Read and lock the complete typed RuleSet aggregate before the binding.
    pub async fn begin_in_tx(
        tx: &'tx mut Transaction<'conn, MySql>,
        spec: CardCreateRuleSetCaptureSpec,
    ) -> Result<Self, AstralError> {
        validate_spec(&spec)?;
        let lookup = crate::TypedSourceRowLookup::PrimaryId {
            id: spec.rule_set_id,
        };
        let lookup_json = serde_json::to_string(&lookup).map_err(|error| {
            AstralError::Validation(format!(
                "CardCreate RuleSet lookup encoding failed: {error}"
            ))
        })?;
        let Some((key, before_image)) = crate::read_typed_source_row_image_in_tx_typed(
            tx,
            crate::TypedSourceTable::RuleSet,
            &lookup,
        )
        .await
        .map_err(map_typed_source_error)?
        else {
            return Err(AstralError::Pending(
                "CardCreate RuleSet before image is absent".into(),
            ));
        };
        if key != spec.rule_set_id || before_image.trim().is_empty() {
            return Err(AstralError::Pending(
                "CardCreate RuleSet typed before image has an unexpected identity".into(),
            ));
        }
        Ok(Self {
            tx: Some(tx),
            spec,
            lookup: lookup_json,
            before_image,
        })
    }

    pub fn with_tx_mut(&mut self) -> &mut Transaction<'conn, MySql> {
        self.tx
            .as_deref_mut()
            .expect("CardCreate RuleSet capture transaction was already finished")
    }

    /// Read and validate every durable fact after the caller's ref/ADD/audit
    /// sequence, then seal the opaque receipt.
    pub async fn finish_in_tx(mut self) -> Result<CardCreateRuleSetReceipt, AstralError> {
        let tx = self.tx.take().ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet capture was already finished".into())
        })?;
        let before: Value = serde_json::from_str(&self.before_image).map_err(|error| {
            AstralError::Pending(format!(
                "CardCreate RuleSet before image is invalid: {error}"
            ))
        })?;
        let lookup = crate::TypedSourceRowLookup::PrimaryId {
            id: self.spec.rule_set_id,
        };
        let Some((after_key, after_image)) = crate::read_typed_source_row_image_in_tx_typed(
            &mut *tx,
            crate::TypedSourceTable::RuleSet,
            &lookup,
        )
        .await
        .map_err(map_typed_source_error)?
        else {
            return Err(AstralError::Pending(
                "CardCreate RuleSet after image is absent".into(),
            ));
        };
        if after_key != self.spec.rule_set_id {
            return Err(AstralError::Pending(
                "CardCreate RuleSet after image key differs from the capture".into(),
            ));
        }
        let after: Value = serde_json::from_str(&after_image).map_err(|error| {
            AstralError::Pending(format!(
                "CardCreate RuleSet after image is invalid: {error}"
            ))
        })?;
        let binding_row = added_binding(&before, &after, &self.spec)?;
        let binding_object = binding_row.as_object().ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet binding row is not an object".into())
        })?;
        let ref_id = positive_i64(binding_object, "id")?;

        let ref_row: super::RefRow = sqlx::query_as(
            "SELECT id, card_id, rule_set_id, CAST(ref_type AS CHAR) AS ref_type, tenant_id \
             FROM card_rule_set_ref WHERE id = ? FOR UPDATE",
        )
        .bind(ref_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| database(error, "CardCreate RuleSet ref readback failed"))?
        .ok_or_else(|| AstralError::Pending("CardCreate RuleSet ref is missing".into()))?;
        if ref_row.id != ref_id
            || ref_row.card_id != self.spec.card_id
            || ref_row.rule_set_id != self.spec.rule_set_id
            || ref_row.ref_type != "BASE"
            || ref_row.tenant_id != Some(self.spec.tenant_id)
        {
            return Err(AstralError::Pending(
                "CardCreate RuleSet ref differs from the typed after image".into(),
            ));
        }

        let head: super::ProjectionHeadRow = sqlx::query_as(
            "SELECT source_generation, last_event_id FROM authorization_projection_head \
             WHERE aggregate_type = ? AND aggregate_id = ? FOR UPDATE",
        )
        .bind(RULE_SET_AGGREGATE)
        .bind(self.spec.rule_set_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| database(error, "CardCreate RuleSet head readback failed"))?
        .ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet projection head is missing".into())
        })?;
        let rule_event_id = head.last_event_id.clone().ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet head has no current event".into())
        })?;
        let rule_event: super::ProjectionEventRow = sqlx::query_as(
            "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
             sequence_number, revoke_fence, status, CAST(payload_json AS CHAR) AS payload_json \
             FROM authorization_projection_outbox WHERE aggregate_type = ? AND aggregate_id = ? \
             AND event_id = ? FOR UPDATE",
        )
        .bind(RULE_SET_AGGREGATE)
        .bind(self.spec.rule_set_id)
        .bind(&rule_event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| database(error, "CardCreate RuleSet event readback failed"))?
        .ok_or_else(|| AstralError::Pending("CardCreate RuleSet current event is missing".into()))?;
        let rule_payload: Value =
            serde_json::from_str(&rule_event.payload_json).map_err(|error| {
                AstralError::Pending(format!(
                    "CardCreate RuleSet event payload is invalid: {error}"
                ))
            })?;
        let rule_payload_object = rule_payload.as_object().ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet event payload is not an object".into())
        })?;
        if rule_event.aggregate_type != RULE_SET_AGGREGATE
            || rule_event.aggregate_id != self.spec.rule_set_id
            || rule_event.event_type != RULE_SET_UPDATE
            || rule_event.source_generation != head.source_generation
            || rule_event.sequence_number != head.source_generation
            || !matches!(rule_event.status.as_str(), "PENDING" | "PROCESSED")
            || rule_payload_object
                .get("operationId")
                .and_then(Value::as_str)
                != Some(self.spec.operation_id.as_str())
        {
            return Err(AstralError::Pending(
                "CardCreate RuleSet current event is not bound to the operation".into(),
            ));
        }
        let expected_rule_tenant = before
            .get("root")
            .and_then(Value::as_object)
            .and_then(|root| root.get("tenant_id"))
            .and_then(|value| value.as_i64());
        if rule_event.tenant_id != expected_rule_tenant {
            return Err(AstralError::Pending(
                "CardCreate RuleSet projection tenant differs from its typed root".into(),
            ));
        }

        let projection = serde_json::json!({
            "eventId": rule_event.event_id,
            "sourceGeneration": rule_event.source_generation,
            "revokeFence": rule_event.revoke_fence,
            "tenantId": rule_event.tenant_id,
        });
        let current_source_event = serde_json::json!({
            "eventId": rule_event.event_id,
            "aggregateType": rule_event.aggregate_type,
            "aggregateId": rule_event.aggregate_id,
            "tenantId": rule_event.tenant_id,
            "eventType": rule_event.event_type,
            "sourceGeneration": rule_event.source_generation,
            "sequenceNumber": rule_event.sequence_number,
            "revokeFence": rule_event.revoke_fence,
            "status": rule_event.status,
            "payload": rule_payload,
        });

        let audit_rows: Vec<super::AuditRow> = sqlx::query_as(
            "SELECT audit_id, rule_set_id, entry_id, changed_by, change_type, \
             CAST(old_value_json AS CHAR) AS old_value_json, CAST(new_value_json AS CHAR) AS new_value_json, \
             tenant_id, aggregate_type, aggregate_id, event_id, source_generation, operation_id \
             FROM rule_set_projection_audit WHERE rule_set_id = ? AND operation_id = ? \
             ORDER BY audit_id LIMIT ? FOR UPDATE",
        )
        .bind(self.spec.rule_set_id)
        .bind(&self.spec.operation_id)
        .bind(MAX_AUDITS + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| database(error, "CardCreate RuleSet audit readback failed"))?;
        if audit_rows.is_empty() || audit_rows.len() as i64 > MAX_AUDITS {
            return Err(AstralError::Pending(
                "CardCreate RuleSet audit set is incomplete or oversized".into(),
            ));
        }
        let mut audits = Vec::with_capacity(audit_rows.len());
        let mut bind_audit = None;
        let mut parent_event_id = None;
        let mut actor_id = None;
        for row in &audit_rows {
            if row.operation_id != self.spec.operation_id
                || row.rule_set_id != self.spec.rule_set_id
                || row.aggregate_type != RULE_SET_AGGREGATE
                || row.aggregate_id != self.spec.rule_set_id
                || row.audit_id <= 0
                || row.changed_by <= 0
            {
                return Err(AstralError::Pending(
                    "CardCreate RuleSet audit row identity is invalid".into(),
                ));
            }
            let detail = row
                .new_value_json
                .as_deref()
                .ok_or_else(|| AstralError::Pending("CardCreate audit has no new value".into()))
                .and_then(|json| {
                    serde_json::from_str::<Value>(json).map_err(|error| {
                        AstralError::Pending(format!("CardCreate audit detail is invalid: {error}"))
                    })
                })?;
            if row.change_type == BIND_CARD {
                if bind_audit.is_some() {
                    return Err(AstralError::Pending(
                        "CardCreate RuleSet audit contains multiple BIND_CARD rows".into(),
                    ));
                }
                let object = detail.as_object().ok_or_else(|| {
                    AstralError::Pending("CardCreate BIND_CARD detail is not an object".into())
                })?;
                if object.get("cardId").and_then(Value::as_i64) != Some(self.spec.card_id)
                    || object.get("tenantId").and_then(Value::as_i64) != Some(self.spec.tenant_id)
                    || object.get("refId").and_then(Value::as_i64) != Some(ref_id)
                    || object.get("refType").and_then(Value::as_str) != Some("BASE")
                {
                    return Err(AstralError::Pending(
                        "CardCreate BIND_CARD detail does not bind the actual ref".into(),
                    ));
                }
                parent_event_id = object
                    .get("parentSourceEventId")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                actor_id = Some(row.changed_by);
                bind_audit = Some(detail.clone());
            } else if row.change_type != "INITIAL_REBUILD" {
                return Err(AstralError::Pending(
                    "CardCreate RuleSet audit contains an unsupported change type".into(),
                ));
            }
            audits.push(super::audit_row_value(row, detail));
        }
        let parent_event_id = parent_event_id.ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet audit lacks BIND_CARD parent identity".into())
        })?;
        let actor_id = actor_id.ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet audit lacks BIND_CARD actor".into())
        })?;
        if current_source_event
            .get("payload")
            .and_then(|payload| payload.get("actorId"))
            .and_then(Value::as_i64)
            != Some(actor_id)
        {
            return Err(AstralError::Pending(
                "CardCreate RuleSet source actor differs from its BIND_CARD audit".into(),
            ));
        }

        let parent_rows: Vec<super::ProjectionEventRow> = sqlx::query_as(
            "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
             sequence_number, revoke_fence, status, CAST(payload_json AS CHAR) AS payload_json \
             FROM authorization_projection_outbox WHERE aggregate_type = ? AND aggregate_id = ? \
             AND event_id = ? FOR UPDATE",
        )
        .bind(CARD_AGGREGATE)
        .bind(self.spec.card_id)
        .bind(&parent_event_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| database(error, "CardCreate CARD parent readback failed"))?;
        let parent_event = parent_rows.into_iter().next().ok_or_else(|| {
            AstralError::Pending("CardCreate CARD parent event is missing".into())
        })?;
        let parent_payload: Value =
            serde_json::from_str(&parent_event.payload_json).map_err(|error| {
                AstralError::Pending(format!(
                    "CardCreate CARD parent payload is invalid: {error}"
                ))
            })?;
        let parent_payload_object = parent_payload.as_object().ok_or_else(|| {
            AstralError::Pending("CardCreate CARD parent payload is not an object".into())
        })?;
        super::validate_creation_payload(
            parent_payload_object,
            self.spec.card_id,
            self.spec.tenant_id,
            actor_id,
            &self.spec.operation_id,
        )
        .map_err(|error| AstralError::Pending(error.to_string()))?;
        if parent_event.event_type != CARD_CREATED
            || parent_event.tenant_id != Some(self.spec.tenant_id)
            || !matches!(parent_event.status.as_str(), "PENDING" | "PROCESSED")
        {
            return Err(AstralError::Pending(
                "CardCreate CARD parent event is not bound to the actual card".into(),
            ));
        }
        let parent_projection = serde_json::json!({
            "eventId": parent_event.event_id,
            "cardId": self.spec.card_id,
            "tenantId": parent_event.tenant_id,
            "sourceGeneration": parent_event.source_generation,
            "revokeFence": parent_event.revoke_fence,
        });
        super::validate_parent_card_projection(
            &mut *tx,
            parent_projection
                .as_object()
                .expect("parent projection object"),
            self.spec.card_id,
            self.spec.tenant_id,
            None,
        )
        .await
        .map_err(map_verify)?;

        let mut add_deltas = Vec::new();
        let delta_rows: Vec<super::DeltaRow> = sqlx::query_as(
            "SELECT tenant_id, card_id, aggregate_type, aggregate_id, event_id, operation_id, \
             event_type, base_version, target_version, source_generation, revoke_fence, \
             invalidates_published_evidence, CAST(before_image_json AS CHAR) AS before_image_json, \
             CAST(delta_json AS CHAR) AS delta_json FROM authorization_delta_event \
             WHERE aggregate_type = ? AND aggregate_id = ? AND operation_id = ? \
             ORDER BY event_id LIMIT ? FOR UPDATE",
        )
        .bind(RULE_SET_AGGREGATE)
        .bind(self.spec.rule_set_id)
        .bind(&self.spec.operation_id)
        .bind(MAX_DELTAS + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| database(error, "CardCreate ADD delta readback failed"))?;
        if delta_rows.len() as i64 > MAX_DELTAS {
            return Err(AstralError::Pending(
                "CardCreate ADD delta evidence exceeds its bound".into(),
            ));
        }
        for row in &delta_rows {
            if row.tenant_id != self.spec.tenant_id
                || row.card_id != Some(self.spec.card_id)
                || row.aggregate_type != RULE_SET_AGGREGATE
                || row.aggregate_id != self.spec.rule_set_id
                || row.operation_id != self.spec.operation_id
                || row.event_type != "ADD"
                || row.source_generation != parent_event.source_generation
                || row.revoke_fence != parent_event.revoke_fence
                || row.invalidates_published_evidence != 0
            {
                return Err(AstralError::Pending(
                    "CardCreate ADD delta identity is invalid".into(),
                ));
            }
            let delta: Value = serde_json::from_str(&row.delta_json).map_err(|error| {
                AstralError::Pending(format!("CardCreate ADD delta is invalid: {error}"))
            })?;
            let rule_set_entry_id = delta
                .get("grant")
                .and_then(|grant| grant.get("provenance"))
                .and_then(|provenance| provenance.get("sourceEntry"))
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    AstralError::Pending(
                        "CardCreate ADD delta lacks a positive RuleSet entry id".into(),
                    )
                })?;
            add_deltas.push(serde_json::json!({
                "eventId": row.event_id,
                "tenantId": row.tenant_id,
                "cardId": row.card_id,
                "aggregateType": row.aggregate_type,
                "aggregateId": row.aggregate_id,
                "operationId": row.operation_id,
                "eventType": row.event_type,
                "baseVersion": row.base_version,
                "targetVersion": row.target_version,
                "sourceGeneration": row.source_generation,
                "revokeFence": row.revoke_fence,
                "invalidatesPublishedEvidence": false,
                "beforeImageJson": row.before_image_json,
                "delta": delta,
                "ruleSetEntryId": rule_set_entry_id,
            }));
        }
        let bind_audit = bind_audit.ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet bind audit detail is missing".into())
        })?;
        let binding = serde_json::json!({
            "schemaVersion": 1,
            "kind": "CARD_CREATE_RULESET_BINDING",
            "table": "rule_set",
            "lookup": self.lookup,
            "ruleSetId": self.spec.rule_set_id,
            "cardId": self.spec.card_id,
            "userId": self.spec.user_id,
            "tenantId": self.spec.tenant_id,
            "domainId": self.spec.domain_id,
            "operationId": self.spec.operation_id,
            "beforeAggregate": before,
            "afterAggregate": after,
            "binding": binding_row,
            "currentSourceEvent": current_source_event,
            "parentCardProjection": parent_projection,
            "projection": projection,
            "audit": audits,
            "bindAudit": bind_audit,
            "addDeltas": add_deltas,
            "emptyRuleSet": delta_rows.is_empty(),
        });
        super::grants::validate_additions(binding.as_object().expect("binding object"))
            .map_err(map_verify)?;
        Ok(CardCreateRuleSetReceipt { evidence: binding })
    }
}

fn validate_spec(spec: &CardCreateRuleSetCaptureSpec) -> Result<(), AstralError> {
    for (name, value) in [
        ("card_id", spec.card_id),
        ("user_id", spec.user_id),
        ("tenant_id", spec.tenant_id),
        ("rule_set_id", spec.rule_set_id),
    ] {
        if value <= 0 {
            return Err(AstralError::Validation(format!(
                "CardCreate RuleSet capture requires positive {name}"
            )));
        }
    }
    if spec.domain_id.is_some_and(|value| value <= 0) {
        return Err(AstralError::Validation(
            "CardCreate RuleSet capture domain_id must be positive when present".into(),
        ));
    }
    if spec.operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "CardCreate RuleSet capture requires a non-empty operation_id".into(),
        ));
    }
    Ok(())
}

fn map_typed_source_error(error: crate::TypedSourceReadError) -> AstralError {
    match error {
        crate::TypedSourceReadError::Validation(message)
        | crate::TypedSourceReadError::Pending(message) => AstralError::Pending(message),
        crate::TypedSourceReadError::Serialization(message) => AstralError::Database(message),
        crate::TypedSourceReadError::SqlxTransient { context, source }
        | crate::TypedSourceReadError::SqlxSchema { context, source } => {
            AstralError::Database(format!("{context}: {source}"))
        }
    }
}

fn database(error: sqlx::Error, context: &str) -> AstralError {
    AstralError::Database(format!("{context}: {error}"))
}

fn map_verify(error: super::CardCreateBindingVerifyError) -> AstralError {
    match error {
        super::CardCreateBindingVerifyError::Pending(message) => AstralError::Pending(message),
        super::CardCreateBindingVerifyError::Database(error) => AstralError::Database(format!(
            "CardCreate RuleSet verification read failed: {error}"
        )),
    }
}

fn positive_i64(object: &Map<String, Value>, field: &str) -> Result<i64, AstralError> {
    let value = object
        .get(field)
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            AstralError::Pending(format!("CardCreate binding {field} is not positive"))
        })?;
    Ok(value)
}

fn aggregate_parts(value: &Value) -> Result<AggregateParts<'_>, AstralError> {
    let object = value.as_object().ok_or_else(|| {
        AstralError::Pending("CardCreate RuleSet aggregate is not an object".into())
    })?;
    let root = object
        .get("root")
        .and_then(Value::as_object)
        .ok_or_else(|| AstralError::Pending("CardCreate RuleSet root is not an object".into()))?;
    let entries = object
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet entries are not an array".into())
        })?;
    let bindings = object
        .get("bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AstralError::Pending("CardCreate RuleSet bindings are not an array".into())
        })?;
    Ok(AggregateParts {
        root,
        entries,
        bindings,
    })
}

fn canonical_values(values: &[Value]) -> Vec<String> {
    let mut values = values.iter().map(Value::to_string).collect::<Vec<_>>();
    values.sort();
    values
}

fn added_binding(
    before: &Value,
    after: &Value,
    spec: &CardCreateRuleSetCaptureSpec,
) -> Result<Value, AstralError> {
    let before_parts = aggregate_parts(before)?;
    let after_parts = aggregate_parts(after)?;
    if before_parts.root != after_parts.root || before_parts.entries != after_parts.entries {
        return Err(AstralError::Pending(
            "CardCreate RuleSet root or entries changed during binding".into(),
        ));
    }
    if after_parts.bindings.len() != before_parts.bindings.len() + 1 {
        return Err(AstralError::Pending(
            "CardCreate RuleSet binding set did not gain exactly one row".into(),
        ));
    }
    let before_canonical = canonical_values(before_parts.bindings);
    let mut candidates = Vec::new();
    for candidate in after_parts.bindings {
        let mut remaining = after_parts.bindings.to_vec();
        let index = remaining
            .iter()
            .position(|value| value == candidate)
            .ok_or_else(|| {
                AstralError::Pending("CardCreate binding candidate is missing".into())
            })?;
        remaining.remove(index);
        if canonical_values(&remaining) == before_canonical {
            candidates.push(candidate.clone());
        }
    }
    if candidates.len() != 1 {
        return Err(AstralError::Pending(
            "CardCreate RuleSet after image does not identify one added binding".into(),
        ));
    }
    let candidate = candidates.pop().expect("one candidate was checked");
    let object = candidate.as_object().ok_or_else(|| {
        AstralError::Pending("CardCreate RuleSet binding row is not an object".into())
    })?;
    if object.get("card_id").and_then(Value::as_i64) != Some(spec.card_id)
        || object.get("rule_set_id").and_then(Value::as_i64) != Some(spec.rule_set_id)
        || object.get("ref_type").and_then(Value::as_str) != Some("BASE")
        || object.get("tenant_id").and_then(Value::as_i64) != Some(spec.tenant_id)
    {
        return Err(AstralError::Pending(
            "CardCreate RuleSet added binding has invalid identity".into(),
        ));
    }
    let binding = serde_json::json!({
        "ruleSetId": spec.rule_set_id,
        "cardId": spec.card_id,
        "userId": spec.user_id,
        "tenantId": spec.tenant_id,
        "domainId": spec.domain_id,
        "operationId": spec.operation_id,
        "beforeAggregate": before,
        "afterAggregate": after,
        "binding": candidate,
    });
    let ref_id = super::validate_aggregate_diff(
        &binding["beforeAggregate"],
        &binding["afterAggregate"],
        binding.as_object().expect("binding object"),
        spec.card_id,
        spec.tenant_id,
    )
    .map_err(map_verify)?;
    if ref_id <= 0 {
        return Err(AstralError::Pending(
            "CardCreate RuleSet added binding id is not positive".into(),
        ));
    }
    Ok(binding["binding"].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_spec_rejects_non_positive_identity() {
        let spec = CardCreateRuleSetCaptureSpec {
            card_id: 0,
            user_id: 2,
            tenant_id: 3,
            domain_id: Some(4),
            operation_id: "op".into(),
            rule_set_id: 5,
        };
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn added_binding_requires_exactly_one_after_row() {
        let spec = CardCreateRuleSetCaptureSpec {
            card_id: 2,
            user_id: 3,
            tenant_id: 4,
            domain_id: Some(5),
            operation_id: "op".into(),
            rule_set_id: 6,
        };
        let before = serde_json::json!({
            "root": {"rule_set_id": 6, "tenant_id": 4},
            "entries": [],
            "bindings": []
        });
        let after = serde_json::json!({
            "root": {"rule_set_id": 6, "tenant_id": 4},
            "entries": [],
            "bindings": [{"id": 7, "card_id": 2, "rule_set_id": 6, "ref_type": "BASE", "tenant_id": 4}]
        });
        assert_eq!(added_binding(&before, &after, &spec).unwrap()["id"], 7);
    }
}
