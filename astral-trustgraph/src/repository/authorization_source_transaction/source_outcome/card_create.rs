//! CardCreate-specific finite RuleSet binding evidence.
//!
//! This child owns the closed proof that a template RuleSet binding changed only
//! by the one expected BASE ref and its ADD contributions. The generic source
//! outcome guard remains responsible for CARD/ELIGIBILITY projection attribution;
//! this receipt only supplies the RuleSet-specific evidence that the shared guard
//! cannot infer from independent aggregate event ids.

use std::collections::BTreeSet;

use astral_types::{AstralError, BindingLayer, GrantDelta, GrantSourceKind};
use serde_json::{Map, Value};
use sqlx::{MySql, Transaction};

use crate::repository::authorization_source_transaction::AuthorizationSourceTransaction;
use crate::repository::rule_set_repository::CardCreateRulesetAddition;

const RULE_SET_TABLE: &str = "rule_set";
const RULE_SET_AGGREGATE: &str = "RULE_SET";
const RULE_SET_UPDATE: &str = "RULE_SET_UPDATE";
const INITIAL_REBUILD_CHANGE_TYPE: &str = "INITIAL_REBUILD";
const BIND_CARD_CHANGE_TYPE: &str = "BIND_CARD";
const INITIAL_REBUILD_REASON: &str = "INITIAL_REBUILD_FOR_CARD_RULE_SET_BINDING";
const MAX_BINDING_AUDIT_ROWS: i64 = 8;
const MAX_BINDING_DELTA_ROWS: i64 = 1024;

struct AggregateParts<'a> {
    root: &'a Map<String, Value>,
    entries: &'a [Value],
    bindings: &'a [Value],
}

#[derive(Debug, Clone)]
pub(crate) struct CardCreateBindingStart {
    pub(crate) rule_set_id: i64,
    pub(crate) card_id: i64,
    pub(crate) user_id: i64,
    pub(crate) tenant_id: i64,
    pub(crate) domain_id: Option<i64>,
    pub(crate) operation_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CardCreateBindingBefore {
    rule_set_id: i64,
    card_id: i64,
    user_id: i64,
    tenant_id: i64,
    domain_id: Option<i64>,
    operation_id: String,
    lookup: String,
    before_image: String,
}

/// Opaque CardCreate RuleSet binding receipt.
///
/// There are no public fields and deliberately no `Deserialize` implementation.
/// The only constructor is [`finish_card_create_binding_in_tx`], after its
/// same-transaction source, projection, audit, reference, and delta checks pass.
#[derive(Debug, Clone)]
pub(crate) struct CardCreateBindingReceipt {
    evidence: Value,
}

impl CardCreateBindingReceipt {
    pub(crate) fn rule_set_id(&self) -> i64 {
        self.evidence
            .get("ruleSetId")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }

    /// Main-owned source-outcome integration consumes this already validated
    /// evidence and attaches it to the independent CardCreate artifact.
    pub(crate) fn source_evidence(&self) -> &Value {
        &self.evidence
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ProjectionHeadRow {
    source_generation: i64,
    last_event_id: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct ProjectionEventRow {
    event_id: String,
    aggregate_type: String,
    aggregate_id: i64,
    tenant_id: Option<i64>,
    event_type: String,
    source_generation: i64,
    sequence_number: i64,
    revoke_fence: i64,
    status: String,
    payload_json: String,
}

#[derive(Debug, sqlx::FromRow)]
struct AuditRow {
    audit_id: i64,
    rule_set_id: i64,
    entry_id: Option<i64>,
    changed_by: i64,
    change_type: String,
    old_value_json: Option<String>,
    new_value_json: Option<String>,
    tenant_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    source_generation: i64,
    operation_id: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DeltaRow {
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    event_id: String,
    operation_id: String,
    event_type: String,
    base_version: i64,
    target_version: i64,
    source_generation: i64,
    revoke_fence: i64,
    invalidates_published_evidence: i8,
    before_image_json: Option<String>,
    delta_json: String,
}

fn pending(message: impl Into<String>) -> AstralError {
    AstralError::Pending(message.into())
}

fn database(error: sqlx::Error, context: &'static str) -> AstralError {
    AstralError::Database(format!("CardCreate RuleSet evidence {context}: {error}"))
}

fn require_positive(value: i64, field: &'static str) -> Result<(), AstralError> {
    if value <= 0 {
        return Err(AstralError::Validation(format!(
            "CardCreate RuleSet evidence requires a positive {field}"
        )));
    }
    Ok(())
}

fn canonical_lookup(rule_set_id: i64) -> Result<String, AstralError> {
    serde_json::to_string(&astral_db::TypedSourceRowLookup::PrimaryId { id: rule_set_id }).map_err(
        |error| AstralError::Validation(format!("RuleSet lookup encoding failed: {error}")),
    )
}

async fn read_rule_set_image(
    tx: &mut Transaction<'_, MySql>,
    rule_set_id: i64,
) -> Result<(i64, String), AstralError> {
    let lookup = astral_db::TypedSourceRowLookup::PrimaryId { id: rule_set_id };
    let image = astral_db::read_typed_source_row_image_in_tx_typed(
        tx,
        astral_db::TypedSourceTable::RuleSet,
        &lookup,
    )
    .await
    .map_err(AstralError::from)?
    .ok_or_else(|| pending("CardCreate RuleSet before image is absent"))?;
    if image.0 != rule_set_id || image.1.trim().is_empty() {
        return Err(pending(
            "CardCreate RuleSet typed image has an unexpected identity",
        ));
    }
    Ok(image)
}

/// Read the complete typed RuleSet aggregate before any remaining binding work.
/// The returned handle is intentionally opaque to callers and can only be sealed
/// by the matching child function after the mutation sequence completes.
pub(crate) async fn begin_card_create_binding_in_raw_tx(
    tx: &mut Transaction<'_, MySql>,
    start: CardCreateBindingStart,
) -> Result<CardCreateBindingBefore, AstralError> {
    let CardCreateBindingStart {
        rule_set_id,
        card_id,
        user_id,
        tenant_id,
        domain_id,
        operation_id,
    } = start;
    require_positive(rule_set_id, "rule_set_id")?;
    require_positive(card_id, "card_id")?;
    require_positive(user_id, "user_id")?;
    require_positive(tenant_id, "tenant_id")?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "CardCreate RuleSet evidence requires a non-empty operation id".into(),
        ));
    }
    let lookup = canonical_lookup(rule_set_id)?;
    let (key, before_image) = read_rule_set_image(tx, rule_set_id).await?;
    if key != rule_set_id {
        return Err(pending("CardCreate RuleSet before image key differs"));
    }
    Ok(CardCreateBindingBefore {
        rule_set_id,
        card_id,
        user_id,
        tenant_id,
        domain_id,
        operation_id: operation_id.to_owned(),
        lookup,
        before_image,
    })
}

fn object_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, AstralError> {
    object.get(key).ok_or_else(|| {
        pending(format!(
            "CardCreate RuleSet evidence is missing field {key}"
        ))
    })
}

fn i64_field(object: &Map<String, Value>, key: &str) -> Result<i64, AstralError> {
    object_field(object, key)?.as_i64().ok_or_else(|| {
        pending(format!(
            "CardCreate RuleSet evidence field {key} is not an integer"
        ))
    })
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, AstralError> {
    object_field(object, key)?.as_str().ok_or_else(|| {
        pending(format!(
            "CardCreate RuleSet evidence field {key} is not text"
        ))
    })
}

fn aggregate_parts(value: &Value) -> Result<AggregateParts<'_>, AstralError> {
    let object = value
        .as_object()
        .ok_or_else(|| pending("CardCreate RuleSet typed image is not an object"))?;
    let root = object_field(object, "root")?
        .as_object()
        .ok_or_else(|| pending("CardCreate RuleSet typed image root is not an object"))?;
    let entries = object_field(object, "entries")?
        .as_array()
        .ok_or_else(|| pending("CardCreate RuleSet typed image entries are not an array"))?;
    let bindings = object_field(object, "bindings")?
        .as_array()
        .ok_or_else(|| pending("CardCreate RuleSet typed image bindings are not an array"))?;
    Ok(AggregateParts {
        root,
        entries,
        bindings,
    })
}

fn canonical_values(values: &[Value]) -> Vec<String> {
    let mut encoded = values.iter().map(Value::to_string).collect::<Vec<_>>();
    encoded.sort();
    encoded
}

fn validate_rule_set_images(
    before_image: &str,
    after_image: &str,
    before: &CardCreateBindingBefore,
    ref_id: i64,
) -> Result<Value, AstralError> {
    let before_image: Value = serde_json::from_str(before_image)
        .map_err(|_| pending("CardCreate RuleSet before image is not valid JSON"))?;
    let after_image: Value = serde_json::from_str(after_image)
        .map_err(|_| pending("CardCreate RuleSet after image is not valid JSON"))?;
    let before_parts = aggregate_parts(&before_image)?;
    let after_parts = aggregate_parts(&after_image)?;
    if i64_field(before_parts.root, "rule_set_id")? != before.rule_set_id
        || i64_field(after_parts.root, "rule_set_id")? != before.rule_set_id
    {
        return Err(pending("CardCreate RuleSet root identity changed"));
    }
    if before_parts.root != after_parts.root || before_parts.entries != after_parts.entries {
        return Err(pending(
            "CardCreate RuleSet root or entries changed during binding",
        ));
    }
    if object_field(before_parts.root, "tenant_id")?
        .as_i64()
        .is_some_and(|tenant_id| tenant_id != before.tenant_id)
    {
        return Err(pending("CardCreate RuleSet belongs to another tenant"));
    }
    if after_parts.bindings.len() != before_parts.bindings.len() + 1 {
        return Err(pending(
            "CardCreate RuleSet binding set did not gain exactly one row",
        ));
    }
    let expected_binding = |value: &Value| -> Result<bool, AstralError> {
        let object = value
            .as_object()
            .ok_or_else(|| pending("CardCreate RuleSet binding image is not an object"))?;
        Ok(i64_field(object, "id")? == ref_id
            && i64_field(object, "card_id")? == before.card_id
            && i64_field(object, "rule_set_id")? == before.rule_set_id
            && string_field(object, "ref_type")? == "BASE"
            && i64_field(object, "tenant_id")? == before.tenant_id)
    };
    let matching = after_parts
        .bindings
        .iter()
        .map(expected_binding)
        .collect::<Result<Vec<_>, _>>()?;
    if matching.iter().filter(|matched| **matched).count() != 1 {
        return Err(pending(
            "CardCreate RuleSet after image does not contain exactly one expected BASE binding",
        ));
    }
    if before_parts
        .bindings
        .iter()
        .map(expected_binding)
        .collect::<Result<Vec<_>, _>>()?
        .contains(&true)
    {
        return Err(pending(
            "CardCreate RuleSet before image already contains the new binding id",
        ));
    }
    let new_index = matching
        .iter()
        .position(|matched| *matched)
        .ok_or_else(|| pending("CardCreate RuleSet new binding cannot be located"))?;
    let mut remaining = after_parts.bindings.to_vec();
    remaining.remove(new_index);
    if canonical_values(&remaining) != canonical_values(before_parts.bindings) {
        return Err(pending(
            "CardCreate RuleSet pre-existing bindings were not preserved exactly",
        ));
    }
    Ok(after_parts.bindings[new_index].clone())
}

fn rule_set_tenant(before: &CardCreateBindingBefore) -> Result<Option<i64>, AstralError> {
    let image: Value = serde_json::from_str(&before.before_image)
        .map_err(|_| pending("CardCreate RuleSet before image is not valid JSON"))?;
    let aggregate = aggregate_parts(&image)?;
    let tenant = object_field(aggregate.root, "tenant_id")?;
    if tenant.is_null() {
        return Ok(None);
    }
    let tenant = tenant
        .as_i64()
        .filter(|value| *value == before.tenant_id)
        .ok_or_else(|| pending("CardCreate RuleSet tenant differs from the card"))?;
    Ok(Some(tenant))
}

fn validate_projection_payload(
    payload_json: &str,
    rule_set_id: i64,
    generation: i64,
    tenant_id: Option<i64>,
    operation_id: &str,
    actor_id: i64,
) -> Result<Value, AstralError> {
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|_| pending("CardCreate RuleSet projection payload is not valid JSON"))?;
    let object = payload
        .as_object()
        .ok_or_else(|| pending("CardCreate RuleSet projection payload is not an object"))?;
    if i64_field(object, "ruleSetId")? != rule_set_id
        || i64_field(object, "generation")? != generation
        || object_field(object, "tenantId")?.as_i64() != tenant_id
        || i64_field(object, "actorId")? != actor_id
        || string_field(object, "operationId")? != operation_id
    {
        return Err(pending(
            "CardCreate RuleSet projection payload is not bound to this operation",
        ));
    }
    Ok(payload)
}

async fn read_projection_event(
    tx: &mut AuthorizationSourceTransaction,
    event_id: &str,
    rule_set_id: i64,
) -> Result<ProjectionEventRow, AstralError> {
    sqlx::query_as::<_, ProjectionEventRow>(
        "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
         sequence_number, revoke_fence, status, CAST(payload_json AS CHAR) AS payload_json \
         FROM authorization_projection_outbox WHERE aggregate_type = 'RULE_SET' \
         AND aggregate_id = ? AND event_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(event_id)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(|error| database(error, "projection event readback failed"))?
    .ok_or_else(|| pending("CardCreate RuleSet projection event is missing"))
}

fn validate_projection_event(
    event: &ProjectionEventRow,
    rule_set_id: i64,
    expected_tenant_id: Option<i64>,
    projection: &astral_db::ProjectionEventIdentity,
    operation_id: &str,
    actor_id: i64,
) -> Result<Value, AstralError> {
    if event.event_id != projection.event_id
        || event.aggregate_type != RULE_SET_AGGREGATE
        || event.aggregate_id != rule_set_id
        || event.tenant_id != expected_tenant_id
        || event.event_type != RULE_SET_UPDATE
        || event.source_generation != projection.source_generation
        || event.sequence_number != projection.source_generation
        || event.revoke_fence != projection.revoke_fence
        || !matches!(event.status.as_str(), "PENDING" | "PROCESSED")
    {
        return Err(pending(
            "CardCreate RuleSet current projection event differs from its receipt",
        ));
    }
    validate_projection_payload(
        &event.payload_json,
        rule_set_id,
        event.source_generation,
        expected_tenant_id,
        operation_id,
        actor_id,
    )
}

fn validate_head(
    head: &ProjectionHeadRow,
    projection: &astral_db::ProjectionEventIdentity,
) -> Result<(), AstralError> {
    if head.source_generation != projection.source_generation
        || head.last_event_id.as_deref() != Some(projection.event_id.as_str())
    {
        return Err(pending(
            "CardCreate RuleSet projection identity is not the current head",
        ));
    }
    Ok(())
}

fn audit_detail_arrays(detail: &Map<String, Value>, key: &str) -> Result<Vec<Value>, AstralError> {
    object_field(detail, key)?
        .as_array()
        .cloned()
        .ok_or_else(|| pending(format!("BIND_CARD audit field {key} is not an array")))
}

fn validate_bind_audit_detail(
    row: &AuditRow,
    before: &CardCreateBindingBefore,
    ref_id: i64,
    parent_event_id: &str,
    addition: &CardCreateRulesetAddition,
) -> Result<Value, AstralError> {
    if row.entry_id.is_some()
        || row.change_type != BIND_CARD_CHANGE_TYPE
        || row.old_value_json.is_some()
        || row.rule_set_id != before.rule_set_id
        || row.aggregate_type != RULE_SET_AGGREGATE
        || row.aggregate_id != before.rule_set_id
        || row.tenant_id != rule_set_tenant(before)?
        || row.operation_id != before.operation_id
        || row.audit_id <= 0
    {
        return Err(pending("BIND_CARD audit row dimensions are invalid"));
    }
    let new_value = row
        .new_value_json
        .as_deref()
        .ok_or_else(|| pending("BIND_CARD audit row has no new value"))?;
    let value: Value = serde_json::from_str(new_value)
        .map_err(|_| pending("BIND_CARD audit new value is not valid JSON"))?;
    let detail = value
        .as_object()
        .ok_or_else(|| pending("BIND_CARD audit new value is not an object"))?;
    if i64_field(detail, "cardId")? != before.card_id
        || i64_field(detail, "tenantId")? != before.tenant_id
        || i64_field(detail, "refId")? != ref_id
        || string_field(detail, "refType")? != "BASE"
        || string_field(detail, "parentSourceEventId")? != parent_event_id
    {
        return Err(pending(
            "BIND_CARD audit binding dimensions do not match the card",
        ));
    }
    let event_values = audit_detail_arrays(detail, "contributionEventIds")?;
    let entry_values = audit_detail_arrays(detail, "ruleSetEntryIds")?;
    let card_values = audit_detail_arrays(detail, "boundCardIds")?;
    let ref_values = audit_detail_arrays(detail, "bindingRefIds")?;
    if event_values.len() != addition.added_entries.len()
        || entry_values.len() != addition.added_entries.len()
        || card_values.len() != addition.added_entries.len()
        || ref_values.len() != addition.added_entries.len()
    {
        return Err(pending(
            "BIND_CARD audit contribution arrays do not match ADD count",
        ));
    }
    for (index, added) in addition.added_entries.iter().enumerate() {
        if event_values[index].as_str() != Some(added.event_id.as_str())
            || entry_values[index].as_i64() != Some(added.entry_id)
            || card_values[index].as_i64() != Some(before.card_id)
            || ref_values[index].as_i64() != Some(ref_id)
        {
            return Err(pending(
                "BIND_CARD audit contribution dimensions do not match ADD provenance",
            ));
        }
    }
    Ok(value)
}

fn validate_initial_rebuild_audit(
    row: &AuditRow,
    before: &CardCreateBindingBefore,
) -> Result<Value, AstralError> {
    if row.audit_id <= 0
        || row.rule_set_id != before.rule_set_id
        || row.entry_id.is_some()
        || row.changed_by <= 0
        || row.change_type != INITIAL_REBUILD_CHANGE_TYPE
        || row.old_value_json.is_some()
        || row.aggregate_type != RULE_SET_AGGREGATE
        || row.aggregate_id != before.rule_set_id
        || row.operation_id != before.operation_id
        || row.tenant_id != rule_set_tenant(before)?
    {
        return Err(pending("INITIAL_REBUILD audit row dimensions are invalid"));
    }
    let new_value = row
        .new_value_json
        .as_deref()
        .ok_or_else(|| pending("INITIAL_REBUILD audit row has no new value"))?;
    let value: Value = serde_json::from_str(new_value)
        .map_err(|_| pending("INITIAL_REBUILD audit new value is not valid JSON"))?;
    let detail = value
        .as_object()
        .ok_or_else(|| pending("INITIAL_REBUILD audit new value is not an object"))?;
    if string_field(detail, "reason")? != INITIAL_REBUILD_REASON
        || i64_field(detail, "ruleSetId")? != before.rule_set_id
        || object_field(detail, "tenantId")? != &serde_json::json!(rule_set_tenant(before)?)
        || string_field(detail, "operationId")? != before.operation_id
    {
        return Err(pending("INITIAL_REBUILD audit reason is not exact"));
    }
    Ok(value)
}

fn validate_audits(
    rows: &[AuditRow],
    before: &CardCreateBindingBefore,
    projection: &astral_db::ProjectionEventIdentity,
    actor_id: i64,
    parent_event_id: &str,
    ref_id: i64,
    addition: &CardCreateRulesetAddition,
) -> Result<(Value, Vec<Value>), AstralError> {
    let mut seen_ids = BTreeSet::new();
    let mut bind = None;
    let mut initial = Vec::new();
    let mut all = Vec::with_capacity(rows.len());
    for row in rows {
        if row.changed_by != actor_id
            || row.event_id.trim().is_empty()
            || row.source_generation <= 0
        {
            return Err(pending("RuleSet audit row lacks valid identity dimensions"));
        }
        if !seen_ids.insert(row.audit_id) {
            return Err(pending(
                "RuleSet audit receipt contains duplicate audit ids",
            ));
        }
        let item = match row.change_type.as_str() {
            BIND_CARD_CHANGE_TYPE => {
                if bind.is_some()
                    || row.event_id != projection.event_id
                    || row.source_generation != projection.source_generation
                {
                    return Err(pending(
                        "CardCreate RuleSet audit must contain one current BIND_CARD row",
                    ));
                }
                let detail =
                    validate_bind_audit_detail(row, before, ref_id, parent_event_id, addition)?;
                bind = Some(detail.clone());
                detail
            }
            INITIAL_REBUILD_CHANGE_TYPE => {
                if !initial.is_empty() {
                    return Err(pending(
                        "CardCreate RuleSet audit contains multiple INITIAL_REBUILD rows",
                    ));
                }
                let detail = validate_initial_rebuild_audit(row, before)?;
                initial.push(detail.clone());
                detail
            }
            _ => {
                return Err(pending(
                    "CardCreate RuleSet audit contains an unknown change type",
                ));
            }
        };
        all.push(serde_json::json!({
            "auditId": row.audit_id,
            "ruleSetId": row.rule_set_id,
            "entryId": row.entry_id,
            "changedBy": row.changed_by,
            "changeType": row.change_type,
            "oldValueJson": row.old_value_json,
            "newValueJson": row.new_value_json,
            "eventId": row.event_id,
            "sourceGeneration": row.source_generation,
            "operationId": row.operation_id,
            "tenantId": row.tenant_id,
            "aggregateType": row.aggregate_type,
            "aggregateId": row.aggregate_id,
            "detail": item,
        }));
    }
    let bind = bind.ok_or_else(|| pending("CardCreate RuleSet audit lacks BIND_CARD"))?;
    Ok((bind, all))
}

fn validate_delta_value(
    row: &DeltaRow,
    addition: &CardCreateRulesetAddition,
    before: &CardCreateBindingBefore,
    ref_id: i64,
    actor_id: i64,
) -> Result<(i64, Value), AstralError> {
    if row.tenant_id != before.tenant_id
        || row.card_id != Some(before.card_id)
        || row.aggregate_type != RULE_SET_AGGREGATE
        || row.aggregate_id != before.rule_set_id
        || row.operation_id != before.operation_id
        || row.event_type != "ADD"
        || row.base_version != 0
        || row.target_version != 1
        || row.revoke_fence != 0
        || row.invalidates_published_evidence != 0
        || row.before_image_json.is_some()
    {
        return Err(pending("CardCreate RuleSet ADD delta contract is invalid"));
    }
    let expected_entry = addition
        .added_entries
        .iter()
        .find(|entry| entry.event_id == row.event_id)
        .map(|entry| entry.entry_id)
        .ok_or_else(|| pending("CardCreate RuleSet delta event is not in the ADD receipt"))?;
    let expected_entry_text = expected_entry.to_string();
    let expected_ref_text = ref_id.to_string();
    let delta: GrantDelta = serde_json::from_str(&row.delta_json).map_err(|_| {
        pending("CardCreate RuleSet ADD delta payload is not valid GrantDelta JSON")
    })?;
    let GrantDelta::Add { grant } = &delta else {
        return Err(pending("CardCreate RuleSet delta payload is not ADD"));
    };
    if grant.card_id != before.card_id
        || grant.user_id != before.user_id
        || grant.tenant.tenant_id != before.tenant_id
        || grant.tenant.domain_id != before.domain_id
        || grant.source_kind != GrantSourceKind::RuleSet
        || grant.binding_layer != BindingLayer::Base
        || grant.provenance.source_id != before.rule_set_id.to_string()
        || grant.provenance.source_entry.as_deref() != Some(expected_entry_text.as_str())
        || grant.provenance.binding_id.as_deref() != Some(expected_ref_text.as_str())
        || grant.provenance.operation_id != before.operation_id
        || grant.provenance.event_id.as_deref() != Some(row.event_id.as_str())
        || grant.provenance.actor_user_id != Some(actor_id)
    {
        return Err(pending(
            "CardCreate RuleSet ADD provenance does not match its binding",
        ));
    }
    Ok((expected_entry, delta_to_value(delta)?))
}

fn delta_to_value(delta: GrantDelta) -> Result<Value, AstralError> {
    serde_json::to_value(delta).map_err(|error| {
        AstralError::Internal(format!("ADD delta evidence encoding failed: {error}"))
    })
}

async fn read_and_validate_deltas(
    tx: &mut AuthorizationSourceTransaction,
    before: &CardCreateBindingBefore,
    ref_id: i64,
    actor_id: i64,
    addition: &CardCreateRulesetAddition,
    parent_projection: &astral_db::ProjectionEventIdentity,
) -> Result<Vec<Value>, AstralError> {
    let rows = sqlx::query_as::<_, DeltaRow>(
        "SELECT tenant_id, card_id, aggregate_type, aggregate_id, event_id, operation_id, \
         event_type, base_version, target_version, source_generation, revoke_fence, \
         invalidates_published_evidence, CAST(before_image_json AS CHAR) AS before_image_json, CAST(delta_json AS CHAR) AS delta_json \
         FROM authorization_delta_event WHERE aggregate_type = 'RULE_SET' \
         AND aggregate_id = ? AND operation_id = ? ORDER BY event_id LIMIT ? FOR UPDATE",
    )
    .bind(before.rule_set_id)
    .bind(&before.operation_id)
    .bind(MAX_BINDING_DELTA_ROWS + 1)
    .fetch_all(&mut ***tx)
    .await
    .map_err(|error| database(error, "delta readback failed"))?;
    if rows.len() as i64 > MAX_BINDING_DELTA_ROWS {
        return Err(pending(
            "CardCreate RuleSet delta evidence exceeds its bound",
        ));
    }
    if rows.len() != addition.added_entries.len() {
        return Err(pending(
            "CardCreate RuleSet current operation has an unknown or missing ADD delta",
        ));
    }
    let expected_ids = addition
        .added_entries
        .iter()
        .map(|entry| entry.event_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut evidence = Vec::with_capacity(rows.len());
    for row in &rows {
        if row.source_generation != parent_projection.source_generation
            || row.revoke_fence != parent_projection.revoke_fence
        {
            return Err(pending(
                "CardCreate ADD is not bound to its CARD parent generation",
            ));
        }
        if !seen.insert(row.event_id.as_str()) || !expected_ids.contains(row.event_id.as_str()) {
            return Err(pending(
                "CardCreate RuleSet delta evidence contains an unknown or duplicate event",
            ));
        }
        let (entry_id, delta) = validate_delta_value(row, addition, before, ref_id, actor_id)?;
        evidence.push(serde_json::json!({
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
            "invalidatesPublishedEvidence": row.invalidates_published_evidence != 0,
            "beforeImageJson": row.before_image_json,
            "delta": delta,
            "ruleSetEntryId": entry_id,
        }));
    }
    if seen.len() != expected_ids.len() {
        return Err(pending(
            "CardCreate RuleSet ADD receipt does not cover every current delta",
        ));
    }
    evidence.sort_by(|left, right| left["eventId"].as_str().cmp(&right["eventId"].as_str()));
    Ok(evidence)
}

/// Seal one RuleSet binding after the existing ensure/ref/ADD/audit sequence.
/// This performs the after image read and validates every durable correlation
/// needed by the opaque receipt, including empty RuleSet bindings with no deltas.
pub(crate) async fn finish_card_create_binding_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    before: CardCreateBindingBefore,
    ref_id: i64,
    rule_projection: &astral_db::ProjectionEventIdentity,
    parent_projection: &astral_db::ProjectionEventIdentity,
    addition: &CardCreateRulesetAddition,
    actor_id: i64,
) -> Result<CardCreateBindingReceipt, AstralError> {
    require_positive(ref_id, "binding ref id")?;
    require_positive(actor_id, "actor id")?;
    if addition.rule_set_id != before.rule_set_id || addition.binding_ref_id != ref_id {
        return Err(pending(
            "CardCreate RuleSet addition identity differs from its binding",
        ));
    }
    let expected_rule_set_tenant = rule_set_tenant(&before)?;
    if rule_projection.tenant_id != expected_rule_set_tenant
        || parent_projection.tenant_id != Some(before.tenant_id)
        || parent_projection.event_id.trim().is_empty()
    {
        return Err(pending(
            "CardCreate RuleSet projection identity has an invalid tenant or parent",
        ));
    }
    let (after_key, after_image) = read_rule_set_image(tx, before.rule_set_id).await?;
    if after_key != before.rule_set_id {
        return Err(pending("CardCreate RuleSet after image key differs"));
    }
    let binding = validate_rule_set_images(&before.before_image, &after_image, &before, ref_id)?;

    let head: ProjectionHeadRow = sqlx::query_as(
        "SELECT source_generation, last_event_id FROM authorization_projection_head \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? FOR UPDATE",
    )
    .bind(before.rule_set_id)
    .fetch_optional(&mut ***tx)
    .await
    .map_err(|error| database(error, "projection head readback failed"))?
    .ok_or_else(|| pending("CardCreate RuleSet projection head is missing"))?;
    validate_head(&head, rule_projection)?;
    let current_event =
        read_projection_event(tx, &rule_projection.event_id, before.rule_set_id).await?;
    let current_payload = validate_projection_event(
        &current_event,
        before.rule_set_id,
        expected_rule_set_tenant,
        rule_projection,
        &before.operation_id,
        actor_id,
    )?;

    let audit_rows = sqlx::query_as::<_, AuditRow>(
        "SELECT audit_id, rule_set_id, entry_id, changed_by, change_type, old_value_json, \
         new_value_json, tenant_id, aggregate_type, aggregate_id, event_id, \
         source_generation, operation_id FROM rule_set_projection_audit \
         WHERE rule_set_id = ? AND operation_id = ? ORDER BY audit_id LIMIT ? FOR UPDATE",
    )
    .bind(before.rule_set_id)
    .bind(&before.operation_id)
    .bind(MAX_BINDING_AUDIT_ROWS + 1)
    .fetch_all(&mut ***tx)
    .await
    .map_err(|error| database(error, "audit readback failed"))?;
    if audit_rows.len() as i64 > MAX_BINDING_AUDIT_ROWS {
        return Err(pending(
            "CardCreate RuleSet audit evidence exceeds its bound",
        ));
    }
    let (bind_detail, audits) = validate_audits(
        &audit_rows,
        &before,
        rule_projection,
        actor_id,
        &parent_projection.event_id,
        ref_id,
        addition,
    )?;
    let deltas =
        read_and_validate_deltas(tx, &before, ref_id, actor_id, addition, parent_projection)
            .await?;

    let evidence = serde_json::json!({
        "schemaVersion": 1,
        "kind": "CARD_CREATE_RULESET_BINDING",
        "table": RULE_SET_TABLE,
        "lookup": before.lookup,
        "ruleSetId": before.rule_set_id,
        "cardId": before.card_id,
        "userId": before.user_id,
        "tenantId": before.tenant_id,
        "domainId": before.domain_id,
        "operationId": before.operation_id,
        "beforeAggregate": serde_json::from_str::<Value>(&before.before_image)
            .map_err(|_| pending("CardCreate RuleSet before image cannot be retained as JSON"))?,
        "afterAggregate": serde_json::from_str::<Value>(&after_image)
            .map_err(|_| pending("CardCreate RuleSet after image cannot be retained as JSON"))?,
        "binding": binding,
        "currentSourceEvent": {
            "eventId": current_event.event_id,
            "aggregateType": current_event.aggregate_type,
            "aggregateId": current_event.aggregate_id,
            "tenantId": current_event.tenant_id,
            "eventType": current_event.event_type,
            "sourceGeneration": current_event.source_generation,
            "sequenceNumber": current_event.sequence_number,
            "revokeFence": current_event.revoke_fence,
            "status": current_event.status,
            "payload": current_payload,
        },
        "parentCardProjection": {
            "eventId": parent_projection.event_id,
            "cardId": before.card_id,
            "tenantId": parent_projection.tenant_id,
            "sourceGeneration": parent_projection.source_generation,
            "revokeFence": parent_projection.revoke_fence,
        },
        "projection": {
            "eventId": rule_projection.event_id,
            "sourceGeneration": rule_projection.source_generation,
            "revokeFence": rule_projection.revoke_fence,
            "tenantId": rule_projection.tenant_id,
        },
        "audit": audits,
        "bindAudit": bind_detail,
        "addDeltas": deltas,
        "emptyRuleSet": addition.added_entries.is_empty(),
    });
    Ok(CardCreateBindingReceipt { evidence })
}

/// Serialize the retained binding receipts for Main’s independent CardCreate
/// source artifact. Every receipt is retained, including empty RuleSets.
pub(crate) fn card_create_binding_evidence(
    receipts: &[CardCreateBindingReceipt],
) -> Result<Value, AstralError> {
    if receipts.is_empty() {
        return Err(pending(
            "CardCreate binding evidence cannot be silently omitted when bindings were processed",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut values = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let rule_set_id = receipt
            .source_evidence()
            .get("ruleSetId")
            .and_then(Value::as_i64)
            .ok_or_else(|| pending("CardCreate binding receipt lacks ruleSetId"))?;
        if !seen.insert(rule_set_id) {
            return Err(pending(
                "CardCreate binding evidence contains duplicate RuleSets",
            ));
        }
        values.push(receipt.source_evidence().clone());
    }
    values.sort_by_key(|value| value["ruleSetId"].as_i64());
    Ok(Value::Array(values))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn before_binding(entries: Vec<Value>, tenant_id: Option<i64>) -> CardCreateBindingBefore {
        CardCreateBindingBefore {
            rule_set_id: 7,
            card_id: 21,
            user_id: 31,
            tenant_id: 41,
            domain_id: None,
            operation_id: "op-1".into(),
            lookup: "{\"id\":7}".into(),
            before_image: serde_json::json!({
                "root": {"rule_set_id": 7, "tenant_id": tenant_id, "name": "n"},
                "entries": entries,
                "bindings": [{"id": 4, "card_id": 20, "rule_set_id": 7, "ref_type": "BASE", "tenant_id": 41}]
            }).to_string(),
        }
    }

    fn after_binding(before: &CardCreateBindingBefore) -> Value {
        let mut image: Value = serde_json::from_str(&before.before_image).unwrap();
        image["bindings"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": 8, "card_id": 21, "rule_set_id": 7, "ref_type": "BASE", "tenant_id": 41,
            }));
        image
    }

    #[test]
    fn binding_diff_preserves_existing_rows_and_accepts_one_base_row() {
        for tenant_id in [None, Some(41)] {
            let before = before_binding(
                vec![serde_json::json!({"entry_id": 9, "effect": "ALLOW"})],
                tenant_id,
            );
            let after = after_binding(&before);
            let binding =
                validate_rule_set_images(&before.before_image, &after.to_string(), &before, 8)
                    .unwrap();
            assert_eq!(binding["id"], 8);
            assert_eq!(rule_set_tenant(&before).unwrap(), tenant_id);
        }
    }

    #[test]
    fn binding_diff_rejects_root_entry_or_binding_drift() {
        let before = before_binding(
            vec![serde_json::json!({"entry_id": 9, "effect": "ALLOW"})],
            Some(41),
        );
        let actual = after_binding(&before);
        for (pointer, value) in [
            ("/root/name", serde_json::json!("changed")),
            ("/entries/0/effect", serde_json::json!("DENY")),
            ("/bindings/0/card_id", serde_json::json!(99)),
            ("/bindings/1/card_id", serde_json::json!(99)),
            ("/bindings/1/ref_type", serde_json::json!("OVERLAY")),
            ("/bindings/1/tenant_id", serde_json::json!(42)),
        ] {
            let mut tampered = actual.clone();
            *tampered.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_rule_set_images(&before.before_image, &tampered.to_string(), &before, 8)
                    .is_err(),
                "accepted drift at {pointer}"
            );
        }
        let foreign = before_binding(Vec::new(), Some(42));
        assert!(rule_set_tenant(&foreign).is_err());
        assert!(validate_rule_set_images(
            &foreign.before_image,
            &after_binding(&foreign).to_string(),
            &foreign,
            8
        )
        .is_err());
    }

    #[test]
    fn new_card_coverage_requires_every_add_and_exact_shared_event_attribution() {
        use super::super::{derive_card_create_coverage, SourceProjectionEvidence};
        let event = astral_db::DeltaSourceEventEvidence {
            tenant_id: 41,
            card_id: Some(21),
            aggregate_type: "RULE_SET".into(),
            aggregate_id: 7,
            event_id: "add-1".into(),
            operation_id: "op-1".into(),
            event_type: "ADD".into(),
            grant_id: "grant-1".into(),
            base_version: 0,
            target_version: 1,
            source_generation: 1,
            revoke_fence: 0,
            invalidates_published_evidence: false,
            delta_event_id: 1,
            revision_id: 1,
            predecessor_revision_id: None,
            grant_revision: 1,
            is_tombstone: false,
            delta_json: "{}".into(),
            semantic_hash_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            compiler_version: "test".into(),
            before_digest_hex: None,
            after_digest_hex: "cc".repeat(32),
        };
        let delta = astral_db::DeltaSourceOutcomeEvidence {
            events: vec![event],
            receipts: Vec::new(),
            before_digest_hex: "aa".repeat(32),
            after_digest_hex: "bb".repeat(32),
            commit_digest_hex: "cc".repeat(32),
        };
        let source = SourceProjectionEvidence {
            outbox_id: 1,
            event_id: "rs-event-1".into(),
            aggregate_type: "RULE_SET".into(),
            aggregate_id: 7,
            tenant_id: None,
            event_type: "RULE_SET_UPDATE".into(),
            source_generation: 99,
            sequence_number: 99,
            revoke_fence: 0,
            payload: serde_json::json!({"operationId": "op-1"}),
        };
        let binding = CardCreateBindingReceipt {
            evidence: serde_json::json!({
                "ruleSetId": 7,
                "addDeltas": [{"eventId": "add-1", "delta": {}, "operationId": "op-1",
                    "aggregateType": "RULE_SET", "aggregateId": 7, "tenantId": 41, "cardId": 21,
                    "sourceGeneration": 1, "revokeFence": 0}],
                "audit": [{"eventId": "rs-event-1", "ruleSetId": 7, "sourceGeneration": 99,
                    "tenantId": null, "operationId": "op-1"}],
            }),
        };
        let sources = [source];
        let coverage =
            derive_card_create_coverage(&delta, &sources, &[], std::slice::from_ref(&binding))
                .unwrap()
                .unwrap();
        assert_eq!(coverage.scopes.len(), 1);
        assert_eq!(coverage.scopes[0].card_identity(), Some((41, 21)));
        for (pointer, replacement) in [
            ("/addDeltas/0/eventId", serde_json::json!("unregistered")),
            ("/addDeltas/0/cardId", serde_json::json!(22)),
            ("/addDeltas/0/sourceGeneration", serde_json::json!(99)),
            ("/audit/0/eventId", serde_json::json!("unregistered")),
            ("/audit/0/sourceGeneration", serde_json::json!(1)),
            ("/audit/0/tenantId", serde_json::json!(41)),
        ] {
            let mut tampered = binding.clone();
            *tampered.evidence.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                derive_card_create_coverage(&delta, &sources, &[], &[tampered]).is_err(),
                "accepted coverage drift at {pointer}"
            );
        }
        assert!(derive_card_create_coverage(&delta, &sources, &[], &[]).is_err());
        let mut unknown = sources[0].clone();
        unknown.aggregate_id = 8;
        assert!(derive_card_create_coverage(&delta, &[unknown], &[], &[binding]).is_err());
    }

    #[test]
    fn empty_ruleset_binding_is_validated_and_retained_without_a_delta() {
        let before = before_binding(Vec::new(), None);
        let after = after_binding(&before);
        let binding =
            validate_rule_set_images(&before.before_image, &after.to_string(), &before, 8).unwrap();
        let receipt = CardCreateBindingReceipt {
            evidence: serde_json::json!({
                "ruleSetId": before.rule_set_id, "beforeAggregate": serde_json::from_str::<Value>(&before.before_image).unwrap(),
                "afterAggregate": after, "binding": binding, "emptyRuleSet": true, "addDeltas": [],
            }),
        };
        let retained = card_create_binding_evidence(std::slice::from_ref(&receipt)).unwrap();
        assert_eq!(retained[0], *receipt.source_evidence());
        assert_eq!(retained[0]["binding"]["card_id"], before.card_id);
        assert!(retained[0]["addDeltas"].as_array().unwrap().is_empty());
        assert!(card_create_binding_evidence(&[receipt.clone(), receipt]).is_err());
    }
}
