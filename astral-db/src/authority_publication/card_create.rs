//! Durable CardCreate RuleSet binding readback.
//!
//! This verifier consumes only the finite binding artifact emitted by the source
//! transaction. It re-reads every durable row while the publication transaction
//! holds its consistency locks; JSON shape alone is never accepted as proof.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use sqlx::{MySql, Transaction};

use super::identity::IdentityStagedEvidence;
use crate::DeltaSourceOutcomeEvidence;

mod capture;
mod grants;

pub use capture::{
    CardCreateRuleSetCapture, CardCreateRuleSetCaptureSpec, CardCreateRuleSetReceipt,
};

/// Structured verifier outcome so eligibility completion can distinguish a
/// durable proof contradiction from a transient SQL/database failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CardCreateBindingVerifyError {
    #[error("CardCreate binding proof is pending: {0}")]
    Pending(String),
    #[error("CardCreate binding database read failed: {0}")]
    Database(#[source] sqlx::Error),
}

type VerifyResult<T> = Result<T, CardCreateBindingVerifyError>;

const RULE_SET_AGGREGATE: &str = "RULE_SET";
const CARD_AGGREGATE: &str = "CARD";
const CARD_CREATED: &str = "CARD_CREATED";
const RULE_SET_UPDATE: &str = "RULE_SET_UPDATE";
const BIND_CARD: &str = "BIND_CARD";
const INITIAL_REBUILD: &str = "INITIAL_REBUILD";
const INITIAL_REBUILD_REASON: &str = "INITIAL_REBUILD_FOR_CARD_RULE_SET_BINDING";
const MAX_BINDINGS: usize = 1024;
const MAX_AUDITS: usize = 8;
const MAX_DELTAS: usize = 1024;

struct AggregateParts<'a> {
    root: &'a Map<String, Value>,
    entries: &'a [Value],
    bindings: &'a [Value],
}

fn pending(message: impl std::fmt::Display) -> CardCreateBindingVerifyError {
    CardCreateBindingVerifyError::Pending(message.to_string())
}

fn database(error: sqlx::Error) -> CardCreateBindingVerifyError {
    CardCreateBindingVerifyError::Database(error)
}

fn object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a Map<String, Value>, CardCreateBindingVerifyError> {
    value
        .as_object()
        .ok_or_else(|| pending(format!("{context} is not an object")))
}

fn field<'a>(
    value: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, CardCreateBindingVerifyError> {
    value
        .get(key)
        .ok_or_else(|| pending(format!("CardCreate binding is missing {key}")))
}

fn i64_field(value: &Map<String, Value>, key: &str) -> Result<i64, CardCreateBindingVerifyError> {
    field(value, key)?
        .as_i64()
        .ok_or_else(|| pending(format!("CardCreate binding {key} is not an integer")))
}

fn string_field<'a>(
    value: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, CardCreateBindingVerifyError> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| pending(format!("CardCreate binding {key} is not text")))
}

fn nullable_i64(
    value: &Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, CardCreateBindingVerifyError> {
    let value = field(value, key)?;
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_i64()
            .map(Some)
            .ok_or_else(|| pending(format!("CardCreate binding {key} is not nullable integer")))
    }
}

fn array<'a>(
    value: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], CardCreateBindingVerifyError> {
    field(value, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| pending(format!("CardCreate binding {key} is not an array")))
}

fn canonical_values(values: &[Value]) -> Vec<String> {
    let mut values = values.iter().map(Value::to_string).collect::<Vec<_>>();
    values.sort();
    values
}

fn aggregate_parts(value: &Value) -> Result<AggregateParts<'_>, CardCreateBindingVerifyError> {
    let value = object(value, "RuleSet aggregate")?;
    let root = object(field(value, "root")?, "RuleSet root")?;
    let entries = field(value, "entries")?
        .as_array()
        .ok_or_else(|| pending("RuleSet entries are not an array"))?;
    let bindings = field(value, "bindings")?
        .as_array()
        .ok_or_else(|| pending("RuleSet bindings are not an array"))?;
    Ok(AggregateParts {
        root,
        entries,
        bindings,
    })
}

fn validate_aggregate_diff(
    before: &Value,
    after: &Value,
    binding: &Map<String, Value>,
    card_id: i64,
    tenant_id: i64,
) -> Result<i64, CardCreateBindingVerifyError> {
    let before_parts = aggregate_parts(before)?;
    let after_parts = aggregate_parts(after)?;
    let rule_set_id = i64_field(binding, "ruleSetId")?;
    if i64_field(before_parts.root, "rule_set_id")? != rule_set_id
        || i64_field(after_parts.root, "rule_set_id")? != rule_set_id
    {
        return Err(pending("RuleSet root identity differs from binding"));
    }
    if before_parts.root != after_parts.root || before_parts.entries != after_parts.entries {
        return Err(pending("RuleSet root or entries changed during CardCreate"));
    }
    let root_tenant = nullable_i64(before_parts.root, "tenant_id")?;
    if root_tenant.is_some_and(|value| value != tenant_id) {
        return Err(pending("RuleSet root belongs to another tenant"));
    }
    if after_parts.bindings.len() != before_parts.bindings.len() + 1 {
        return Err(pending("CardCreate must add exactly one RuleSet binding"));
    }
    let expected = |value: &Value| -> Result<bool, CardCreateBindingVerifyError> {
        let value = object(value, "RuleSet binding row")?;
        Ok(i64_field(value, "card_id")? == card_id
            && i64_field(value, "rule_set_id")? == rule_set_id
            && string_field(value, "ref_type")? == "BASE"
            && nullable_i64(value, "tenant_id")? == Some(tenant_id))
    };
    let mut matching = Vec::new();
    for value in after_parts.bindings {
        if expected(value)? {
            matching.push(value);
        }
    }
    if matching.len() != 1 {
        return Err(pending(
            "RuleSet after image lacks one unique BASE card binding",
        ));
    }
    for value in before_parts.bindings {
        if expected(value)? {
            return Err(pending(
                "RuleSet before image already contains the new card binding",
            ));
        }
    }
    let new_binding = object(matching[0], "new RuleSet binding")?;
    let ref_id = i64_field(new_binding, "id")?;
    let declared_binding = object(field(binding, "binding")?, "binding")?;
    if declared_binding != new_binding {
        return Err(pending(
            "retained binding differs from the typed after image",
        ));
    }
    let mut remaining = after_parts.bindings.to_vec();
    let index = remaining
        .iter()
        .position(|value| value == matching[0])
        .ok_or_else(|| pending("new RuleSet binding cannot be located"))?;
    remaining.remove(index);
    if canonical_values(&remaining) != canonical_values(before_parts.bindings) {
        return Err(pending(
            "pre-existing RuleSet bindings were not retained exactly",
        ));
    }
    Ok(ref_id)
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

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct CreatedCardRow {
    card_id: i64,
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: Option<i64>,
    card_type: String,
    level_id: Option<i64>,
    priority: i32,
    is_primary: bool,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct RefRow {
    id: i64,
    card_id: i64,
    rule_set_id: i64,
    ref_type: String,
    tenant_id: Option<i64>,
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

fn validate_creation_payload(
    payload: &Map<String, Value>,
    card_id: i64,
    tenant_id: i64,
    actor_id: i64,
    operation_id: &str,
) -> VerifyResult<()> {
    if actor_id <= 0
        || operation_id.trim().is_empty()
        || i64_field(payload, "cardId")? != card_id
        || nullable_i64(payload, "tenantId")? != Some(tenant_id)
        || i64_field(payload, "actorId")? != actor_id
        || string_field(payload, "operationId")? != operation_id
    {
        return Err(pending(
            "CARD_CREATED payload actor/operation/card binding differs",
        ));
    }
    Ok(())
}

async fn validate_parent_card_projection(
    tx: &mut Transaction<'_, MySql>,
    binding: &Map<String, Value>,
    card_id: i64,
    tenant_id: i64,
    delta: Option<&DeltaSourceOutcomeEvidence>,
) -> VerifyResult<(i64, i64)> {
    let parent = object(
        field(binding, "parentCardProjection")?,
        "parentCardProjection",
    )?;
    let bind_audits = array(binding, "audit")?
        .iter()
        .filter(|audit| audit.get("changeType").and_then(Value::as_str) == Some(BIND_CARD))
        .collect::<Vec<_>>();
    if bind_audits.len() != 1 {
        return Err(pending("CARD_CREATED requires one BIND_CARD actor"));
    }
    let actor_id = i64_field(object(bind_audits[0], "BIND_CARD audit")?, "changedBy")?;
    let operation_id = string_field(binding, "operationId")?;
    let event_id = string_field(parent, "eventId")?;
    if i64_field(parent, "cardId")? != card_id
        || nullable_i64(parent, "tenantId")? != Some(tenant_id)
    {
        return Err(pending("parentCardProjection card identity differs"));
    }
    let expected_generation = i64_field(parent, "sourceGeneration")?;
    let expected_fence = i64_field(parent, "revokeFence")?;
    let row: ProjectionEventRow = sqlx::query_as(
        "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
             sequence_number, revoke_fence, status, CAST(payload_json AS CHAR) AS payload_json \
             FROM authorization_projection_outbox WHERE aggregate_type = ? AND aggregate_id = ? \
             AND event_id = ? FOR UPDATE",
    )
    .bind(CARD_AGGREGATE)
    .bind(card_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database)?
    .ok_or_else(|| pending("CARD_CREATED parent event is missing"))?;
    if row.event_id != event_id
        || row.aggregate_type != CARD_AGGREGATE
        || row.aggregate_id != card_id
        || row.tenant_id != Some(tenant_id)
        || row.event_type != CARD_CREATED
        || row.source_generation != expected_generation
        || row.sequence_number != expected_generation
        || row.revoke_fence != expected_fence
        || !matches!(row.status.as_str(), "PENDING" | "PROCESSED")
    {
        return Err(pending(
            "CARD_CREATED parent projection differs from its receipt",
        ));
    }
    let payload: Value = serde_json::from_str(&row.payload_json).map_err(pending)?;
    let payload = object(&payload, "CARD_CREATED payload")?;
    validate_creation_payload(payload, card_id, tenant_id, actor_id, operation_id)?;
    if let Some(delta) = delta {
        if delta.events.is_empty() {
            return Err(pending("CardCreate delta evidence is empty"));
        }
        if delta.events.iter().any(|event| {
            event.tenant_id != tenant_id
                || event.card_id != Some(card_id)
                || event.source_generation as i64 != expected_generation
                || event.revoke_fence as i64 != expected_fence
        }) {
            return Err(pending(
                "CardCreate delta is not bound to CARD_CREATED parent",
            ));
        }
    }
    Ok((expected_generation, expected_fence))
}

fn audit_row_value(row: &AuditRow, detail: Value) -> Value {
    serde_json::json!({
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
        "detail": detail,
    })
}

fn audit_detail(row: &AuditRow) -> Result<Value, CardCreateBindingVerifyError> {
    let json = row
        .new_value_json
        .as_deref()
        .ok_or_else(|| pending("CardCreate audit row has no new value"))?;
    serde_json::from_str(json).map_err(pending)
}

struct AuditVerificationContext<'a> {
    binding: &'a Map<String, Value>,
    rule_set_id: i64,
    tenant_id: i64,
    operation_id: &'a str,
    projection: &'a Map<String, Value>,
    ref_id: i64,
    card_id: i64,
}

async fn verify_audits(
    tx: &mut Transaction<'_, MySql>,
    context: &AuditVerificationContext<'_>,
) -> Result<(), CardCreateBindingVerifyError> {
    let &AuditVerificationContext {
        binding,
        rule_set_id,
        tenant_id,
        operation_id,
        projection,
        ref_id,
        card_id,
    } = context;
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT audit_id, rule_set_id, entry_id, changed_by, change_type, \
         CAST(old_value_json AS CHAR) AS old_value_json, CAST(new_value_json AS CHAR) AS new_value_json, tenant_id, \
         aggregate_type, aggregate_id, event_id, source_generation, operation_id \
         FROM rule_set_projection_audit WHERE rule_set_id = ? AND operation_id = ? \
         ORDER BY audit_id LIMIT ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(operation_id)
    .bind((MAX_AUDITS + 1) as i64)
    .fetch_all(&mut **tx)
    .await
    .map_err(database)?;
    if rows.is_empty() || rows.len() > MAX_AUDITS {
        return Err(pending(
            "CardCreate RuleSet audit set is incomplete or oversized",
        ));
    }
    let declared = array(binding, "audit")?;
    if declared.len() != rows.len() {
        return Err(pending(
            "retained RuleSet audit count differs from durable rows",
        ));
    }
    let expected_rule_set_tenant = nullable_i64(projection, "tenantId")?;
    let mut actual = Vec::with_capacity(rows.len());
    let mut bind_count = 0;
    let mut initial_count = 0;
    let mut actor_id = None;
    for row in &rows {
        if row.audit_id <= 0
            || row.rule_set_id != rule_set_id
            || row.aggregate_type != RULE_SET_AGGREGATE
            || row.aggregate_id != rule_set_id
            || row.operation_id != operation_id
            || row.tenant_id != expected_rule_set_tenant
            || row.changed_by <= 0
            || row.event_id.trim().is_empty()
            || row.source_generation <= 0
        {
            return Err(pending("RuleSet audit row identity is invalid"));
        }
        let detail = audit_detail(row)?;
        match row.change_type.as_str() {
            BIND_CARD => {
                bind_count += 1;
                actor_id = Some(row.changed_by);
                if row.event_id != string_field(projection, "eventId")?
                    || row.source_generation != i64_field(projection, "sourceGeneration")?
                {
                    return Err(pending(
                        "BIND_CARD audit is not the current RuleSet projection",
                    ));
                }
                let detail_object = object(&detail, "BIND_CARD detail")?;
                if i64_field(detail_object, "cardId")? != card_id
                    || i64_field(detail_object, "tenantId")? != tenant_id
                    || i64_field(detail_object, "refId")? != ref_id
                    || string_field(detail_object, "refType")? != "BASE"
                {
                    return Err(pending("BIND_CARD audit does not bind the card/ref"));
                }
                if string_field(detail_object, "parentSourceEventId")?
                    != string_field(
                        object(
                            field(binding, "parentCardProjection")?,
                            "parentCardProjection",
                        )?,
                        "eventId",
                    )?
                {
                    return Err(pending("BIND_CARD audit parent event differs"));
                }
            }
            INITIAL_REBUILD => {
                initial_count += 1;
                if row.entry_id.is_some() || row.old_value_json.is_some() {
                    return Err(pending("INITIAL_REBUILD audit has entry or old image"));
                }
                let detail_object = object(&detail, "INITIAL_REBUILD detail")?;
                if string_field(detail_object, "reason")? != INITIAL_REBUILD_REASON
                    || i64_field(detail_object, "ruleSetId")? != rule_set_id
                    || nullable_i64(detail_object, "tenantId")? != expected_rule_set_tenant
                    || string_field(detail_object, "operationId")? != operation_id
                {
                    return Err(pending(
                        "INITIAL_REBUILD audit is not bound to this operation",
                    ));
                }
            }
            _ => return Err(pending("RuleSet audit contains an unsupported change type")),
        }
        actual.push(audit_row_value(row, detail));
    }
    if bind_count != 1 || initial_count > 1 {
        return Err(pending(
            "CardCreate RuleSet audit must contain one BIND_CARD",
        ));
    }
    actual.sort_by_key(|value| value["auditId"].as_i64());
    let mut declared = declared.to_vec();
    declared.sort_by_key(|value| value["auditId"].as_i64());
    if actual != declared {
        return Err(pending(
            "retained RuleSet audit differs from durable readback",
        ));
    }
    let bind_audit = object(field(binding, "bindAudit")?, "bindAudit")?;
    let actual_bind = actual
        .iter()
        .find(|value| value["changeType"] == BIND_CARD)
        .and_then(|value| value.get("detail"))
        .ok_or_else(|| pending("BIND_CARD detail is missing"))?;
    if bind_audit != object(actual_bind, "durable BIND_CARD detail")? {
        return Err(pending("retained bindAudit differs from durable audit"));
    }
    let actor_id = actor_id.ok_or_else(|| pending("BIND_CARD actor is missing"))?;
    let payload = object(
        field(
            object(field(binding, "currentSourceEvent")?, "currentSourceEvent")?,
            "payload",
        )?,
        "current source payload",
    )?;
    if i64_field(payload, "actorId")? != actor_id
        || string_field(payload, "operationId")? != operation_id
    {
        return Err(pending(
            "RuleSet projection payload actor/operation differs",
        ));
    }
    Ok(())
}

struct DeltaVerificationContext<'a> {
    binding: &'a Map<String, Value>,
    delta: Option<&'a DeltaSourceOutcomeEvidence>,
    rule_set_id: i64,
    card_id: i64,
    tenant_id: i64,
    operation_id: &'a str,
    parent_generation: i64,
    parent_fence: i64,
}

async fn verify_deltas(
    tx: &mut Transaction<'_, MySql>,
    context: &DeltaVerificationContext<'_>,
) -> Result<(), CardCreateBindingVerifyError> {
    let &DeltaVerificationContext {
        binding,
        delta,
        rule_set_id,
        card_id,
        tenant_id,
        operation_id,
        parent_generation,
        parent_fence,
    } = context;
    let expected_additions = grants::validate_additions(binding)?;
    let declared = array(binding, "addDeltas")?;
    let empty = field(binding, "emptyRuleSet")?
        .as_bool()
        .ok_or_else(|| pending("emptyRuleSet is not boolean"))?;
    if empty != declared.is_empty() {
        return Err(pending("emptyRuleSet does not match addDeltas"));
    }
    let rows: Vec<DeltaRow> = sqlx::query_as(
        "SELECT tenant_id, card_id, aggregate_type, aggregate_id, event_id, operation_id, \
         event_type, base_version, target_version, source_generation, revoke_fence, \
         invalidates_published_evidence, CAST(before_image_json AS CHAR) AS before_image_json, \
         CAST(delta_json AS CHAR) AS delta_json \
         FROM authorization_delta_event WHERE aggregate_type = ? AND aggregate_id = ? \
         AND operation_id = ? ORDER BY event_id LIMIT ? FOR UPDATE",
    )
    .bind(RULE_SET_AGGREGATE)
    .bind(rule_set_id)
    .bind(operation_id)
    .bind((MAX_DELTAS + 1) as i64)
    .fetch_all(&mut **tx)
    .await
    .map_err(database)?;
    if rows.len() > MAX_DELTAS || rows.len() != declared.len() {
        return Err(pending(
            "CardCreate ADD delta count differs from durable rows",
        ));
    }
    if empty {
        if !rows.is_empty()
            || delta.is_some_and(|value| {
                value.events.iter().any(|event| {
                    event.aggregate_type == RULE_SET_AGGREGATE
                        && event.aggregate_id == rule_set_id
                        && event.operation_id == operation_id
                })
            })
        {
            return Err(pending("empty RuleSet binding has durable ADD evidence"));
        }
        return Ok(());
    }
    let delta = delta.ok_or_else(|| pending("non-empty RuleSet binding lacks source delta"))?;
    let mut expected_ids = BTreeSet::new();
    for value in declared {
        let value = object(value, "addDeltas item")?;
        let event_id = string_field(value, "eventId")?;
        if !expected_ids.insert(event_id.to_owned())
            || string_field(value, "aggregateType")? != RULE_SET_AGGREGATE
            || i64_field(value, "aggregateId")? != rule_set_id
            || string_field(value, "operationId")? != operation_id
            || string_field(value, "eventType")? != "ADD"
            || i64_field(value, "sourceGeneration")? != parent_generation
            || i64_field(value, "revokeFence")? != parent_fence
        {
            return Err(pending("retained ADD delta identity is invalid"));
        }
        let event = delta
            .events
            .iter()
            .find(|event| event.event_id == event_id)
            .ok_or_else(|| pending("retained ADD delta is absent from the source batch"))?;
        let expected = expected_additions
            .get(event_id)
            .ok_or_else(|| pending("retained ADD has no complete source contribution"))?;
        let event_delta: astral_types::GrantDelta =
            serde_json::from_str(&event.delta_json).map_err(pending)?;
        if event.aggregate_type != RULE_SET_AGGREGATE
            || event.aggregate_id != rule_set_id
            || event.operation_id != operation_id
            || event.semantic_hash_hex != expected.semantic_hash_hex
            || event.dependency_hash_hex != expected.dependency_hash_hex
            || event_delta != expected.delta
        {
            return Err(pending(
                "retained ADD delta is absent from the source batch",
            ));
        }
    }
    if rows.iter().any(|row| {
        row.tenant_id != tenant_id
            || row.card_id != Some(card_id)
            || row.aggregate_type != RULE_SET_AGGREGATE
            || row.aggregate_id != rule_set_id
            || row.operation_id != operation_id
            || row.event_type != "ADD"
            || row.source_generation != parent_generation
            || row.revoke_fence != parent_fence
            || row.invalidates_published_evidence != 0
            || !expected_ids.contains(&row.event_id)
    }) || rows
        .iter()
        .map(|row| row.event_id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != expected_ids.len()
    {
        return Err(pending(
            "durable ADD delta rows differ from the retained batch",
        ));
    }
    for row in &rows {
        let declared = array(binding, "addDeltas")?
            .iter()
            .find(|value| value["eventId"].as_str() == Some(row.event_id.as_str()))
            .ok_or_else(|| pending("durable ADD event is not retained"))?;
        let declared = object(declared, "addDeltas item")?;
        let actual_delta: Value = serde_json::from_str(&row.delta_json).map_err(pending)?;
        if field(declared, "tenantId")?.as_i64() != Some(row.tenant_id)
            || field(declared, "cardId")?.as_i64() != row.card_id
            || field(declared, "baseVersion")?.as_i64() != Some(row.base_version)
            || field(declared, "targetVersion")?.as_i64() != Some(row.target_version)
            || field(declared, "invalidatesPublishedEvidence")?.as_bool() != Some(false)
            || field(declared, "beforeImageJson")?
                != &row
                    .before_image_json
                    .as_ref()
                    .map_or(Value::Null, |value| Value::String(value.clone()))
            || field(declared, "delta")? != &actual_delta
        {
            return Err(pending(
                "retained ADD delta payload differs from durable row",
            ));
        }
    }
    Ok(())
}

/// Verify a new card's complete template binding set against its durable rows.
/// Other card mutations cannot carry CardCreate binding evidence.
pub(crate) async fn verify_card_create_bindings_structured_in_tx(
    tx: &mut Transaction<'_, MySql>,
    artifact: &IdentityStagedEvidence,
) -> VerifyResult<()> {
    let new_cards = artifact
        .targets
        .iter()
        .filter(|target| {
            target.entity == "user_card"
                && matches!(target.before, super::identity::IdentityPresence::Absent)
        })
        .collect::<Vec<_>>();
    let values = artifact.fanout.get("cardCreateRuleSetBindings");
    if new_cards.is_empty() {
        return if values.is_none() {
            Ok(())
        } else {
            Err(pending(
                "CardCreate binding evidence accompanies another source mutation",
            ))
        };
    }
    if new_cards.len() != 1 {
        return Err(pending("CardCreate requires exactly one new-card target"));
    }
    let card_target = new_cards[0];
    let card_id = card_target
        .key
        .get("cardId")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or_else(|| pending("CardCreate target has no positive card id"))?;
    let super::identity::IdentityPresence::Present(after_card) = &card_target.after else {
        return Err(pending("CardCreate target has no after image"));
    };
    let after_card_object = object(after_card, "created card after image")?;
    let tenant_id = i64_field(after_card_object, "tenantId")?;
    let user_id = i64_field(after_card_object, "userId")?;
    let domain_id = nullable_i64(after_card_object, "domainId")?;
    if tenant_id <= 0 || user_id <= 0 || i64_field(after_card_object, "cardId")? != card_id {
        return Err(pending("CardCreate target identity is invalid"));
    }
    let current: CreatedCardRow = sqlx::query_as(
        "SELECT card_id, card_status, user_id, tenant_id, domain_id, template_id, \
         card_type, level_id, priority, is_primary, CAST(valid_from AS CHAR) AS valid_from, \
         CAST(valid_until AS CHAR) AS valid_until FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database)?
    .ok_or_else(|| pending("created card is missing"))?;
    if serde_json::to_value(&current).map_err(pending)? != *after_card {
        return Err(pending(
            "created card differs from its complete retained after image",
        ));
    }
    let expected_rulesets: Vec<i64> = match current.template_id {
        Some(template_id) => sqlx::query_scalar(
            "SELECT rule_set_id FROM rule_set WHERE source_type = 'TEMPLATE' \
             AND source_id = ? AND enabled = 1 ORDER BY rule_set_id LIMIT ? FOR UPDATE",
        )
        .bind(template_id)
        .bind((MAX_BINDINGS + 1) as i64)
        .fetch_all(&mut **tx)
        .await
        .map_err(database)?,
        None => Vec::new(),
    };
    if expected_rulesets.len() > MAX_BINDINGS {
        return Err(pending("CardCreate template RuleSet set exceeds its bound"));
    }
    let refs: Vec<RefRow> = sqlx::query_as(
        "SELECT id, card_id, rule_set_id, CAST(ref_type AS CHAR) AS ref_type, tenant_id \
         FROM card_rule_set_ref WHERE card_id = ? ORDER BY rule_set_id, id LIMIT ? FOR UPDATE",
    )
    .bind(card_id)
    .bind((MAX_BINDINGS + 1) as i64)
    .fetch_all(&mut **tx)
    .await
    .map_err(database)?;
    if refs.len() > MAX_BINDINGS
        || refs.iter().any(|row| {
            row.id <= 0
                || row.card_id != card_id
                || row.ref_type != "BASE"
                || row.tenant_id != Some(tenant_id)
        })
    {
        return Err(pending("new card has an invalid or oversized binding set"));
    }
    let actual_rulesets = refs
        .iter()
        .map(|row| row.rule_set_id)
        .collect::<BTreeSet<_>>();
    if actual_rulesets.len() != refs.len()
        || actual_rulesets != expected_rulesets.into_iter().collect::<BTreeSet<_>>()
    {
        return Err(pending(
            "new card BASE references differ from its complete template set",
        ));
    }
    let values = match values {
        Some(value) => value
            .as_array()
            .ok_or_else(|| pending("cardCreateRuleSetBindings is not an array"))?
            .as_slice(),
        None if refs.is_empty() => &[],
        None => {
            return Err(pending(
                "CardCreate omits its nonempty RuleSet binding evidence",
            ))
        }
    };
    if values.len() != refs.len() {
        return Err(pending(
            "CardCreate retained binding count differs from the complete ref set",
        ));
    }
    let operation_id = values
        .first()
        .map(|value| string_field(object(value, "CardCreate binding")?, "operationId"))
        .transpose()?
        .unwrap_or("");
    if !values.is_empty() && operation_id.trim().is_empty() {
        return Err(pending("CardCreate binding operation identity is missing"));
    }
    let mut seen_rulesets = BTreeSet::new();
    let mut parent: Option<(String, i64, i64)> = None;
    for value in values {
        let binding = object(value, "CardCreate binding")?;
        if i64_field(binding, "schemaVersion")? != 1
            || string_field(binding, "kind")? != "CARD_CREATE_RULESET_BINDING"
            || string_field(binding, "table")? != "rule_set"
            || i64_field(binding, "userId")? != user_id
            || nullable_i64(binding, "domainId")? != domain_id
            || i64_field(binding, "cardId")? != card_id
            || i64_field(binding, "tenantId")? != tenant_id
            || string_field(binding, "operationId")? != operation_id
        {
            return Err(pending(
                "CardCreate bindings disagree on card/tenant/operation",
            ));
        }
        let rule_set_id = i64_field(binding, "ruleSetId")?;
        if !seen_rulesets.insert(rule_set_id) {
            return Err(pending("CardCreate binding repeats a RuleSet"));
        }
        let before = field(binding, "beforeAggregate")?;
        let after = field(binding, "afterAggregate")?;
        let ref_id = validate_aggregate_diff(before, after, binding, card_id, tenant_id)?;
        let current = crate::read_typed_source_row_image_in_tx_typed(
            tx,
            crate::TypedSourceTable::RuleSet,
            &crate::TypedSourceRowLookup::PrimaryId { id: rule_set_id },
        )
        .await
        .map_err(|error| match error {
            crate::TypedSourceReadError::SqlxTransient { source, .. }
            | crate::TypedSourceReadError::SqlxSchema { source, .. } => database(source),
            other => pending(other),
        })?
        .ok_or_else(|| pending("CardCreate RuleSet aggregate is missing"))?;
        let current: Value = serde_json::from_str(&current.1).map_err(pending)?;
        if &current != after {
            return Err(pending(
                "current RuleSet aggregate differs from the retained after image",
            ));
        }
        let parent_projection = object(
            field(binding, "parentCardProjection")?,
            "parentCardProjection",
        )?;
        let delta = artifact.delta.as_ref();
        let parent_identity =
            validate_parent_card_projection(tx, binding, card_id, tenant_id, delta).await?;
        if let Some(previous) = parent.as_ref() {
            if previous
                != &(
                    string_field(parent_projection, "eventId")?.to_owned(),
                    parent_identity.0,
                    parent_identity.1,
                )
            {
                return Err(pending("CardCreate bindings disagree on CARD parent"));
            }
        } else {
            parent = Some((
                string_field(parent_projection, "eventId")?.to_owned(),
                parent_identity.0,
                parent_identity.1,
            ));
        }
        let projection = object(field(binding, "projection")?, "RuleSet projection")?;
        let expected_tenant = object(before, "RuleSet aggregate")?;
        let expected_tenant = nullable_i64(
            object(field(expected_tenant, "root")?, "RuleSet root")?,
            "tenant_id",
        )?;
        if nullable_i64(projection, "tenantId")? != expected_tenant {
            return Err(pending("RuleSet projection tenant differs from its root"));
        }
        let head: ProjectionHeadRow = sqlx::query_as(
            "SELECT source_generation, last_event_id FROM authorization_projection_head \
             WHERE aggregate_type = ? AND aggregate_id = ? FOR UPDATE",
        )
        .bind(RULE_SET_AGGREGATE)
        .bind(rule_set_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)?
        .ok_or_else(|| pending("RuleSet projection head is missing"))?;
        if head.source_generation != i64_field(projection, "sourceGeneration")?
            || head.last_event_id.as_deref() != Some(string_field(projection, "eventId")?)
        {
            return Err(pending("RuleSet projection is not the current head"));
        }
        let event_id = string_field(projection, "eventId")?;
        let event: ProjectionEventRow = sqlx::query_as(
            "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
             sequence_number, revoke_fence, status, CAST(payload_json AS CHAR) AS payload_json \
             FROM authorization_projection_outbox WHERE aggregate_type = ? AND aggregate_id = ? \
             AND event_id = ? FOR UPDATE",
        )
        .bind(RULE_SET_AGGREGATE)
        .bind(rule_set_id)
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)?
        .ok_or_else(|| pending("RuleSet current projection event is missing"))?;
        let current = object(field(binding, "currentSourceEvent")?, "currentSourceEvent")?;
        if event.event_id != event_id
            || event.aggregate_type != RULE_SET_AGGREGATE
            || event.aggregate_id != rule_set_id
            || event.event_type != RULE_SET_UPDATE
            || event.tenant_id != expected_tenant
            || event.source_generation != i64_field(projection, "sourceGeneration")?
            || event.sequence_number != event.source_generation
            || event.revoke_fence != i64_field(projection, "revokeFence")?
            || !matches!(event.status.as_str(), "PENDING" | "PROCESSED")
            || event.event_id != string_field(current, "eventId")?
            || event.source_generation != i64_field(current, "sourceGeneration")?
            || event.revoke_fence != i64_field(current, "revokeFence")?
        {
            return Err(pending(
                "RuleSet current source event differs from durable event",
            ));
        }
        let payload: Value = serde_json::from_str(&event.payload_json).map_err(pending)?;
        if field(current, "payload")? != &payload {
            return Err(pending("retained RuleSet projection payload differs"));
        }
        let ref_row: RefRow = sqlx::query_as(
            "SELECT id, card_id, rule_set_id, CAST(ref_type AS CHAR) AS ref_type, tenant_id \
             FROM card_rule_set_ref WHERE id = ? FOR UPDATE",
        )
        .bind(ref_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)?
        .ok_or_else(|| pending("CardCreate RuleSet ref is missing"))?;
        if ref_row.id != ref_id
            || ref_row.card_id != card_id
            || ref_row.rule_set_id != rule_set_id
            || ref_row.ref_type != "BASE"
            || ref_row.tenant_id != Some(tenant_id)
        {
            return Err(pending("CardCreate RuleSet ref differs from its receipt"));
        }
        verify_audits(
            tx,
            &AuditVerificationContext {
                binding,
                rule_set_id,
                tenant_id,
                operation_id,
                projection,
                ref_id,
                card_id,
            },
        )
        .await?;
        verify_deltas(
            tx,
            &DeltaVerificationContext {
                binding,
                delta,
                rule_set_id,
                card_id,
                tenant_id,
                operation_id,
                parent_generation: parent_identity.0,
                parent_fence: parent_identity.1,
            },
        )
        .await?;
    }
    if seen_rulesets != actual_rulesets {
        return Err(pending(
            "CardCreate retained RuleSets differ from the complete durable set",
        ));
    }
    let declared_adds = values
        .iter()
        .map(|value| array(object(value, "CardCreate binding")?, "addDeltas"))
        .collect::<VerifyResult<Vec<_>>>()?;
    let mut declared_events = BTreeSet::new();
    for event in declared_adds.into_iter().flatten() {
        if !declared_events.insert(string_field(object(event, "CardCreate ADD")?, "eventId")?) {
            return Err(pending("CardCreate repeats a retained ADD event"));
        }
    }
    let actual_events = artifact
        .delta
        .as_ref()
        .map(|delta| {
            delta
                .events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if declared_events != actual_events {
        return Err(pending(
            "CardCreate binding ADDs differ from the complete source delta batch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_parent_rejects_actor_operation_and_card_tampering() {
        let payload = serde_json::json!({
            "cardId": 21, "tenantId": 41, "actorId": 51, "operationId": "create-card"
        });
        let payload = payload.as_object().unwrap();
        validate_creation_payload(payload, 21, 41, 51, "create-card").unwrap();
        for (key, replacement) in [
            ("cardId", serde_json::json!(22)),
            ("tenantId", serde_json::json!(42)),
            ("actorId", serde_json::json!(52)),
            ("operationId", serde_json::json!("another-operation")),
        ] {
            let mut changed = payload.clone();
            changed.insert(key.into(), replacement);
            assert!(validate_creation_payload(&changed, 21, 41, 51, "create-card").is_err());
            let mut missing = payload.clone();
            missing.remove(key);
            assert!(validate_creation_payload(&missing, 21, 41, 51, "create-card").is_err());
        }
        assert!(validate_creation_payload(payload, 21, 41, 0, "create-card").is_err());
        assert!(validate_creation_payload(payload, 21, 41, 51, "").is_err());
    }

    #[test]
    fn typed_ruleset_image_uses_snake_case_fields() {
        let value = serde_json::json!({
            "root": {"rule_set_id": 7, "tenant_id": null},
            "entries": [],
            "bindings": []
        });
        let aggregate = aggregate_parts(&value).unwrap();
        assert_eq!(aggregate.root["rule_set_id"], 7);
        assert!(aggregate.entries.is_empty());
        assert!(aggregate.bindings.is_empty());
    }

    fn binding_fixture(tenant: Option<i64>) -> (Value, Value, Map<String, Value>) {
        let before = serde_json::json!({
            "root": {"rule_set_id": 7, "tenant_id": tenant, "name": "rules"},
            "entries": [{"entry_id": 11, "effect": "ALLOW"}],
            "bindings": [{"id": 3, "card_id": 20, "rule_set_id": 7, "ref_type": "BASE", "tenant_id": 41}]
        });
        let new = serde_json::json!({"id": 8, "card_id": 21, "rule_set_id": 7, "ref_type": "BASE", "tenant_id": 41});
        let mut after = before.clone();
        after["bindings"].as_array_mut().unwrap().push(new.clone());
        let binding = serde_json::json!({"ruleSetId": 7, "binding": new})
            .as_object()
            .unwrap()
            .clone();
        (before, after, binding)
    }

    #[test]
    fn aggregate_diff_accepts_only_the_exact_new_base_ref() {
        for tenant in [None, Some(41)] {
            let (before, after, binding) = binding_fixture(tenant);
            assert_eq!(
                validate_aggregate_diff(&before, &after, &binding, 21, 41).unwrap(),
                8
            );
            for (pointer, replacement) in [
                ("/root/name", serde_json::json!("changed")),
                ("/entries/0/effect", serde_json::json!("DENY")),
                ("/bindings/0/card_id", serde_json::json!(99)),
                ("/bindings/1/card_id", serde_json::json!(99)),
                ("/bindings/1/ref_type", serde_json::json!("OVERLAY")),
                ("/bindings/1/tenant_id", serde_json::json!(42)),
            ] {
                let mut changed = after.clone();
                *changed.pointer_mut(pointer).unwrap() = replacement;
                assert!(
                    validate_aggregate_diff(&before, &changed, &binding, 21, 41).is_err(),
                    "{pointer}"
                );
            }
        }
    }

    #[test]
    fn aggregate_diff_rejects_duplicate_missing_and_foreign_bindings() {
        let (before, mut after, binding) = binding_fixture(Some(41));
        after["bindings"]
            .as_array_mut()
            .unwrap()
            .push(binding["binding"].clone());
        assert!(validate_aggregate_diff(&before, &after, &binding, 21, 41).is_err());
        assert!(validate_aggregate_diff(&before, &before, &binding, 21, 41).is_err());
        let (mut before, mut after, binding) = binding_fixture(Some(42));
        assert!(validate_aggregate_diff(&before, &after, &binding, 21, 41).is_err());
        before["root"]["tenant_id"] = Value::Null;
        after["root"]["tenant_id"] = Value::Null;
        before["bindings"][0] = binding["binding"].clone();
        after["bindings"][0] = binding["binding"].clone();
        assert!(validate_aggregate_diff(&before, &after, &binding, 21, 41).is_err());
    }
}
