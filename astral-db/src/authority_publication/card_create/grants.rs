//! Complete CardCreate contribution reconstruction from locked RuleSet images.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{
    aggregate_parts, array, field, i64_field, nullable_i64, object, pending, string_field,
    VerifyResult,
};
use crate::grant_ledger::{
    build_ruleset_add_draft, derive_ruleset_contribution_event_id, RuleSetEntryLedgerFacts,
    RuleSetGrantDeltaDraft, RuleSetMutationKind,
};

fn nullable_text<'a>(value: &'a Map<String, Value>, key: &str) -> VerifyResult<Option<&'a str>> {
    let value = field(value, key)?;
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_str()
            .map(Some)
            .ok_or_else(|| pending(format!("RuleSet entry {key} is not nullable text")))
    }
}

pub(super) fn validate_additions(
    binding: &Map<String, Value>,
) -> VerifyResult<BTreeMap<String, RuleSetGrantDeltaDraft>> {
    let aggregate = aggregate_parts(field(binding, "afterAggregate")?)?;
    let rule_set_id = i64_field(binding, "ruleSetId")?;
    let card_id = i64_field(binding, "cardId")?;
    let tenant_id = i64_field(binding, "tenantId")?;
    let user_id = i64_field(binding, "userId")?;
    let domain_id = nullable_i64(binding, "domainId")?;
    let operation_id = string_field(binding, "operationId")?;
    let ref_id = i64_field(object(field(binding, "binding")?, "binding")?, "id")?;
    let source = object(field(binding, "currentSourceEvent")?, "currentSourceEvent")?;
    let payload = object(field(source, "payload")?, "source payload")?;
    let actor_id = i64_field(payload, "actorId")?;
    let parent = object(
        field(binding, "parentCardProjection")?,
        "parentCardProjection",
    )?;
    let projection = crate::ProjectionEventIdentity {
        event_id: string_field(parent, "eventId")?.to_owned(),
        source_generation: i64_field(parent, "sourceGeneration")?,
        revoke_fence: i64_field(parent, "revokeFence")?,
        tenant_id: Some(tenant_id),
    };
    let mut expected = BTreeMap::new();
    let mut entry_ids = BTreeSet::new();
    for entry in aggregate.entries {
        let entry = object(entry, "RuleSet entry")?;
        let entry_id = i64_field(entry, "entry_id")?;
        if entry_id <= 0
            || !entry_ids.insert(entry_id)
            || i64_field(entry, "rule_set_id")? != rule_set_id
            || nullable_i64(entry, "tenant_id")?.is_some_and(|id| id != tenant_id)
        {
            return Err(pending("CardCreate RuleSet entry identity differs"));
        }
        match i64_field(entry, "enabled")? {
            0 => continue,
            1 => {}
            _ => return Err(pending("RuleSet entry enabled flag is invalid")),
        }
        let effect = string_field(entry, "effect")?;
        if effect.eq_ignore_ascii_case("DENY") {
            continue;
        }
        if !effect.eq_ignore_ascii_case("ALLOW") {
            return Err(pending("RuleSet entry effect is unsupported"));
        }
        let facts = RuleSetEntryLedgerFacts {
            tenant_id,
            domain_id,
            card_id,
            user_id,
            rule_set_id,
            entry_id,
            ref_id,
            ref_type: "BASE",
            resource: string_field(entry, "resource_type")?.trim(),
            resource_id: nullable_i64(entry, "resource_id")?,
            action: string_field(entry, "action_code")?.trim(),
            condition_json: nullable_text(entry, "condition_json")?,
            valid_from: nullable_text(entry, "valid_from")?,
            valid_to: nullable_text(entry, "valid_to")?,
        };
        let event_id =
            derive_ruleset_contribution_event_id(operation_id, &facts, RuleSetMutationKind::Add)
                .map_err(pending)?;
        let draft =
            build_ruleset_add_draft(&facts, operation_id, Some(actor_id), &projection, &event_id)
                .map_err(pending)?;
        if expected.insert(event_id, draft).is_some() {
            return Err(pending("CardCreate contribution identity is duplicated"));
        }
    }
    let declared = array(binding, "addDeltas")?;
    if declared.len() != expected.len() {
        return Err(pending(
            "CardCreate ADDs do not cover every enabled ALLOW entry",
        ));
    }
    let mut seen = BTreeSet::new();
    for declared in declared {
        let declared = object(declared, "CardCreate ADD")?;
        let event_id = string_field(declared, "eventId")?;
        let draft = expected
            .get(event_id)
            .ok_or_else(|| pending("CardCreate ADD has no materializable entry"))?;
        let delta: astral_types::GrantDelta =
            serde_json::from_value(field(declared, "delta")?.clone()).map_err(pending)?;
        if !seen.insert(event_id)
            || i64_field(declared, "ruleSetEntryId")?.to_string()
                != match &draft.delta {
                    astral_types::GrantDelta::Add { grant } => {
                        grant.provenance.source_entry.as_deref()
                    }
                    _ => None,
                }
                .ok_or_else(|| pending("expected ADD has no entry provenance"))?
            || i64_field(declared, "baseVersion")? != 0
            || i64_field(declared, "targetVersion")? != 1
            || !field(declared, "beforeImageJson")?.is_null()
            || delta != draft.delta
        {
            return Err(pending(
                "CardCreate ADD differs from its complete source contribution",
            ));
        }
    }
    validate_audit_vectors(binding, &expected)?;
    Ok(expected)
}

fn validate_audit_vectors(
    binding: &Map<String, Value>,
    expected: &BTreeMap<String, RuleSetGrantDeltaDraft>,
) -> VerifyResult<()> {
    let detail = object(field(binding, "bindAudit")?, "bindAudit")?;
    let events = array(detail, "contributionEventIds")?;
    let entries = array(detail, "ruleSetEntryIds")?;
    let cards = array(detail, "boundCardIds")?;
    let refs = array(detail, "bindingRefIds")?;
    if [events.len(), entries.len(), cards.len(), refs.len()]
        .iter()
        .any(|count| *count != expected.len())
    {
        return Err(pending(
            "CardCreate audit vectors do not cover the complete ADD set",
        ));
    }
    let ref_id = i64_field(object(field(binding, "binding")?, "binding")?, "id")?;
    let card_id = i64_field(binding, "cardId")?;
    let mut seen = BTreeSet::new();
    for (index, event) in events.iter().enumerate() {
        let event = event
            .as_str()
            .ok_or_else(|| pending("audit event is not text"))?;
        let draft = expected
            .get(event)
            .ok_or_else(|| pending("audit has an unknown ADD event"))?;
        let astral_types::GrantDelta::Add { grant } = &draft.delta else {
            return Err(pending("audit contribution is not ADD"));
        };
        if !seen.insert(event)
            || entries[index].as_i64().map(|id| id.to_string()).as_deref()
                != grant.provenance.source_entry.as_deref()
            || cards[index].as_i64() != Some(card_id)
            || refs[index].as_i64() != Some(ref_id)
        {
            return Err(pending("CardCreate audit contribution dimensions differ"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Map<String, Value> {
        let facts = RuleSetEntryLedgerFacts {
            tenant_id: 41,
            domain_id: Some(5),
            card_id: 21,
            user_id: 31,
            rule_set_id: 7,
            entry_id: 11,
            ref_id: 8,
            ref_type: "BASE",
            resource: "rule_set",
            resource_id: Some(71),
            action: "read",
            condition_json: None,
            valid_from: Some("2026-11-08 00:00:00"),
            valid_to: Some("2026-11-09 00:00:00"),
        };
        let event = derive_ruleset_contribution_event_id(
            "card-create-21",
            &facts,
            RuleSetMutationKind::Add,
        )
        .unwrap();
        let projection = crate::ProjectionEventIdentity {
            event_id: uuid::Uuid::new_v4().to_string(),
            source_generation: 1,
            revoke_fence: 0,
            tenant_id: Some(41),
        };
        let draft =
            build_ruleset_add_draft(&facts, "card-create-21", Some(32), &projection, &event)
                .unwrap();
        serde_json::json!({
            "ruleSetId": 7, "cardId": 21, "userId": 31, "tenantId": 41,
            "domainId": 5, "operationId": "card-create-21", "binding": {"id": 8},
            "currentSourceEvent": {"payload": {"actorId": 32}},
            "parentCardProjection": {"eventId": projection.event_id, "sourceGeneration": 1, "revokeFence": 0},
            "afterAggregate": {
                "root": {}, "bindings": [],
                "entries": [{"entry_id": 11, "rule_set_id": 7, "tenant_id": null,
                    "enabled": 1, "effect": "ALLOW", "resource_type": "rule_set",
                    "resource_id": 71, "action_code": "read", "condition_json": null,
                    "valid_from": "2026-11-08 00:00:00", "valid_to": "2026-11-09 00:00:00"}]
            },
            "addDeltas": [{"eventId": event, "ruleSetEntryId": 11, "baseVersion": 0,
                "targetVersion": 1, "beforeImageJson": null, "delta": draft.delta}],
            "bindAudit": {"contributionEventIds": [event], "ruleSetEntryIds": [11],
                "boundCardIds": [21], "bindingRefIds": [8]}
        }).as_object().unwrap().clone()
    }

    #[test]
    fn exact_add_reconstruction_rejects_grant_and_provenance_tampering() {
        let binding = binding();
        let expected = validate_additions(&binding).unwrap();
        assert_eq!(expected.len(), 1);
        let astral_types::GrantDelta::Add { grant } = &expected.values().next().unwrap().delta
        else {
            panic!("expected ADD")
        };
        assert_eq!(grant.resource, "rule_set:71");
        assert!(grant.validity.not_before.is_some());
        for (pointer, replacement) in [
            (
                "/addDeltas/0/delta/grant/resource",
                serde_json::json!("rule_set:*"),
            ),
            (
                "/addDeltas/0/delta/grant/action",
                serde_json::json!("delete"),
            ),
            ("/addDeltas/0/delta/grant/userId", serde_json::json!(33)),
            (
                "/addDeltas/0/delta/grant/provenance/bindingId",
                serde_json::json!("9"),
            ),
            (
                "/addDeltas/0/delta/grant/provenance/actorUserId",
                serde_json::json!(33),
            ),
            (
                "/addDeltas/0/delta/grant/provenance/sourceEntry",
                serde_json::json!("12"),
            ),
            ("/addDeltas/0/baseVersion", serde_json::json!(1)),
            ("/addDeltas/0/ruleSetEntryId", serde_json::json!(12)),
            ("/bindAudit/bindingRefIds/0", serde_json::json!(9)),
            (
                "/bindAudit/contributionEventIds/0",
                serde_json::json!("foreign"),
            ),
            (
                "/afterAggregate/entries/0/condition_json",
                serde_json::json!("{\"restrict\":true}"),
            ),
        ] {
            let mut changed = Value::Object(binding.clone());
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_additions(changed.as_object().unwrap()).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn complete_allow_set_cannot_be_omitted_or_replaced_by_empty_evidence() {
        let binding = binding();
        let mut changed = Value::Object(binding.clone());
        changed["addDeltas"] = serde_json::json!([]);
        assert!(validate_additions(changed.as_object().unwrap()).is_err());
        let mut changed = Value::Object(binding.clone());
        let mut another = changed["afterAggregate"]["entries"][0].clone();
        another["entry_id"] = serde_json::json!(12);
        changed["afterAggregate"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(another);
        assert!(validate_additions(changed.as_object().unwrap()).is_err());
        let mut changed = Value::Object(binding);
        changed["afterAggregate"]["entries"][0]["effect"] = serde_json::json!("DENY");
        changed["addDeltas"] = serde_json::json!([]);
        changed["bindAudit"] = serde_json::json!({"contributionEventIds": [], "ruleSetEntryIds": [], "boundCardIds": [], "bindingRefIds": []});
        assert!(validate_additions(changed.as_object().unwrap())
            .unwrap()
            .is_empty());
    }
}
