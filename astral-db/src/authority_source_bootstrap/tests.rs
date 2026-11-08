use super::*;
use astral_types::{
    AuthoritySourceBootstrapBundle, AuthoritySourceBootstrapCapability,
    AuthoritySourceBootstrapKind, AuthoritySourceBootstrapReservation,
    AuthoritySourceBootstrapState, AuthoritySourceBootstrapTicket, ResourceRegistry,
    SourceBootstrapRuleSetEntry, SourceBootstrapRuleSetRoot, SourceBootstrapTemplateRoot,
    SourceBootstrapTemplateRule, AUTHORIZATION_EDITION,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

fn complete_bundle() -> AuthoritySourceBootstrapBundle {
    let registry = ResourceRegistry::global();
    let mut template_rules = Vec::new();
    let mut rule_set_entries = Vec::new();
    for resource in registry.list_resources() {
        for action in registry.list_actions(&resource).unwrap_or_default() {
            let priority = 100_000 - template_rules.len() as i32;
            template_rules.push(SourceBootstrapTemplateRule {
                resource_type: resource.clone(),
                resource_id: None,
                action_code: action.clone(),
                effect: "ALLOW".to_owned(),
                condition_json: None,
                priority,
                enabled: true,
            });
            rule_set_entries.push(SourceBootstrapRuleSetEntry {
                resource_type: resource.clone(),
                resource_id: None,
                action_code: action,
                effect: "ALLOW".to_owned(),
                condition_json: None,
                priority,
                enabled: true,
                valid_from: None,
                valid_to: None,
                tenant_id: None,
            });
        }
    }
    AuthoritySourceBootstrapBundle {
        kind: AuthoritySourceBootstrapKind::TemplateRuleSet,
        template: SourceBootstrapTemplateRoot {
            domain_id: 1,
            tenant_id: None,
            parent_template_id: None,
            template_code: "bootstrap-code".to_owned(),
            template_name: "bootstrap".to_owned(),
            card_type: "SYSTEM".to_owned(),
            template_scope: Some("SYSTEM".to_owned()),
            version_no: Some(1),
            default_priority: Some(100),
            default_roles_json: Some("{\"root\":true}".to_owned()),
            resource_scope_json: Some("[\"all\"]".to_owned()),
            status: "ACTIVE".to_owned(),
        },
        template_rules,
        rule_set: SourceBootstrapRuleSetRoot {
            name: "bootstrap-code".to_owned(),
            code: "bootstrap-code".to_owned(),
            description: Some("root bootstrap".to_owned()),
            source_type: "TEMPLATE".to_owned(),
            enabled: true,
            tenant_id: None,
        },
        rule_set_entries,
        bindings: Vec::new(),
    }
}

fn signed_ticket() -> AuthoritySourceBootstrapTicket {
    let mut ticket = AuthoritySourceBootstrapTicket {
        protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-1".to_owned(),
        root_id: "root-1".to_owned(),
        trust_root_digest: "aa".repeat(32),
        root_key_id: "root-key".to_owned(),
        operation_id: "op-bootstrap-1".to_owned(),
        event_id: "event-bootstrap-1".to_owned(),
        nonce: "nonce-bootstrap-1".to_owned(),
        issued_at: 1_000,
        not_before: 1_000,
        expires_at: 2_000,
        service_id: "bootstrap-runner".to_owned(),
        database_id: "db-1".to_owned(),
        payload: complete_bundle(),
        signature: String::new(),
    };
    ticket
        .sign(&SigningKey::from_bytes(&[7; 32]))
        .expect("complete bundle signs");
    ticket
}

fn generated_ids(ticket: &AuthoritySourceBootstrapTicket) -> GeneratedIds {
    GeneratedIds {
        template_id: 11,
        template_rule_ids: (0..ticket.payload.template_rules.len())
            .map(|index| 21 + index as i64)
            .collect(),
        rule_set_id: 31,
        entry_ids: (0..ticket.payload.rule_set_entries.len())
            .map(|index| 41 + index as i64)
            .collect(),
        binding_ids: Vec::new(),
    }
}

fn typed_after_images(
    ticket: &AuthoritySourceBootstrapTicket,
    generated: &GeneratedIds,
) -> Vec<BootstrapImageEvidence> {
    let template = &ticket.payload.template;
    let template_image = json!({
        "template_id": generated.template_id,
        "domain_id": template.domain_id,
        "tenant_id": template.tenant_id,
        "parent_template_id": template.parent_template_id,
        "template_code": template.template_code,
        "template_name": template.template_name,
        "card_type": template.card_type,
        "template_scope": template.template_scope.as_deref().unwrap_or("SYSTEM"),
        "version_no": template.version_no.unwrap_or(1),
        "default_priority": template.default_priority.unwrap_or(100),
        "default_roles_json": template.default_roles_json,
        "resource_scope_json": template.resource_scope_json,
        "status": template.status,
    });
    let permission_rules: Vec<Value> = ticket
        .payload
        .template_rules
        .iter()
        .zip(&generated.template_rule_ids)
        .map(|(rule, rule_id)| {
            json!({
                "template_rule_id": rule_id,
                "template_id": generated.template_id,
                "effect": rule.effect,
                "resource_type": rule.resource_type,
                "resource_id": rule.resource_id,
                "action_code": rule.action_code,
                "condition_json": rule.condition_json,
                "priority": rule.priority,
                "enabled": i32::from(rule.enabled),
            })
        })
        .collect();
    let signed_root = &ticket.payload.rule_set;
    let rule_set_root = json!({
        "rule_set_id": generated.rule_set_id,
        "name": signed_root.name,
        "code": signed_root.code,
        "description": signed_root.description,
        "source_type": signed_root.source_type,
        "source_id": generated.template_id,
        "enabled": i32::from(signed_root.enabled),
        "tenant_id": signed_root.tenant_id,
    });
    let entries: Vec<Value> = ticket
        .payload
        .rule_set_entries
        .iter()
        .zip(&generated.entry_ids)
        .map(|(entry, entry_id)| {
            json!({
                "entry_id": entry_id,
                "rule_set_id": generated.rule_set_id,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "action_code": entry.action_code,
                "effect": entry.effect,
                "condition_json": entry.condition_json,
                "priority": entry.priority,
                "enabled": i32::from(entry.enabled),
                "valid_from": entry.valid_from,
                "valid_to": entry.valid_to,
                "tenant_id": entry.tenant_id,
            })
        })
        .collect();
    let rule_set_image = json!({
        "root": rule_set_root,
        "entries": entries,
        "bindings": [],
    });
    let aggregate = json!({
        "template_root": template_image,
        "permission_rules": permission_rules,
        "linked_rule_set": rule_set_image,
    });
    vec![
        BootstrapImageEvidence {
            table: TypedSourceTable::UserCardTemplate.as_str().to_owned(),
            image: serde_json::to_string(&template_image).expect("template image JSON"),
        },
        BootstrapImageEvidence {
            table: TypedSourceTable::PermissionRuleTemplate.as_str().to_owned(),
            image: serde_json::to_string(&aggregate).expect("aggregate image JSON"),
        },
        BootstrapImageEvidence {
            table: TypedSourceTable::RuleSet.as_str().to_owned(),
            image: serde_json::to_string(&rule_set_image).expect("RuleSet image JSON"),
        },
    ]
}

fn permit_binding_fixture() -> (
    AuthoritySourceBootstrapTicket,
    AuthoritySourceBootstrapCapability,
    AuthoritySourceBootstrapReservation,
    String,
) {
    let ticket = signed_ticket();
    let ticket_digest = ticket.artifact_digest().expect("ticket digest");
    let capability = AuthoritySourceBootstrapCapability {
        protocol_version: ticket.protocol_version,
        authorization_edition: ticket.authorization_edition,
        authority_id: ticket.authority_id.clone(),
        operation_id: ticket.operation_id.clone(),
        event_id: ticket.event_id.clone(),
        ticket_digest: ticket_digest.clone(),
        reservation_id: "reservation-1".to_owned(),
        service_id: ticket.service_id.clone(),
        database_id: ticket.database_id.clone(),
        root_key_id: ticket.root_key_id.clone(),
        trust_root_digest: ticket.trust_root_digest.clone(),
        authority_term: 1,
        global_fence_sequence: 2,
        gate_epoch: 3,
        read_gate_digest: "bb".repeat(32),
        key_id: "signer-1".to_owned(),
        key_epoch: 1,
        issued_at: 1_000,
        not_before: 1_000,
        expires_at: 2_000,
        capability_nonce: "capability-nonce".to_owned(),
        signature: "00".repeat(64),
    };
    let reservation = AuthoritySourceBootstrapReservation {
        reservation_id: capability.reservation_id.clone(),
        operation_id: ticket.operation_id.clone(),
        event_id: ticket.event_id.clone(),
        ticket_digest: ticket_digest.clone(),
        service_id: ticket.service_id.clone(),
        database_id: ticket.database_id.clone(),
        state: AuthoritySourceBootstrapState::Reserved,
        authority_term: 1,
        global_fence_sequence: 2,
        created_at: 1_000,
        updated_at: 1_000,
        completed_at: None,
    };
    (ticket, capability, reservation, ticket_digest)
}

#[test]
fn complete_bundle_ticket_and_typed_payload_images_are_accepted() {
    let ticket = signed_ticket();
    ticket
        .payload
        .validate()
        .expect("complete registry-covered bundle");
    ticket
        .verify(&SigningKey::from_bytes(&[7; 32]).verifying_key())
        .expect("ROOT signature verifies");
    let ids = generated_ids(&ticket);
    let images = typed_after_images(&ticket, &ids);
    validate_signed_payload_images_from_evidence(&ticket, &ids, &images)
        .expect("actual complete typed images match signed payload");
}

#[test]
fn generated_ids_allow_cross_table_auto_increment_collisions() {
    let ticket = signed_ticket();
    let mut generated = generated_ids(&ticket);
    assert!(generated.template_rule_ids.len() >= 2);
    assert!(generated.entry_ids.len() >= 2);
    generated.template_id = 1;
    generated.rule_set_id = 1;
    generated.template_rule_ids[0] = 1;
    generated.entry_ids[0] = 1;
    validate_generated_ids(&generated, &ticket)
        .expect("independent AUTO_INCREMENT tables may reuse the same numeric id");

    let mut duplicate_template_rules = generated.clone();
    duplicate_template_rules.template_rule_ids[1] = duplicate_template_rules.template_rule_ids[0];
    assert!(validate_generated_ids(&duplicate_template_rules, &ticket).is_err());

    let mut duplicate_entries = generated;
    duplicate_entries.entry_ids[1] = duplicate_entries.entry_ids[0];
    assert!(validate_generated_ids(&duplicate_entries, &ticket).is_err());
}

#[test]
fn every_signed_payload_image_group_rejects_tampering() {
    let ticket = signed_ticket();
    let ids = generated_ids(&ticket);
    let cases = [
        ("template_id", 0, json!(999)),
        ("template_code", 0, json!("tampered-code")),
        ("template_name", 0, json!("tampered-name")),
        ("card_type", 0, json!("USER")),
        ("template_scope", 0, json!("ORG")),
        ("version_no", 0, json!(2)),
        ("default_priority", 0, json!(101)),
        ("status", 0, json!("DISABLED")),
    ];
    for (field, image_index, value) in cases {
        let mut images = typed_after_images(&ticket, &ids);
        let mut image: Value = serde_json::from_str(&images[image_index].image).unwrap();
        image[field] = value;
        images[image_index].image = serde_json::to_string(&image).unwrap();
        assert!(
            validate_signed_payload_images_from_evidence(&ticket, &ids, &images).is_err(),
            "{field}"
        );
    }

    let mut aggregate_images = typed_after_images(&ticket, &ids);
    let mut aggregate: Value = serde_json::from_str(&aggregate_images[1].image).unwrap();
    aggregate["permission_rules"][0]["action_code"] = json!("tampered-action");
    aggregate_images[1].image = serde_json::to_string(&aggregate).unwrap();
    assert!(
        validate_signed_payload_images_from_evidence(&ticket, &ids, &aggregate_images).is_err()
    );

    let mut ruleset_images = typed_after_images(&ticket, &ids);
    let mut ruleset: Value = serde_json::from_str(&ruleset_images[2].image).unwrap();
    ruleset["root"]["code"] = json!("tampered-code");
    ruleset_images[2].image = serde_json::to_string(&ruleset).unwrap();
    assert!(validate_signed_payload_images_from_evidence(&ticket, &ids, &ruleset_images).is_err());
}

#[test]
fn permit_binding_rejects_each_identity_boundary() {
    let (ticket, capability, reservation, digest) = permit_binding_fixture();
    validate_permit_binding(&ticket, &digest, &capability, &reservation).expect("bound permit");

    let mut ticket_case = ticket.clone();
    ticket_case.operation_id.push_str("-wrong");
    assert!(validate_permit_binding(&ticket_case, &digest, &capability, &reservation).is_err());
    let mut capability_case = capability.clone();
    capability_case.event_id.push_str("-wrong");
    assert!(validate_permit_binding(&ticket, &digest, &capability_case, &reservation).is_err());
    let mut reservation_case = reservation.clone();
    reservation_case.service_id.push_str("-wrong");
    assert!(validate_permit_binding(&ticket, &digest, &capability, &reservation_case).is_err());
    reservation_case = reservation.clone();
    reservation_case.ticket_digest = "ff".repeat(32);
    assert!(validate_permit_binding(&ticket, &digest, &capability, &reservation_case).is_err());
    capability_case = capability.clone();
    capability_case.reservation_id.push_str("-wrong");
    assert!(validate_permit_binding(&ticket, &digest, &capability_case, &reservation).is_err());
    assert!(validate_permit_binding(&ticket, &"00".repeat(32), &capability, &reservation).is_err());
}

#[test]
fn retained_json_is_typed_canonical_and_digest_bound() {
    let ids = GeneratedIds {
        template_id: 11,
        template_rule_ids: vec![21, 22],
        rule_set_id: 31,
        entry_ids: vec![41, 42],
        binding_ids: Vec::new(),
    };
    let canonical = canonical_json(&ids, "generated ids").unwrap();
    let reordered = r#"{"entryIds":[41,42],"bindingIds":[],"ruleSetId":31,"templateRuleIds":[21,22],"templateId":11}"#;
    let (decoded, reencoded) =
        canonicalize_stored_json::<GeneratedIds>(reordered, "generated ids").unwrap();
    assert_eq!(decoded, ids);
    assert_eq!(reencoded, canonical);
    assert!(
        canonicalize_stored_json::<GeneratedIds>(r#"{"templateId":11}"#, "generated ids").is_err()
    );

    let images = vec![("user_card_template", canonical.clone())];
    let original = digest_images(&images);
    let changed = digest_images(&[("user_card_template", format!("{canonical} "))]);
    assert_ne!(original, changed);
    assert!(!digest_matches(&[0; 32], &original));
}

fn audit_fixture(ticket: &AuthoritySourceBootstrapTicket) -> AuditReceiptImage {
    AuditReceiptImage {
        id: 7,
        user_id: 42,
        action: AUDIT_ACTION.to_owned(),
        resource: AUDIT_RESOURCE.to_owned(),
        decision: AUDIT_DECISION.to_owned(),
        reason: Some("ROOT_SIGNED_SOURCE_BOOTSTRAP".to_owned()),
        card_id: None,
        detail: None,
        event_type: Some(AUDIT_EVENT_TYPE.to_owned()),
        source_ip: None,
        request_id: Some(ticket.operation_id.clone()),
        domain_id: Some(ticket.payload.template.domain_id),
        tenant_id: ticket.payload.template.tenant_id,
        created_at: Some("1000".to_owned()),
    }
}

#[test]
fn audit_receipt_and_digest_reject_field_tampering() {
    let ticket = signed_ticket();
    let ids = generated_ids(&ticket);
    let ticket_digest = ticket.artifact_digest().unwrap();
    let payload_digest = ticket.payload_digest().unwrap();
    let detail = bootstrap_audit_detail(BootstrapAuditDetail {
        ticket: &ticket,
        actor_user_id: 42,
        ticket_digest: &ticket_digest,
        payload_digest: &payload_digest,
        capability_digest: &"cc".repeat(32),
        generated_ids: &ids,
        before_image_digest: &"11".repeat(32),
        after_image_digest: &"22".repeat(32),
    })
    .unwrap();
    let mut actual = audit_fixture(&ticket);
    actual.detail = Some(detail.clone());
    validate_audit_receipt(&actual, 42, &ticket, &detail).expect("fixed audit receipt");

    let original_digest = digest_audit_receipt(&actual).unwrap();
    actual.action = "other-action".to_owned();
    assert!(validate_audit_receipt(&actual, 42, &ticket, &detail).is_err());
    assert_ne!(original_digest, digest_audit_receipt(&actual).unwrap());
    actual.action = AUDIT_ACTION.to_owned();
    actual.detail = Some(detail.replace("actorUserId", "tamperedActor"));
    assert!(
        validate_audit_receipt(&actual, 42, &ticket, actual.detail.as_deref().unwrap()).is_err()
    );
}

#[test]
fn source_shape_guard_scans_only_production_bridge() {
    let production = include_str!("../authority_source_bootstrap.rs")
        .split("#[cfg(test)]")
        .next()
        .expect("production bridge source");
    assert!(production.contains("source bootstrap bindings require a real WorkerOwned delta path"));
    assert!(!production.contains("consume_authorization_admission_in_tx"));
    assert!(production.contains("authority_source_bootstrap_use"));
    assert!(production.contains("reconcile exact DB and quorum state"));
}
