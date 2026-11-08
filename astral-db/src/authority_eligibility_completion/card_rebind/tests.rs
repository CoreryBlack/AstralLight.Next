use super::*;

use astral_types::{
    AuthorityCardRebindBaseRef, AuthorityCardRebindCardImage, AuthorityCardRebindEvidence,
    AuthorityCardRebindRuleSetAggregate, AuthorityEligibilityCardCompletion,
    AuthorityEligibilityCompletionEvidence, AuthorityProtocolScope, AuthorizationAuthorityScope,
    AuthorizationDomainScope,
};
use serde_json::{json, Value};

use crate::authority_config_source::TypedSourceReadError;

const CARD_ID: i64 = 42;
const TENANT_ID: i64 = 3;
const USER_ID: i64 = 7;
const DOMAIN_ID: i64 = 9;
const OLD_TEMPLATE_ID: i64 = 10;
const NEW_TEMPLATE_ID: i64 = 20;
const OLD_RULE_SET_ID: i64 = 101;
const NEW_RULE_SET_ID: i64 = 202;
const OLD_REF_ID: i64 = 1001;
const NEW_REF_ID: i64 = 2001;
const OPERATION_ID: &str = "operation-card-rebind-1";
const PARENT_EVENT_ID: &str = "card-parent-event-1";

fn canonical(value: Value) -> String {
    serde_json::to_string(&value).expect("fixture JSON is serializable")
}

fn template_image(
    template_id: i64,
    domain_id: i64,
    tenant_id: Option<i64>,
    status: &str,
    card_type: &str,
) -> String {
    canonical(json!({
        "template_id": template_id,
        "domain_id": domain_id,
        "tenant_id": tenant_id,
        "parent_template_id": null,
        "template_code": format!("template-{template_id}"),
        "template_name": "Rebind fixture",
        "card_type": card_type,
        "template_scope": "ORG",
        "version_no": 1,
        "default_priority": 10,
        "default_roles_json": null,
        "resource_scope_json": null,
        "status": status,
        "created_at": "2026-11-08 00:00:00",
        "updated_at": "2026-11-08 00:00:00"
    }))
}

fn card_image(template_id: Option<i64>) -> AuthorityCardRebindCardImage {
    AuthorityCardRebindCardImage {
        card_id: CARD_ID,
        card_status: "ACTIVE".into(),
        user_id: Some(USER_ID),
        tenant_id: Some(TENANT_ID),
        domain_id: Some(DOMAIN_ID),
        template_id,
        card_type: "STANDARD".into(),
        level_id: Some(4),
        priority: 10,
        is_primary: true,
        valid_from: Some("2026-11-08 00:00:00".into()),
        valid_until: None,
    }
}

fn base_ref(id: i64, rule_set_id: i64, created_at: &str) -> AuthorityCardRebindBaseRef {
    AuthorityCardRebindBaseRef {
        id,
        card_id: CARD_ID,
        rule_set_id,
        ref_type: "BASE".into(),
        tenant_id: Some(TENANT_ID),
        created_at: created_at.into(),
    }
}

fn rule_set(
    rule_set_id: i64,
    source_id: i64,
    binding: Option<&AuthorityCardRebindBaseRef>,
) -> AuthorityCardRebindRuleSetAggregate {
    let entry_id = rule_set_id * 10 + 1;
    let bindings = binding
        .map(|row| {
            vec![json!({
                "id": row.id,
                "card_id": row.card_id,
                "rule_set_id": row.rule_set_id,
                "ref_type": row.ref_type,
                "created_at": row.created_at,
                "tenant_id": row.tenant_id
            })]
        })
        .unwrap_or_default();
    let image = json!({
        "root": {
            "rule_set_id": rule_set_id,
            "name": format!("RuleSet {rule_set_id}"),
            "code": format!("rules-{rule_set_id}"),
            "description": null,
            "source_type": "TEMPLATE",
            "source_id": source_id,
            "enabled": 1,
            "created_at": "2026-11-08 00:00:00",
            "updated_at": "2026-11-08 00:00:00",
            "tenant_id": TENANT_ID
        },
        "entries": [{
            "entry_id": entry_id,
            "rule_set_id": rule_set_id,
            "resource_type": "monitor",
            "resource_id": 88,
            "action_code": "read",
            "effect": "DENY",
            "condition_json": null,
            "priority": 1,
            "enabled": 1,
            "valid_from": null,
            "valid_to": null,
            "created_at": "2026-11-08 00:00:00",
            "updated_at": "2026-11-08 00:00:00",
            "tenant_id": TENANT_ID
        }],
        "bindings": bindings
    });
    AuthorityCardRebindRuleSetAggregate {
        rule_set_id,
        canonical_image: canonical(image),
    }
}

fn valid_rebind() -> AuthorityCardRebindEvidence {
    let old_ref = base_ref(OLD_REF_ID, OLD_RULE_SET_ID, "2026-11-08 00:00:01");
    let new_ref = base_ref(NEW_REF_ID, NEW_RULE_SET_ID, "2026-11-08 00:00:02");
    AuthorityCardRebindEvidence {
        card_id: CARD_ID,
        tenant_id: TENANT_ID,
        user_id: USER_ID,
        domain_id: Some(DOMAIN_ID),
        old_template_id: Some(OLD_TEMPLATE_ID),
        new_template_id: NEW_TEMPLATE_ID,
        new_template_image: template_image(
            NEW_TEMPLATE_ID,
            DOMAIN_ID,
            Some(TENANT_ID),
            "ACTIVE",
            "STANDARD",
        ),
        before_card: card_image(Some(OLD_TEMPLATE_ID)),
        after_card: card_image(Some(NEW_TEMPLATE_ID)),
        old_base_refs: vec![old_ref.clone()],
        new_base_refs: vec![new_ref.clone()],
        before_rule_sets: vec![
            rule_set(OLD_RULE_SET_ID, OLD_TEMPLATE_ID, Some(&old_ref)),
            rule_set(NEW_RULE_SET_ID, NEW_TEMPLATE_ID, None),
        ],
        after_rule_sets: vec![
            rule_set(OLD_RULE_SET_ID, OLD_TEMPLATE_ID, None),
            rule_set(NEW_RULE_SET_ID, NEW_TEMPLATE_ID, Some(&new_ref)),
        ],
    }
}

fn empty_rebind() -> AuthorityCardRebindEvidence {
    AuthorityCardRebindEvidence {
        card_id: CARD_ID,
        tenant_id: TENANT_ID,
        user_id: USER_ID,
        domain_id: Some(DOMAIN_ID),
        old_template_id: None,
        new_template_id: NEW_TEMPLATE_ID,
        new_template_image: template_image(
            NEW_TEMPLATE_ID,
            DOMAIN_ID,
            Some(TENANT_ID),
            "ACTIVE",
            "STANDARD",
        ),
        before_card: card_image(None),
        after_card: card_image(Some(NEW_TEMPLATE_ID)),
        old_base_refs: Vec::new(),
        new_base_refs: Vec::new(),
        before_rule_sets: Vec::new(),
        after_rule_sets: Vec::new(),
    }
}

fn completion() -> AuthorityEligibilityCompletionEvidence {
    AuthorityEligibilityCompletionEvidence {
        cards: vec![AuthorityEligibilityCardCompletion {
            scope: AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                tenant_id: TENANT_ID,
                card_id: CARD_ID,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            }),
            generation: 5,
            revoke_watermark: 2,
            outbox_event_id: "eligibility-event-1".into(),
            message_id: "eligibility-message-1".into(),
        }],
        zero_card_selection: None,
    }
}

fn valid_parent() -> ParentCardProjection {
    ParentCardProjection {
        event_id: PARENT_EVENT_ID.into(),
        source_generation: 3,
        revoke_fence: 1,
    }
}

fn valid_audit(
    evidence: &AuthorityCardRebindEvidence,
    parent: &ParentCardProjection,
) -> RebindAudit {
    RebindAudit {
        id: 9001,
        user_id: evidence.user_id,
        card_id: Some(evidence.card_id),
        tenant_id: Some(evidence.tenant_id),
        domain_id: evidence.domain_id,
        action: "card_template_change".into(),
        resource: "user_card".into(),
        decision: "CARD_UPDATED".into(),
        event_type: "USER_CARD_MUTATION".into(),
        detail: Some(
            json!({
                "actorId": evidence.user_id,
                "ownerUserId": evidence.user_id,
                "operationId": OPERATION_ID,
                "targetCardId": evidence.card_id,
                "fromTemplateId": evidence.old_template_id,
                "toTemplateId": evidence.new_template_id,
                "templateChanged": true,
                "action": "card_template_change",
                "parentEventId": parent.event_id,
                "baseRefs": {
                    "before": evidence.old_base_refs,
                    "after": evidence.new_base_refs
                }
            })
            .to_string(),
        ),
    }
}

#[test]
fn complete_rebind_fixture_preserves_card_refs_timestamps_and_full_aggregates() {
    let evidence = valid_rebind();

    evidence.validate().expect("complete evidence is valid");
    assert!(no_allow_contributions(&evidence.before_rule_sets).unwrap());
    assert!(no_allow_contributions(&evidence.after_rule_sets).unwrap());
    validate_aggregate_transition(&evidence).expect("aggregate transition is exact");

    let before: Value =
        serde_json::from_str(&evidence.before_rule_sets[0].canonical_image).unwrap();
    let after: Value = serde_json::from_str(&evidence.after_rule_sets[1].canonical_image).unwrap();
    assert_eq!(before["root"]["source_id"], OLD_TEMPLATE_ID);
    assert_eq!(after["root"]["source_id"], NEW_TEMPLATE_ID);
    assert_eq!(before["entries"].as_array().unwrap().len(), 1);
    assert_eq!(after["entries"].as_array().unwrap().len(), 1);
    assert_eq!(before["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(after["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(
        before["bindings"][0]["created_at"],
        evidence.old_base_refs[0].created_at
    );
    assert_eq!(
        after["bindings"][0]["created_at"],
        evidence.new_base_refs[0].created_at
    );
    assert_eq!(target(&evidence).unwrap().key, json!({"cardId": CARD_ID}));
}

#[test]
fn different_templates_with_no_base_refs_or_aggregates_are_a_valid_empty_rebind() {
    let evidence = empty_rebind();

    evidence.validate().expect("empty-to-empty rebind is valid");
    validate_aggregate_transition(&evidence).expect("empty aggregate transition is valid");
    assert_ne!(evidence.old_template_id, Some(evidence.new_template_id));
    assert!(evidence.before_rule_sets.is_empty());
    assert!(evidence.after_rule_sets.is_empty());
}

#[test]
fn enabled_allow_contribution_is_rejected_before_completion_and_publication() {
    let mut evidence = valid_rebind();
    let mut before: Value =
        serde_json::from_str(&evidence.before_rule_sets[0].canonical_image).unwrap();
    before["entries"][0]["effect"] = json!("ALLOW");
    evidence.before_rule_sets[0].canonical_image = canonical(before);

    assert!(!no_allow_contributions(&evidence.before_rule_sets).unwrap());
    let error = validate_aggregate_transition(&evidence).expect_err("enabled ALLOW must reject");
    assert!(error.to_string().contains("materializable ALLOW"));
}

#[test]
fn template_scope_tenant_domain_status_and_card_type_mismatches_fail_closed() {
    for (field, value) in [
        ("tenant_id", json!(4)),
        ("domain_id", json!(10)),
        ("status", json!("DISABLED")),
        ("card_type", json!("ELEVATED")),
    ] {
        let mut evidence = valid_rebind();
        let mut image: Value = serde_json::from_str(&evidence.new_template_image).unwrap();
        image[field] = value;
        evidence.new_template_image = canonical(image);
        assert!(
            evidence.validate_template().is_err(),
            "template field {field} drift must be rejected"
        );
    }
}

#[test]
fn ref_created_at_and_template_owner_drift_break_aggregate_consistency() {
    let mut timestamp_drift = valid_rebind();
    timestamp_drift.old_base_refs[0].created_at = "2026-11-08 00:00:99".into();
    assert!(validate_aggregate_transition(&timestamp_drift).is_err());

    let mut owner_drift = valid_rebind();
    for aggregate in &mut owner_drift.before_rule_sets {
        if aggregate.rule_set_id == OLD_RULE_SET_ID {
            let mut image: Value = serde_json::from_str(&aggregate.canonical_image).unwrap();
            image["root"]["source_id"] = json!(NEW_TEMPLATE_ID);
            aggregate.canonical_image = canonical(image);
        }
    }
    for aggregate in &mut owner_drift.after_rule_sets {
        if aggregate.rule_set_id == OLD_RULE_SET_ID {
            let mut image: Value = serde_json::from_str(&aggregate.canonical_image).unwrap();
            image["root"]["source_id"] = json!(NEW_TEMPLATE_ID);
            aggregate.canonical_image = canonical(image);
        }
    }
    assert!(validate_aggregate_transition(&owner_drift).is_err());
}

#[test]
fn audit_binds_actor_operation_parent_and_base_ref_transition() {
    let evidence = valid_rebind();
    let parent = valid_parent();
    let audit = valid_audit(&evidence, &parent);
    validate_audit(&audit, &parent, &evidence, OPERATION_ID).expect("audit is exact");

    for mutation in 0..4 {
        let mut tampered = valid_audit(&evidence, &parent);
        let mut detail: Value = serde_json::from_str(tampered.detail.as_ref().unwrap()).unwrap();
        match mutation {
            0 => detail["actorId"] = json!(999),
            1 => detail["operationId"] = json!("other-operation"),
            2 => detail["parentEventId"] = json!("other-parent"),
            3 => detail["baseRefs"]["before"][0]["createdAt"] = json!("drift"),
            _ => unreachable!(),
        }
        tampered.detail = Some(detail.to_string());
        assert!(validate_audit(&tampered, &parent, &evidence, OPERATION_ID).is_err());
    }
}

#[test]
fn receipts_require_exact_key_kind_rows_and_durable_identity_without_duplicates() {
    let evidence = valid_rebind();
    let parent = valid_parent();
    let audit = valid_audit(&evidence, &parent);
    let expected = expected_receipts(&evidence, &audit, &parent, &completion(), OPERATION_ID)
        .expect("fixture receipts build");
    validate_receipts(&expected, &expected).expect("exact receipt set passes");

    let mut wrong_kind = expected.clone();
    wrong_kind[0].kind = "INSERT".into();
    assert!(validate_receipts(&wrong_kind, &expected).is_err());

    let mut wrong_key = expected.clone();
    wrong_key[0].key = json!({"cardId": CARD_ID + 1});
    assert!(validate_receipts(&wrong_key, &expected).is_err());

    let mut wrong_rows = expected.clone();
    wrong_rows[0].rows_affected = 2;
    assert!(validate_receipts(&wrong_rows, &expected).is_err());

    let mut wrong_id = expected.clone();
    wrong_id[0].durable_id = "foreign-card".into();
    assert!(validate_receipts(&wrong_id, &expected).is_err());

    let mut duplicate = expected.clone();
    duplicate.push(expected[0].clone());
    assert!(validate_receipts(&duplicate, &expected).is_err());
}

#[test]
fn typed_sql_errors_keep_transient_schema_and_proof_paths_distinct() {
    assert!(matches!(
        TypedSourceReadError::from_sqlx("pool", sqlx::Error::PoolTimedOut),
        TypedSourceReadError::SqlxTransient {
            context: "pool",
            ..
        }
    ));
    assert!(matches!(
        TypedSourceReadError::from_sqlx(
            "io",
            sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
        ),
        TypedSourceReadError::SqlxTransient { context: "io", .. }
    ));
    assert!(matches!(
        TypedSourceReadError::from_sqlx("schema", sqlx::Error::Protocol("bad packet".into())),
        TypedSourceReadError::SqlxSchema {
            context: "schema",
            ..
        }
    ));

    let transient = verification_error(TypedSourceReadError::from_sqlx(
        "worker",
        sqlx::Error::PoolTimedOut,
    ));
    assert!(matches!(
        transient,
        EligibilityVerificationError::Transient(_)
    ));

    let schema = verification_error(TypedSourceReadError::from_sqlx(
        "decode",
        sqlx::Error::Protocol("bad packet".into()),
    ));
    assert!(matches!(schema, EligibilityVerificationError::Proof(_)));

    let pending = verification_error(TypedSourceReadError::Pending("contradictory fact".into()));
    assert!(matches!(pending, EligibilityVerificationError::Proof(_)));
}
