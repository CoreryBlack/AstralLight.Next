//! Read-only adoption checks for the pre-approved superadmin template aggregate.
//!
//! Startup discovers the unique active SUPER_ADMIN template and verifies the
//! complete typed aggregate already present in source. Initialization remains an
//! explicitly approved source operation; this module never materializes it.

use std::collections::BTreeSet;

use astral_db::{read_typed_source_row_image_in_tx, TypedSourceRowLookup, TypedSourceTable};
use astral_types::{ResourceRegistry, ACTION_ALIASES};
use serde::Deserialize;
use sqlx::MySqlPool;

use crate::repository::template_repository::template_rows_to_entry_requests;

const VALIDATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Clone, Debug, Deserialize)]
struct TemplateRoot {
    template_id: i64,
    domain_id: i64,
    tenant_id: Option<i64>,
    parent_template_id: Option<i64>,
    template_code: String,
    template_name: String,
    card_type: String,
    template_scope: String,
    version_no: i32,
    default_priority: i32,
    default_roles_json: Option<String>,
    resource_scope_json: Option<String>,
    status: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct RuleFields {
    resource_type: Option<String>,
    resource_id: Option<i64>,
    action_code: Option<String>,
    effect: String,
    condition_json: Option<String>,
    priority: i32,
    enabled: i32,
}

#[derive(Clone, Debug, Deserialize)]
struct TemplateRule {
    template_rule_id: i64,
    template_id: i64,
    #[serde(flatten)]
    fields: RuleFields,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RuleSetRoot {
    rule_set_id: i64,
    name: String,
    code: String,
    description: Option<String>,
    source_type: String,
    source_id: Option<i64>,
    enabled: i32,
    created_at: Option<String>,
    updated_at: Option<String>,
    tenant_id: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct RuleSetEntry {
    entry_id: i64,
    rule_set_id: i64,
    #[serde(flatten)]
    fields: RuleFields,
    valid_from: Option<String>,
    valid_to: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    tenant_id: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct RuleSetBinding {
    id: i64,
    card_id: i64,
    rule_set_id: i64,
    ref_type: String,
    created_at: Option<String>,
    tenant_id: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct RuleSetAggregate {
    root: RuleSetRoot,
    entries: Vec<RuleSetEntry>,
    bindings: Vec<RuleSetBinding>,
}

#[derive(Clone, Debug, Deserialize)]
struct TemplateAggregate {
    template_root: TemplateRoot,
    permission_rules: Vec<TemplateRule>,
    linked_rule_set: RuleSetAggregate,
}

fn adoption_required(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "SUPERADMIN_INIT_FAILED: {message}; complete explicitly approved V7 initialization or source mutation before restarting"
    )
}

fn action_is_registered(registry: &ResourceRegistry, resource: &str, action: &str) -> bool {
    if registry.validate(resource, action).is_ok() {
        return true;
    }
    ACTION_ALIASES
        .iter()
        .find(|(alias, _)| *alias == action)
        .is_some_and(|(_, expanded)| {
            expanded
                .iter()
                .all(|expanded_action| registry.validate(resource, expanded_action).is_ok())
        })
}

fn action_covered_by_rule(stored_action: &str, requested_action: &str) -> bool {
    stored_action == requested_action
        || ACTION_ALIASES
            .iter()
            .find(|(alias, _)| *alias == stored_action)
            .is_some_and(|(_, expanded)| expanded.contains(&requested_action))
}

fn validate_template_rule_fields(
    rule: &TemplateRule,
    registry: &ResourceRegistry,
) -> anyhow::Result<()> {
    if rule.template_rule_id <= 0 || !matches!(rule.fields.enabled, 0 | 1) {
        return Err(adoption_required(
            "template rule identity or enabled state is invalid",
        ));
    }
    if rule.fields.enabled == 0 {
        return Ok(());
    }
    let resource = rule
        .fields
        .resource_type
        .as_deref()
        .ok_or_else(|| adoption_required("enabled template rule has no resource type"))?;
    let action = rule
        .fields
        .action_code
        .as_deref()
        .ok_or_else(|| adoption_required("enabled template rule has no action code"))?;
    if !action_is_registered(registry, resource, action) {
        return Err(adoption_required(format!(
            "template rule {resource}/{action} is not registered"
        )));
    }
    let canonical_effect = template_rows_to_entry_requests(vec![(
        rule.fields.effect.clone(),
        resource.to_owned(),
        rule.fields.resource_id,
        action.to_owned(),
        rule.fields.condition_json.clone(),
        rule.fields.priority,
    )])
    .map_err(|error| adoption_required(format!("template rule validation failed: {error}")))?;
    if canonical_effect.len() != 1 || canonical_effect[0].effect != "ALLOW" {
        return Err(adoption_required(
            "enabled superadmin template rules must persist canonical ALLOW",
        ));
    }
    Ok(())
}

fn validate_aggregate(
    aggregate: &TemplateAggregate,
    registry: &ResourceRegistry,
) -> anyhow::Result<()> {
    let template = &aggregate.template_root;
    let rule_set = &aggregate.linked_rule_set.root;
    if template.template_id <= 0
        || template.domain_id <= 0
        || template.tenant_id.is_none_or(|id| id <= 0)
        || template.template_code.trim().is_empty()
        || template.template_name.trim().is_empty()
        || template.card_type != "SUPER_ADMIN"
        || template.status != "ACTIVE"
        || rule_set.rule_set_id <= 0
        || rule_set.code != template.template_code
        || rule_set.code.trim().is_empty()
        || rule_set.name.trim().is_empty()
        || rule_set.source_type != "TEMPLATE"
        || rule_set.source_id != Some(template.template_id)
        || rule_set.tenant_id != template.tenant_id
        || rule_set.enabled != 1
    {
        return Err(adoption_required("template or RuleSet ownership differs"));
    }

    let _complete_template_root = (
        &template.parent_template_id,
        &template.template_scope,
        &template.version_no,
        &template.default_priority,
        &template.default_roles_json,
        &template.resource_scope_json,
        &template.created_at,
        &template.updated_at,
    );
    let _complete_rule_set_root = (
        &rule_set.description,
        &rule_set.created_at,
        &rule_set.updated_at,
    );

    let mut template_rule_ids = BTreeSet::new();
    for rule in &aggregate.permission_rules {
        if rule.template_id != template.template_id
            || !template_rule_ids.insert(rule.template_rule_id)
        {
            return Err(adoption_required(
                "template rule has a foreign or duplicate owner",
            ));
        }
        validate_template_rule_fields(rule, registry)?;
        let _complete_template_rule = (&rule.created_at, &rule.updated_at);
    }

    // The shared template writer reads enabled rows in this exact order before
    // delegating to RuleSet ledger churn. Keep the comparison row-based so a
    // duplicate, omission, or ordering drift cannot disappear in a map.
    let mut expected_ordered = aggregate
        .permission_rules
        .iter()
        .filter(|rule| rule.fields.enabled == 1)
        .map(|rule| (rule.template_rule_id, rule.fields.clone()))
        .collect::<Vec<_>>();
    expected_ordered.sort_by(|(left_id, left_fields), (right_id, right_fields)| {
        right_fields
            .priority
            .cmp(&left_fields.priority)
            .then_with(|| left_id.cmp(right_id))
    });
    let expected_entries: Vec<RuleFields> = expected_ordered
        .into_iter()
        .map(|(_, fields)| fields)
        .collect();

    let mut entry_ids = BTreeSet::new();
    let mut actual_entries = Vec::with_capacity(aggregate.linked_rule_set.entries.len());
    for entry in &aggregate.linked_rule_set.entries {
        if entry.entry_id <= 0
            || !entry_ids.insert(entry.entry_id)
            || entry.rule_set_id != rule_set.rule_set_id
            || entry.valid_from.is_some()
            || entry.valid_to.is_some()
            || entry.tenant_id.is_some()
            || entry.fields.enabled != 1
        {
            return Err(adoption_required(
                "RuleSet entry provenance or state differs",
            ));
        }
        actual_entries.push(entry.fields.clone());
        let _complete_entry = (&entry.created_at, &entry.updated_at);
    }
    if actual_entries != expected_entries {
        return Err(adoption_required(
            "RuleSet entries differ from the ordered enabled template source",
        ));
    }

    let mut binding_ids = BTreeSet::new();
    let mut binding_keys = BTreeSet::new();
    for binding in &aggregate.linked_rule_set.bindings {
        if binding.id <= 0
            || binding.card_id <= 0
            || !binding_ids.insert(binding.id)
            || !binding_keys.insert((
                binding.card_id,
                binding.rule_set_id,
                binding.ref_type.clone(),
            ))
            || binding.rule_set_id != rule_set.rule_set_id
            || !matches!(binding.ref_type.as_str(), "BASE" | "OVERLAY")
            || binding.tenant_id != template.tenant_id
        {
            return Err(adoption_required(
                "RuleSet binding provenance or state differs",
            ));
        }
        let _complete_binding_timestamp = &binding.created_at;
    }

    for resource in registry.list_resources() {
        for action in registry.list_actions(&resource).unwrap_or_default() {
            let covered = aggregate.permission_rules.iter().any(|rule| {
                let fields = &rule.fields;
                let alias_write_covers_crud = fields.action_code.as_deref() == Some("write")
                    && matches!(action.as_str(), "create" | "update" | "delete");
                fields.enabled == 1
                    && fields.resource_id.is_none()
                    && fields.condition_json.is_none()
                    && fields.resource_type.as_deref() == Some(resource.as_str())
                    && (fields
                        .action_code
                        .as_deref()
                        .is_some_and(|stored| action_covered_by_rule(stored, &action))
                        || alias_write_covers_crud)
            });
            if !covered {
                return Err(adoption_required(format!(
                    "registered action {resource}/{action} is missing from the approved template"
                )));
            }
        }
    }
    Ok(())
}

pub(super) async fn validate(db: &MySqlPool, registry: &ResourceRegistry) -> anyhow::Result<()> {
    tokio::time::timeout(VALIDATION_TIMEOUT, async {
        let mut tx = db.begin().await?;
        let validation = async {
            let template_ids: Vec<i64> = sqlx::query_scalar(
                "SELECT template_id FROM user_card_template \
                 WHERE card_type = 'SUPER_ADMIN' AND status = 'ACTIVE' \
                 ORDER BY template_id LIMIT 2",
            )
            .fetch_all(&mut *tx)
            .await?;
            let [template_id] = template_ids.as_slice() else {
                return Err(adoption_required(
                    "exactly one active SUPER_ADMIN template is required",
                ));
            };
            let image = read_typed_source_row_image_in_tx(
                &mut tx,
                TypedSourceTable::PermissionRuleTemplate,
                &TypedSourceRowLookup::PermissionRuleTemplateAggregate {
                    template_id: *template_id,
                },
            )
            .await?
            .ok_or_else(|| adoption_required("superadmin aggregate is absent"))?;
            let aggregate: TemplateAggregate = serde_json::from_str(&image.1)?;
            let code_matches: Vec<i64> = sqlx::query_scalar(
                "SELECT rule_set_id FROM rule_set WHERE code = ? ORDER BY rule_set_id LIMIT 2 FOR UPDATE",
            )
            .bind(&aggregate.linked_rule_set.root.code)
            .fetch_all(&mut *tx)
            .await?;
            match code_matches.as_slice() {
                [rule_set_id] if *rule_set_id == aggregate.linked_rule_set.root.rule_set_id => {
                    validate_aggregate(&aggregate, registry)
                }
                [] => Err(adoption_required("linked RuleSet code has no unique owner")),
                [_] => Err(adoption_required("linked RuleSet code resolves to a different root")),
                _ => Err(adoption_required("linked RuleSet code is not unique")),
            }
        }
        .await;
        tx.rollback().await?;
        validation
    })
    .await
    .map_err(|_| adoption_required("template validation timed out; source state is unchanged"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(code: &str) -> TemplateRoot {
        TemplateRoot {
            template_id: 8,
            domain_id: 9,
            tenant_id: Some(2),
            parent_template_id: None,
            template_code: code.to_owned(),
            template_name: "Super admin".to_owned(),
            card_type: "SUPER_ADMIN".to_owned(),
            template_scope: "SYSTEM".to_owned(),
            version_no: 1,
            default_priority: 100,
            default_roles_json: None,
            resource_scope_json: None,
            status: "ACTIVE".to_owned(),
            created_at: None,
            updated_at: None,
        }
    }

    fn valid_fixture(code: &str) -> TemplateAggregate {
        let template_root = root(code);
        let registry = ResourceRegistry::global();
        let mut rules = Vec::new();
        let mut source_rows = Vec::new();
        let mut template_rule_id = 1_i64;
        for resource in registry.list_resources() {
            for action in registry.list_actions(&resource).unwrap_or_default() {
                let priority = 100_000_i32 - template_rule_id as i32;
                rules.push(TemplateRule {
                    template_rule_id,
                    template_id: template_root.template_id,
                    fields: RuleFields {
                        resource_type: Some(resource.clone()),
                        resource_id: None,
                        action_code: Some(action.clone()),
                        effect: "ALLOW".to_owned(),
                        condition_json: None,
                        priority,
                        enabled: 1,
                    },
                    created_at: None,
                    updated_at: None,
                });
                source_rows.push((
                    "ALLOW".to_owned(),
                    resource.clone(),
                    None,
                    action,
                    None,
                    priority,
                ));
                template_rule_id += 1;
            }
        }

        // Keep the fixture on the same canonical template-to-entry conversion
        // used by production; the test only supplies the complete source rows.
        let requests = template_rows_to_entry_requests(source_rows)
            .expect("the compiled registry must produce valid template rows");
        let ordered = rules.iter().map(|rule| rule.template_rule_id).zip(requests);
        let mut ordered = ordered.collect::<Vec<_>>();
        ordered.sort_by(|(left_id, left), (right_id, right)| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left_id.cmp(right_id))
        });
        let entries = ordered
            .into_iter()
            .enumerate()
            .map(|(offset, (_, entry))| RuleSetEntry {
                entry_id: 20 + offset as i64,
                rule_set_id: 10,
                fields: RuleFields {
                    resource_type: entry.resource_type,
                    resource_id: entry.resource_id,
                    action_code: entry.action_code,
                    effect: entry.effect,
                    condition_json: entry.condition_json,
                    priority: entry.priority,
                    enabled: 1,
                },
                valid_from: None,
                valid_to: None,
                created_at: None,
                updated_at: None,
                tenant_id: None,
            })
            .collect();
        TemplateAggregate {
            template_root: template_root.clone(),
            permission_rules: rules,
            linked_rule_set: RuleSetAggregate {
                root: RuleSetRoot {
                    rule_set_id: 10,
                    name: code.to_owned(),
                    code: code.to_owned(),
                    description: None,
                    source_type: "TEMPLATE".to_owned(),
                    source_id: Some(template_root.template_id),
                    enabled: 1,
                    created_at: None,
                    updated_at: None,
                    tenant_id: template_root.tenant_id,
                },
                entries,
                bindings: Vec::new(),
            },
        }
    }

    fn assert_baseline_ok_and_failure(candidate: TemplateAggregate, expected: &str) {
        let registry = ResourceRegistry::global();
        let baseline = valid_fixture("artifact-code");
        assert!(
            validate_aggregate(&baseline, registry).is_ok(),
            "complete registry fixture must validate before applying a negative mutation"
        );
        let error = validate_aggregate(&candidate, registry)
            .expect_err("independent negative mutation must fail closed");
        assert!(
            error.to_string().contains(expected),
            "expected error containing {expected:?}, got {error}"
        );
    }

    #[test]
    fn artifact_code_is_not_a_fixed_literal_and_alias_mapping_is_accepted() {
        let aggregate = valid_fixture("artifact-code-not-a-fixed-literal");
        assert!(validate_aggregate(&aggregate, ResourceRegistry::global()).is_ok());
        assert!(action_covered_by_rule("write", "create"));
        assert!(action_covered_by_rule("write", "update"));
        assert!(action_covered_by_rule("write", "delete"));
    }

    #[test]
    fn owner_condition_priority_and_entry_order_drift_fail_closed_independently() {
        let mut owner = valid_fixture("artifact-code");
        owner.permission_rules[0].template_id = 999;
        assert_baseline_ok_and_failure(owner, "foreign or duplicate owner");

        let mut condition = valid_fixture("artifact-code");
        condition.permission_rules[0].fields.condition_json = Some("{}".to_owned());
        assert_baseline_ok_and_failure(
            condition,
            "condition_json does not contain a supported condition",
        );

        let mut order = valid_fixture("artifact-code");
        order.linked_rule_set.entries.swap(0, 1);
        assert_baseline_ok_and_failure(order, "RuleSet entries differ");

        let mut priority = valid_fixture("artifact-code");
        priority.linked_rule_set.entries[0].fields.priority = -1;
        assert_baseline_ok_and_failure(priority, "RuleSet entries differ");
    }

    #[test]
    fn unregistered_resource_or_action_drift_fails_closed_independently() {
        let mut resource = valid_fixture("artifact-code");
        resource.permission_rules[0].fields.resource_type = Some("unknown_resource".to_owned());
        assert_baseline_ok_and_failure(resource, "is not registered");

        let mut action = valid_fixture("artifact-code");
        action.permission_rules[0].fields.action_code = Some("unknown_action".to_owned());
        assert_baseline_ok_and_failure(action, "is not registered");
    }

    #[test]
    fn binding_owner_and_tenant_drift_fail_closed() {
        let mut binding = valid_fixture("artifact-code");
        binding.linked_rule_set.bindings.push(RuleSetBinding {
            id: 1,
            card_id: 42,
            rule_set_id: 99,
            ref_type: "BASE".to_owned(),
            created_at: None,
            tenant_id: Some(2),
        });
        assert_baseline_ok_and_failure(binding, "RuleSet binding provenance or state differs");
    }

    #[test]
    fn startup_validation_never_mutates_or_materializes_source() {
        let source = include_str!("superadmin_template.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "INSERT INTO",
            ".execute(",
            "DELETE FROM",
            ".commit(",
            "create_rule_set_from_template",
            "SourceMutationCapability",
        ] {
            assert!(
                !production.contains(forbidden),
                "startup contains {forbidden}"
            );
        }
        assert!(production.contains("tx.rollback().await"));
        assert!(production.contains("tokio::time::timeout(VALIDATION_TIMEOUT"));
    }
}
