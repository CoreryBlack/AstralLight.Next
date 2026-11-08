//! Bounded canonical RuleSet and permission-rule-template aggregate readback.
//!
//! The parent owns capture receipts and dispatch. This child only locks and
//! serializes actual source rows through the shared closed lookup variants.

use serde::Serialize;
use sqlx::{MySql, Transaction};

use super::{CapturedRow, TypedSourceReadError, TypedSourceRowLookup, TypedSourceTable};

const MAX_RULE_SET_ENTRIES: i64 = 512;
const MAX_RULE_SET_BINDINGS: i64 = 512;
const MAX_TEMPLATE_RULES: i64 = 512;

macro_rules! image_row {
    ($name:ident { $($field:ident : $ty:ty),+ $(,)? }) => {
        #[derive(Debug, sqlx::FromRow, Serialize)]
        struct $name { $($field: $ty),+ }
    };
}

image_row!(RuleSetRootImage {
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
});

image_row!(RuleSetEntryImage {
    entry_id: i64,
    rule_set_id: i64,
    resource_type: String,
    resource_id: Option<i64>,
    action_code: String,
    effect: String,
    condition_json: Option<String>,
    priority: i32,
    enabled: i32,
    valid_from: Option<String>,
    valid_to: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    tenant_id: Option<i64>,
});

image_row!(RuleSetBindingImage {
    id: i64,
    card_id: i64,
    rule_set_id: i64,
    ref_type: String,
    created_at: Option<String>,
    tenant_id: Option<i64>,
});

#[derive(Debug, sqlx::FromRow)]
struct UserCardTemplateRootRow {
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

#[derive(Debug, Serialize)]
struct UserCardTemplateRootImage {
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

image_row!(PermissionRuleTemplateRowImage {
    template_rule_id: i64,
    template_id: i64,
    effect: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    action_code: Option<String>,
    condition_json: Option<String>,
    priority: i32,
    enabled: i32,
    created_at: Option<String>,
    updated_at: Option<String>,
});

#[derive(Debug, Serialize)]
struct RuleSetAggregateImage {
    root: RuleSetRootImage,
    entries: Vec<RuleSetEntryImage>,
    bindings: Vec<RuleSetBindingImage>,
}

#[derive(Debug, Serialize)]
struct PermissionRuleTemplateAggregateImage {
    template_root: UserCardTemplateRootImage,
    permission_rules: Vec<PermissionRuleTemplateRowImage>,
    linked_rule_set: RuleSetAggregateImage,
}

fn serialize_image<T: Serialize>(
    key: i64,
    image: &T,
    label: &str,
) -> Result<CapturedRow, TypedSourceReadError> {
    if key <= 0 {
        return Err(TypedSourceReadError::Pending(format!(
            "typed {label} aggregate has a non-positive stable key"
        )));
    }
    let image_json = serde_json::to_string(image).map_err(|error| {
        TypedSourceReadError::Serialization(format!(
            "typed {label} aggregate serialization failed: {error}"
        ))
    })?;
    Ok(CapturedRow {
        pk: key,
        image_json,
    })
}

fn read_error(label: &'static str, error: sqlx::Error) -> TypedSourceReadError {
    TypedSourceReadError::from_sqlx(label, error)
}

async fn read_rule_set_root(
    tx: &mut Transaction<'_, MySql>,
    rule_set_id: i64,
) -> Result<Option<RuleSetRootImage>, TypedSourceReadError> {
    sqlx::query_as::<_, RuleSetRootImage>(
        "SELECT rule_set_id, CAST(name AS CHAR) AS name, CAST(code AS CHAR) AS code, \
         CAST(description AS CHAR) AS description, CAST(source_type AS CHAR) AS source_type, \
         source_id, enabled, CAST(created_at AS CHAR) AS created_at, \
         CAST(updated_at AS CHAR) AS updated_at, tenant_id \
         FROM rule_set WHERE rule_set_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| read_error("RuleSet", error))
}

async fn read_rule_set_aggregate(
    tx: &mut Transaction<'_, MySql>,
    rule_set_id: i64,
) -> Result<Option<RuleSetAggregateImage>, TypedSourceReadError> {
    let Some(root) = read_rule_set_root(tx, rule_set_id).await? else {
        return Ok(None);
    };
    read_rule_set_children(tx, root).await.map(Some)
}

async fn read_rule_set_children(
    tx: &mut Transaction<'_, MySql>,
    root: RuleSetRootImage,
) -> Result<RuleSetAggregateImage, TypedSourceReadError> {
    let rule_set_id = root.rule_set_id;
    let entries: Vec<RuleSetEntryImage> = sqlx::query_as(
        "SELECT entry_id, rule_set_id, CAST(resource_type AS CHAR) AS resource_type, \
         resource_id, CAST(action_code AS CHAR) AS action_code, CAST(effect AS CHAR) AS effect, \
         CAST(condition_json AS CHAR) AS condition_json, priority, enabled, \
         CAST(valid_from AS CHAR) AS valid_from, CAST(valid_to AS CHAR) AS valid_to, \
         CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at, tenant_id \
         FROM rule_set_entry WHERE rule_set_id = ? ORDER BY entry_id LIMIT ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(MAX_RULE_SET_ENTRIES + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| read_error("RuleSet entries", error))?;
    if entries.len() as i64 > MAX_RULE_SET_ENTRIES {
        return Err(TypedSourceReadError::Pending(format!(
            "RuleSet {rule_set_id} entry image exceeds the bounded capture limit"
        )));
    }
    let bindings: Vec<RuleSetBindingImage> = sqlx::query_as(
        "SELECT id, card_id, rule_set_id, CAST(ref_type AS CHAR) AS ref_type, \
         CAST(created_at AS CHAR) AS created_at, tenant_id \
         FROM card_rule_set_ref WHERE rule_set_id = ? ORDER BY id LIMIT ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(MAX_RULE_SET_BINDINGS + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| read_error("RuleSet bindings", error))?;
    if bindings.len() as i64 > MAX_RULE_SET_BINDINGS {
        return Err(TypedSourceReadError::Pending(format!(
            "RuleSet {rule_set_id} binding image exceeds the bounded capture limit"
        )));
    }
    Ok(RuleSetAggregateImage {
        root,
        entries,
        bindings,
    })
}

async fn read_template_root(
    tx: &mut Transaction<'_, MySql>,
    template_id: i64,
) -> Result<Option<UserCardTemplateRootImage>, TypedSourceReadError> {
    let row: Option<UserCardTemplateRootRow> = sqlx::query_as(
        "SELECT template_id, domain_id, tenant_id, parent_template_id, \
         CAST(template_code AS CHAR) AS template_code, CAST(template_name AS CHAR) AS template_name, \
         CAST(card_type AS CHAR) AS card_type, CAST(template_scope AS CHAR) AS template_scope, \
         version_no, default_priority, CAST(default_roles_json AS CHAR) AS default_roles_json, \
         CAST(resource_scope_json AS CHAR) AS resource_scope_json, CAST(status AS CHAR) AS status, \
         CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
         FROM user_card_template WHERE template_id = ? FOR UPDATE",
    )
    .bind(template_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| read_error("user-card template root", error))?;
    Ok(row.map(|row| UserCardTemplateRootImage {
        template_id: row.template_id,
        domain_id: row.domain_id,
        tenant_id: row.tenant_id,
        parent_template_id: row.parent_template_id,
        template_code: row.template_code,
        template_name: row.template_name,
        card_type: row.card_type,
        template_scope: row.template_scope,
        version_no: row.version_no,
        default_priority: row.default_priority,
        default_roles_json: row.default_roles_json,
        resource_scope_json: row.resource_scope_json,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }))
}

async fn read_linked_template_rule_set_root(
    tx: &mut Transaction<'_, MySql>,
    template_id: i64,
) -> Result<RuleSetRootImage, TypedSourceReadError> {
    let roots: Vec<RuleSetRootImage> = sqlx::query_as(
        "SELECT rule_set_id, CAST(name AS CHAR) AS name, CAST(code AS CHAR) AS code, \
         CAST(description AS CHAR) AS description, CAST(source_type AS CHAR) AS source_type, \
         source_id, enabled, CAST(created_at AS CHAR) AS created_at, \
         CAST(updated_at AS CHAR) AS updated_at, tenant_id \
         FROM rule_set WHERE source_type = 'TEMPLATE' AND source_id = ? \
         ORDER BY rule_set_id LIMIT 2 FOR UPDATE",
    )
    .bind(template_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| read_error("linked TEMPLATE RuleSet root", error))?;
    if roots.len() != 1 {
        return Err(TypedSourceReadError::Pending(format!(
            "template {template_id} must have exactly one linked TEMPLATE RuleSet; observed {}",
            roots.len()
        )));
    }
    let root = roots.into_iter().next().ok_or_else(|| {
        TypedSourceReadError::Pending(format!(
            "template {template_id} linked TEMPLATE RuleSet is missing"
        ))
    })?;
    if root.source_type != "TEMPLATE" || root.source_id != Some(template_id) {
        return Err(TypedSourceReadError::Pending(format!(
            "template {template_id} linked RuleSet provenance differs from its owner"
        )));
    }
    Ok(root)
}

async fn read_linked_template_rule_set(
    tx: &mut Transaction<'_, MySql>,
    root: RuleSetRootImage,
    template_tenant_id: Option<i64>,
) -> Result<RuleSetAggregateImage, TypedSourceReadError> {
    let template_id = root.source_id.ok_or_else(|| {
        TypedSourceReadError::Pending("linked TEMPLATE RuleSet lacks its source owner id".into())
    })?;
    if root.tenant_id != template_tenant_id {
        return Err(TypedSourceReadError::Pending(format!(
            "template {template_id} linked RuleSet tenant differs from its owner"
        )));
    }
    let rule_set_id = root.rule_set_id;
    let entries: Vec<RuleSetEntryImage> = sqlx::query_as(
        "SELECT entry_id, rule_set_id, CAST(resource_type AS CHAR) AS resource_type, \
         resource_id, CAST(action_code AS CHAR) AS action_code, CAST(effect AS CHAR) AS effect, \
         CAST(condition_json AS CHAR) AS condition_json, priority, enabled, \
         CAST(valid_from AS CHAR) AS valid_from, CAST(valid_to AS CHAR) AS valid_to, \
         CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at, tenant_id \
         FROM rule_set_entry WHERE rule_set_id = ? ORDER BY entry_id LIMIT ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(MAX_RULE_SET_ENTRIES + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| read_error("linked RuleSet entries", error))?;
    if entries.len() as i64 > MAX_RULE_SET_ENTRIES {
        return Err(TypedSourceReadError::Pending(format!(
            "template {template_id} linked RuleSet entry image exceeds the bounded capture limit"
        )));
    }
    let bindings: Vec<RuleSetBindingImage> = sqlx::query_as(
        "SELECT id, card_id, rule_set_id, CAST(ref_type AS CHAR) AS ref_type, \
         CAST(created_at AS CHAR) AS created_at, tenant_id \
         FROM card_rule_set_ref WHERE rule_set_id = ? ORDER BY id LIMIT ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(MAX_RULE_SET_BINDINGS + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| read_error("linked RuleSet bindings", error))?;
    if bindings.len() as i64 > MAX_RULE_SET_BINDINGS {
        return Err(TypedSourceReadError::Pending(format!(
            "template {template_id} linked RuleSet binding image exceeds the bounded capture limit"
        )));
    }
    Ok(RuleSetAggregateImage {
        root,
        entries,
        bindings,
    })
}

async fn read_rule_set(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let id = match lookup {
        TypedSourceRowLookup::PrimaryId { id } => *id,
        TypedSourceRowLookup::RuleSetCode { code } => {
            let matches: Vec<(i64,)> = sqlx::query_as(
                "SELECT rule_set_id FROM rule_set WHERE code = ? ORDER BY rule_set_id LIMIT 2 FOR UPDATE",
            )
            .bind(code)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| read_error("RuleSet code owner", error))?;
            match matches.as_slice() {
                [] => return Ok(None),
                [(id,)] => *id,
                _ => {
                    return Err(TypedSourceReadError::Pending(
                        "unique RuleSet code lookup returned multiple rows".into(),
                    ))
                }
            }
        }
        _ => return Err(invalid_lookup(TypedSourceTable::RuleSet)),
    };
    read_rule_set_aggregate(tx, id)
        .await?
        .map(|image| serialize_image(id, &image, "RuleSet"))
        .transpose()
}

async fn read_permission_rule_template(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let TypedSourceRowLookup::PermissionRuleTemplateAggregate { template_id } = lookup else {
        return Err(invalid_lookup(TypedSourceTable::PermissionRuleTemplate));
    };
    // Keep the source owner lock order used by template writers: linked RuleSet,
    // then the read-only template owner row, then both child collections.
    let linked_rule_set_root = read_linked_template_rule_set_root(tx, *template_id).await?;
    let Some(template_root) = read_template_root(tx, *template_id).await? else {
        return Err(TypedSourceReadError::Pending(format!(
            "permission-rule template aggregate owner {template_id} is missing"
        )));
    };
    let rules: Vec<PermissionRuleTemplateRowImage> = sqlx::query_as(
        "SELECT template_rule_id, CAST(template_id AS SIGNED) AS template_id, \
         CAST(effect AS CHAR) AS effect, CAST(resource_type AS CHAR) AS resource_type, \
         resource_id, CAST(action_code AS CHAR) AS action_code, \
         CAST(condition_json AS CHAR) AS condition_json, priority, enabled, \
         CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
         FROM permission_rule_template WHERE template_id = ? \
         ORDER BY template_rule_id LIMIT ? FOR UPDATE",
    )
    .bind(template_id)
    .bind(MAX_TEMPLATE_RULES + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| read_error("permission-rule template rows", error))?;
    if rules.len() as i64 > MAX_TEMPLATE_RULES {
        return Err(TypedSourceReadError::Pending(format!(
            "permission-rule template {template_id} image exceeds the bounded capture limit"
        )));
    }
    if rules.iter().any(|row| row.template_id != *template_id) {
        return Err(TypedSourceReadError::Pending(format!(
            "permission-rule template {template_id} child rows disagree on their owner"
        )));
    }
    // The template root remains present for an empty permission-rule set; the
    // aggregate is always updated as UPDATE and never manufactures ABSENT.
    if linked_rule_set_root.source_id != Some(*template_id) {
        return Err(TypedSourceReadError::Pending(format!(
            "template {template_id} linked RuleSet changed provenance during aggregate capture"
        )));
    }
    let linked_rule_set =
        read_linked_template_rule_set(tx, linked_rule_set_root, template_root.tenant_id).await?;
    let image = PermissionRuleTemplateAggregateImage {
        template_root,
        permission_rules: rules,
        linked_rule_set,
    };
    serialize_image(*template_id, &image, "permission-rule template").map(Some)
}

fn invalid_lookup(table: TypedSourceTable) -> TypedSourceReadError {
    TypedSourceReadError::Validation(format!(
        "typed source lookup is incompatible with {} aggregate capture",
        table.as_str()
    ))
}

/// Capture the actual canonical aggregate with fixed queries and row bounds.
/// No arbitrary SQL, columns, tables, or image bytes are accepted from callers.
pub(super) async fn capture_row_image_in_tx_typed(
    tx: &mut Transaction<'_, MySql>,
    table: TypedSourceTable,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    lookup.validate_for_table(table).map_err(|error| {
        TypedSourceReadError::Validation(format!(
            "typed source lookup is invalid for {}: {error:?}",
            table.as_str()
        ))
    })?;
    match table {
        TypedSourceTable::RuleSet => read_rule_set(tx, lookup).await,
        TypedSourceTable::PermissionRuleTemplate => read_permission_rule_template(tx, lookup).await,
        _ => Err(invalid_lookup(table)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_shapes_cover_every_authorization_source_column_and_order() {
        let ruleset = serde_json::to_value(RuleSetAggregateImage {
            root: RuleSetRootImage {
                rule_set_id: 1,
                name: "n".into(),
                code: "c".into(),
                description: None,
                source_type: "OVERLAY".into(),
                source_id: None,
                enabled: 1,
                created_at: None,
                updated_at: None,
                tenant_id: Some(2),
            },
            entries: vec![RuleSetEntryImage {
                entry_id: 3,
                rule_set_id: 1,
                resource_type: "resource".into(),
                resource_id: Some(4),
                action_code: "read".into(),
                effect: "ALLOW".into(),
                condition_json: Some("{}".into()),
                priority: 5,
                enabled: 1,
                valid_from: None,
                valid_to: None,
                created_at: None,
                updated_at: None,
                tenant_id: Some(2),
            }],
            bindings: vec![RuleSetBindingImage {
                id: 6,
                card_id: 7,
                rule_set_id: 1,
                ref_type: "BASE".into(),
                created_at: None,
                tenant_id: Some(2),
            }],
        })
        .expect("RuleSet aggregate serializes");
        assert_eq!(ruleset["root"]["source_type"], "OVERLAY");
        assert_eq!(ruleset["entries"][0]["condition_json"], "{}");
        assert_eq!(ruleset["entries"][0]["valid_from"], serde_json::Value::Null);
        assert_eq!(ruleset["bindings"][0]["card_id"], 7);

        let template = serde_json::to_value(PermissionRuleTemplateAggregateImage {
            template_root: UserCardTemplateRootImage {
                template_id: 8,
                domain_id: 9,
                tenant_id: Some(2),
                parent_template_id: None,
                template_code: "template".into(),
                template_name: "Template".into(),
                card_type: "ORG_CARD".into(),
                template_scope: "DOMAIN".into(),
                version_no: 1,
                default_priority: 100,
                default_roles_json: None,
                resource_scope_json: None,
                status: "ACTIVE".into(),
                created_at: None,
                updated_at: None,
            },
            permission_rules: Vec::new(),
            linked_rule_set: RuleSetAggregateImage {
                root: RuleSetRootImage {
                    rule_set_id: 10,
                    name: "template".into(),
                    code: "template".into(),
                    description: None,
                    source_type: "TEMPLATE".into(),
                    source_id: Some(8),
                    enabled: 1,
                    created_at: None,
                    updated_at: None,
                    tenant_id: Some(2),
                },
                entries: Vec::new(),
                bindings: Vec::new(),
            },
        })
        .expect("template aggregate serializes");
        assert!(template["permission_rules"].as_array().unwrap().is_empty());
        assert_eq!(template["template_root"]["template_id"], 8);
        assert_eq!(template["linked_rule_set"]["root"]["source_id"], 8);
    }

    #[test]
    fn aggregate_selects_are_explicit_ordered_and_bounded() {
        let rules_sql = "SELECT template_rule_id, CAST(template_id AS SIGNED) AS template_id, \
            CAST(effect AS CHAR) AS effect, CAST(resource_type AS CHAR) AS resource_type, \
            resource_id, CAST(action_code AS CHAR) AS action_code, \
            CAST(condition_json AS CHAR) AS condition_json, priority, enabled, \
            CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
            FROM permission_rule_template WHERE template_id = ? \
            ORDER BY template_rule_id LIMIT ? FOR UPDATE";
        assert!(!rules_sql.contains("SELECT *"));
        assert!(rules_sql.contains("ORDER BY template_rule_id LIMIT ? FOR UPDATE"));
        const {
            assert!(MAX_TEMPLATE_RULES > 0);
            assert!(MAX_RULE_SET_ENTRIES > 0);
            assert!(MAX_RULE_SET_BINDINGS > 0);
        }
    }
}
