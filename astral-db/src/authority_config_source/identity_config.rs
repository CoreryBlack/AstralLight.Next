//! Allowlisted row-image readers for identity and governance configuration sources.
//!
//! This child owns only SQL lookup and canonical row serialization. The parent
//! module owns transaction-bound capture handles, receipt construction, and
//! evidence dispatch.

use serde::Serialize;
use sqlx::{MySql, Transaction};

use super::{CapturedRow, TypedSourceReadError, TypedSourceRowLookup, TypedSourceTable};

macro_rules! image_row {
    ($name:ident { $($field:ident : $ty:ty),+ $(,)? }) => {
        #[derive(Debug, sqlx::FromRow, Serialize)]
        struct $name { $($field: $ty),+ }
    };
}

image_row!(UserCardLevelDefinitionImage {
    level_id: i64,
    domain_id: i64,
    level_no: i32,
    level_code: String,
    level_name: String,
    status: String,
    upgrade_strategy_json: Option<String>,
    description: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
});

#[derive(Debug, Serialize)]
struct IdentityLevelTemplateImage {
    template_id: i64,
    template_code: String,
    template_name: String,
    domain_id: i64,
    principal_type: String,
    grant_type: String,
    level_no: i32,
    user_card_template_id: Option<i64>,
    status: String,
    version_no: i32,
    force_cover: bool,
    description: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    resource_maps: Vec<LevelTemplateResourceMapImage>,
    action_maps: Vec<LevelTemplateActionMapImage>,
}

image_row!(IdentityLevelTemplateParentRow {
    template_id: i64,
    template_code: String,
    template_name: String,
    domain_id: i64,
    principal_type: String,
    grant_type: String,
    level_no: i32,
    user_card_template_id: Option<i64>,
    status: String,
    version_no: i32,
    force_cover: bool,
    description: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
});

image_row!(LevelTemplateResourceMapImage {
    id: i64,
    template_id: i64,
    resource_type_id: i64,
    priority: i32,
    created_at: Option<String>,
    updated_at: Option<String>,
});

image_row!(LevelTemplateActionMapImage {
    id: i64,
    template_id: i64,
    action_id: i64,
    effect: String,
    created_at: Option<String>,
    updated_at: Option<String>,
});

image_row!(UserCardTemplateImage {
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
});

image_row!(InheritanceConfigImage {
    id: i64,
    resource_type: String,
    inheritance_mode: String,
    updated_at: Option<String>,
});

const MAX_LEVEL_TEMPLATE_MAP_ROWS: i64 = 512;

const LEVEL_SELECT: &str =
    "SELECT level_id, domain_id, level_no, CAST(level_code AS CHAR) AS level_code, \
    CAST(level_name AS CHAR) AS level_name, CAST(status AS CHAR) AS status, \
    CAST(upgrade_strategy_json AS CHAR) AS upgrade_strategy_json, \
    CAST(description AS CHAR) AS description, CAST(created_at AS CHAR) AS created_at, \
    CAST(updated_at AS CHAR) AS updated_at FROM user_card_level_definition";
const LEVEL_TEMPLATE_SELECT: &str =
    "SELECT template_id, CAST(template_code AS CHAR) AS template_code, \
    CAST(template_name AS CHAR) AS template_name, domain_id, \
    CAST(principal_type AS CHAR) AS principal_type, CAST(grant_type AS CHAR) AS grant_type, \
    level_no, user_card_template_id, CAST(status AS CHAR) AS status, version_no, force_cover, \
    CAST(description AS CHAR) AS description, CAST(created_at AS CHAR) AS created_at, \
    CAST(updated_at AS CHAR) AS updated_at FROM identity_level_template";
const CARD_TEMPLATE_SELECT: &str = "SELECT template_id, CAST(domain_id AS SIGNED) AS domain_id, \
    CAST(tenant_id AS SIGNED) AS tenant_id, parent_template_id, \
    CAST(template_code AS CHAR) AS template_code, CAST(template_name AS CHAR) AS template_name, \
    CAST(card_type AS CHAR) AS card_type, CAST(template_scope AS CHAR) AS template_scope, \
    version_no, default_priority, CAST(default_roles_json AS CHAR) AS default_roles_json, \
    CAST(resource_scope_json AS CHAR) AS resource_scope_json, CAST(status AS CHAR) AS status, \
    CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
    FROM user_card_template";
const INHERITANCE_SELECT: &str = "SELECT id, CAST(resource_type AS CHAR) AS resource_type, \
    CAST(inheritance_mode AS CHAR) AS inheritance_mode, CAST(updated_at AS CHAR) AS updated_at \
    FROM permission_inheritance_config";

fn row_image<T: Serialize>(
    pk: i64,
    row: &T,
    label: &str,
) -> Result<CapturedRow, TypedSourceReadError> {
    if pk <= 0 {
        return Err(TypedSourceReadError::Pending(format!(
            "typed {label} source row has a non-positive primary key"
        )));
    }
    let image_json = serde_json::to_string(row).map_err(|error| {
        TypedSourceReadError::Serialization(format!(
            "typed {label} source image serialization failed: {error}"
        ))
    })?;
    Ok(CapturedRow { pk, image_json })
}

async fn read_level(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let row: Option<UserCardLevelDefinitionImage> = match lookup {
        TypedSourceRowLookup::PrimaryId { id } => {
            sqlx::query_as(&format!("{LEVEL_SELECT} WHERE level_id = ? FOR UPDATE"))
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        TypedSourceRowLookup::LevelNatural {
            domain_id,
            level_code,
        } => {
            sqlx::query_as(&format!(
                "{LEVEL_SELECT} WHERE domain_id = ? AND level_code = ? FOR UPDATE"
            ))
            .bind(domain_id)
            .bind(level_code)
            .fetch_optional(&mut **tx)
            .await
        }
        _ => return Err(invalid_lookup(TypedSourceTable::UserCardLevelDefinition)),
    }
    .map_err(read_error)?;
    row.map(|row| row_image(row.level_id, &row, "user-card-level-definition"))
        .transpose()
}

async fn read_level_template(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let row: Option<IdentityLevelTemplateParentRow> = match lookup {
        TypedSourceRowLookup::PrimaryId { id } => {
            sqlx::query_as(&format!(
                "{LEVEL_TEMPLATE_SELECT} WHERE template_id = ? FOR UPDATE"
            ))
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
        }
        TypedSourceRowLookup::LevelTemplateNatural {
            domain_id,
            template_code,
        } => {
            sqlx::query_as(&format!(
                "{LEVEL_TEMPLATE_SELECT} WHERE domain_id = ? AND template_code = ? FOR UPDATE"
            ))
            .bind(domain_id)
            .bind(template_code)
            .fetch_optional(&mut **tx)
            .await
        }
        _ => return Err(invalid_lookup(TypedSourceTable::IdentityLevelTemplate)),
    }
    .map_err(read_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let template_id = row.template_id;
    let resource_maps: Vec<LevelTemplateResourceMapImage> = sqlx::query_as(
        "SELECT id, template_id, resource_type_id, priority, \
         CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
         FROM identity_level_template_resource_map \
         WHERE template_id = ? ORDER BY id LIMIT ? FOR UPDATE",
    )
    .bind(template_id)
    .bind(MAX_LEVEL_TEMPLATE_MAP_ROWS + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(read_error)?;
    if resource_maps.len() as i64 > MAX_LEVEL_TEMPLATE_MAP_ROWS {
        return Err(TypedSourceReadError::Pending(format!(
            "identity level template {template_id} resource-map image exceeds the bounded capture limit"
        )));
    }
    let action_maps: Vec<LevelTemplateActionMapImage> = sqlx::query_as(
        "SELECT id, template_id, action_id, CAST(effect AS CHAR) AS effect, \
         CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at \
         FROM identity_level_template_action_map \
         WHERE template_id = ? ORDER BY id LIMIT ? FOR UPDATE",
    )
    .bind(template_id)
    .bind(MAX_LEVEL_TEMPLATE_MAP_ROWS + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(read_error)?;
    if action_maps.len() as i64 > MAX_LEVEL_TEMPLATE_MAP_ROWS {
        return Err(TypedSourceReadError::Pending(format!(
            "identity level template {template_id} action-map image exceeds the bounded capture limit"
        )));
    }
    let image = IdentityLevelTemplateImage {
        template_id: row.template_id,
        template_code: row.template_code,
        template_name: row.template_name,
        domain_id: row.domain_id,
        principal_type: row.principal_type,
        grant_type: row.grant_type,
        level_no: row.level_no,
        user_card_template_id: row.user_card_template_id,
        status: row.status,
        version_no: row.version_no,
        force_cover: row.force_cover,
        description: row.description,
        created_at: row.created_at,
        updated_at: row.updated_at,
        resource_maps,
        action_maps,
    };
    row_image(template_id, &image, "identity-level-template").map(Some)
}

async fn read_card_template(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let row: Option<UserCardTemplateImage> = match lookup {
        TypedSourceRowLookup::PrimaryId { id } => {
            sqlx::query_as(&format!(
                "{CARD_TEMPLATE_SELECT} WHERE template_id = ? FOR UPDATE"
            ))
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
        }
        TypedSourceRowLookup::CardTemplateNatural {
            domain_id,
            template_code,
        } => {
            sqlx::query_as(&format!(
                "{CARD_TEMPLATE_SELECT} WHERE domain_id = ? AND template_code = ? FOR UPDATE"
            ))
            .bind(domain_id)
            .bind(template_code)
            .fetch_optional(&mut **tx)
            .await
        }
        _ => return Err(invalid_lookup(TypedSourceTable::UserCardTemplate)),
    }
    .map_err(read_error)?;
    row.map(|row| row_image(row.template_id, &row, "user-card-template"))
        .transpose()
}

async fn read_inheritance_config(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let row: Option<InheritanceConfigImage> = match lookup {
        TypedSourceRowLookup::PrimaryId { id } => {
            sqlx::query_as(&format!("{INHERITANCE_SELECT} WHERE id = ? FOR UPDATE"))
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
        }
        TypedSourceRowLookup::InheritanceResourceType { resource_type } => {
            sqlx::query_as(&format!(
                "{INHERITANCE_SELECT} WHERE resource_type = ? FOR UPDATE"
            ))
            .bind(resource_type)
            .fetch_optional(&mut **tx)
            .await
        }
        _ => return Err(invalid_lookup(TypedSourceTable::InheritanceConfig)),
    }
    .map_err(read_error)?;
    row.map(|row| row_image(row.id, &row, "inheritance-config"))
        .transpose()
}

fn invalid_lookup(table: TypedSourceTable) -> TypedSourceReadError {
    TypedSourceReadError::Validation(format!(
        "typed source lookup is incompatible with {}",
        table.as_str()
    ))
}

fn read_error(error: sqlx::Error) -> TypedSourceReadError {
    TypedSourceReadError::from_sqlx("typed identity config image readback", error)
}

/// Read one actual row (or complete level-template aggregate) under FOR UPDATE.
/// The caller supplies only closed table and lookup enums; all values are bound.
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
        TypedSourceTable::UserCardLevelDefinition => read_level(tx, lookup).await,
        TypedSourceTable::IdentityLevelTemplate => read_level_template(tx, lookup).await,
        TypedSourceTable::UserCardTemplate => read_card_template(tx, lookup).await,
        TypedSourceTable::InheritanceConfig => read_inheritance_config(tx, lookup).await,
        _ => Err(invalid_lookup(table)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_config_image_shapes_keep_all_owner_fields() {
        let level = UserCardLevelDefinitionImage {
            level_id: 1,
            domain_id: 2,
            level_no: 3,
            level_code: "L3".into(),
            level_name: "Level 3".into(),
            status: "ACTIVE".into(),
            upgrade_strategy_json: None,
            description: None,
            created_at: None,
            updated_at: None,
        };
        let image = serde_json::to_value(level).expect("canonical row encodes");
        assert_eq!(image["level_id"], 1);
        assert_eq!(image["domain_id"], 2);
        assert_eq!(image["level_code"], "L3");
        assert!(image.get("status").is_some());

        let resource_map = LevelTemplateResourceMapImage {
            id: 11,
            template_id: 4,
            resource_type_id: 7,
            priority: 10,
            created_at: None,
            updated_at: None,
        };
        let action_map = LevelTemplateActionMapImage {
            id: 12,
            template_id: 4,
            action_id: 8,
            effect: "ALLOW".into(),
            created_at: None,
            updated_at: None,
        };
        assert_eq!(
            serde_json::to_value(resource_map).unwrap()["resource_type_id"],
            7
        );
        assert_eq!(serde_json::to_value(action_map).unwrap()["action_id"], 8);
    }
}
