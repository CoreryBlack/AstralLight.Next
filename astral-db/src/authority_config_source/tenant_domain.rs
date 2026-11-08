//! Allowlisted row-image readers for TrustGraph department, domain, and tenant metadata.
//!
//! The parent owns transaction-bound capture handles, receipt construction, and dispatch.
//! This child performs only fixed-schema `FOR UPDATE` readback through closed lookup enums.

use astral_types::authority_config_sensitive_field_digest;
use serde::Serialize;
use sqlx::{MySql, Transaction};

use super::{CapturedRow, TypedSourceReadError, TypedSourceRowLookup, TypedSourceTable};

macro_rules! image_row {
    ($name:ident { $($field:ident : $ty:ty),+ $(,)? }) => {
        #[derive(Debug, sqlx::FromRow, Serialize)]
        struct $name { $($field: $ty),+ }
    };
}

image_row!(DepartmentImage {
    dept_id: i64,
    tenant_id: i64,
    sub_tenant_id: Option<i64>,
    dept_name: String,
    dept_code: Option<String>,
    parent_dept_id: Option<i64>,
    sort_order: i32,
    status: String,
    description: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
});

image_row!(DomainImage {
    domain_id: i64,
    domain_code: Option<String>,
    domain_name: String,
    domain_description: Option<String>,
    status: String,
    created_at: Option<String>,
    updated_at: Option<String>,
});

// Raw sensitive values exist only in this short-lived DB row value. It does not
// implement Serialize; `read_tenant` immediately replaces non-null fields with
// the approved tenant-bound digests before any evidence image can be produced.
#[derive(Debug, sqlx::FromRow)]
struct TenantRawImage {
    tenant_id: i64,
    tenant_code: String,
    tenant_name: String,
    tenant_type: String,
    status: String,
    parent_tenant_id: Option<i64>,
    path: Option<String>,
    depth: i32,
    contact_person: Option<String>,
    contact_phone: Option<String>,
    contact_email: Option<String>,
    max_members: i32,
    max_admins: i32,
    current_members: i32,
    license_key: Option<String>,
    license_expires: Option<String>,
    logo_url: Option<String>,
    settings_json: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct TenantImage {
    tenant_id: i64,
    tenant_code: String,
    tenant_name: String,
    tenant_type: String,
    status: String,
    parent_tenant_id: Option<i64>,
    path: Option<String>,
    depth: i32,
    contact_person: Option<String>,
    contact_phone: Option<String>,
    contact_email: Option<String>,
    max_members: i32,
    max_admins: i32,
    current_members: i32,
    license_key_digest: Option<String>,
    license_expires: Option<String>,
    logo_url: Option<String>,
    settings_json: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const DEPARTMENT_IMAGE_SELECT: &str = "SELECT dept_id, tenant_id, sub_tenant_id, \
    CAST(dept_name AS CHAR) AS dept_name, CAST(dept_code AS CHAR) AS dept_code, parent_dept_id, sort_order, \
    CAST(status AS CHAR) AS status, CAST(description AS CHAR) AS description, CAST(created_at AS CHAR) AS created_at, \
    CAST(updated_at AS CHAR) AS updated_at FROM departments";
const DOMAIN_IMAGE_SELECT: &str = "SELECT domain_id, CAST(domain_code AS CHAR) AS domain_code, \
    CAST(domain_name AS CHAR) AS domain_name, CAST(domain_description AS CHAR) AS domain_description, \
    CAST(status AS CHAR) AS status, CAST(created_at AS CHAR) AS created_at, \
    CAST(updated_at AS CHAR) AS updated_at FROM platform_domain";
const TENANT_IMAGE_SELECT: &str = "SELECT tenant_id, CAST(tenant_code AS CHAR) AS tenant_code, \
    CAST(tenant_name AS CHAR) AS tenant_name, CAST(tenant_type AS CHAR) AS tenant_type, \
    CAST(status AS CHAR) AS status, parent_tenant_id, CAST(path AS CHAR) AS path, depth, \
    CAST(contact_person AS CHAR) AS contact_person, CAST(contact_phone AS CHAR) AS contact_phone, \
    CAST(contact_email AS CHAR) AS contact_email, max_members, max_admins, current_members, \
    CAST(license_key AS CHAR) AS license_key, CAST(license_expires AS CHAR) AS license_expires, \
    CAST(logo_url AS CHAR) AS logo_url, CAST(settings_json AS CHAR) AS settings_json, \
    CAST(created_at AS CHAR) AS created_at, CAST(updated_at AS CHAR) AS updated_at FROM tenant";

fn sensitive_digest(
    tenant_id: i64,
    field: &'static str,
    value: Option<String>,
) -> Result<Option<String>, TypedSourceReadError> {
    value
        .map(|value| {
            authority_config_sensitive_field_digest(tenant_id, field, &value).map_err(|_| {
                TypedSourceReadError::Validation(format!(
                    "tenant {field} evidence digest could not be derived"
                ))
            })
        })
        .transpose()
}

const DEPARTMENT_INSERT_SQL: &str = "INSERT INTO departments \
    (tenant_id, sub_tenant_id, dept_name, dept_code, parent_dept_id, sort_order, status, description) \
    VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)";
const DOMAIN_INSERT_SQL: &str = "INSERT INTO platform_domain \
    (domain_code, domain_name, domain_description, status) VALUES (?, ?, ?, ?)";
const TENANT_INSERT_SQL: &str = "INSERT INTO tenant \
    (tenant_code, tenant_name, tenant_type, status, parent_tenant_id, path, depth) \
    VALUES (?, ?, 'ENTERPRISE', 'ACTIVE', ?, ?, ?)";

fn captured_generated_id(
    result: &sqlx::mysql::MySqlQueryResult,
    label: &str,
) -> Result<i64, TypedSourceReadError> {
    if result.rows_affected() != 1 {
        return Err(TypedSourceReadError::Validation(format!(
            "typed {label} insert affected {} rows; refusing unproven source evidence",
            result.rows_affected()
        )));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            TypedSourceReadError::Serialization(format!(
                "typed {label} insert returned an unusable generated id"
            ))
        })
}

pub(super) struct DepartmentInsert {
    pub tenant_id: i64,
    pub sub_tenant_id: Option<i64>,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: i32,
    pub description: Option<String>,
}

/// Fixed delegate-owned department INSERT followed by exact generated-id
/// readback. The parent capture handle records the immutable insert intent and
/// seals the returned row; callers cannot supply the resulting identity.
pub(super) async fn insert_department_and_capture_in_tx(
    tx: &mut Transaction<'_, MySql>,
    input: DepartmentInsert,
) -> Result<(i64, CapturedRow), TypedSourceReadError> {
    let DepartmentInsert {
        tenant_id,
        sub_tenant_id,
        name,
        code,
        parent_id,
        sort_order,
        description,
    } = input;
    let result = sqlx::query(DEPARTMENT_INSERT_SQL)
        .bind(tenant_id)
        .bind(sub_tenant_id)
        .bind(name)
        .bind(code)
        .bind(parent_id)
        .bind(sort_order)
        .bind(description)
        .execute(&mut **tx)
        .await
        .map_err(|error| TypedSourceReadError::from_sqlx("typed department insert", error))?;
    let id = captured_generated_id(&result, "department")?;
    let row = read_department(tx, &TypedSourceRowLookup::PrimaryId { id })
        .await?
        .ok_or_else(|| {
            TypedSourceReadError::Pending("typed department insert has no locked after row".into())
        })?;
    if row.pk != id {
        return Err(TypedSourceReadError::Pending(
            "typed department after readback differs from its observed insert id".into(),
        ));
    }
    Ok((id, row))
}

pub(super) async fn insert_domain_and_capture_in_tx(
    tx: &mut Transaction<'_, MySql>,
    code: Option<String>,
    name: String,
    description: Option<String>,
    status: String,
) -> Result<(i64, CapturedRow), TypedSourceReadError> {
    let result = sqlx::query(DOMAIN_INSERT_SQL)
        .bind(code)
        .bind(name)
        .bind(description)
        .bind(status)
        .execute(&mut **tx)
        .await
        .map_err(|error| TypedSourceReadError::from_sqlx("typed domain insert", error))?;
    let id = captured_generated_id(&result, "domain")?;
    let row = read_domain(tx, &TypedSourceRowLookup::PrimaryId { id })
        .await?
        .ok_or_else(|| {
            TypedSourceReadError::Pending("typed domain insert has no locked after row".into())
        })?;
    if row.pk != id {
        return Err(TypedSourceReadError::Pending(
            "typed domain after readback differs from its observed insert id".into(),
        ));
    }
    Ok((id, row))
}

pub(super) async fn insert_tenant_and_capture_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_code: String,
    name: String,
    parent_id: Option<i64>,
    path: String,
    depth: i32,
) -> Result<(i64, CapturedRow), TypedSourceReadError> {
    let result = sqlx::query(TENANT_INSERT_SQL)
        .bind(tenant_code)
        .bind(name)
        .bind(parent_id)
        .bind(&path)
        .bind(depth)
        .execute(&mut **tx)
        .await
        .map_err(|error| TypedSourceReadError::from_sqlx("typed tenant insert", error))?;
    let id = captured_generated_id(&result, "tenant")?;
    // Preserve tenant_repository's existing materialized-path behavior within
    // the same source transaction, then capture only the final actual row.
    let tenant_path = if depth == 0 {
        format!("/{id}")
    } else {
        format!("{}/{id}", path.trim_end_matches('/'))
    };
    let updated = sqlx::query("UPDATE tenant SET path = ? WHERE tenant_id = ?")
        .bind(&tenant_path)
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(|error| TypedSourceReadError::from_sqlx("typed tenant path update", error))?;
    if updated.rows_affected() != 1 {
        return Err(TypedSourceReadError::Pending(
            "typed tenant path correction did not affect exactly one inserted row".into(),
        ));
    }
    let row = read_tenant(tx, &TypedSourceRowLookup::PrimaryId { id })
        .await?
        .ok_or_else(|| {
            TypedSourceReadError::Pending("typed tenant insert has no locked after row".into())
        })?;
    if row.pk != id {
        return Err(TypedSourceReadError::Pending(
            "typed tenant after readback differs from its observed insert id".into(),
        ));
    }
    Ok((id, row))
}

fn invalid_lookup(table: TypedSourceTable) -> TypedSourceReadError {
    TypedSourceReadError::Validation(format!(
        "typed source lookup is invalid for {}",
        table.as_str()
    ))
}

fn row_image<T: Serialize>(
    pk: i64,
    row: &T,
    table: &str,
) -> Result<CapturedRow, TypedSourceReadError> {
    if pk <= 0 {
        return Err(TypedSourceReadError::Pending(format!(
            "typed {table} source row has a non-positive primary key"
        )));
    }
    let image_json = serde_json::to_string(row).map_err(|error| {
        TypedSourceReadError::Serialization(format!(
            "typed {table} source image serialization failed: {error}"
        ))
    })?;
    Ok(CapturedRow { pk, image_json })
}

async fn read_department(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let TypedSourceRowLookup::PrimaryId { id } = lookup else {
        return Err(invalid_lookup(TypedSourceTable::Department));
    };
    let row: Option<DepartmentImage> = sqlx::query_as::<_, DepartmentImage>(&format!(
        "{DEPARTMENT_IMAGE_SELECT} WHERE dept_id = ? FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        TypedSourceReadError::from_sqlx("typed department source image readback", error)
    })?;
    row.map(|row| row_image(row.dept_id, &row, "department"))
        .transpose()
}

async fn read_domain(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let TypedSourceRowLookup::PrimaryId { id } = lookup else {
        return Err(invalid_lookup(TypedSourceTable::Domain));
    };
    let row: Option<DomainImage> = sqlx::query_as::<_, DomainImage>(&format!(
        "{DOMAIN_IMAGE_SELECT} WHERE domain_id = ? FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        TypedSourceReadError::from_sqlx("typed domain source image readback", error)
    })?;
    row.map(|row| row_image(row.domain_id, &row, "domain"))
        .transpose()
}

async fn read_tenant(
    tx: &mut Transaction<'_, MySql>,
    lookup: &TypedSourceRowLookup,
) -> Result<Option<CapturedRow>, TypedSourceReadError> {
    let TypedSourceRowLookup::PrimaryId { id } = lookup else {
        return Err(invalid_lookup(TypedSourceTable::Tenant));
    };
    let raw: Option<TenantRawImage> = sqlx::query_as::<_, TenantRawImage>(&format!(
        "{TENANT_IMAGE_SELECT} WHERE tenant_id = ? FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        TypedSourceReadError::from_sqlx("typed tenant source image readback", error)
    })?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let tenant_id = raw.tenant_id;
    let image = TenantImage {
        tenant_id,
        tenant_code: raw.tenant_code,
        tenant_name: raw.tenant_name,
        tenant_type: raw.tenant_type,
        status: raw.status,
        parent_tenant_id: raw.parent_tenant_id,
        path: raw.path,
        depth: raw.depth,
        contact_person: sensitive_digest(tenant_id, "contact_person", raw.contact_person)?,
        contact_phone: sensitive_digest(tenant_id, "contact_phone", raw.contact_phone)?,
        contact_email: sensitive_digest(tenant_id, "contact_email", raw.contact_email)?,
        max_members: raw.max_members,
        max_admins: raw.max_admins,
        current_members: raw.current_members,
        license_key_digest: sensitive_digest(tenant_id, "license_key", raw.license_key)?,
        license_expires: raw.license_expires,
        logo_url: raw.logo_url,
        settings_json: raw.settings_json,
        created_at: raw.created_at,
        updated_at: raw.updated_at,
    };
    row_image(tenant_id, &image, "tenant").map(Some)
}

/// Read one actual metadata row (or prove absence) using only closed table and
/// lookup enums. Image columns and values are never supplied by the caller.
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
        TypedSourceTable::Department => read_department(tx, lookup).await,
        TypedSourceTable::Domain => read_domain(tx, lookup).await,
        TypedSourceTable::Tenant => read_tenant(tx, lookup).await,
        _ => Err(invalid_lookup(table)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_images_select_full_department_and_domain_row_shapes() {
        for (sql, columns) in [
            (
                DEPARTMENT_IMAGE_SELECT,
                [
                    "dept_id",
                    "tenant_id",
                    "sub_tenant_id",
                    "dept_name",
                    "dept_code",
                    "parent_dept_id",
                    "sort_order",
                    "status",
                    "description",
                    "created_at",
                    "updated_at",
                ]
                .as_slice(),
            ),
            (
                DOMAIN_IMAGE_SELECT,
                [
                    "domain_id",
                    "domain_code",
                    "domain_name",
                    "domain_description",
                    "status",
                    "created_at",
                    "updated_at",
                ]
                .as_slice(),
            ),
        ] {
            for column in columns {
                assert!(sql.contains(column), "missing source column {column}");
            }
            assert!(!sql.contains("SELECT *"));
        }
    }

    #[test]
    fn tenant_image_reads_sensitive_columns_but_serializes_only_tenant_bound_digests() {
        for column in [
            "tenant_id",
            "tenant_code",
            "tenant_name",
            "tenant_type",
            "status",
            "parent_tenant_id",
            "path",
            "depth",
            "contact_person",
            "contact_phone",
            "contact_email",
            "license_key",
            "license_expires",
            "max_members",
            "max_admins",
            "current_members",
            "logo_url",
            "settings_json",
            "created_at",
            "updated_at",
        ] {
            assert!(
                TENANT_IMAGE_SELECT.contains(column),
                "missing tenant source column {column}"
            );
        }

        let person_digest = sensitive_digest(42, "contact_person", Some("private person".into()))
            .expect("digest should be derived")
            .expect("non-null input should have a digest");
        let license_digest = sensitive_digest(42, "license_key", Some("private license".into()))
            .expect("digest should be derived")
            .expect("non-null input should have a digest");
        let image = TenantImage {
            tenant_id: 42,
            tenant_code: "T42".into(),
            tenant_name: "Tenant".into(),
            tenant_type: "ENTERPRISE".into(),
            status: "ACTIVE".into(),
            parent_tenant_id: None,
            path: Some("/42".into()),
            depth: 0,
            contact_person: Some(person_digest.clone()),
            contact_phone: None,
            contact_email: None,
            max_members: 10,
            max_admins: 1,
            current_members: 0,
            license_key_digest: Some(license_digest.clone()),
            license_expires: None,
            logo_url: None,
            settings_json: None,
            created_at: None,
            updated_at: None,
        };
        let encoded = serde_json::to_value(image).expect("tenant image should serialize");
        assert_eq!(encoded["contact_person"], person_digest);
        assert_eq!(encoded["license_key_digest"], license_digest);
        assert!(encoded.get("contact_person_digest").is_none());
        assert!(encoded.get("license_key").is_none());
        assert!(encoded.get("contact_phone").unwrap().is_null());
        assert!(encoded.get("contact_email").unwrap().is_null());
    }
}
