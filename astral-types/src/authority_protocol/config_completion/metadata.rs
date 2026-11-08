use super::{
    AuthorityConfigSourceImage, AuthorityConfigSourceLookup, AuthorityConfigSourceTable,
    AuthorityProtocolError,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DepartmentImage {
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainImage {
    domain_id: i64,
    domain_code: Option<String>,
    domain_name: String,
    domain_description: Option<String>,
    status: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_optional_text(value: Option<&str>, max_bytes: usize) -> bool {
    value.is_none_or(|value| valid_text(value, max_bytes))
}

fn valid_optional_digest(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn decode<T>(text: &str) -> Result<T, AuthorityProtocolError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let image: T = serde_json::from_str(text).map_err(|_| AuthorityProtocolError::InvalidText {
        field: "source_row_image",
    })?;
    if serde_json::to_string(&image).map_err(|_| AuthorityProtocolError::CanonicalSerialization)?
        != text
    {
        return Err(AuthorityProtocolError::InvalidText {
            field: "source_row_canonical",
        });
    }
    Ok(image)
}

pub(super) fn validate_actual_row(
    receipt: &AuthorityConfigSourceImage,
    lookup: &AuthorityConfigSourceLookup,
    image_text: &str,
) -> Result<(), AuthorityProtocolError> {
    match (receipt.table, lookup) {
        (
            AuthorityConfigSourceTable::Department,
            AuthorityConfigSourceLookup::DepartmentInsertIntent {
                id,
                tenant_id,
                sub_tenant_id,
                dept_name,
                dept_code,
                parent_dept_id,
                sort_order,
                description,
            },
        ) => {
            let row: DepartmentImage = decode(image_text)?;
            if row.dept_id != receipt.key
                || row.dept_id != *id
                || row.tenant_id != *tenant_id
                || row.sub_tenant_id != *sub_tenant_id
                || row.dept_name != *dept_name
                || row.dept_code != *dept_code
                || row.parent_dept_id != *parent_dept_id
                || row.sort_order != *sort_order
                || row.status != "ACTIVE"
                || row.description.as_deref() != description.as_deref()
                || row.dept_id <= 0
                || row.tenant_id <= 0
                || row.sub_tenant_id.is_some_and(|value| value <= 0)
                || row.parent_dept_id.is_some_and(|value| value <= 0)
                || !valid_text(&row.dept_name, 128)
                || !valid_optional_text(row.dept_code.as_deref(), 64)
                || !valid_text(&row.status, 32)
                || !valid_optional_text(row.description.as_deref(), 512)
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        (AuthorityConfigSourceTable::Department, AuthorityConfigSourceLookup::PrimaryId { id }) => {
            let row: DepartmentImage = decode(image_text)?;
            if row.dept_id != receipt.key
                || row.dept_id != *id
                || row.dept_id <= 0
                || row.tenant_id <= 0
                || row.sub_tenant_id.is_some_and(|value| value <= 0)
                || row.parent_dept_id.is_some_and(|value| value <= 0)
                || !valid_text(&row.dept_name, 128)
                || !valid_optional_text(row.dept_code.as_deref(), 64)
                || !valid_text(&row.status, 32)
                || !valid_optional_text(row.description.as_deref(), 512)
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        (
            AuthorityConfigSourceTable::Domain,
            AuthorityConfigSourceLookup::DomainInsertIntent {
                id,
                domain_code,
                domain_name,
                domain_description,
                status,
            },
        ) => {
            let row: DomainImage = decode(image_text)?;
            if row.domain_id != receipt.key
                || row.domain_id != *id
                || row.domain_code != *domain_code
                || row.domain_name != *domain_name
                || row.domain_description != *domain_description
                || row.status != *status
                || row.domain_id <= 0
                || !valid_optional_text(row.domain_code.as_deref(), 512)
                || !valid_text(&row.domain_name, 128)
                || !valid_optional_text(row.domain_description.as_deref(), 512)
                || !valid_text(&row.status, 32)
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        (AuthorityConfigSourceTable::Domain, AuthorityConfigSourceLookup::PrimaryId { id }) => {
            let row: DomainImage = decode(image_text)?;
            if row.domain_id != receipt.key
                || row.domain_id != *id
                || row.domain_id <= 0
                || !valid_optional_text(row.domain_code.as_deref(), 512)
                || !valid_text(&row.domain_name, 128)
                || !valid_optional_text(row.domain_description.as_deref(), 512)
                || !valid_text(&row.status, 32)
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        (
            AuthorityConfigSourceTable::Tenant,
            AuthorityConfigSourceLookup::TenantInsertIntent {
                id,
                tenant_code,
                tenant_name,
                tenant_type,
                parent_tenant_id,
                path,
                depth,
            },
        ) => {
            let row: TenantImage = decode(image_text)?;
            if row.tenant_id != receipt.key
                || row.tenant_id != *id
                || row.tenant_code != *tenant_code
                || row.tenant_name != *tenant_name
                || row.tenant_type != *tenant_type
                || row.parent_tenant_id != *parent_tenant_id
                || row.path.as_deref() != Some(path.as_str())
                || row.depth != *depth
                || row.status != "ACTIVE"
                || row.tenant_type != "ENTERPRISE"
                || row.tenant_id <= 0
                || row.parent_tenant_id.is_some_and(|value| value <= 0)
                || row.depth < 0
                || !valid_text(&row.tenant_code, 64)
                || !valid_text(&row.tenant_name, 128)
                || !valid_optional_text(row.path.as_deref(), 512)
                || !valid_text(&row.status, 32)
                || !valid_optional_digest(row.contact_person.as_deref())
                || !valid_optional_digest(row.contact_phone.as_deref())
                || !valid_optional_digest(row.contact_email.as_deref())
                || !valid_optional_digest(row.license_key_digest.as_deref())
                || row.max_members < 0
                || row.max_admins < 0
                || row.current_members < 0
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        (AuthorityConfigSourceTable::Tenant, AuthorityConfigSourceLookup::PrimaryId { id }) => {
            let row: TenantImage = decode(image_text)?;
            if row.tenant_id != receipt.key
                || row.tenant_id != *id
                || row.tenant_id <= 0
                || row.tenant_type != "ENTERPRISE"
                || row.parent_tenant_id.is_some_and(|value| value <= 0)
                || row.depth < 0
                || !valid_text(&row.tenant_code, 64)
                || !valid_text(&row.tenant_name, 128)
                || !valid_optional_text(row.path.as_deref(), 512)
                || !valid_text(&row.status, 32)
                || !valid_optional_digest(row.contact_person.as_deref())
                || !valid_optional_digest(row.contact_phone.as_deref())
                || !valid_optional_digest(row.contact_email.as_deref())
                || !valid_optional_digest(row.license_key_digest.as_deref())
                || row.max_members < 0
                || row.max_admins < 0
                || row.current_members < 0
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        _ => return Err(AuthorityProtocolError::ScopeMismatch),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::AuthorityConfigSourceOperation;
    use super::*;
    use sha2::{Digest, Sha256};

    const INSERT: AuthorityConfigSourceOperation = AuthorityConfigSourceOperation::Insert;

    fn source_image(
        table: AuthorityConfigSourceTable,
        key: i64,
        lookup: &AuthorityConfigSourceLookup,
        operation: AuthorityConfigSourceOperation,
        row_json: &str,
    ) -> AuthorityConfigSourceImage {
        let digest = hex::encode(Sha256::digest(row_json.as_bytes()));
        AuthorityConfigSourceImage {
            table,
            key,
            lookup: serde_json::to_string(lookup).expect("serialize closed lookup"),
            operation,
            before_image_digest: digest.clone(),
            after_image_digest: digest,
            before_image: row_json.to_owned(),
            after_image: row_json.to_owned(),
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct DepartmentRowFixture<'a> {
        id: i64,
        tenant_id: i64,
        sub_tenant_id: Option<i64>,
        name: &'a str,
        code: Option<&'a str>,
        parent: Option<i64>,
        sort_order: i32,
        description: Option<&'a str>,
    }

    fn department_row(fixture: DepartmentRowFixture<'_>) -> String {
        let DepartmentRowFixture {
            id,
            tenant_id,
            sub_tenant_id,
            name,
            code,
            parent,
            sort_order,
            description,
        } = fixture;
        serde_json::to_string(&DepartmentImage {
            dept_id: id,
            tenant_id,
            sub_tenant_id,
            dept_name: name.to_owned(),
            dept_code: code.map(str::to_owned),
            parent_dept_id: parent,
            sort_order,
            status: "ACTIVE".to_owned(),
            description: description.map(str::to_owned),
            created_at: None,
            updated_at: None,
        })
        .expect("serialize department row")
    }

    fn domain_row(
        id: i64,
        code: Option<&str>,
        name: &str,
        description: Option<&str>,
        status: &str,
    ) -> String {
        serde_json::to_string(&DomainImage {
            domain_id: id,
            domain_code: code.map(str::to_owned),
            domain_name: name.to_owned(),
            domain_description: description.map(str::to_owned),
            status: status.to_owned(),
            created_at: None,
            updated_at: None,
        })
        .expect("serialize domain row")
    }

    #[derive(Debug, Clone)]
    struct TenantRowFixture {
        id: i64,
        code: String,
        name: String,
        parent: Option<i64>,
        path: String,
        depth: i32,
        contact_email: Option<String>,
        license_key_digest: Option<String>,
    }

    fn tenant_row(fixture: TenantRowFixture) -> String {
        let TenantRowFixture {
            id,
            code,
            name,
            parent,
            path,
            depth,
            contact_email,
            license_key_digest,
        } = fixture;
        serde_json::to_string(&TenantImage {
            tenant_id: id,
            tenant_code: code,
            tenant_name: name,
            tenant_type: "ENTERPRISE".to_owned(),
            status: "ACTIVE".to_owned(),
            parent_tenant_id: parent,
            path: Some(path),
            depth,
            contact_person: None,
            contact_phone: None,
            contact_email,
            max_members: 1000,
            max_admins: 10,
            current_members: 0,
            license_key_digest,
            license_expires: None,
            logo_url: None,
            settings_json: None,
            created_at: None,
            updated_at: None,
        })
        .expect("serialize tenant row")
    }

    #[test]
    fn department_domain_and_tenant_insert_intents_validate_actual_full_rows() {
        let department_lookup = AuthorityConfigSourceLookup::DepartmentInsertIntent {
            id: 11,
            tenant_id: 7,
            sub_tenant_id: Some(8),
            dept_name: "Operations".into(),
            dept_code: Some("OPS".into()),
            parent_dept_id: Some(9),
            sort_order: -3,
            description: Some("Regional operations".into()),
        };
        let department = department_row(DepartmentRowFixture {
            id: 11,
            tenant_id: 7,
            sub_tenant_id: Some(8),
            name: "Operations",
            code: Some("OPS"),
            parent: Some(9),
            sort_order: -3,
            description: Some("Regional operations"),
        });
        let department_receipt = source_image(
            AuthorityConfigSourceTable::Department,
            11,
            &department_lookup,
            INSERT,
            &department,
        );
        validate_actual_row(&department_receipt, &department_lookup, &department).unwrap();

        let domain_lookup = AuthorityConfigSourceLookup::DomainInsertIntent {
            id: 12,
            domain_code: None,
            domain_name: "Trust Graph".into(),
            domain_description: None,
            status: "ACTIVE".into(),
        };
        let domain = domain_row(12, None, "Trust Graph", None, "ACTIVE");
        let domain_receipt = source_image(
            AuthorityConfigSourceTable::Domain,
            12,
            &domain_lookup,
            INSERT,
            &domain,
        );
        validate_actual_row(&domain_receipt, &domain_lookup, &domain).unwrap();

        let tenant_lookup = AuthorityConfigSourceLookup::TenantInsertIntent {
            id: 13,
            tenant_code: "tenant-operation-digest".into(),
            tenant_name: "Example tenant".into(),
            tenant_type: "ENTERPRISE".into(),
            parent_tenant_id: Some(3),
            path: "/3/13".into(),
            depth: 1,
        };
        let tenant = tenant_row(TenantRowFixture {
            id: 13,
            code: "tenant-operation-digest".into(),
            name: "Example tenant".into(),
            parent: Some(3),
            path: "/3/13".into(),
            depth: 1,
            contact_email: None,
            license_key_digest: None,
        });
        let tenant_receipt = source_image(
            AuthorityConfigSourceTable::Tenant,
            13,
            &tenant_lookup,
            INSERT,
            &tenant,
        );
        validate_actual_row(&tenant_receipt, &tenant_lookup, &tenant).unwrap();
    }

    #[test]
    fn metadata_lookup_rejects_wrong_table_or_actual_key_and_insert_intent_mismatch() {
        let lookup = AuthorityConfigSourceLookup::DepartmentInsertIntent {
            id: 11,
            tenant_id: 7,
            sub_tenant_id: None,
            dept_name: "Operations".into(),
            dept_code: None,
            parent_dept_id: None,
            sort_order: 0,
            description: None,
        };
        assert!(lookup
            .validate_for_table(AuthorityConfigSourceTable::Department)
            .is_ok());
        assert!(lookup
            .validate_for_table(AuthorityConfigSourceTable::Domain)
            .is_err());

        let row = department_row(DepartmentRowFixture {
            id: 11,
            tenant_id: 7,
            sub_tenant_id: None,
            name: "Operations",
            code: None,
            parent: None,
            sort_order: 0,
            description: None,
        });
        let receipt = source_image(
            AuthorityConfigSourceTable::Department,
            11,
            &lookup,
            INSERT,
            &row,
        );
        let mut wrong_key_receipt = receipt.clone();
        wrong_key_receipt.key = 99;
        assert!(validate_actual_row(&wrong_key_receipt, &lookup, &row).is_err());

        for wrong_row in [
            department_row(DepartmentRowFixture {
                id: 11,
                tenant_id: 7,
                sub_tenant_id: None,
                name: "Different name",
                code: None,
                parent: None,
                sort_order: 0,
                description: None,
            }),
            department_row(DepartmentRowFixture {
                id: 11,
                tenant_id: 7,
                sub_tenant_id: None,
                name: "Operations",
                code: None,
                parent: None,
                sort_order: 1,
                description: None,
            }),
        ] {
            assert!(validate_actual_row(&receipt, &lookup, &wrong_row).is_err());
        }
        let wrong_table = AuthorityConfigSourceImage {
            table: AuthorityConfigSourceTable::Tenant,
            ..receipt
        };
        assert!(validate_actual_row(&wrong_table, &lookup, &row).is_err());
    }

    #[test]
    fn tenant_image_binds_sensitive_digests_and_preserves_nulls() {
        let email_digest = super::super::authority_config_sensitive_field_digest(
            13,
            "contact_email",
            "owner@example.test",
        )
        .unwrap();
        let key_digest = super::super::authority_config_sensitive_field_digest(
            13,
            "license_key",
            "license-raw-value",
        )
        .unwrap();
        let lookup = AuthorityConfigSourceLookup::TenantInsertIntent {
            id: 13,
            tenant_code: "tenant-op-hash".into(),
            tenant_name: "Example tenant".into(),
            tenant_type: "ENTERPRISE".into(),
            parent_tenant_id: None,
            path: "/13".into(),
            depth: 0,
        };
        let row = tenant_row(TenantRowFixture {
            id: 13,
            code: "tenant-op-hash".into(),
            name: "Example tenant".into(),
            parent: None,
            path: "/13".into(),
            depth: 0,
            contact_email: Some(email_digest.clone()),
            license_key_digest: Some(key_digest.clone()),
        });
        let receipt = source_image(
            AuthorityConfigSourceTable::Tenant,
            13,
            &lookup,
            INSERT,
            &row,
        );
        validate_actual_row(&receipt, &lookup, &row).unwrap();
        assert!(!row.contains("owner@example.test"));
        assert!(!row.contains("license-raw-value"));

        let with_raw_email = row.replace(&email_digest, "owner@example.test");
        assert!(validate_actual_row(&receipt, &lookup, &with_raw_email).is_err());

        let mut null_lookup = lookup.clone();
        if let AuthorityConfigSourceLookup::TenantInsertIntent { path, .. } = &mut null_lookup {
            *path = "/14".into();
        }
        let null_row = tenant_row(TenantRowFixture {
            id: 13,
            code: "tenant-op-hash".into(),
            name: "Example tenant".into(),
            parent: None,
            path: "/14".into(),
            depth: 0,
            contact_email: None,
            license_key_digest: None,
        });
        let null_receipt = source_image(
            AuthorityConfigSourceTable::Tenant,
            13,
            &null_lookup,
            INSERT,
            &null_row,
        );
        validate_actual_row(&null_receipt, &null_lookup, &null_row).unwrap();
        let malformed_digest_row = tenant_row(TenantRowFixture {
            id: 13,
            code: "tenant-op-hash".into(),
            name: "Example tenant".into(),
            parent: None,
            path: "/14".into(),
            depth: 0,
            contact_email: Some("g".repeat(64)),
            license_key_digest: None,
        });
        let malformed_receipt = source_image(
            AuthorityConfigSourceTable::Tenant,
            13,
            &null_lookup,
            INSERT,
            &malformed_digest_row,
        );
        assert!(
            validate_actual_row(&malformed_receipt, &null_lookup, &malformed_digest_row).is_err()
        );
    }
}
