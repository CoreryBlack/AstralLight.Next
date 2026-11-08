//! Exact artifact contract for the additive commerce billing-cycle column.
//!
//! This migration only adds a nullable compatibility column. Existing NULL
//! values are intentionally preserved as unknown and are never backfilled.

use std::collections::HashSet;

use super::{Migration, MigrationError, SchemaColumnContract};
use sqlx::MySqlPool;

pub(super) const VERSION: i64 = 20261107000011;
pub(super) const SOURCE_SHA384: &str = "1a8ae651b38065a4f23d4da14ce595cc21cf14db1ea97f44e9b9af81309ebd751e86171f236ec69a2ec4be4dc8e42b75";
pub(super) const TABLES: &[&str] = &[];
pub(super) const BOUND_TABLE: &str = "platform_package";
pub(super) const COLUMNS: &[(&str, &str)] = &[(BOUND_TABLE, "billing_cycle")];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[];

pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[SchemaColumnContract {
    table: BOUND_TABLE,
    name: "billing_cycle",
    column_type: "VARCHAR(32)",
    not_null: false,
    default: None,
    charset: Some("ascii"),
    collation: Some("ascii_bin"),
}];

const CANONICAL_BASE_COLUMNS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "package_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "package_name",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "package_code",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "description",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "price",
        column_type: "DECIMAL(10,2)",
        not_null: false,
        default: Some("0.00"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "status",
        column_type: "VARCHAR(16)",
        not_null: false,
        default: Some("ACTIVE"),
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "version_no",
        column_type: "INT",
        not_null: false,
        default: Some("1"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "created_at",
        column_type: "DATETIME",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: BOUND_TABLE,
        name: "updated_at",
        column_type: "DATETIME",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant",
        name: "tenant_name",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: "tenant",
        name: "status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("ACTIVE"),
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: "tenant",
        name: "parent_tenant_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant",
        name: "path",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: "tenant",
        name: "depth",
        column_type: "INT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant",
        name: "created_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant",
        name: "updated_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "purchase_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "sub_tenant_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "package_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "status",
        column_type: "VARCHAR(16)",
        not_null: false,
        default: Some("ACTIVE"),
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_0900_ai_ci"),
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "purchased_at",
        column_type: "DATETIME",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "expired_at",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "created_at",
        column_type: "DATETIME",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "tenant_purchase",
        name: "updated_at",
        column_type: "DATETIME",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
];

fn pending_column_is_defined(
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
    column: &SchemaColumnContract,
) -> bool {
    !applied_versions.contains(&VERSION)
        && migrations.iter().any(|migration| {
            migration.version == VERSION
                && super::migration_matches_known_source(migration)
                && super::migration_defines_existing_column(migration, column.table, column.name)
        })
}

#[cfg(test)]
fn canonical_base_columns_are_defined(
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> bool {
    CANONICAL_BASE_COLUMNS.iter().all(|column| {
        migrations.iter().any(|migration| {
            !applied_versions.contains(&migration.version)
                && super::migration_matches_known_source(migration)
                && (super::migration_defines_column(migration, column.table, column.name)
                    || super::migration_defines_existing_column(
                        migration,
                        column.table,
                        column.name,
                    ))
        })
    })
}

async fn validate_canonical_base(pool: &MySqlPool) -> Result<(), MigrationError> {
    for table in ["platform_package", "tenant", "tenant_purchase"] {
        if !super::schema_table_exists(pool, table).await? {
            return Err(MigrationError::Failed(format!(
                "BLOCKED: commerce runtime requires canonical full_schema_v4 table {table}; legacy migration 19/24 adoption is unresolved"
            )));
        }
    }
    for column in CANONICAL_BASE_COLUMNS {
        if !super::schema_column_exists(pool, column.table, column.name).await? {
            return Err(MigrationError::Failed(format!(
                "BLOCKED: platform_package/tenant commerce base is missing canonical column {}.{}; legacy migration 19/24 shapes and full_schema_v4 are divergent",
                column.table, column.name
            )));
        }
    }
    super::validate_schema_columns(pool, CANONICAL_BASE_COLUMNS)
        .await
        .map_err(|error| {
            MigrationError::Failed(format!(
                "BLOCKED: canonical commerce base schema is incompatible with full_schema_v4; refusing to select or rewrite historical migration 19/24: {error}"
            ))
        })
}

/// Validate the adopted runtime schema before commerce repositories are served.
/// This is intentionally separate from migration preflight: an already-recorded
/// migration must still fail closed if the live base schema later drifts.
pub(super) async fn validate_runtime(pool: &MySqlPool) -> Result<(), MigrationError> {
    validate_canonical_base(pool).await?;
    super::validate_schema_columns(pool, COLUMN_CONTRACTS)
        .await
        .map_err(|error| {
            MigrationError::Failed(format!(
                "BLOCKED: commerce billing-cycle runtime column contract is not adopted: {error}"
            ))
        })
}

pub(super) async fn preflight(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let table_exists = super::schema_table_exists(pool, BOUND_TABLE).await?;
    if !table_exists {
        return Err(MigrationError::Failed(
            "BLOCKED: commerce billing-cycle adoption requires the canonical full_schema_v4 platform_package base; no historical migration is silently selected as its creator".into(),
        ));
    }

    validate_canonical_base(pool).await?;

    let column = &COLUMN_CONTRACTS[0];
    if super::schema_column_exists(pool, column.table, column.name).await? {
        super::validate_schema_columns(pool, std::slice::from_ref(column)).await?;
        return Ok(true);
    }

    if !pending_column_is_defined(applied_versions, migrations, column) {
        return Err(MigrationError::Failed(format!(
            "commerce billing-cycle preflight found missing column {}.{} without its pending exact migration",
            column.table, column.name
        )));
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn pending_column_requires_unapplied_source_pinned_add_column() {
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("commerce migration must be embedded")
            .clone();
        let mut applied = HashSet::new();
        assert!(pending_column_is_defined(
            &applied,
            std::slice::from_ref(&migration),
            &COLUMN_CONTRACTS[0]
        ));

        applied.insert(VERSION);
        assert!(!pending_column_is_defined(
            &applied,
            std::slice::from_ref(&migration),
            &COLUMN_CONTRACTS[0]
        ));

        applied.clear();
        assert!(!pending_column_is_defined(
            &applied,
            &[],
            &COLUMN_CONTRACTS[0]
        ));

        let mut rewritten = migration;
        rewritten.sql = format!("{}\nSELECT 1;", rewritten.sql).into();
        assert!(!pending_column_is_defined(
            &applied,
            &[rewritten],
            &COLUMN_CONTRACTS[0]
        ));
    }

    #[test]
    fn canonical_adoption_does_not_accept_legacy_creator_as_base() {
        let creator = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == 20240630000019)
            .expect("legacy platform package creator must be embedded")
            .clone();
        let applied = HashSet::new();
        assert!(!creator.sql.contains("package_id BIGINT"));
        assert!(!creator.sql.contains("package_code VARCHAR(64)"));
        assert!(!CANONICAL_BASE_COLUMNS.iter().all(|column| {
            super::super::migration_defines_column(&creator, column.table, column.name)
                || super::super::migration_defines_existing_column(
                    &creator,
                    column.table,
                    column.name,
                )
        }));
        assert!(!canonical_base_columns_are_defined(&applied, &[creator]));
    }

    #[test]
    fn commerce_column_contract_rejects_type_nullability_and_default_drift() {
        use super::super::schema_column_contract_matches;

        let expected = &COLUMN_CONTRACTS[0];
        assert!(schema_column_contract_matches(
            expected.name,
            expected.column_type,
            "YES",
            None,
            expected.charset,
            expected.collation,
            expected,
        ));
        assert!(!schema_column_contract_matches(
            expected.name,
            "VARCHAR(64)",
            "YES",
            None,
            expected.charset,
            expected.collation,
            expected,
        ));
        assert!(!schema_column_contract_matches(
            expected.name,
            expected.column_type,
            "NO",
            None,
            expected.charset,
            expected.collation,
            expected,
        ));
        assert!(!schema_column_contract_matches(
            expected.name,
            expected.column_type,
            "YES",
            Some("MONTHLY"),
            expected.charset,
            expected.collation,
            expected,
        ));
    }

    #[test]
    fn commerce_column_contract_rejects_charset_and_collation_drift() {
        use super::super::schema_column_contract_matches;

        let expected = &COLUMN_CONTRACTS[0];
        assert!(!schema_column_contract_matches(
            expected.name,
            expected.column_type,
            "YES",
            None,
            Some("utf8mb4"),
            expected.collation,
            expected,
        ));
        assert!(!schema_column_contract_matches(
            expected.name,
            expected.column_type,
            "YES",
            None,
            expected.charset,
            Some("ascii_general_ci"),
            expected,
        ));
    }

    #[test]
    fn exact_commerce_billing_cycle_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000011_commerce_billing_cycle.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        assert!(TABLES.is_empty());
        assert_eq!(COLUMNS, &[(BOUND_TABLE, "billing_cycle")]);
        assert!(INDEXES.is_empty());
        assert_eq!(COLUMN_CONTRACTS.len(), 1);
        assert!(!COLUMN_CONTRACTS[0].not_null);
        assert_eq!(COLUMN_CONTRACTS[0].charset, Some("ascii"));
        assert_eq!(COLUMN_CONTRACTS[0].collation, Some("ascii_bin"));
    }
}
