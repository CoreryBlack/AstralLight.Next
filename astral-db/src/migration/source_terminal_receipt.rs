//! Additive retention contract for complete V7 independent-completion responses.

use super::{incremental_scalar_column, Migration, MigrationError, SchemaColumnContract};
use sqlx::MySqlPool;

pub(super) const VERSION: i64 = 20261107000012;
pub(super) const SOURCE_SHA384: &str = "e73f54a05391b806ad8b758eec36f8279bf0a3ce9d4ae15fb367e7ed249c64fd56404d34644b7742198b48b8c96e626a";
pub(super) const TABLES: &[&str] = &[];
const TABLE: &str = "authority_source_outcome";
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLE, "authority_terminal_kind"),
    (TABLE, "authority_terminal_response"),
    (TABLE, "authority_terminal_response_digest"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[];
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: TABLE,
        name: "authority_terminal_kind",
        column_type: "VARCHAR(32)",
        not_null: false,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLE, "authority_terminal_response", "JSON", false, None),
    incremental_scalar_column(
        TABLE,
        "authority_terminal_response_digest",
        "BINARY(32)",
        false,
        None,
    ),
];

fn pending_column_is_defined(
    applied_versions: &std::collections::HashSet<i64>,
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

pub(super) async fn preflight(
    pool: &MySqlPool,
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let table_exists = super::schema_table_exists(pool, TABLE).await?;
    if !table_exists
        && !migrations.iter().any(|migration| {
            !applied_versions.contains(&migration.version)
                && super::migration_matches_known_source(migration)
                && super::migration_defines_table(migration, TABLE)
        })
    {
        return Err(MigrationError::Failed(format!(
            "terminal receipt preflight found missing table {TABLE} without a pending creator"
        )));
    }
    let mut complete = true;
    for column in COLUMN_CONTRACTS {
        if table_exists && super::schema_column_exists(pool, column.table, column.name).await? {
            super::validate_schema_columns(pool, std::slice::from_ref(column)).await?;
        } else {
            complete = false;
            if !pending_column_is_defined(applied_versions, migrations, column) {
                return Err(MigrationError::Failed(format!(
                    "terminal receipt preflight found missing column {}.{} without its pending exact migration",
                    column.table, column.name
                )));
            }
        }
    }
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn missing_terminal_columns_require_the_pending_exact_migration() {
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .unwrap()
            .clone();
        let migrations = vec![migration.clone()];
        let mut applied = std::collections::HashSet::new();
        for column in COLUMN_CONTRACTS {
            assert!(pending_column_is_defined(&applied, &migrations, column));
            assert!(!pending_column_is_defined(&applied, &[], column));
        }
        applied.insert(VERSION);
        assert!(!pending_column_is_defined(
            &applied,
            &migrations,
            &COLUMN_CONTRACTS[0]
        ));
        applied.clear();
        let mut changed = migration;
        changed.sql = format!("{}\nSELECT 1;", changed.sql).into();
        assert!(!pending_column_is_defined(
            &applied,
            &[changed],
            &COLUMN_CONTRACTS[0]
        ));
    }

    #[test]
    fn terminal_column_contract_rejects_existing_metadata_drift() {
        use super::super::schema_column_contract_matches;

        for column in COLUMN_CONTRACTS {
            assert!(schema_column_contract_matches(
                column.name,
                column.column_type,
                "YES",
                None,
                column.charset,
                column.collation,
                column,
            ));
            for (column_type, nullable, default, charset, collation) in [
                ("BIGINT", "YES", None, None, None),
                (
                    column.column_type,
                    "NO",
                    None,
                    column.charset,
                    column.collation,
                ),
                (
                    column.column_type,
                    "YES",
                    Some("0"),
                    column.charset,
                    column.collation,
                ),
                (
                    column.column_type,
                    "YES",
                    None,
                    Some("utf8mb4"),
                    column.collation,
                ),
                (
                    column.column_type,
                    "YES",
                    None,
                    column.charset,
                    Some("utf8mb4_bin"),
                ),
            ] {
                assert!(!schema_column_contract_matches(
                    column.name,
                    column_type,
                    nullable,
                    default,
                    charset,
                    collation,
                    column,
                ));
            }
        }
    }

    #[test]
    fn terminal_preflight_checks_existing_columns_and_defers_full_missing_schema() {
        let source = include_str!("../migration.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let preflight = production
            .split("async fn preflight_schema_contract_before_sqlx(")
            .nth(1)
            .unwrap()
            .split("fn migration_matches_known_source")
            .next()
            .unwrap();
        let terminal = preflight
            .find("source_terminal_receipt::preflight(pool, applied_versions, migrations).await?")
            .expect("terminal preflight must run before the full validator");
        let full = preflight
            .find("validate_schema_contract(pool).await?")
            .unwrap();
        assert!(terminal < full);
        assert!(preflight.contains("&& terminal_receipt_complete"));
        let terminal_source = include_str!("source_terminal_receipt.rs");
        let terminal_production = terminal_source.split("#[cfg(test)]").next().unwrap();
        assert!(terminal_production
            .contains("super::validate_schema_columns(pool, std::slice::from_ref(column)).await?"));
        assert!(terminal_production
            .contains("pending_column_is_defined(applied_versions, migrations, column)"));
    }

    #[test]
    fn exact_terminal_receipt_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000012_source_terminal_receipt.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("terminal receipt migration must be embedded");
        let artifact = super::super::exact_migration_artifact_contract(migration)
            .expect("terminal receipt migration must be source-pinned");
        assert!(super::super::migration_requires_exact_artifact_parse(
            VERSION
        ));
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        for (table, column) in COLUMNS {
            assert!(super::super::migration_defines_existing_column(
                migration, table, column
            ));
        }
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
        assert!(COLUMN_CONTRACTS.iter().all(|column| !column.not_null));
    }
}
