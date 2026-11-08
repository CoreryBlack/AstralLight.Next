//! Exact schema contract for non-authorization protected business operations.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000004;
pub(super) const SOURCE_SHA384: &str = "17642707e350d7099a44ad1012e290b2a75b93eb4b04f792602394dff7612ec35a3bbc7db5f72d198100fccd8225fb4d";
pub(super) const TABLES: &[&str] = &["protected_mutation_operation"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    ("protected_mutation_operation", "operation_id"),
    ("protected_mutation_operation", "resource"),
    ("protected_mutation_operation", "request_digest"),
    ("protected_mutation_operation", "result_json"),
    ("protected_mutation_operation", "created_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "protected_mutation_operation",
        "PRIMARY",
        &["operation_id", "resource"],
        true,
    ),
    (
        "protected_mutation_operation",
        "idx_pmo_created",
        &["created_at"],
        false,
    ),
];
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: TABLES[0],
        name: "operation_id",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    SchemaColumnContract {
        table: TABLES[0],
        name: "resource",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[0], "request_digest", "BINARY(32)", true, None),
    incremental_scalar_column(TABLES[0], "result_json", "JSON", false, None),
    incremental_scalar_column(TABLES[0], "created_at", "BIGINT", true, None),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_operation_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000004_protected_mutation.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .unwrap();
        assert_eq!(source, migration.sql.as_ref());
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
    }
}
