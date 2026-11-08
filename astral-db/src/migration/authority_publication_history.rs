//! Exact artifact contract for the V7 authority publication certificate history.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000007;
pub(super) const SOURCE_SHA384: &str = "5020bbb10a119b2c0dc048ffaa123ff0a68fb0fabebe7ac55c157a38c42cecfad3e0d7416b456ecf5477a2afdec0ce99";
pub(super) const TABLES: &[&str] = &["authorization_scope_certificate_history"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "certificate_hash"),
    (TABLES[0], "scope_hash"),
    (TABLES[0], "reservation_id"),
    (TABLES[0], "operation_id"),
    (TABLES[0], "certificate_id"),
    (TABLES[0], "authority_id"),
    (TABLES[0], "authority_term"),
    (TABLES[0], "global_fence_sequence"),
    (TABLES[0], "parent_certificate_hash"),
    (TABLES[0], "certificate_json"),
    (TABLES[0], "observed_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["certificate_hash"], true),
    (
        TABLES[0],
        "idx_asch_scope_order",
        &["scope_hash", "authority_term", "global_fence_sequence"],
        false,
    ),
    (
        TABLES[0],
        "idx_asch_reservation",
        &["reservation_id", "operation_id"],
        false,
    ),
];
const fn ascii(
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name,
        column_type,
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    }
}
const fn scalar(table: &'static str, name: &'static str, ty: &'static str) -> SchemaColumnContract {
    incremental_scalar_column(table, name, ty, true, None)
}
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    scalar(TABLES[0], "certificate_hash", "BINARY(32)"),
    scalar(TABLES[0], "scope_hash", "BINARY(32)"),
    ascii(TABLES[0], "reservation_id", "VARCHAR(128)"),
    ascii(TABLES[0], "operation_id", "VARCHAR(64)"),
    ascii(TABLES[0], "certificate_id", "VARCHAR(128)"),
    ascii(TABLES[0], "authority_id", "VARCHAR(128)"),
    scalar(TABLES[0], "authority_term", "BIGINT UNSIGNED"),
    scalar(TABLES[0], "global_fence_sequence", "BIGINT UNSIGNED"),
    incremental_scalar_column(
        TABLES[0],
        "parent_certificate_hash",
        "BINARY(32)",
        false,
        None,
    ),
    scalar(TABLES[0], "certificate_json", "JSON"),
    scalar(TABLES[0], "observed_at", "BIGINT"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_publication_history_schema_is_registered() {
        let source =
            include_str!("../../migrations/20261107000007_authority_publication_history.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .unwrap();
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
    }
}
