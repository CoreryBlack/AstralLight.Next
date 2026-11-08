//! Exact artifact contract for the source-proven empty-card origin ledger.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000010;
pub(super) const SOURCE_SHA384: &str = "cae52a9ba048db055014c4839b6ddf8fced652964e3d18e69ea1eec151e03ca1d71657d1ec8f1d82d0eb25c64090f778";
pub(super) const TABLES: &[&str] = &["authority_empty_card_origin"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "tenant_id"),
    (TABLES[0], "card_id"),
    (TABLES[0], "create_operation_id"),
    (TABLES[0], "reservation_id"),
    (TABLES[0], "event_id"),
    (TABLES[0], "admission_proof_id"),
    (TABLES[0], "service_id"),
    (TABLES[0], "database_id"),
    (TABLES[0], "request_binding_digest"),
    (TABLES[0], "source_commit_digest"),
    (TABLES[0], "before_image_digest"),
    (TABLES[0], "after_image_digest"),
    (TABLES[0], "source_outcome_digest"),
    (TABLES[0], "staged_evidence_digest"),
    (TABLES[0], "source_receipts"),
    (TABLES[0], "staged_evidence"),
    (TABLES[0], "state"),
    (TABLES[0], "authority_terminal_receipt"),
    (TABLES[0], "authority_terminal_receipt_digest"),
    (TABLES[0], "created_at"),
    (TABLES[0], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["tenant_id", "card_id"], true),
    (TABLES[0], "uk_aceo_card_id", &["card_id"], true),
    (TABLES[0], "uk_aceo_reservation", &["reservation_id"], true),
    (
        TABLES[0],
        "idx_aceo_operation",
        &["create_operation_id"],
        false,
    ),
];

pub(super) const CONSTRAINTS: &[super::ExactMigrationConstraintContract] = &[
    super::ExactMigrationConstraintContract::Check {
        table: TABLES[0],
        name: "chk_aceo_state",
        expression: "STATE IN ('PENDING', 'COMPLETED')",
    },
    super::ExactMigrationConstraintContract::Check {
        table: TABLES[0],
        name: "chk_aceo_terminal_pair",
        expression: "(STATE = 'PENDING' AND AUTHORITY_TERMINAL_RECEIPT IS NULL AND AUTHORITY_TERMINAL_RECEIPT_DIGEST IS NULL) OR (STATE = 'COMPLETED' AND AUTHORITY_TERMINAL_RECEIPT IS NOT NULL AND AUTHORITY_TERMINAL_RECEIPT_DIGEST IS NOT NULL)",
    },
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
    scalar(TABLES[0], "tenant_id", "BIGINT"),
    scalar(TABLES[0], "card_id", "BIGINT"),
    ascii(TABLES[0], "create_operation_id", "VARCHAR(128)"),
    ascii(TABLES[0], "reservation_id", "VARCHAR(128)"),
    ascii(TABLES[0], "event_id", "VARCHAR(128)"),
    ascii(TABLES[0], "admission_proof_id", "VARCHAR(128)"),
    ascii(TABLES[0], "service_id", "VARCHAR(128)"),
    ascii(TABLES[0], "database_id", "VARCHAR(128)"),
    scalar(TABLES[0], "request_binding_digest", "BINARY(32)"),
    scalar(TABLES[0], "source_commit_digest", "BINARY(32)"),
    scalar(TABLES[0], "before_image_digest", "BINARY(32)"),
    scalar(TABLES[0], "after_image_digest", "BINARY(32)"),
    scalar(TABLES[0], "source_outcome_digest", "BINARY(32)"),
    scalar(TABLES[0], "staged_evidence_digest", "BINARY(32)"),
    scalar(TABLES[0], "source_receipts", "JSON"),
    scalar(TABLES[0], "staged_evidence", "JSON"),
    ascii(TABLES[0], "state", "VARCHAR(16)"),
    incremental_scalar_column(TABLES[0], "authority_terminal_receipt", "JSON", false, None),
    incremental_scalar_column(
        TABLES[0],
        "authority_terminal_receipt_digest",
        "BINARY(32)",
        false,
        None,
    ),
    scalar(TABLES[0], "created_at", "BIGINT"),
    scalar(TABLES[0], "updated_at", "BIGINT"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_empty_card_origin_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000010_empty_card_origin.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("empty-card origin migration must be registered in MIGRATOR");
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
    }
}
