//! Exact schema contract for the durable authority source-outcome record.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000006;
pub(super) const SOURCE_SHA384: &str = "ad35babf4aa5c0616348e228acd6179dc087be3c520574e27ce11fb41de67edbb1f5b195a1db897ad2f95e439d5ac823";
pub(super) const TABLES: &[&str] = &["authority_source_outcome"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "reservation_id"),
    (TABLES[0], "operation_id"),
    (TABLES[0], "event_id"),
    (TABLES[0], "admission_proof_id"),
    (TABLES[0], "request_binding_digest"),
    (TABLES[0], "mutation_kind"),
    (TABLES[0], "service_id"),
    (TABLES[0], "database_id"),
    (TABLES[0], "source_commit_digest"),
    (TABLES[0], "before_image_digest"),
    (TABLES[0], "after_image_digest"),
    (TABLES[0], "source_receipts"),
    (TABLES[0], "staged_evidence"),
    (TABLES[0], "status"),
    (TABLES[0], "attempts"),
    (TABLES[0], "lease_owner"),
    (TABLES[0], "lease_until"),
    (TABLES[0], "generation"),
    (TABLES[0], "authority_disposition"),
    (TABLES[0], "last_error"),
    (TABLES[0], "outcome_digest"),
    (TABLES[0], "committed_at"),
    (TABLES[0], "created_at"),
    (TABLES[0], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["reservation_id"], true),
    (TABLES[0], "uk_aso_proof", &["admission_proof_id"], true),
    (
        TABLES[0],
        "idx_aso_status_lease",
        &["status", "lease_until"],
        false,
    ),
    (TABLES[0], "idx_aso_operation", &["operation_id"], false),
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

/// ASCII text column that is NULLABLE in the exact SQL (lease owner,
/// authority disposition).
const fn nullable_ascii(
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name,
        column_type,
        not_null: false,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    }
}

pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    ascii(TABLES[0], "reservation_id", "VARCHAR(128)"),
    ascii(TABLES[0], "operation_id", "VARCHAR(64)"),
    ascii(TABLES[0], "event_id", "VARCHAR(128)"),
    ascii(TABLES[0], "admission_proof_id", "VARCHAR(128)"),
    incremental_scalar_column(
        TABLES[0],
        "request_binding_digest",
        "BINARY(32)",
        true,
        None,
    ),
    ascii(TABLES[0], "mutation_kind", "VARCHAR(24)"),
    ascii(TABLES[0], "service_id", "VARCHAR(128)"),
    ascii(TABLES[0], "database_id", "VARCHAR(128)"),
    incremental_scalar_column(TABLES[0], "source_commit_digest", "BINARY(32)", false, None),
    incremental_scalar_column(TABLES[0], "before_image_digest", "BINARY(32)", false, None),
    incremental_scalar_column(TABLES[0], "after_image_digest", "BINARY(32)", false, None),
    incremental_scalar_column(TABLES[0], "source_receipts", "JSON", false, None),
    incremental_scalar_column(TABLES[0], "staged_evidence", "JSON", false, None),
    ascii(TABLES[0], "status", "VARCHAR(16)"),
    incremental_scalar_column(TABLES[0], "attempts", "INT UNSIGNED", true, Some("0")),
    nullable_ascii(TABLES[0], "lease_owner", "VARCHAR(128)"),
    incremental_scalar_column(TABLES[0], "lease_until", "BIGINT", false, None),
    incremental_scalar_column(TABLES[0], "generation", "BIGINT UNSIGNED", true, Some("0")),
    nullable_ascii(TABLES[0], "authority_disposition", "VARCHAR(32)"),
    incremental_scalar_column(TABLES[0], "last_error", "TEXT", false, None),
    incremental_scalar_column(TABLES[0], "outcome_digest", "BINARY(32)", true, None),
    incremental_scalar_column(TABLES[0], "committed_at", "BIGINT", true, None),
    incremental_scalar_column(TABLES[0], "created_at", "BIGINT", true, None),
    incremental_scalar_column(TABLES[0], "updated_at", "BIGINT", true, None),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_source_outcome_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000006_authority_source_outcome.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("source outcome migration must be registered in MIGRATOR");
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
    }
}
