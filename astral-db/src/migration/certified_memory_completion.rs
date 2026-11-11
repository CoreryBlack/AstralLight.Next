//! Exact schema contract for the CertifiedMemory family completion ledger.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261109000001;
pub(super) const SOURCE_SHA384: &str = "0cbc88d1b692203b0898543017481bd0ee8a86ea8b6f46b7f1cd5e39a43534601046157e0c21efc22f0a0d0d09f967dc";
pub(super) const TABLES: &[&str] = &["authority_certified_memory_completion"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "family"),
    (TABLES[0], "scope_key"),
    (TABLES[0], "tenant_id"),
    (TABLES[0], "scope_generation"),
    (TABLES[0], "revoke_watermark"),
    (TABLES[0], "state"),
    (TABLES[0], "reconciliation_state"),
    (TABLES[0], "reservation_id"),
    (TABLES[0], "operation_id"),
    (TABLES[0], "event_id"),
    (TABLES[0], "message_id"),
    (TABLES[0], "source_commit_digest"),
    (TABLES[0], "source_outcome_digest"),
    (TABLES[0], "before_content_digest"),
    (TABLES[0], "after_content_digest"),
    (TABLES[0], "complete_content_digest"),
    (TABLES[0], "audit_correlation_id"),
    (TABLES[0], "inventory_json"),
    (TABLES[0], "payload_json"),
    (TABLES[0], "dependency_frontier_json"),
    (TABLES[0], "authority_completion_receipt_id"),
    (TABLES[0], "created_at"),
    (TABLES[0], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        TABLES[0],
        "PRIMARY",
        &["family", "scope_key", "scope_generation"],
        true,
    ),
    (
        TABLES[0],
        "idx_acmc_scope_frontier",
        &[
            "scope_key",
            "tenant_id",
            "scope_generation",
            "revoke_watermark",
        ],
        false,
    ),
    (
        TABLES[0],
        "idx_acmc_state",
        &["state", "reconciliation_state", "updated_at"],
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

const fn scalar(
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
) -> SchemaColumnContract {
    incremental_scalar_column(table, name, column_type, true, None)
}

pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    ascii(TABLES[0], "family", "VARCHAR(32)"),
    ascii(TABLES[0], "scope_key", "VARCHAR(256)"),
    incremental_scalar_column(TABLES[0], "tenant_id", "BIGINT", false, None),
    scalar(TABLES[0], "scope_generation", "BIGINT UNSIGNED"),
    scalar(TABLES[0], "revoke_watermark", "BIGINT UNSIGNED"),
    ascii(TABLES[0], "state", "VARCHAR(16)"),
    ascii(TABLES[0], "reconciliation_state", "VARCHAR(16)"),
    ascii(TABLES[0], "reservation_id", "VARCHAR(128)"),
    ascii(TABLES[0], "operation_id", "VARCHAR(128)"),
    ascii(TABLES[0], "event_id", "VARCHAR(128)"),
    nullable_ascii(TABLES[0], "message_id", "VARCHAR(128)"),
    scalar(TABLES[0], "source_commit_digest", "BINARY(32)"),
    scalar(TABLES[0], "source_outcome_digest", "BINARY(32)"),
    incremental_scalar_column(
        TABLES[0],
        "before_content_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(TABLES[0], "after_content_digest", "BINARY(32)", false, None),
    incremental_scalar_column(
        TABLES[0],
        "complete_content_digest",
        "BINARY(32)",
        false,
        None,
    ),
    ascii(TABLES[0], "audit_correlation_id", "VARCHAR(128)"),
    scalar(TABLES[0], "inventory_json", "JSON"),
    scalar(TABLES[0], "payload_json", "JSON"),
    scalar(TABLES[0], "dependency_frontier_json", "JSON"),
    ascii(TABLES[0], "authority_completion_receipt_id", "VARCHAR(128)"),
    scalar(TABLES[0], "created_at", "BIGINT"),
    scalar(TABLES[0], "updated_at", "BIGINT"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_certified_memory_completion_schema_is_registered() {
        let source =
            include_str!("../../migrations/20261109000001_certified_memory_completion.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("certified memory completion migration must be registered");
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
        let operation_id = COLUMN_CONTRACTS
            .iter()
            .find(|column| column.name == "operation_id")
            .expect("completion operation id contract must be registered");
        let expanded = &super::super::certified_memory_operation_width::COLUMN_CONTRACTS[0];
        assert_eq!(operation_id.table, expanded.table);
        assert_eq!(operation_id.column_type, expanded.column_type);
        assert_eq!(operation_id.not_null, expanded.not_null);
        assert_eq!(operation_id.default, expanded.default);
        assert_eq!(operation_id.charset, expanded.charset);
        assert_eq!(operation_id.collation, expanded.collation);
    }
}
