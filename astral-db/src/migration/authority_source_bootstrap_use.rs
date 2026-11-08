//! Exact schema contract for the ROOT source-bootstrap capability-use record.
//!
//! The root migration owner registers this child in `migration.rs`. This child
//! deliberately does not execute DDL and does not own migration registration.

use super::{incremental_scalar_column, Migration, MigrationError, SchemaColumnContract};
use sqlx::MySqlPool;

pub(super) const VERSION: i64 = 20261107000014;
pub(super) const SOURCE_SHA384: &str = "4e04b49392e81b1c00c160412a32630f66f64a182ea64652fbf43d881301cb7c575ae8552d3acab51a8334bd2fac961a";
pub(super) const TABLES: &[&str] = &["authority_source_bootstrap_use"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "reservation_id"),
    (TABLES[0], "operation_id"),
    (TABLES[0], "event_id"),
    (TABLES[0], "capability_nonce"),
    (TABLES[0], "authority_id"),
    (TABLES[0], "service_id"),
    (TABLES[0], "database_id"),
    (TABLES[0], "authority_term"),
    (TABLES[0], "global_fence_sequence"),
    (TABLES[0], "key_epoch"),
    (TABLES[0], "ticket_digest"),
    (TABLES[0], "capability_digest"),
    (TABLES[0], "source_payload_digest"),
    (TABLES[0], "before_image_digest"),
    (TABLES[0], "source_commit_digest"),
    (TABLES[0], "after_image_digest"),
    (TABLES[0], "source_outcome_digest"),
    (TABLES[0], "staged_evidence_digest"),
    (TABLES[0], "audit_receipt_digest"),
    (TABLES[0], "generated_ids"),
    (TABLES[0], "source_receipts"),
    (TABLES[0], "outcome_json"),
    (TABLES[0], "staged_evidence"),
    (TABLES[0], "state"),
    (TABLES[0], "committed_at"),
    (TABLES[0], "created_at"),
    (TABLES[0], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["reservation_id"], true),
    (TABLES[0], "uk_asbu_operation", &["operation_id"], true),
    (TABLES[0], "uk_asbu_event", &["event_id"], true),
    (
        TABLES[0],
        "uk_asbu_capability_nonce",
        &["capability_nonce"],
        true,
    ),
    (
        TABLES[0],
        "idx_asbu_ticket_digest",
        &["ticket_digest"],
        false,
    ),
    (TABLES[0], "idx_asbu_state", &["state"], false),
];

const fn ascii(name: &'static str) -> SchemaColumnContract {
    SchemaColumnContract {
        table: TABLES[0],
        name,
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    }
}

const fn digest(name: &'static str) -> SchemaColumnContract {
    incremental_scalar_column(TABLES[0], name, "BINARY(32)", true, None)
}

const fn json(name: &'static str) -> SchemaColumnContract {
    incremental_scalar_column(TABLES[0], name, "JSON", true, None)
}

pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    ascii("reservation_id"),
    ascii("operation_id"),
    ascii("event_id"),
    ascii("capability_nonce"),
    ascii("authority_id"),
    ascii("service_id"),
    ascii("database_id"),
    incremental_scalar_column(TABLES[0], "authority_term", "BIGINT", true, None),
    incremental_scalar_column(TABLES[0], "global_fence_sequence", "BIGINT", true, None),
    incremental_scalar_column(TABLES[0], "key_epoch", "BIGINT", true, None),
    digest("ticket_digest"),
    digest("capability_digest"),
    digest("source_payload_digest"),
    digest("before_image_digest"),
    digest("source_commit_digest"),
    digest("after_image_digest"),
    digest("source_outcome_digest"),
    digest("staged_evidence_digest"),
    digest("audit_receipt_digest"),
    json("generated_ids"),
    json("source_receipts"),
    json("outcome_json"),
    json("staged_evidence"),
    SchemaColumnContract {
        table: TABLES[0],
        name: "state",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[0], "committed_at", "BIGINT", true, None),
    incremental_scalar_column(TABLES[0], "created_at", "BIGINT", true, None),
    incremental_scalar_column(TABLES[0], "updated_at", "BIGINT", true, None),
];

fn pending_exact_creator(
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
) -> bool {
    !applied_versions.contains(&VERSION)
        && migrations.iter().any(|migration| {
            migration.version == VERSION
                && super::migration_matches_known_source(migration)
                && super::migration_defines_table(migration, TABLES[0])
        })
}

/// Validate migration 14 before SQLx executes it.
///
/// A missing table is tolerated only when the exact embedded migration 14 is
/// still pending. Once a table exists, the creator is never treated as a
/// repair mechanism: every declared column and index must already match the
/// exact runtime contract. This keeps partial CREATE TABLE results fail-closed.
pub(super) async fn preflight(
    pool: &MySqlPool,
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let table = TABLES[0];
    if !super::schema_table_exists(pool, table).await? {
        if applied_versions.contains(&VERSION) {
            return Err(MigrationError::Failed(format!(
                "source bootstrap migration {VERSION} is recorded but table {table} is missing"
            )));
        }
        if !pending_exact_creator(applied_versions, migrations) {
            return Err(MigrationError::Failed(format!(
                "source bootstrap preflight found missing table {table} without the exact pending migration {VERSION}"
            )));
        }
        return Ok(false);
    }

    super::validate_schema_columns(pool, COLUMN_CONTRACTS).await?;
    super::validate_indexes(pool, INDEXES).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn source_bootstrap_use_pending_creator_is_source_pinned() {
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("source bootstrap migration embedded")
            .clone();
        let migrations = vec![migration.clone()];
        let applied = std::collections::HashSet::new();
        assert!(pending_exact_creator(&applied, &migrations));

        let mut applied = std::collections::HashSet::new();
        applied.insert(VERSION);
        assert!(!pending_exact_creator(&applied, &migrations));

        let mut tampered = migration;
        tampered.sql = format!("{}\nSELECT 1;", tampered.sql).into();
        assert!(!pending_exact_creator(
            &std::collections::HashSet::new(),
            &[tampered]
        ));
        assert!(!pending_exact_creator(
            &std::collections::HashSet::new(),
            &[]
        ));
    }

    #[test]
    fn source_bootstrap_use_exact_artifact_contract_is_registered() {
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("source bootstrap migration embedded");
        let artifact = super::super::exact_migration_artifact_contract(migration)
            .expect("source bootstrap migration exact artifact contract");
        let source =
            include_str!("../../migrations/20261107000014_authority_source_bootstrap_use.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        assert!(super::super::migration_requires_exact_artifact_parse(
            VERSION
        ));
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        for table in TABLES {
            assert!(super::super::migration_defines_table(migration, table));
        }
        for (table, column) in COLUMNS {
            assert!(super::super::migration_defines_column(
                migration, table, column
            ));
        }
        for (table, index, columns, unique) in INDEXES {
            assert!(super::super::migration_defines_index(
                migration, table, index, columns, *unique
            ));
        }
    }

    #[test]
    fn source_bootstrap_use_metadata_contract_rejects_drift() {
        use super::super::schema_column_contract_matches;

        for column in COLUMN_CONTRACTS {
            assert!(schema_column_contract_matches(
                column.name,
                column.column_type,
                "NO",
                column.default,
                column.charset,
                column.collation,
                column,
            ));
            for (column_type, nullable, default, charset, collation) in [
                ("VARCHAR(1)", "NO", None, None, None),
                (
                    column.column_type,
                    "YES",
                    column.default,
                    column.charset,
                    column.collation,
                ),
                (
                    column.column_type,
                    "NO",
                    Some("0"),
                    column.charset,
                    column.collation,
                ),
                (
                    column.column_type,
                    "NO",
                    column.default,
                    Some("utf8mb4"),
                    column.collation,
                ),
                (
                    column.column_type,
                    "NO",
                    column.default,
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
    fn source_bootstrap_use_existing_table_path_is_exact_only() {
        let source = include_str!("authority_source_bootstrap_use.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("validate_schema_columns(pool, COLUMN_CONTRACTS).await?"));
        assert!(production.contains("validate_indexes(pool, INDEXES).await?"));
        assert!(!production.contains("pending_column_is_defined"));
        assert!(production.contains(
            "source bootstrap migration {VERSION} is recorded but table {table} is missing"
        ));
    }
}
