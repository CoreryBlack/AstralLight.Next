//! V7 source capability consumption schema, separate from historical migrations.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000001;
pub(super) const SOURCE_SHA384: &str =
    "2afb700b41948089beed1471a0bf16916a85ecd85c6f32f8c41404f7ef5be1b54d4a1df9b56b532dfb0b5b75a0614da7";
pub(super) const TABLES: &[&str] = &["authorization_admission_use"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    ("authorization_admission_use", "proof_id"),
    ("authorization_admission_use", "request_nonce"),
    ("authorization_admission_use", "operation_id"),
    ("authorization_admission_use", "event_id"),
    ("authorization_admission_use", "authority_id"),
    ("authorization_admission_use", "authority_term"),
    ("authorization_admission_use", "global_fence_sequence"),
    ("authorization_admission_use", "key_epoch"),
    ("authorization_admission_use", "proof_digest"),
    ("authorization_admission_use", "consumed_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "authorization_admission_use",
        "PRIMARY",
        &["proof_id"],
        true,
    ),
    (
        "authorization_admission_use",
        "uk_aau_request_nonce",
        &["request_nonce"],
        true,
    ),
    (
        "authorization_admission_use",
        "idx_aau_operation_event",
        &["operation_id", "event_id"],
        false,
    ),
];
const fn text_column(
    name: &'static str,
    column_type: &'static str,
    ascii: bool,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table: "authorization_admission_use",
        name,
        column_type,
        not_null: true,
        default: None,
        charset: Some(if ascii { "ascii" } else { "utf8mb4" }),
        collation: if ascii { Some("ascii_bin") } else { None },
    }
}
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    text_column("proof_id", "VARCHAR(128)", true),
    text_column("request_nonce", "VARCHAR(255)", true),
    text_column("operation_id", "VARCHAR(128)", false),
    text_column("event_id", "VARCHAR(128)", false),
    text_column("authority_id", "VARCHAR(128)", false),
    incremental_scalar_column(
        "authorization_admission_use",
        "authority_term",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_admission_use",
        "global_fence_sequence",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_admission_use",
        "key_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_admission_use",
        "proof_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_admission_use",
        "consumed_at",
        "BIGINT",
        true,
        None,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn migration_consumption_identity_is_immutable_and_registered() {
        let source = include_str!("../../migrations/20261107000001_authority_production.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .expect("V7 consumption migration embedded");
        assert_eq!(migration.sql.as_ref(), source);
        let artifact = super::super::exact_migration_artifact_contract(migration)
            .expect("V7 consumption migration exact contract");
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
    }
}
