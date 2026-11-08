//! Exact artifact contract for V7 quorum evidence projections.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000005;
pub(super) const SOURCE_SHA384: &str = "2a7ce522158a9e189445c1bd8b1460b4c330d093d3bed6e8e3bcb743c475b4c744eebaa7bb8b96b7b87911c04d50efd7";
pub(super) const TABLES: &[&str] = &[
    "authorization_global_projection",
    "authorization_scope_certificate",
    "authorization_request_proof",
    "authorization_source_reservation",
];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "projection_id"),
    (TABLES[0], "authority_id"),
    (TABLES[0], "authority_term"),
    (TABLES[0], "global_fence_sequence"),
    (TABLES[0], "key_epoch"),
    (TABLES[0], "chain_digest"),
    (TABLES[0], "frontier_json"),
    (TABLES[0], "observed_at"),
    (TABLES[1], "scope_hash"),
    (TABLES[1], "certificate_hash"),
    (TABLES[1], "certificate_json"),
    (TABLES[1], "observed_at"),
    (TABLES[2], "proof_id"),
    (TABLES[2], "request_nonce"),
    (TABLES[2], "scope_hash"),
    (TABLES[2], "certificate_hash"),
    (TABLES[2], "request_digest"),
    (TABLES[2], "proof_json"),
    (TABLES[2], "expires_at"),
    (TABLES[3], "operation_id"),
    (TABLES[3], "proof_id"),
    (TABLES[3], "request_digest"),
    (TABLES[3], "reservation_json"),
    (TABLES[3], "disposition"),
    (TABLES[3], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["projection_id"], true),
    (TABLES[1], "PRIMARY", &["scope_hash"], true),
    (TABLES[1], "uk_asc_certificate", &["certificate_hash"], true),
    (TABLES[2], "PRIMARY", &["proof_id"], true),
    (TABLES[2], "uk_arp_nonce", &["request_nonce"], true),
    (TABLES[2], "idx_arp_expiry", &["expires_at"], false),
    (TABLES[3], "PRIMARY", &["operation_id"], true),
    (TABLES[3], "uk_asr_proof", &["proof_id"], true),
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
    scalar(TABLES[0], "projection_id", "BIGINT"),
    ascii(TABLES[0], "authority_id", "VARCHAR(128)"),
    scalar(TABLES[0], "authority_term", "BIGINT"),
    scalar(TABLES[0], "global_fence_sequence", "BIGINT"),
    scalar(TABLES[0], "key_epoch", "BIGINT"),
    scalar(TABLES[0], "chain_digest", "BINARY(32)"),
    scalar(TABLES[0], "frontier_json", "JSON"),
    scalar(TABLES[0], "observed_at", "BIGINT"),
    scalar(TABLES[1], "scope_hash", "BINARY(32)"),
    scalar(TABLES[1], "certificate_hash", "BINARY(32)"),
    scalar(TABLES[1], "certificate_json", "JSON"),
    scalar(TABLES[1], "observed_at", "BIGINT"),
    ascii(TABLES[2], "proof_id", "VARCHAR(128)"),
    ascii(TABLES[2], "request_nonce", "VARCHAR(128)"),
    scalar(TABLES[2], "scope_hash", "BINARY(32)"),
    scalar(TABLES[2], "certificate_hash", "BINARY(32)"),
    scalar(TABLES[2], "request_digest", "BINARY(32)"),
    scalar(TABLES[2], "proof_json", "JSON"),
    scalar(TABLES[2], "expires_at", "BIGINT"),
    ascii(TABLES[3], "operation_id", "VARCHAR(64)"),
    ascii(TABLES[3], "proof_id", "VARCHAR(128)"),
    scalar(TABLES[3], "request_digest", "BINARY(32)"),
    scalar(TABLES[3], "reservation_json", "JSON"),
    ascii(TABLES[3], "disposition", "VARCHAR(32)"),
    scalar(TABLES[3], "updated_at", "BIGINT"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_quorum_projection_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000005_authority_projections.sql");
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
