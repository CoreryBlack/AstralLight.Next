//! Exact schema contract for the password-reset delivery binding
//! (taskId `authority-v7-peripheral-20261107` post-review fix).
//!
//! The binding columns make every password_reset_token row
//! PENDING-by-construction: consumption joins `al_delivery_intent` (index
//! probe on message_id) and requires, in the password update transaction,
//! `state = 'DELIVERED'` plus BYTE-EXACT equality of both bindings via
//! `CAST(... AS BINARY)` (intent columns are utf8mb4_unicode_ci while the
//! binding columns are ascii_bin; a raw `=` would coerce to case/pad-
//! insensitive matching). Old rows (NULL binding) and rows with a
//! missing/mismatched operation binding can never be consumed; there is no
//! automatic backfill.

use super::SchemaColumnContract;

pub(super) const VERSION: i64 = 20261107000008;
pub(super) const SOURCE_SHA384: &str = "dea249552fe4df09f7189fc84431e16d9cae762005bcb6b0b779be1b02ee4001224a3293047cd8923cdb2eeb40e798b2";
/// ALTER-only migration on a pre-existing table: it defines NO tables (the
/// baseline creator owns `password_reset_token`); declaring one here would
/// fail the exact-artifact source match (no CREATE TABLE artifact exists).
pub(super) const TABLES: &[&str] = &[];
/// The pre-existing table this migration binds (referenced literally because
/// an ALTER-only migration declares no tables of its own).
pub(super) const BOUND_TABLE: &str = "password_reset_token";
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (BOUND_TABLE, "delivery_message_id"),
    (BOUND_TABLE, "operation_id"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[(
    BOUND_TABLE,
    "idx_prt_delivery_message",
    &["delivery_message_id"],
    false,
)];
const fn text_ascii(
    name: &'static str,
    ty: &'static str,
    required: bool,
    default: Option<&'static str>,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table: BOUND_TABLE,
        name,
        column_type: ty,
        not_null: required,
        default,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    }
}
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    text_ascii("delivery_message_id", "VARCHAR(64)", false, None),
    text_ascii("operation_id", "VARCHAR(192)", false, None),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    /// The registered artifact contract must pin the exact additive SQL body:
    /// canonical LF SHA-384 of the migration file (the file is LF-only, so
    /// canonical == raw bytes).
    #[test]
    fn exact_binding_schema_is_registered() {
        let source =
            include_str!("../../migrations/20261107000008_password_reset_delivery_binding.sql");
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
    }

    /// Binding columns are NULLable: legacy rows keep NULL and are refused by
    /// the consumption join (fail-closed, no automatic backfill).
    #[test]
    fn binding_columns_are_nullable_and_ascii() {
        for contract in COLUMN_CONTRACTS {
            match contract.name {
                "delivery_message_id" | "operation_id" => {
                    assert!(!contract.not_null, "{contract:?} must stay NULLable");
                    assert_eq!(contract.charset, Some("ascii"), "{contract:?}");
                    assert_eq!(contract.collation, Some("ascii_bin"), "{contract:?}");
                }
                _ => {}
            }
        }
    }
}
