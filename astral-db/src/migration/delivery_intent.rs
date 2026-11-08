//! Exact schema contract for the shared delivery intent owner.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000003;
pub(super) const SOURCE_SHA384: &str = "b14b1f46858cbd195eb4f8f9350c2efca5e66d0548b381ba35379fd87ce265f4aafb000a1c2ebd3093be456b481ba5c2";
pub(super) const TABLES: &[&str] = &["al_delivery_intent"];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "id"),
    (TABLES[0], "message_id"),
    (TABLES[0], "operation_id"),
    (TABLES[0], "channel_kind"),
    (TABLES[0], "recipient"),
    (TABLES[0], "subject"),
    (TABLES[0], "body_sha256"),
    (TABLES[0], "payload_class"),
    (TABLES[0], "state"),
    (TABLES[0], "attempts"),
    (TABLES[0], "max_attempts"),
    (TABLES[0], "generation"),
    (TABLES[0], "lease_owner"),
    (TABLES[0], "lease_expires_at"),
    (TABLES[0], "provider_reference"),
    (TABLES[0], "last_detail"),
    (TABLES[0], "settled_at"),
    (TABLES[0], "created_at"),
    (TABLES[0], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["id"], true),
    (
        TABLES[0],
        "uq_delivery_intent_message",
        &["message_id"],
        true,
    ),
    (
        TABLES[0],
        "idx_delivery_intent_operation",
        &["operation_id"],
        false,
    ),
    (
        TABLES[0],
        "idx_delivery_intent_state",
        &["state", "lease_expires_at"],
        false,
    ),
];
const fn text(
    name: &'static str,
    ty: &'static str,
    required: bool,
    default: Option<&'static str>,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table: TABLES[0],
        name,
        column_type: ty,
        not_null: required,
        default,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_unicode_ci"),
    }
}
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    incremental_scalar_column(TABLES[0], "id", "BIGINT UNSIGNED", true, None),
    text("message_id", "VARCHAR(64)", true, None),
    text("operation_id", "VARCHAR(192)", true, None),
    text("channel_kind", "VARCHAR(16)", true, None),
    text("recipient", "VARCHAR(2048)", true, None),
    text("subject", "VARCHAR(512)", false, None),
    text("body_sha256", "CHAR(64)", false, None),
    text("payload_class", "VARCHAR(16)", true, Some("STANDARD")),
    text("state", "VARCHAR(16)", true, Some("QUEUED")),
    incremental_scalar_column(TABLES[0], "attempts", "INT", true, Some("0")),
    incremental_scalar_column(TABLES[0], "max_attempts", "INT", true, Some("3")),
    incremental_scalar_column(TABLES[0], "generation", "BIGINT", true, Some("0")),
    text("lease_owner", "VARCHAR(128)", false, None),
    incremental_scalar_column(TABLES[0], "lease_expires_at", "DATETIME(6)", false, None),
    text("provider_reference", "VARCHAR(256)", false, None),
    text("last_detail", "VARCHAR(512)", false, None),
    incremental_scalar_column(TABLES[0], "settled_at", "DATETIME(6)", false, None),
    incremental_scalar_column(
        TABLES[0],
        "created_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
    incremental_scalar_column(
        TABLES[0],
        "updated_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_delivery_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000003_delivery_intent.sql");
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
