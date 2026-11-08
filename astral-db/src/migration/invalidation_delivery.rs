//! Exact artifact and schema contract for recipient-specific invalidation delivery.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000009;
pub(super) const SOURCE_SHA384: &str = "d98ed7157b4e35ef1f9c58f48e86f7f4eb1be610f130c4864b09c81ca6440e47106a08eff950f3ed77e1d177ca95f517";
pub(super) const TABLES: &[&str] = &[
    "authorization_invalidation_delivery_journal",
    "authorization_invalidation_delivery_leg",
    "authorization_invalidation_delivery_receipt",
];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    (TABLES[0], "message_id"),
    (TABLES[0], "operation_id"),
    (TABLES[0], "source_database_id"),
    (TABLES[0], "envelope_sha256"),
    (TABLES[0], "payload_sha256"),
    (TABLES[0], "envelope_json"),
    (TABLES[0], "message_type"),
    (TABLES[0], "schema_version"),
    (TABLES[0], "origin_region"),
    (TABLES[0], "target_region"),
    (TABLES[0], "ordering_key"),
    (TABLES[0], "tenant_id"),
    (TABLES[0], "authority_metadata_json"),
    (TABLES[0], "roster_version"),
    (TABLES[0], "recipient_roster_json"),
    (TABLES[0], "recipient_roster_sha256"),
    (TABLES[0], "status"),
    (TABLES[0], "created_at"),
    (TABLES[0], "updated_at"),
    (TABLES[1], "message_id"),
    (TABLES[1], "leg_id"),
    (TABLES[1], "recipient_region"),
    (TABLES[1], "recipient_node"),
    (TABLES[1], "recipient_database_id"),
    (TABLES[1], "transport_kind"),
    (TABLES[1], "endpoint"),
    (TABLES[1], "peer_certificate_sha256"),
    (TABLES[1], "envelope_sha256"),
    (TABLES[1], "payload_sha256"),
    (TABLES[1], "status"),
    (TABLES[1], "attempts"),
    (TABLES[1], "generation"),
    (TABLES[1], "lease_owner"),
    (TABLES[1], "lease_token"),
    (TABLES[1], "lease_expires_at"),
    (TABLES[1], "last_error"),
    (TABLES[1], "created_at"),
    (TABLES[1], "updated_at"),
    (TABLES[2], "message_id"),
    (TABLES[2], "leg_id"),
    (TABLES[2], "target_database_id"),
    (TABLES[2], "target_region"),
    (TABLES[2], "target_node"),
    (TABLES[2], "envelope_sha256"),
    (TABLES[2], "payload_sha256"),
    (TABLES[2], "operation_id"),
    (TABLES[2], "message_type"),
    (TABLES[2], "schema_version"),
    (TABLES[2], "origin_region"),
    (TABLES[2], "ordering_key"),
    (TABLES[2], "tenant_id"),
    (TABLES[2], "authority_metadata_json"),
    (TABLES[2], "receipt_status"),
    (TABLES[2], "received_at"),
    (TABLES[2], "updated_at"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (TABLES[0], "PRIMARY", &["message_id"], true),
    (
        TABLES[0],
        "idx_aidj_created",
        &["created_at", "message_id"],
        false,
    ),
    (TABLES[0], "idx_aidj_operation", &["operation_id"], false),
    (TABLES[1], "PRIMARY", &["message_id", "leg_id"], true),
    (
        TABLES[1],
        "idx_aidl_state_created",
        &["status", "created_at", "message_id"],
        false,
    ),
    (
        TABLES[1],
        "idx_aidl_recipient_state",
        &[
            "recipient_database_id",
            "recipient_region",
            "recipient_node",
            "status",
        ],
        false,
    ),
    (TABLES[2], "PRIMARY", &["message_id", "leg_id"], true),
    (
        TABLES[2],
        "idx_aidr_target",
        &[
            "target_database_id",
            "target_region",
            "target_node",
            "receipt_status",
        ],
        false,
    ),
];

const fn text(
    table: &'static str,
    name: &'static str,
    ty: &'static str,
    ascii: bool,
    required: bool,
    default: Option<&'static str>,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name,
        column_type: ty,
        not_null: required,
        default,
        charset: Some(if ascii { "ascii" } else { "utf8mb4" }),
        collation: Some(if ascii { "ascii_bin" } else { "utf8mb4_bin" }),
    }
}

pub(super) const CONSTRAINTS: &[super::ExactMigrationConstraintContract] = &[
    super::ExactMigrationConstraintContract::ForeignKey {
        table: TABLES[1],
        name: "fk_aidl_journal",
        columns: &["message_id"],
        referenced_table: TABLES[0],
        referenced_columns: &["message_id"],
        on_delete: "RESTRICT",
    },
    super::ExactMigrationConstraintContract::ForeignKey {
        table: TABLES[2],
        name: "fk_aidr_leg",
        columns: &["message_id", "leg_id"],
        referenced_table: TABLES[1],
        referenced_columns: &["message_id", "leg_id"],
        on_delete: "RESTRICT",
    },
];

pub(super) const FOREIGN_KEYS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        TABLES[1],
        "fk_aidl_journal",
        "message_id",
        TABLES[0],
        "message_id",
        "RESTRICT",
    ),
    (
        TABLES[2],
        "fk_aidr_leg",
        "message_id",
        TABLES[1],
        "message_id",
        "RESTRICT",
    ),
    (
        TABLES[2],
        "fk_aidr_leg",
        "leg_id",
        TABLES[1],
        "leg_id",
        "RESTRICT",
    ),
];

pub(super) async fn validate_runtime_foreign_keys(
    pool: &sqlx::MySqlPool,
) -> Result<(), super::MigrationError> {
    for table in TABLES {
        let expected: Vec<_> = FOREIGN_KEYS
            .iter()
            .copied()
            .filter(|(owner, ..)| owner == table)
            .collect();
        if !super::schema_foreign_keys_match(pool, table, &expected).await? {
            return Err(super::MigrationError::Failed(format!(
                "invalidation delivery foreign key contract differs for {table}"
            )));
        }
    }
    Ok(())
}

pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    text(TABLES[0], "message_id", "VARCHAR(128)", false, true, None),
    text(TABLES[0], "operation_id", "VARCHAR(128)", false, true, None),
    text(
        TABLES[0],
        "source_database_id",
        "VARCHAR(128)",
        true,
        true,
        None,
    ),
    incremental_scalar_column(TABLES[0], "envelope_sha256", "BINARY(32)", true, None),
    text(TABLES[0], "payload_sha256", "CHAR(64)", true, true, None),
    text(TABLES[0], "envelope_json", "MEDIUMTEXT", false, true, None),
    text(TABLES[0], "message_type", "VARCHAR(64)", true, true, None),
    incremental_scalar_column(TABLES[0], "schema_version", "INT", true, None),
    text(TABLES[0], "origin_region", "VARCHAR(64)", true, true, None),
    text(TABLES[0], "target_region", "VARCHAR(64)", true, false, None),
    text(
        TABLES[0],
        "ordering_key",
        "VARCHAR(256)",
        false,
        false,
        None,
    ),
    incremental_scalar_column(TABLES[0], "tenant_id", "BIGINT", false, None),
    text(
        TABLES[0],
        "authority_metadata_json",
        "MEDIUMTEXT",
        false,
        false,
        None,
    ),
    text(TABLES[0], "roster_version", "VARCHAR(64)", true, true, None),
    text(
        TABLES[0],
        "recipient_roster_json",
        "MEDIUMTEXT",
        false,
        true,
        None,
    ),
    incremental_scalar_column(
        TABLES[0],
        "recipient_roster_sha256",
        "BINARY(32)",
        true,
        None,
    ),
    text(
        TABLES[0],
        "status",
        "VARCHAR(16)",
        true,
        true,
        Some("READY"),
    ),
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
    text(TABLES[1], "message_id", "VARCHAR(128)", false, true, None),
    text(TABLES[1], "leg_id", "CHAR(64)", true, true, None),
    text(
        TABLES[1],
        "recipient_region",
        "VARCHAR(64)",
        true,
        true,
        None,
    ),
    text(
        TABLES[1],
        "recipient_node",
        "VARCHAR(128)",
        true,
        true,
        None,
    ),
    text(
        TABLES[1],
        "recipient_database_id",
        "VARCHAR(128)",
        true,
        true,
        None,
    ),
    text(TABLES[1], "transport_kind", "VARCHAR(16)", true, true, None),
    text(TABLES[1], "endpoint", "VARCHAR(2048)", true, false, None),
    text(
        TABLES[1],
        "peer_certificate_sha256",
        "CHAR(64)",
        true,
        false,
        None,
    ),
    incremental_scalar_column(TABLES[1], "envelope_sha256", "BINARY(32)", true, None),
    text(TABLES[1], "payload_sha256", "CHAR(64)", true, true, None),
    text(
        TABLES[1],
        "status",
        "VARCHAR(24)",
        true,
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(TABLES[1], "attempts", "INT", true, Some("0")),
    incremental_scalar_column(TABLES[1], "generation", "BIGINT", true, Some("0")),
    text(TABLES[1], "lease_owner", "VARCHAR(128)", true, false, None),
    text(TABLES[1], "lease_token", "CHAR(36)", true, false, None),
    incremental_scalar_column(TABLES[1], "lease_expires_at", "DATETIME(6)", false, None),
    text(TABLES[1], "last_error", "VARCHAR(512)", false, false, None),
    incremental_scalar_column(
        TABLES[1],
        "created_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
    incremental_scalar_column(
        TABLES[1],
        "updated_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
    text(TABLES[2], "message_id", "VARCHAR(128)", false, true, None),
    text(TABLES[2], "leg_id", "CHAR(64)", true, true, None),
    text(
        TABLES[2],
        "target_database_id",
        "VARCHAR(128)",
        true,
        true,
        None,
    ),
    text(TABLES[2], "target_region", "VARCHAR(64)", true, true, None),
    text(TABLES[2], "target_node", "VARCHAR(128)", true, true, None),
    incremental_scalar_column(TABLES[2], "envelope_sha256", "BINARY(32)", true, None),
    text(TABLES[2], "payload_sha256", "CHAR(64)", true, true, None),
    text(TABLES[2], "operation_id", "VARCHAR(128)", false, true, None),
    text(TABLES[2], "message_type", "VARCHAR(64)", true, true, None),
    incremental_scalar_column(TABLES[2], "schema_version", "INT", true, None),
    text(TABLES[2], "origin_region", "VARCHAR(64)", true, true, None),
    text(
        TABLES[2],
        "ordering_key",
        "VARCHAR(256)",
        false,
        false,
        None,
    ),
    incremental_scalar_column(TABLES[2], "tenant_id", "BIGINT", false, None),
    text(
        TABLES[2],
        "authority_metadata_json",
        "MEDIUMTEXT",
        false,
        false,
        None,
    ),
    text(TABLES[2], "receipt_status", "VARCHAR(16)", true, true, None),
    incremental_scalar_column(
        TABLES[2],
        "received_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
    incremental_scalar_column(
        TABLES[2],
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
    fn delivery_journal_schema_is_registered_exactly() {
        let source =
            include_str!("../../migrations/20261107000009_invalidation_delivery_journal.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|m| m.version == VERSION)
            .unwrap();
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
    }
}
