//! Exact schema contract for durable cross-replica verification
//! (challenges / one-shot proofs / subject budgets; taskId
//! `global-authority-20261107-verification`).
//!
//! Delivery has no table here by contract: outbox/intent/lease state is owned
//! by the shared `astral_common::delivery` stack
//! (`DeliveryOwner` + `SqlxDeliveryIntentRepository` over `al_delivery_intent`);
//! verification only supplies purpose/target context and a stable operation id.

use super::{incremental_scalar_column, SchemaColumnContract};

pub(super) const VERSION: i64 = 20261107000002;
pub(super) const SOURCE_SHA384: &str = "36ab40e52679444a34337624923c4d08edadfd3d6b4f50b90a8de4fad87149d51e34f18519d2d4c4f2f34e4fb5243099";
pub(super) const TABLES: &[&str] = &[
    "verification_challenge",
    "verification_proof",
    "verification_budget",
];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    // verification_challenge
    ("verification_challenge", "id"),
    ("verification_challenge", "purpose"),
    ("verification_challenge", "target_hash"),
    ("verification_challenge", "code_digest"),
    ("verification_challenge", "operation_id"),
    ("verification_challenge", "attempts"),
    ("verification_challenge", "expires_at"),
    ("verification_challenge", "closed_at"),
    ("verification_challenge", "close_kind"),
    ("verification_challenge", "created_at"),
    // verification_proof
    ("verification_proof", "id"),
    ("verification_proof", "purpose"),
    ("verification_proof", "target_hash"),
    ("verification_proof", "proof_hash"),
    ("verification_proof", "challenge_id"),
    ("verification_proof", "expires_at"),
    ("verification_proof", "consumed_at"),
    ("verification_proof", "consumed_ref"),
    ("verification_proof", "created_at"),
    // verification_budget
    ("verification_budget", "scope"),
    ("verification_budget", "subject_kind"),
    ("verification_budget", "subject_hash"),
    ("verification_budget", "purpose"),
    ("verification_budget", "window_start"),
    ("verification_budget", "hit_count"),
];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("verification_challenge", "PRIMARY", &["id"], true),
    (
        "verification_challenge",
        "uk_vch_operation",
        &["operation_id", "purpose"],
        true,
    ),
    (
        "verification_challenge",
        "idx_vch_open",
        &["target_hash", "purpose", "closed_at", "expires_at"],
        false,
    ),
    (
        "verification_challenge",
        "idx_vch_expires",
        &["expires_at"],
        false,
    ),
    ("verification_proof", "PRIMARY", &["id"], true),
    ("verification_proof", "uk_vpf_hash", &["proof_hash"], true),
    (
        "verification_proof",
        "idx_vpf_open",
        &["purpose", "target_hash", "consumed_at", "expires_at"],
        false,
    ),
    (
        "verification_proof",
        "idx_vpf_expires",
        &["expires_at"],
        false,
    ),
    (
        "verification_proof",
        "idx_vpf_challenge",
        &["challenge_id"],
        false,
    ),
    (
        "verification_budget",
        "PRIMARY",
        &[
            "scope",
            "subject_kind",
            "subject_hash",
            "purpose",
            "window_start",
        ],
        true,
    ),
];
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    // verification_challenge：机器值 VARCHAR 一律 ascii/ascii_bin（purpose 由
    // 注册表常量、operation_id 由字符集校验、close_kind 由仓储常量保证 ASCII）。
    incremental_scalar_column(TABLES[0], "id", "BIGINT UNSIGNED", true, None),
    SchemaColumnContract {
        table: TABLES[0],
        name: "purpose",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[0], "target_hash", "BINARY(32)", true, None),
    incremental_scalar_column(TABLES[0], "code_digest", "BINARY(32)", true, None),
    SchemaColumnContract {
        table: TABLES[0],
        name: "operation_id",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[0], "attempts", "INT UNSIGNED", true, Some("0")),
    incremental_scalar_column(TABLES[0], "expires_at", "DATETIME", true, None),
    incremental_scalar_column(TABLES[0], "closed_at", "DATETIME", false, None),
    SchemaColumnContract {
        table: TABLES[0],
        name: "close_kind",
        column_type: "VARCHAR(16)",
        not_null: false,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(
        TABLES[0],
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // verification_proof：consumed_ref 承载用户名（可能非 ASCII）→ 显式
    // utf8mb4/utf8mb4_bin，保证 live-DB 合同与 MySQL 版本无关。
    incremental_scalar_column(TABLES[1], "id", "BIGINT UNSIGNED", true, None),
    SchemaColumnContract {
        table: TABLES[1],
        name: "purpose",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[1], "target_hash", "BINARY(32)", true, None),
    incremental_scalar_column(TABLES[1], "proof_hash", "BINARY(32)", true, None),
    incremental_scalar_column(TABLES[1], "challenge_id", "BIGINT UNSIGNED", true, None),
    incremental_scalar_column(TABLES[1], "expires_at", "DATETIME", true, None),
    incremental_scalar_column(TABLES[1], "consumed_at", "DATETIME", false, None),
    SchemaColumnContract {
        table: TABLES[1],
        name: "consumed_ref",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_bin"),
    },
    incremental_scalar_column(
        TABLES[1],
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // verification_budget：scope/subject_kind 为仓储常量（ASCII），主键即
    // 跨副本原子预算的行锁边界。
    SchemaColumnContract {
        table: TABLES[2],
        name: "scope",
        column_type: "VARCHAR(8)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    SchemaColumnContract {
        table: TABLES[2],
        name: "subject_kind",
        column_type: "VARCHAR(8)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[2], "subject_hash", "BINARY(32)", true, None),
    SchemaColumnContract {
        table: TABLES[2],
        name: "purpose",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_scalar_column(TABLES[2], "window_start", "DATETIME", true, None),
    incremental_scalar_column(TABLES[2], "hit_count", "INT UNSIGNED", true, Some("0")),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    /// 不可变注册契约：源文件字节哈希、MIGRATOR 注册、解析产物与常量三方
    /// 对牌（对齐 protected_mutation.rs 惯例）。MIGRATOR 注册由 migration.rs
    /// 完成（main 登记本模块后生效）。
    #[test]
    fn exact_verification_schema_is_registered() {
        let source = include_str!("../../migrations/20261107000002_verification_durable.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        let migration = super::super::MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == VERSION)
            .unwrap();
        assert_eq!(source, migration.sql.as_ref());
        let artifact = super::super::exact_migration_artifact_contract(migration).unwrap();
        assert_eq!(artifact.tables, TABLES);
        assert_eq!(artifact.columns, COLUMNS);
        assert_eq!(artifact.indexes, INDEXES);
    }

    /// 列契约内部一致性：每张表的每个声明列都有契约、契约表名必须在 TABLES
    /// 内（防止表/列清单与契约漂移）。
    #[test]
    fn column_contracts_cover_every_declared_column() {
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
        for (contract, (table, name)) in COLUMN_CONTRACTS.iter().zip(COLUMNS) {
            assert_eq!(contract.table, *table);
            assert_eq!(contract.name, *name);
        }
        for table in TABLES {
            for (contract_table, _) in COLUMNS {
                assert!(
                    TABLES.contains(contract_table),
                    "column contract table must be declared"
                );
            }
            assert!(COLUMNS
                .iter()
                .any(|(column_table, _)| *column_table == *table));
        }
    }
}
