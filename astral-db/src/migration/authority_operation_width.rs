//! Exact contract and fail-closed runtime seam for V7 operation-id width.
//!
//! The six creator contracts remain immutable at VARCHAR(64).  This child owns
//! only the ALTER migration that widens those operation identities to 128.
//! `COLUMN_CONTRACTS` is the resulting runtime contract; `BASELINE_COLUMN_CONTRACTS`
//! is used only to recognize the exact pre-migration state during preflight.

use super::{Migration, MigrationError, SchemaColumnContract};
use sqlx::MySqlPool;

pub(super) const VERSION: i64 = 20261107000013;
pub(super) const SOURCE_SHA384: &str = "98e4740842861260789cb40e577e8a3f72ed24c53829588451cd2c51e6cc1bb6dedbef279db720cf26bcd3343a7e0ab7";

/// ALTER-only migrations declare no created tables.  The physical table for
/// the historical operation-audit correlation is async_operation_item.
pub(super) const TABLES: &[&str] = &[];
pub(super) const COLUMNS: &[(&str, &str)] = &[
    ("verification_challenge", "operation_id"),
    ("protected_mutation_operation", "operation_id"),
    ("authorization_source_reservation", "operation_id"),
    ("authority_source_outcome", "operation_id"),
    ("authorization_scope_certificate_history", "operation_id"),
    ("async_operation_item", "operation_id"),
];

/// No index is created by the SQL artifact.  Existing indexes are listed in
/// PRESERVED_INDEXES and are validated by preflight/runtime integration.
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[];
pub(super) const PRESERVED_INDEXES: &[(&str, &str, &[&str], bool)] = &[
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
    (
        "protected_mutation_operation",
        "PRIMARY",
        &["operation_id", "resource"],
        true,
    ),
    (
        "protected_mutation_operation",
        "idx_pmo_created",
        &["created_at"],
        false,
    ),
    (
        "authorization_source_reservation",
        "PRIMARY",
        &["operation_id"],
        true,
    ),
    (
        "authorization_source_reservation",
        "uk_asr_proof",
        &["proof_id"],
        true,
    ),
    (
        "authority_source_outcome",
        "PRIMARY",
        &["reservation_id"],
        true,
    ),
    (
        "authority_source_outcome",
        "uk_aso_proof",
        &["admission_proof_id"],
        true,
    ),
    (
        "authority_source_outcome",
        "idx_aso_status_lease",
        &["status", "lease_until"],
        false,
    ),
    (
        "authority_source_outcome",
        "idx_aso_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_scope_certificate_history",
        "PRIMARY",
        &["certificate_hash"],
        true,
    ),
    (
        "authorization_scope_certificate_history",
        "idx_asch_scope_order",
        &["scope_hash", "authority_term", "global_fence_sequence"],
        false,
    ),
    (
        "authorization_scope_certificate_history",
        "idx_asch_reservation",
        &["reservation_id", "operation_id"],
        false,
    ),
    (
        "async_operation_item",
        "PRIMARY",
        &["task_id", "card_id"],
        true,
    ),
    (
        "async_operation_item",
        "uk_async_operation_item_operation",
        &["operation_id"],
        true,
    ),
    (
        "async_operation_item",
        "idx_async_operation_item_status",
        &["task_id", "status", "card_id"],
        false,
    ),
];

const BASELINE_CREATORS: &[(&str, i64)] = &[
    ("verification_challenge", 20261107000002),
    ("protected_mutation_operation", 20261107000004),
    ("authorization_source_reservation", 20261107000005),
    ("authority_source_outcome", 20261107000006),
    ("authorization_scope_certificate_history", 20261107000007),
    // The historical operation_audit_correlation migration creates this table.
    ("async_operation_item", 20261003000002),
];

const fn ascii_contract(table: &'static str, ty: &'static str) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name: "operation_id",
        column_type: ty,
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    }
}

const fn utf8mb4_contract(table: &'static str, ty: &'static str) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name: "operation_id",
        column_type: ty,
        not_null: true,
        default: None,
        charset: Some("utf8mb4"),
        collation: Some("utf8mb4_unicode_ci"),
    }
}

pub(super) const BASELINE_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    ascii_contract("verification_challenge", "VARCHAR(64)"),
    ascii_contract("protected_mutation_operation", "VARCHAR(64)"),
    ascii_contract("authorization_source_reservation", "VARCHAR(64)"),
    ascii_contract("authority_source_outcome", "VARCHAR(64)"),
    ascii_contract("authorization_scope_certificate_history", "VARCHAR(64)"),
    utf8mb4_contract("async_operation_item", "VARCHAR(64)"),
];

/// Resulting live schema contract after migration 13.
pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    ascii_contract("verification_challenge", "VARCHAR(128)"),
    ascii_contract("protected_mutation_operation", "VARCHAR(128)"),
    ascii_contract("authorization_source_reservation", "VARCHAR(128)"),
    ascii_contract("authority_source_outcome", "VARCHAR(128)"),
    ascii_contract("authorization_scope_certificate_history", "VARCHAR(128)"),
    utf8mb4_contract("async_operation_item", "VARCHAR(128)"),
];
pub(super) const RUNTIME_COLUMN_CONTRACTS: &[SchemaColumnContract] = COLUMN_CONTRACTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WidthState {
    Legacy64,
    Final128,
    Unknown,
}

fn classify_metadata(
    name: &str,
    column_type: &str,
    nullable: &str,
    default: Option<&str>,
    charset: Option<&str>,
    collation: Option<&str>,
    contracts: (&SchemaColumnContract, &SchemaColumnContract),
) -> WidthState {
    let (baseline, runtime) = contracts;
    if super::schema_column_contract_matches(
        name,
        column_type,
        nullable,
        default,
        charset,
        collation,
        baseline,
    ) {
        return WidthState::Legacy64;
    }
    if super::schema_column_contract_matches(
        name,
        column_type,
        nullable,
        default,
        charset,
        collation,
        runtime,
    ) {
        return WidthState::Final128;
    }
    WidthState::Unknown
}

fn pending_exact_width_migration(
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
    table: &str,
    column: &str,
) -> bool {
    !applied_versions.contains(&VERSION)
        && migrations.iter().any(|migration| {
            migration.version == VERSION
                && super::migration_matches_known_source(migration)
                && super::migration_defines_existing_column(migration, table, column)
        })
}

fn pending_exact_creator(
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
    table: &str,
) -> bool {
    let Some((_, version)) = BASELINE_CREATORS
        .iter()
        .find(|(candidate, _)| *candidate == table)
    else {
        return false;
    };
    !applied_versions.contains(version)
        && migrations.iter().any(|migration| {
            migration.version == *version
                && super::migration_matches_known_source(migration)
                && super::migration_defines_table(migration, table)
        })
}

async fn inspect_width_state(
    pool: &MySqlPool,
    baseline: &SchemaColumnContract,
    runtime: &SchemaColumnContract,
) -> Result<WidthState, MigrationError> {
    let metadata: Option<super::SchemaColumnMetadataRow> =
        sqlx::query_as(super::SCHEMA_COLUMN_METADATA_SQL)
            .bind(baseline.table)
            .bind(baseline.name)
            .fetch_optional(pool)
            .await
            .map_err(|error| {
                MigrationError::Failed(format!(
                    "inspect operation width {}.{}: {error}",
                    baseline.table, baseline.name
                ))
            })?;
    let Some((name, column_type, nullable, default, charset, collation)) = metadata else {
        return Err(MigrationError::Failed(format!(
            "operation width preflight found missing {}.{}",
            baseline.table, baseline.name
        )));
    };
    let name = super::metadata_text("COLUMN_NAME", &name, baseline.table, baseline.name)?;
    let column_type =
        super::metadata_text("COLUMN_TYPE", &column_type, baseline.table, baseline.name)?;
    let nullable = super::metadata_text("IS_NULLABLE", &nullable, baseline.table, baseline.name)?;
    let default = default
        .as_deref()
        .map(|value| super::metadata_text("COLUMN_DEFAULT", value, baseline.table, baseline.name))
        .transpose()?;
    let charset = super::metadata_optional_name(
        "CHARACTER_SET_NAME",
        charset.as_deref(),
        baseline.table,
        baseline.name,
    )?;
    let collation = super::metadata_optional_name(
        "COLLATION_NAME",
        collation.as_deref(),
        baseline.table,
        baseline.name,
    )?;
    Ok(classify_metadata(
        &name,
        &column_type,
        &nullable,
        default.as_deref(),
        charset.as_deref(),
        collation.as_deref(),
        (baseline, runtime),
    ))
}

/// Preflight distinguishes exact legacy, exact final, and unknown metadata.
/// Legacy is allowed only while this source-pinned migration is pending;
/// after VERSION is recorded, legacy state is always rejected.
pub(super) async fn preflight(
    pool: &MySqlPool,
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let mut complete = true;
    for (baseline, runtime) in BASELINE_COLUMN_CONTRACTS
        .iter()
        .zip(RUNTIME_COLUMN_CONTRACTS)
    {
        let table_exists = super::schema_table_exists(pool, baseline.table).await?;
        if !table_exists {
            if applied_versions.contains(&VERSION) {
                return Err(MigrationError::Failed(format!(
                    "operation width migration {VERSION} is recorded but target table {} is missing",
                    baseline.table
                )));
            }
            complete = false;
            if !pending_exact_creator(applied_versions, migrations, baseline.table) {
                return Err(MigrationError::Failed(format!(
                    "operation width preflight found missing table {} without its exact pending creator",
                    baseline.table
                )));
            }
            continue;
        }
        if !super::schema_column_exists(pool, baseline.table, baseline.name).await? {
            return Err(MigrationError::Failed(format!(
                "operation width preflight found missing existing column {}.{}; creator migrations cannot repair a partial table",
                baseline.table, baseline.name
            )));
        }
        let state = inspect_width_state(pool, baseline, runtime).await?;
        match state {
            WidthState::Final128 => {}
            WidthState::Legacy64 => {
                if applied_versions.contains(&VERSION) {
                    return Err(MigrationError::Failed(format!(
                        "operation width migration {VERSION} is recorded but {}.{} remains VARCHAR(64)",
                        baseline.table, baseline.name
                    )));
                }
                if !pending_exact_width_migration(
                    applied_versions,
                    migrations,
                    baseline.table,
                    baseline.name,
                ) {
                    return Err(MigrationError::Failed(format!(
                        "legacy operation width {}.{} is accepted only with the pending exact migration {VERSION}",
                        baseline.table, baseline.name
                    )));
                }
                complete = false;
            }
            WidthState::Unknown => {
                return Err(MigrationError::Failed(format!(
                    "operation width preflight found unknown metadata at {}.{}",
                    baseline.table, baseline.name
                )));
            }
        }
        let indexes: Vec<(&str, &str, &[&str], bool)> = PRESERVED_INDEXES
            .iter()
            .filter(|(table, _, _, _)| *table == baseline.table)
            .copied()
            .collect();
        super::validate_indexes(pool, &indexes).await?;
    }
    Ok(complete)
}

/// Resolve a historical creator contract to the V7 runtime width.  Main uses
/// this seam in each existing runtime validator, including the review runtime
/// validator for async_operation_item.operation_id.
pub(super) fn resolved_runtime_columns(
    base_contracts: &[SchemaColumnContract],
) -> Vec<SchemaColumnContract> {
    base_contracts
        .iter()
        .map(|base| {
            RUNTIME_COLUMN_CONTRACTS
                .iter()
                .find(|runtime| runtime.table == base.table && runtime.name == base.name)
                .copied()
                .unwrap_or(*base)
        })
        .collect()
}

pub(super) async fn validate_runtime_columns(
    pool: &MySqlPool,
    base_contracts: &[SchemaColumnContract],
) -> Result<(), MigrationError> {
    let resolved = resolved_runtime_columns(base_contracts);
    super::validate_schema_columns(pool, &resolved).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_source_and_artifact_contract_are_pinned() {
        let source = include_str!("../../migrations/20261107000013_authority_operation_width.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
        assert!(TABLES.is_empty());
        assert_eq!(COLUMNS.len(), 6);
        assert!(INDEXES.is_empty());
        assert_eq!(COLUMN_CONTRACTS.len(), COLUMNS.len());
        assert_eq!(PRESERVED_INDEXES.len(), 18);
    }

    #[test]
    fn historical_audit_name_resolves_to_async_operation_item() {
        assert_eq!(COLUMNS[5], ("async_operation_item", "operation_id"));
        assert!(
            BASELINE_CREATORS
                .iter()
                .any(|(table, version)| *table == "async_operation_item"
                    && *version == 20261003000002)
        );
        assert!(PRESERVED_INDEXES
            .iter()
            .any(|(table, index, columns, unique)| {
                *table == "async_operation_item"
                    && *index == "uk_async_operation_item_operation"
                    && *columns == ["operation_id"]
                    && *unique
            }));
    }

    #[test]
    fn exact_legacy_and_final_metadata_are_the_only_accepted_shapes() {
        for expected in BASELINE_COLUMN_CONTRACTS {
            assert_eq!(
                classify_metadata(
                    expected.name,
                    expected.column_type,
                    "NO",
                    None,
                    expected.charset,
                    expected.collation,
                    (
                        expected,
                        RUNTIME_COLUMN_CONTRACTS
                            .iter()
                            .find(|runtime| runtime.table == expected.table)
                            .unwrap()
                    ),
                ),
                WidthState::Legacy64
            );
        }
        for expected in RUNTIME_COLUMN_CONTRACTS {
            let baseline = BASELINE_COLUMN_CONTRACTS
                .iter()
                .find(|baseline| baseline.table == expected.table && baseline.name == expected.name)
                .expect("every runtime operation column must have a legacy baseline");
            assert_eq!(
                classify_metadata(
                    expected.name,
                    expected.column_type,
                    "NO",
                    None,
                    expected.charset,
                    expected.collation,
                    (baseline, expected),
                ),
                WidthState::Final128
            );
        }
    }

    #[test]
    fn unknown_type_charset_collation_nullability_or_default_is_rejected() {
        let expected = &BASELINE_COLUMN_CONTRACTS[0];
        let invalid = [
            ("VARCHAR(63)", "NO", None, Some("ascii"), Some("ascii_bin")),
            ("VARCHAR(64)", "YES", None, Some("ascii"), Some("ascii_bin")),
            (
                "VARCHAR(64)",
                "NO",
                None,
                Some("utf8mb4"),
                Some("utf8mb4_bin"),
            ),
            (
                "VARCHAR(64)",
                "NO",
                None,
                Some("ascii"),
                Some("utf8mb4_bin"),
            ),
            (
                "VARCHAR(64)",
                "NO",
                Some("0"),
                Some("ascii"),
                Some("ascii_bin"),
            ),
        ];
        for (column_type, nullable, default, charset, collation) in invalid {
            assert_eq!(
                classify_metadata(
                    expected.name,
                    column_type,
                    nullable,
                    default,
                    charset,
                    collation,
                    (expected, &RUNTIME_COLUMN_CONTRACTS[0]),
                ),
                WidthState::Unknown
            );
        }
    }

    #[test]
    fn legacy_is_rejected_after_application_and_only_pending_exact_source_allows_it() {
        let pending = std::collections::HashSet::new();
        assert!(!pending.contains(&VERSION));
        assert!(!pending_exact_width_migration(
            &pending,
            &[],
            COLUMNS[0].0,
            COLUMNS[0].1
        ));
        let mut applied = std::collections::HashSet::new();
        applied.insert(VERSION);
        assert!(applied.contains(&VERSION));
        assert!(!pending_exact_width_migration(
            &applied,
            &[],
            COLUMNS[0].0,
            COLUMNS[0].1
        ));
    }

    #[test]
    fn runtime_resolver_replaces_only_the_six_operation_columns() {
        let base = vec![
            BASELINE_COLUMN_CONTRACTS[0],
            SchemaColumnContract {
                table: "unrelated",
                name: "value",
                column_type: "BIGINT",
                not_null: true,
                default: None,
                charset: None,
                collation: None,
            },
        ];
        let resolved = resolved_runtime_columns(&base);
        assert_eq!(resolved[0], RUNTIME_COLUMN_CONTRACTS[0]);
        assert_eq!(resolved[1], base[1]);
    }

    #[test]
    fn every_runtime_column_keeps_the_baseline_nullability_default_and_encoding() {
        for (baseline, runtime) in BASELINE_COLUMN_CONTRACTS
            .iter()
            .zip(RUNTIME_COLUMN_CONTRACTS)
        {
            assert_eq!(baseline.table, runtime.table);
            assert_eq!(baseline.name, runtime.name);
            assert_eq!(baseline.not_null, runtime.not_null);
            assert_eq!(baseline.default, runtime.default);
            assert_eq!(baseline.charset, runtime.charset);
            assert_eq!(baseline.collation, runtime.collation);
            assert_eq!(baseline.column_type, "VARCHAR(64)");
            assert_eq!(runtime.column_type, "VARCHAR(128)");
        }
    }
}
