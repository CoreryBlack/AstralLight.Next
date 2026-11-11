//! Exact contract for the CertifiedMemory completion operation-id width expansion.

use super::{Migration, MigrationError, SchemaColumnContract};
use sqlx::MySqlPool;

pub(super) const VERSION: i64 = 20261109000002;
pub(super) const SOURCE_SHA384: &str = "c1ccf0a25b9ffcc561b6e466ca1cc076227201788ce44b52f7c9b46b5aed5cfd242ed6913fa39bcd621d5053518252a6";
pub(super) const TABLES: &[&str] = &[];
pub(super) const COLUMNS: &[(&str, &str)] =
    &[("authority_certified_memory_completion", "operation_id")];
pub(super) const INDEXES: &[(&str, &str, &[&str], bool)] = &[];

const BASELINE: SchemaColumnContract = SchemaColumnContract {
    table: "authority_certified_memory_completion",
    name: "operation_id",
    column_type: "VARCHAR(64)",
    not_null: true,
    default: None,
    charset: Some("ascii"),
    collation: Some("ascii_bin"),
};

pub(super) const COLUMN_CONTRACTS: &[SchemaColumnContract] = &[SchemaColumnContract {
    table: "authority_certified_memory_completion",
    name: "operation_id",
    column_type: "VARCHAR(128)",
    not_null: true,
    default: None,
    charset: Some("ascii"),
    collation: Some("ascii_bin"),
}];

fn pending_exact_migration(
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
) -> bool {
    !applied_versions.contains(&VERSION)
        && migrations.iter().any(|migration| {
            migration.version == VERSION
                && super::migration_matches_known_source(migration)
                && super::migration_defines_existing_column(
                    migration,
                    BASELINE.table,
                    BASELINE.name,
                )
        })
}

fn classify(column_type: &str, nullable: &str, charset: &str, collation: &str) -> &'static str {
    match (column_type, nullable, charset, collation) {
        ("VARCHAR(64)", "NO", "ascii", "ascii_bin") => "legacy",
        ("VARCHAR(128)", "NO", "ascii", "ascii_bin") => "final",
        _ => "unknown",
    }
}

pub(super) async fn preflight(
    pool: &MySqlPool,
    applied_versions: &std::collections::HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    if !super::schema_table_exists(pool, BASELINE.table).await? {
        if applied_versions.contains(&VERSION) {
            return Err(MigrationError::Failed(
                "CertifiedMemory operation-width migration is recorded but its table is missing"
                    .into(),
            ));
        }
        return Ok(false);
    }
    let metadata: Option<super::SchemaColumnMetadataRow> =
        sqlx::query_as(super::SCHEMA_COLUMN_METADATA_SQL)
            .bind(BASELINE.table)
            .bind(BASELINE.name)
            .fetch_optional(pool)
            .await
            .map_err(|error| {
                MigrationError::Failed(format!("inspect CertifiedMemory operation width: {error}"))
            })?;
    let Some((name, column_type, nullable, default, charset, collation)) = metadata else {
        return Err(MigrationError::Failed(
            "CertifiedMemory operation_id column is missing".into(),
        ));
    };
    let name = super::metadata_text("COLUMN_NAME", &name, BASELINE.table, BASELINE.name)?;
    let column_type =
        super::metadata_text("COLUMN_TYPE", &column_type, BASELINE.table, BASELINE.name)?;
    let nullable = super::metadata_text("IS_NULLABLE", &nullable, BASELINE.table, BASELINE.name)?;
    let default = default
        .as_deref()
        .map(|value| super::metadata_text("COLUMN_DEFAULT", value, BASELINE.table, BASELINE.name))
        .transpose()?;
    let charset = super::metadata_optional_name(
        "CHARACTER_SET_NAME",
        charset.as_deref(),
        BASELINE.table,
        BASELINE.name,
    )?;
    let collation = super::metadata_optional_name(
        "COLLATION_NAME",
        collation.as_deref(),
        BASELINE.table,
        BASELINE.name,
    )?;
    if name != BASELINE.name || default.is_some() {
        return Err(MigrationError::Failed(
            "CertifiedMemory operation_id metadata is not canonical".into(),
        ));
    }
    let state = classify(
        &column_type,
        &nullable,
        charset.as_deref().unwrap_or_default(),
        collation.as_deref().unwrap_or_default(),
    );
    match state {
        "final" => Ok(true),
        "legacy"
            if !applied_versions.contains(&VERSION)
                && pending_exact_migration(applied_versions, migrations) =>
        {
            Ok(false)
        }
        "legacy" => Err(MigrationError::Failed(
            "CertifiedMemory operation_id remains VARCHAR(64) after width migration".into(),
        )),
        _ => Err(MigrationError::Failed(
            "CertifiedMemory operation_id has unknown metadata".into(),
        )),
    }
}

pub(super) async fn validate_runtime_columns(pool: &MySqlPool) -> Result<(), MigrationError> {
    super::validate_schema_columns(pool, COLUMN_CONTRACTS).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    #[test]
    fn exact_source_hash_is_pinned() {
        let source =
            include_str!("../../migrations/20261109000002_certified_memory_operation_width.sql");
        assert_eq!(
            format!("{:x}", Sha384::digest(source.as_bytes())),
            SOURCE_SHA384
        );
    }

    #[test]
    fn only_legacy_and_final_shapes_are_accepted() {
        assert_eq!(
            classify("VARCHAR(64)", "NO", "ascii", "ascii_bin"),
            "legacy"
        );
        assert_eq!(
            classify("VARCHAR(128)", "NO", "ascii", "ascii_bin"),
            "final"
        );
        assert_eq!(
            classify("VARCHAR(127)", "NO", "ascii", "ascii_bin"),
            "unknown"
        );
        assert_eq!(
            classify("VARCHAR(128)", "YES", "ascii", "ascii_bin"),
            "unknown"
        );
    }
}
