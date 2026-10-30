use super::*;
use astral_types::AUTHORIZATION_EDITION;

const TABLE: &str = "authorization_projection_manifest";
const INVALID_SEAL_ROW_SQL: &str = "SELECT EXISTS(SELECT 1 FROM authorization_projection_manifest \
    WHERE manifest_digest_version IS NULL OR manifest_digest_version <> ? OR sealed_at IS NULL \
    OR YEAR(sealed_at) NOT BETWEEN 1000 AND 9999 \
    OR MONTH(sealed_at) NOT BETWEEN 1 AND 12 OR DAY(sealed_at) NOT BETWEEN 1 AND 31 \
    OR LAST_DAY(sealed_at) IS NULL OR DAY(sealed_at) > DAY(LAST_DAY(sealed_at)) \
    OR MICROSECOND(sealed_at) <> 0)";

pub(super) async fn authorization_projection_manifest_v3_recorded(
    pool: &MySqlPool,
) -> Result<bool, MigrationError> {
    if !migration_history_table_exists(pool).await? {
        return Ok(false);
    }
    Ok(recorded_successful_versions(pool)
        .await?
        .contains(&AUTHORIZATION_PROJECTION_MANIFEST_V3_VERSION))
}

fn check_manifest_v3_state(
    recorded: bool,
    version_present: bool,
    timestamp_present: bool,
    has_rows: bool,
) -> Result<bool, MigrationError> {
    match (version_present, timestamp_present) {
        (true, true) if !recorded && has_rows => Err(MigrationError::Failed(
            "authorization manifest v3 has rows but no successful migration history; explicit recovery is required before migration".to_owned(),
        )),
        (true, true) => Ok(true),
        (false, false) if !recorded && !has_rows => Ok(false),
        (false, false) if !recorded => Err(MigrationError::Failed(
            "legacy authorization manifests have no v3 seal; reconcile and rebuild derived state explicitly before migration; no seal backfill or data deletion is permitted".to_owned(),
        )),
        _ => Err(MigrationError::Failed(
            "authorization manifest v3 schema is partial or recorded seal columns are missing; explicit recovery is required".to_owned(),
        )),
    }
}

async fn validate_rows(pool: &MySqlPool) -> Result<(), MigrationError> {
    let invalid: i64 = sqlx::query_scalar(INVALID_SEAL_ROW_SQL)
        .bind(AUTHORIZATION_EDITION)
        .fetch_one(pool)
        .await
        .map_err(|error| MigrationError::Failed(format!("inspect v3 manifest seals: {error}")))?;
    if invalid != 0 {
        return Err(MigrationError::Failed(
            "authorization manifest contains unsupported digest versions or invalid UTC-second seal timestamps; refusing to infer or repair publication evidence".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_exact_schema(pool: &MySqlPool) -> Result<(), MigrationError> {
    validate_schema_columns(pool, AUTHORIZATION_PROJECTION_MANIFEST_V3_COLUMN_CONTRACTS).await?;
    let base: Vec<_> = INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
        .iter()
        .filter(|column| column.table == TABLE)
        .copied()
        .collect();
    let expected = incremental_projection_resolved_column_contract(TABLE, &base);
    if !schema_columns_match(pool, &expected).await? {
        return Err(MigrationError::Failed(
            "authorization manifest v3 schema has unexpected columns, order, type, nullability, or default drift".to_owned(),
        ));
    }
    validate_rows(pool).await
}

pub(super) async fn preflight_manifest_v3(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let migration = migrations
        .iter()
        .find(|migration| migration.version == AUTHORIZATION_PROJECTION_MANIFEST_V3_VERSION)
        .filter(|migration| exact_migration_artifact_contract(migration).is_some())
        .ok_or_else(|| MigrationError::Failed(
            "authorization manifest v3 migration is missing or differs from its pinned contract".to_owned(),
        ))?;
    for (table, column) in AUTHORIZATION_PROJECTION_MANIFEST_V3_COLUMNS {
        if !migration_defines_existing_column(migration, table, column) {
            return Err(MigrationError::Failed(format!(
                "authorization manifest v3 migration does not define {table}.{column}"
            )));
        }
    }
    let recorded = authorization_projection_manifest_v3_recorded(pool).await?;
    if recorded != applied_versions.contains(&AUTHORIZATION_PROJECTION_MANIFEST_V3_VERSION) {
        return Err(MigrationError::Failed(
            "authorization manifest v3 history disagrees with the migration execution plan"
                .to_owned(),
        ));
    }
    if !schema_table_exists(pool, TABLE).await? {
        if recorded {
            return Err(MigrationError::Failed(
                "authorization manifest v3 migration is recorded but its table is missing"
                    .to_owned(),
            ));
        }
        return Ok(false);
    }
    let version_present = schema_column_exists(pool, TABLE, "manifest_digest_version").await?;
    let timestamp_present = schema_column_exists(pool, TABLE, "sealed_at").await?;
    let has_rows: i64 =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM authorization_projection_manifest)")
            .fetch_one(pool)
            .await
            .map_err(|error| {
                MigrationError::Failed(format!("inspect legacy manifest rows: {error}"))
            })?;
    let complete =
        check_manifest_v3_state(recorded, version_present, timestamp_present, has_rows != 0)?;
    if complete {
        validate_exact_schema(pool).await?;
    }
    Ok(complete)
}

pub(super) async fn validate_manifest_v3_runtime(pool: &MySqlPool) -> Result<(), MigrationError> {
    validate_exact_schema(pool).await
}

pub(super) async fn validate_manifest_v3_postcondition(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    if !authorization_projection_manifest_v3_recorded(pool).await? {
        return Err(MigrationError::RecoveryRequired {
            reason:
                "authorization manifest v3 has no successful migration history after SQLx execution"
                    .to_owned(),
        });
    }
    validate_exact_schema(pool)
        .await
        .map_err(|error| MigrationError::RecoveryRequired {
            reason: format!("authorization manifest v3 postcondition failed: {error}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_state_accepts_only_empty_legacy_schema_or_complete_seals() {
        assert!(!check_manifest_v3_state(false, false, false, false).unwrap());
        assert!(check_manifest_v3_state(false, false, false, true).is_err());
        assert!(check_manifest_v3_state(false, true, true, true).is_err());
        assert!(check_manifest_v3_state(false, true, true, false).unwrap());
        for has_rows in [false, true] {
            assert!(check_manifest_v3_state(true, true, true, has_rows).unwrap());
            assert!(check_manifest_v3_state(true, true, false, has_rows).is_err());
            assert!(check_manifest_v3_state(true, false, true, has_rows).is_err());
            assert!(check_manifest_v3_state(true, false, false, has_rows).is_err());
        }
    }

    #[test]
    fn v3_artifact_and_calendar_probes_are_pinned_without_backfill() {
        let migration = MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == AUTHORIZATION_PROJECTION_MANIFEST_V3_VERSION)
            .unwrap();
        assert!(exact_migration_artifact_contract(migration).is_some());
        let artifacts = parsed_migration_artifacts(migration).unwrap();
        assert!(exact_contract_artifacts_match_source(
            exact_migration_artifact_contract(migration).unwrap(),
            &artifacts
        ));
        for (table, column) in AUTHORIZATION_PROJECTION_MANIFEST_V3_COLUMNS {
            assert!(migration_defines_existing_column(migration, table, column));
        }
        assert!(!is_java_baseline_era(migration.version));
        let source = AUTHORIZATION_PROJECTION_MANIFEST_V3_MIGRATION_SQL;
        assert!(source.contains("@astral_manifest_v3_row_count = 0"));
        assert_eq!(source.matches("ALTER TABLE authorization_projection_manifest ADD COLUMN manifest_digest_version").count(), 1);
        for probe in [
            "YEAR(sealed_at)",
            "MONTH(sealed_at)",
            "DAY(sealed_at)",
            "LAST_DAY(sealed_at)",
        ] {
            assert!(source.contains(probe));
            assert!(INVALID_SEAL_ROW_SQL.contains(probe));
        }
        assert!(INVALID_SEAL_ROW_SQL.contains("manifest_digest_version <> ?"));
        assert!(INVALID_SEAL_ROW_SQL.contains("MICROSECOND(sealed_at) <> 0"));
        let normalized = source.to_ascii_uppercase();
        assert!(!normalized.contains("UPDATE AUTHORIZATION_PROJECTION_MANIFEST"));
        assert!(!normalized.contains("DELETE FROM"));
        assert!(!normalized.contains("DROP TABLE"));
    }

    #[test]
    fn v3_tail_and_metadata_refuse_partial_reordered_and_recorded_missing_columns() {
        let base: Vec<_> = INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
            .iter()
            .filter(|column| column.table == TABLE)
            .copied()
            .collect();
        let resolved = incremental_projection_resolved_column_contract(TABLE, &base);
        let names: Vec<_> = resolved
            .iter()
            .map(|column| column.name.to_owned())
            .collect();
        let old_count = names.len() - 2;
        let validate = |actual: &[String], recorded| {
            validate_resolved_archive_column_order(
                TABLE,
                &base,
                actual,
                Some(true),
                Some(false),
                Some(true),
                Some(recorded),
            )
        };
        assert!(validate(&names[..old_count], false).is_ok());
        assert!(validate(&names[..old_count], true).is_err());
        assert!(validate(&names[..old_count + 1], false).is_err());
        assert!(validate(&names, true).is_ok());
        let mut reordered = names.clone();
        reordered.swap(old_count, old_count + 1);
        assert!(validate(&reordered, false).is_err());
        let mut extra = names;
        extra.push("unexpected".to_owned());
        assert!(validate(&extra, false).is_err());
        for expected in AUTHORIZATION_PROJECTION_MANIFEST_V3_COLUMN_CONTRACTS {
            assert!(schema_column_contract_matches(
                expected.name,
                expected.column_type,
                "NO",
                None,
                None,
                None,
                expected
            ));
            assert!(!schema_column_contract_matches(
                expected.name,
                expected.column_type,
                "YES",
                None,
                None,
                None,
                expected
            ));
            assert!(!schema_column_contract_matches(
                expected.name,
                expected.column_type,
                "NO",
                Some("3"),
                None,
                None,
                expected
            ));
            assert!(!schema_column_contract_matches(
                expected.name,
                "VARCHAR(32)",
                "NO",
                None,
                None,
                None,
                expected
            ));
        }
    }
}
