use super::*;

const REMOVAL_SQL: &str =
    include_str!("../../../migrations/20261004000001_drop_redundant_archive_indexes.sql");

fn rows(contract: &[(&str, &str, &[&str], bool)]) -> Vec<(String, bool, u64, String)> {
    contract
        .iter()
        .flat_map(|(_, index, columns, unique)| {
            columns.iter().enumerate().map(move |(position, column)| {
                (
                    (*index).to_owned(),
                    !*unique,
                    position as u64 + 1,
                    (*column).to_owned(),
                )
            })
        })
        .collect()
}

#[test]
fn archive_index_removal_reentry_does_not_bypass_dirty_history() {
    assert!(REMOVAL_SQL.contains("success=0"));
    assert!(REMOVAL_SQL
        .replace("\r\n", "\n")
        .contains("normal\n-- job refuses rerun"));
    assert!(REMOVAL_SQL.contains("does not authorize clearing that row"));
    let production = include_str!("../../migration.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let apply = production
        .split("async fn apply_migrations(")
        .nth(1)
        .unwrap()
        .split("async fn ")
        .next()
        .unwrap();
    let dirty = apply.find("WHERE success = 0").unwrap();
    assert!(dirty < apply.find("apply_migrations_with_mysql8_compat").unwrap());
    assert!(apply.contains("MigrationError::Failed"));
}

#[test]
fn archive_index_removal_artifact_is_pinned_and_only_drops_the_duplicates() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION)
        .unwrap();
    assert_eq!(migration.sql, REMOVAL_SQL);
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        REDUNDANT_ARCHIVE_INDEX_REMOVAL_SQL_SHA384
    );
    assert!(exact_migration_artifact_contract(migration).is_some());
    let statements = sql_statements(REMOVAL_SQL).unwrap();
    let drops: Vec<_> = statements
        .iter()
        .flat_map(|statement| sql_string_literals(statement).unwrap())
        .filter(|literal| literal.starts_with("ALTER TABLE"))
        .collect();
    assert_eq!(
        drops,
        [
            "ALTER TABLE authorization_impact_plan DROP INDEX idx_aip_aggregate",
            "ALTER TABLE authorization_projection_manifest DROP INDEX idx_apm_aggregate",
        ]
    );
    assert_eq!(
        statements
            .iter()
            .filter(|statement| normalized_sql_fragment(statement).starts_with("PREPARE "))
            .count(),
        2
    );
    assert_eq!(
        statements
            .iter()
            .filter(
                |statement| normalized_sql_fragment(statement).starts_with("DEALLOCATE PREPARE ")
            )
            .count(),
        2
    );
    let mut altered = migration.clone();
    altered.sql = Cow::Owned(
        migration
            .sql
            .replace("idx_apm_aggregate", "uk_apm_generation"),
    );
    assert!(exact_migration_artifact_contract(&altered).is_none());
    assert!(!is_java_baseline_era(migration.version));
}

#[test]
fn archive_index_removal_pending_and_partial_states_preserve_unique_contracts() {
    for mask in 0..4 {
        let mut present = HashSet::new();
        for (position, (_, _, index)) in POST_CREATOR_INDEX_REMOVALS.iter().enumerate() {
            if mask & (1 << position) != 0 {
                present.insert(*index);
            }
        }
        for (_, table, index) in POST_CREATOR_INDEX_REMOVALS {
            let contract = resolve_archive_index_contract(table, &HashSet::new(), &present);
            assert_eq!(
                contract.iter().any(|(_, name, _, _)| name == index),
                present.contains(index)
            );
            let duplicate = INCREMENTAL_PROJECTION_ARCHIVE_INDEXES
                .iter()
                .find(|(owner, name, _, _)| owner == table && name == index)
                .unwrap();
            assert!(!duplicate.3);
            assert!(contract.iter().any(|(_, name, columns, unique)| *unique
                && *columns == duplicate.2
                && name != index));
            assert!(schema_index_rows_match(table, rows(&contract), &contract));
        }
    }
}

#[test]
fn archive_index_removal_recorded_state_rejects_recreated_or_drifted_indexes() {
    let recorded = HashSet::from([REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION]);
    let present: HashSet<_> = POST_CREATOR_INDEX_REMOVALS
        .iter()
        .map(|(_, _, index)| *index)
        .collect();
    for (_, table, index) in POST_CREATOR_INDEX_REMOVALS {
        let contract = resolve_archive_index_contract(table, &recorded, &present);
        assert!(contract.iter().all(|(_, name, _, _)| name != index));
        let mut recreated = rows(&contract);
        let old = INCREMENTAL_PROJECTION_ARCHIVE_INDEXES
            .iter()
            .find(|(owner, name, _, _)| owner == table && name == index)
            .unwrap();
        recreated.extend(rows(std::slice::from_ref(old)));
        assert!(!schema_index_rows_match(table, recreated, &contract));
        let mut extra = rows(&contract);
        extra.push((
            "unexpected_index".to_owned(),
            true,
            1,
            "tenant_id".to_owned(),
        ));
        assert!(!schema_index_rows_match(table, extra, &contract));
        let mut missing_unique = contract.clone();
        missing_unique.retain(|(_, name, _, unique)| !*unique || *name == "PRIMARY");
        assert!(!schema_index_rows_match(
            table,
            rows(&missing_unique),
            &contract
        ));
    }
}

#[test]
fn archive_index_removal_pending_same_name_drift_is_not_tolerated() {
    for (_, table, index) in POST_CREATOR_INDEX_REMOVALS {
        let contract =
            resolve_archive_index_contract(table, &HashSet::new(), &HashSet::from([*index]));
        let mut wrong_column = rows(&contract);
        wrong_column
            .iter_mut()
            .find(|row| row.0 == *index)
            .unwrap()
            .3 = "wrong_column".to_owned();
        assert!(!schema_index_rows_match(table, wrong_column, &contract));
        let mut wrong_unique = rows(&contract);
        for row in wrong_unique.iter_mut().filter(|row| row.0 == *index) {
            row.1 = false;
        }
        assert!(!schema_index_rows_match(table, wrong_unique, &contract));
        let mut reordered = rows(&contract);
        for row in reordered.iter_mut().filter(|row| row.0 == *index) {
            row.2 = 5 - row.2;
        }
        assert!(!schema_index_rows_match(table, reordered, &contract));
    }
}

#[test]
fn archive_index_removal_keeps_the_creator_checksum_and_artifacts_intact() {
    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == INCREMENTAL_PROJECTION_ARCHIVE_VERSION)
        .unwrap();
    assert_eq!(
        canonical_sha384_hex(creator.sql.as_bytes()),
        INCREMENTAL_PROJECTION_ARCHIVE_SQL_SHA384
    );
    let contract = exact_migration_artifact_contract(creator).unwrap();
    assert_eq!(contract.indexes, INCREMENTAL_PROJECTION_ARCHIVE_INDEXES);
    for (_, table, index) in POST_CREATOR_INDEX_REMOVALS {
        assert!(contract
            .indexes
            .iter()
            .any(|(owner, name, _, _)| owner == table && name == index));
    }
}

#[test]
fn archive_index_removal_postcondition_precedes_backfill_and_requires_proof() {
    let production = include_str!("../../migration.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let apply = production
        .split("async fn apply_migrations_with_mysql8_compat")
        .nth(1)
        .unwrap()
        .split("const RULE_SET_PROJECTION_BACKFILL_MARKER")
        .next()
        .unwrap();
    assert!(
        apply.find(".run(pool)").unwrap()
            < apply
                .find("validate_archive_index_removal_postcondition(pool).await?")
                .unwrap()
    );
    assert!(
        apply
            .find("validate_archive_index_removal_postcondition(pool).await?")
            .unwrap()
            < apply
                .find("backfill_rule_set_projection(pool).await?")
                .unwrap()
    );
    let check = production
        .split("async fn validate_archive_index_removal_postcondition")
        .nth(1)
        .unwrap()
        .split("async fn validate_cross_city_table_contract")
        .next()
        .unwrap();
    assert!(check.contains("recorded.contains(&REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION)"));
    assert!(check.contains("validate_incremental_projection_archive_table_contract"));
    assert!(check.contains("MigrationError::RecoveryRequired"));
}
