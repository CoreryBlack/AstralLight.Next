use super::*;

mod archive_indexes;

fn normalize_schema_source_default_contracts() -> bool {
    [
        (Some("unix_timestamp()"), Some("(UNIX_TIMESTAMP())")),
        (Some("(current_timestamp(6))"), Some("CURRENT_TIMESTAMP(6)")),
        (Some("CURRENT_TIMESTAMP(6)"), Some("CURRENT_TIMESTAMP(6)")),
        (None, None),
    ]
    .into_iter()
    .all(|(actual, expected)| column_default_matches(actual, expected))
}

/// Partition lease table (multi-tenant redesign Phase 1, default-off): the
/// additive scheduling-only table consumed exclusively by the partitioned
/// projector scheduler (20260921000001).
const AUTHORIZATION_PROJECTION_PARTITION_LEASE_VERSION: i64 = 20260921000001;

/// Org-scope authority source tables (multi-tenant redesign Phase 2,
/// default-off behind `ASTRAL_ORG_SCOPE_ENABLED`): the fully additive
/// creator migration of the separately versioned org-scope authority
/// chain (20260922000001).
const ORG_SCOPE_AUTHORITY_VERSION: i64 = 20260922000001;
const AL_MESSAGE_OUTBOX_VERSION: i64 = 20260929000001;
/// Cross-city runtime-proof slice (P4, default-off): durable node key
/// registry, replay-reservation ledger, commit receipts, activation mint
/// records, and authoritative city-scope registry. The current embedded
/// migration chain tail.
const CROSS_CITY_RUNTIME_PROOF_VERSION: i64 = 20261001000002;
const CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261001000002_cross_city_runtime_proof.sql");
const IDENTITY_CREDENTIAL_FENCE_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261003000001_identity_credential_fence.sql");
const ASYNC_OPERATION_CORRELATION_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261003000002_operation_audit_correlation.sql");
const REVIEW_SCHEMA_REPAIR_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261003000003_review_schema_contract_repair.sql");
const LEARN_ASSIGNMENT_CREATOR_VERSION: i64 = 20260705000001;
const LEARN_ASSIGNMENT_CREATOR_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260705000001_learn_missing_tables.sql");
const CHAT_DELIVERY_INTENT_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261003000004_chat_delivery_intent.sql");
const LEARN_SYSTEM_ASSIGNMENT_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261003000005_learn_atomic_intents.sql");

/// Redis-free 运行路径新增的 Rust-owned additive 尾部（均在 cross-city
/// runtime-proof 之后、必须保持 embedded、绝不被 Java baseline 吸收）：
/// 000003 MQ consumer durable lease（幂等 MySQL 化）、000004 invalidation
/// inbox、000005 invalidation scope sequence（当前链尾）。
const RUNTIME_REDIS_FREE_TAIL_VERSION: i64 = 20261001000005;
const RUNTIME_REDIS_FREE_TAIL_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261001000005_invalidation_scope_sequence.sql");
const MQ_IDEMPOTENCY_LEASE_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261001000003_mq_idempotency_lease.sql");
/// 20261001000001 Redis-free Gateway 内部请求护栏（durable SET NX EX 等价，
/// `auth_internal_request_guard` 表）。
const AUTH_INTERNAL_REQUEST_GUARD_VERSION: i64 = 20261001000001;
const AUTH_INTERNAL_REQUEST_GUARD_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261001000001_auth_internal_request_guard.sql");
/// 20261001000003 MQ consumer durable lease（幂等 MySQL 化）：由
/// `astral_db::mq_idempotency_repository` 独占读写 `mq_consumer_lease`，
/// 必须保持 embedded 且绝不被 Java baseline 吸收。
const MQ_IDEMPOTENCY_LEASE_VERSION: i64 = 20261001000003;
/// 20261001000004 per-node durable invalidation inbox（Rabbit 失效广播的
/// durable per-node receipt；owner 为 `astral_db::InvalidationInboxRepository`）。
const INVALIDATION_INBOX_VERSION: i64 = 20261001000004;
const INVALIDATION_INBOX_MIGRATION_SQL: &str =
    include_str!("../../migrations/20261001000004_invalidation_inbox.sql");

const RUNTIME_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260818000001_rust_runtime_schema.sql");
const RUNTIME_REPAIR_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260818000002_rust_runtime_schema_repair.sql");
const AUDIT_QUARANTINE_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260818000003_audit_quarantine.sql");
const QUARANTINE_HARDENING_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260818000004_quarantine_replay_hardening.sql");
const MONITOR_SCHEMA_REPAIR_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260820000001_monitor_schema_repair.sql");
const RULE_SET_PROJECTION_SCHEMA_REPAIR_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260822000001_rule_set_projection_schema_repair.sql");
const SNAPSHOT_VALIDITY_SCHEMA_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260822000002_snapshot_validity_windows.sql");
const RULE_SET_SNAPSHOT_MANIFEST_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260825000001_rule_set_snapshot_manifest.sql");
const INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260825000002_incremental_projection_archive.sql");
const AUTHORIZATION_PROJECTION_LINEAGE_FENCE_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260827000001_authorization_projection_lineage_fence.sql");
const DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260914000001_delta_event_published_evidence_invalidation.sql");
const LEGACY_SNAPSHOT_DECOMMISSION_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260827000002_legacy_snapshot_tables_decommission.sql");
const HEAD_PROJECTION_STATUS_RETIREMENT_VERSION: i64 = 20260831000001;
const DELTA_CLAIM_GRANT_CHAIN_INDEX_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260903000001_delta_claim_grant_chain_index.sql");
const IDENTITY_CARD_DUAL_CARD_SEPARATION_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260830000001_identity_card_dual_card_separation.sql");
const CROSS_CITY_SCHEMA_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260831000002_cross_city_schema.sql");
const AL_MESSAGE_OUTBOX_MIGRATION_SQL: &str =
    include_str!("../../migrations/20260929000001_al_message_outbox.sql");

fn historical_auth_migration() -> &'static Migration {
    MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == AUTH_FAMILY_SCHEMA_CONTRACT_VERSION)
        .expect("historical auth migration must remain embedded")
}

fn auth_session_resilience_migration() -> &'static Migration {
    MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == AUTH_SESSION_RESILIENCE_VERSION)
        .expect("auth session resilience migration must remain embedded")
}

fn tenant_school_cutover_migration() -> &'static Migration {
    MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == TENANT_SCHOOL_CUTOVER_VERSION)
        .expect("tenant school cutover migration must remain embedded")
}

fn trustgraph_runtime_migration() -> &'static Migration {
    MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == TRUSTGRAPH_RUNTIME_TABLES_VERSION)
        .expect("TrustGraph runtime migration must remain embedded")
}

#[test]
fn lock_cleanup_preserves_original_errors_and_escalates_success_cleanup_failure() {
    let original = MigrationError::Failed("original failure".into());
    let cleanup = MigrationError::Failed("cleanup failure".into());

    assert!(matches!(
        resolve_migration_result(Err(original), Ok(())),
        Err(MigrationError::Failed(message)) if message == "original failure"
    ));
    assert!(matches!(
        resolve_migration_result(
            Err(MigrationError::Failed("original failure".into())),
            Err(cleanup)
        ),
        Err(MigrationError::Failed(message)) if message == "original failure"
    ));
    assert!(matches!(
        resolve_migration_result(Ok(()), Err(MigrationError::Failed("cleanup failure".into()))),
        Err(MigrationError::RecoveryRequired { reason })
            if reason.contains("cleanup failure")
    ));
    assert!(resolve_migration_result(Ok(()), Ok(())).is_ok());
}

#[test]
fn migration_lock_release_is_scoped_after_all_migration_work() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let acquire = source
        .find("acquire_migration_lock(&mut lock_connection).await?")
        .expect("lock acquisition must exist");
    let release = source
        .find("let cleanup_result = release_migration_lock(&mut lock_connection).await")
        .expect("lock cleanup must exist");
    let result_scope = source
        .find("let migration_result = async {")
        .expect("migration result scope must exist");
    assert!(acquire < result_scope);
    assert!(result_scope < release);
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    assert_eq!(
        production_source
            .matches("release_migration_lock(&mut lock_connection)")
            .count(),
        1
    );
}

#[test]
fn trustgraph_runtime_mysql8_compatibility_rewrites_exactly_one_statement() {
    let migration = trustgraph_runtime_migration();
    let source = include_bytes!("../../migrations/20260729000002_trustgraph_runtime_tables.sql");
    let compatible = historical_mysql8_compatible_sql(migration)
        .expect("target migration must match its compatibility contract");

    assert_eq!(migration.version, TRUSTGRAPH_RUNTIME_TABLES_VERSION);
    assert_eq!(TRUSTGRAPH_RUNTIME_INCOMPATIBLE_STATEMENTS.len(), 1);
    assert_eq!(
        migration.sql.matches("ADD COLUMN IF NOT EXISTS").count(),
        TRUSTGRAPH_RUNTIME_INCOMPATIBLE_STATEMENTS.len()
    );
    assert_eq!(compatible.matches("SELECT 1;").count(), 1);
    assert_eq!(compatible.matches("ADD COLUMN IF NOT EXISTS").count(), 0);
    assert!(compatible.contains("CREATE TABLE IF NOT EXISTS sod_policy"));
    assert!(compatible.contains("UPDATE sod_policy SET status = 'ACTIVE'"));
    assert!(compatible.contains("idx_sod_status"));
    assert!(compatible.contains("CREATE TABLE IF NOT EXISTS sod_violation"));
    assert!(compatible.contains("CREATE TABLE IF NOT EXISTS identity_global_admin"));
    assert_eq!(
        canonical_sha384_hex(source),
        TRUSTGRAPH_RUNTIME_TABLES_SQL_SHA384
    );
}

#[test]
fn trustgraph_runtime_mysql8_compatibility_rejects_changed_or_partial_sql() {
    let migration = trustgraph_runtime_migration();
    let mut changed = migration.clone();
    changed.sql = migration
        .sql
        .replacen("VARCHAR(16)", "VARCHAR(32)", 1)
        .into();
    assert!(historical_mysql8_compatible_sql(&changed).is_err());

    let mut partial = migration.clone();
    partial.sql = format!(
        "{}\nALTER TABLE sod_policy ADD COLUMN IF NOT EXISTS audit_flag BOOLEAN;",
        migration.sql
    )
    .into();
    assert!(historical_mysql8_compatible_sql(&partial).is_err());

    let mut wrong_version = migration.clone();
    wrong_version.version = TRUSTGRAPH_RUNTIME_TABLES_VERSION + 1;
    assert!(historical_mysql8_compatible_sql(&wrong_version).is_err());
}

#[test]
fn trustgraph_runtime_mysql8_compatibility_preserves_source_checksum() {
    let migration = trustgraph_runtime_migration();
    let source = include_bytes!("../../migrations/20260729000002_trustgraph_runtime_tables.sql");
    let raw_checksum = migration.checksum.as_ref().to_vec();
    let compatible = historical_mysql8_compatible_sql(migration)
        .expect("target migration must match its compatibility contract");

    assert_ne!(compatible.as_bytes(), migration.sql.as_bytes());
    assert_eq!(migration.checksum.as_ref(), raw_checksum.as_slice());
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        TRUSTGRAPH_RUNTIME_TABLES_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(source),
        TRUSTGRAPH_RUNTIME_TABLES_SQL_SHA384
    );
    assert_eq!(migration.sql.as_bytes(), source);
}

#[test]
fn trustgraph_runtime_contracts_match_exact_baseline_and_source_metadata() {
    assert_eq!(TRUSTGRAPH_RUNTIME_TABLES.len(), 3);
    assert_eq!(TRUSTGRAPH_BASELINE_COLUMN_CONTRACT.len(), 31);
    assert_eq!(TRUSTGRAPH_SOURCE_COLUMN_CONTRACT.len(), 31);
    assert_eq!(TRUSTGRAPH_BASELINE_INDEXES.len(), 10);
    assert_eq!(TRUSTGRAPH_BASELINE_READY_INDEXES.len(), 11);
    assert_eq!(TRUSTGRAPH_SOURCE_INDEXES.len(), 9);
    assert_eq!(TRUSTGRAPH_SOURCE_FOREIGN_KEYS.len(), 1);

    let baseline_status = TRUSTGRAPH_BASELINE_COLUMN_CONTRACT
        .iter()
        .find(|column| column.table == "sod_policy" && column.name == "status")
        .expect("baseline status contract");
    assert_eq!(
        (
            baseline_status.column_type,
            baseline_status.not_null,
            baseline_status.default,
            baseline_status.collation
        ),
        (
            "VARCHAR(16)",
            false,
            Some("ACTIVE"),
            Some(MYSQL_SCHEMA_COLLATION)
        )
    );
    let source_status = TRUSTGRAPH_SOURCE_COLUMN_CONTRACT
        .iter()
        .find(|column| column.table == "sod_policy" && column.name == "status")
        .expect("source status contract");
    assert_eq!(
        (
            source_status.column_type,
            source_status.not_null,
            source_status.default,
            source_status.collation
        ),
        (
            "VARCHAR(16)",
            true,
            Some("ACTIVE"),
            Some(MYSQL_SCHEMA_COLLATION)
        )
    );

    assert!(TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| { *index == "uk_policy_name" }));
    assert!(TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| { *index == "idx_conflict_type" }));
    assert!(TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| { *index == "idx_policy" }));
    assert!(TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| { *index == "idx_card" }));
    assert!(TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| { *index == "idx_user" }));
    assert!(!TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| *index == "idx_sod_type" || *index == "idx_sv_policy"));
    assert!(!TRUSTGRAPH_BASELINE_READY_INDEXES
        .iter()
        .any(|(_, index, _, _)| *index == "idx_sod_type" || *index == "idx_sv_policy"));
    assert_eq!(
        TRUSTGRAPH_BASELINE_READY_INDEXES.len(),
        TRUSTGRAPH_BASELINE_INDEXES.len() + 1
    );
    assert!(TRUSTGRAPH_BASELINE_READY_INDEXES
        .iter()
        .any(|(_, index, columns, unique)| {
            *index == "idx_sod_status" && columns == &["status"] && !*unique
        }));

    assert!(TRUSTGRAPH_SOURCE_INDEXES
        .iter()
        .any(|(_, index, _, _)| *index == "idx_sod_type"));
    assert!(TRUSTGRAPH_SOURCE_INDEXES
        .iter()
        .any(|(_, index, _, _)| *index == "idx_sv_policy"));
    assert_eq!(
        TRUSTGRAPH_SOURCE_FOREIGN_KEYS[0],
        (
            "sod_violation",
            "fk_sod_violation_policy",
            "policy_id",
            "sod_policy",
            "policy_id",
            "CASCADE"
        )
    );
}

#[test]
fn trustgraph_baseline_repair_does_not_require_alias_indexes_or_foreign_key() {
    assert!(!TRUSTGRAPH_BASELINE_INDEXES
        .iter()
        .any(|(_, index, _, _)| *index == "idx_sod_status"));
    assert!(TRUSTGRAPH_BASELINE_READY_INDEXES
        .iter()
        .any(|(_, index, _, _)| *index == "idx_sod_status"));
    assert!(TRUSTGRAPH_SOURCE_FOREIGN_KEYS
        .iter()
        .any(|(_, _, _, _, _, rule)| { *rule == "CASCADE" }));
    assert!(SCHEMA_FOREIGN_KEY_LIST_SQL.contains("REFERENCED_TABLE_NAME"));
    assert!(TRUSTGRAPH_BASELINE_RUNTIME_NULLS_SQL.contains("status IS NULL"));
    assert!(TRUSTGRAPH_BASELINE_RUNTIME_NULLS_SQL.contains("policy_name IS NULL"));
    assert!(TRUSTGRAPH_BASELINE_RUNTIME_NULLS_SQL.contains("card_id IS NULL"));
}

#[test]
fn trustgraph_preflight_runs_before_sqlx_history_execution() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let preflight = source
        .find("preflight_historical_migration_schema_contract(pool, migration")
        .expect("apply preflight must exist");
    let sqlx_run = source.find(".run(pool)").expect("SQLx run must exist");
    assert!(preflight < sqlx_run);
    let apply_body = source
        .split("pub async fn apply_migrations(database_url")
        .nth(1)
        .and_then(|body| {
            body.split("pub async fn connect_and_validate_schema")
                .next()
        })
        .expect("apply function body");
    assert!(apply_body.contains("preflight_before_baseline_adoption(&pool).await?"));
    assert!(!apply_body
        .contains("preflight_trustgraph_runtime_schema_contract(pool, runtime_migration"));
    assert!(source
        .contains("TrustGraph runtime migration is recorded but all runtime tables are missing"));
    assert!(!apply_body.contains("materialize missing TrustGraph runtime tables"));
}

#[test]
fn trustgraph_baseline_preflight_always_runs_readiness_after_index_convergence() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let baseline_arm = source
        .split("TrustgraphRuntimeSchemaState::Baseline {")
        .nth(1)
        .and_then(|body| {
            body.split("TrustgraphRuntimeSchemaState::BaselineReady")
                .next()
        })
        .expect("baseline arm must exist");
    let ready_arm = source
        .split("TrustgraphRuntimeSchemaState::BaselineReady => {")
        .nth(1)
        .and_then(|body| body.split("TrustgraphRuntimeSchemaState::Source").next())
        .expect("baseline-ready arm must exist");
    assert!(baseline_arm.contains("ensure_trustgraph_runtime_baseline_ready(pool).await?"));
    assert!(ready_arm.contains("ensure_trustgraph_runtime_baseline_ready(pool).await?"));
    assert!(ready_arm.contains("Index existence is not data validity"));
}

#[test]
fn sqlx_history_success_is_after_preflight_and_final_failure_is_recovery_required() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let preflight = source
        .find("preflight_schema_contract_before_sqlx(pool, &applied_versions")
        .expect("schema preflight call must exist");
    let sqlx_run = source
        .find("migrator\n        .run(pool)")
        .expect("SQLx run must exist");
    assert!(preflight < sqlx_run);
    let final_validation = source
        .find("validate_schema_contract(&pool).await.map_err")
        .expect("final contract validation must exist");
    let release_lock = source
        .find("release_migration_lock(&mut lock_connection).await")
        .expect("migration lock release must exist");
    assert!(final_validation < release_lock);
    assert!(source.contains("MigrationError::RecoveryRequired"));
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    assert!(!production_source.contains("DELETE FROM _sqlx_migrations"));
    assert!(!production_source.contains("UPDATE _sqlx_migrations"));
}

#[test]
fn pending_create_table_does_not_claim_to_repair_existing_artifacts() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == 20260818000001)
        .expect("runtime migration must remain embedded");
    assert!(migration_defines_table(migration, "audit_log"));
    assert!(!migration_defines_existing_column(
        migration,
        "audit_log",
        "user_id"
    ));
    assert!(!migration_defines_existing_index(
        migration,
        "audit_log",
        "idx_al_user",
        &["user_id"],
        false
    ));

    let repair = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == 20260818000002)
        .expect("runtime repair migration must remain embedded");
    assert!(migration_defines_existing_column(
        repair,
        "audit_log",
        "user_id"
    ));
    assert!(migration_defines_existing_index(
        repair,
        "audit_log",
        "idx_al_user",
        &["user_id"],
        false
    ));
}

#[test]
fn exact_runtime_contract_covers_real_split_creator_and_repair() {
    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RUST_RUNTIME_SCHEMA_VERSION)
        .expect("runtime creator migration must remain embedded");
    let repair = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RUST_RUNTIME_SCHEMA_REPAIR_VERSION)
        .expect("runtime repair migration must remain embedded");
    let pending = [creator, repair];

    assert_eq!(
        canonical_sha384_hex(RUNTIME_MIGRATION_SQL.as_bytes()),
        RUST_RUNTIME_SCHEMA_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(RUNTIME_REPAIR_MIGRATION_SQL.as_bytes()),
        RUST_RUNTIME_SCHEMA_REPAIR_SQL_SHA384
    );
    assert!(migration_defines_table(creator, "audit_log"));
    assert!(migration_defines_index(
        creator,
        "audit_log",
        "PRIMARY",
        &["id"],
        true
    ));
    assert!(!migration_defines_existing_index(
        repair,
        "audit_log",
        "PRIMARY",
        &["id"],
        true
    ));

    let required_columns = REQUIRED_SCHEMA_COLUMNS
        .iter()
        .find(|(table, _)| *table == "audit_log")
        .map(|(_, columns)| *columns)
        .expect("audit_log columns must be registered");
    for column in required_columns {
        assert!(
            pending
                .iter()
                .any(|migration| pending_migration_defines_column(migration, "audit_log", column)),
            "split pending migrations must define audit_log.{column}"
        );
    }
    for (table, index, columns, unique) in REQUIRED_SCHEMA_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table == "audit_log")
    {
        assert!(
            pending.iter().any(|migration| {
                pending_migration_defines_index(migration, table, index, columns, *unique)
            }),
            "split pending migrations must define {table}.{index}"
        );
    }
}

#[test]
fn preflight_accepts_creator_owned_primary_for_fresh_runtime_tables_only() {
    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RUST_RUNTIME_SCHEMA_VERSION)
        .expect("runtime creator migration must remain embedded");
    let repair = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RUST_RUNTIME_SCHEMA_REPAIR_VERSION)
        .expect("runtime repair migration must remain embedded");

    for table in ["audit_log", "pending_compensation"] {
        let absent_tables = HashSet::from([table]);
        let primary = REQUIRED_SCHEMA_INDEXES
            .iter()
            .find(|(index_table, index, _, _)| *index_table == table && *index == "PRIMARY")
            .map(|(_, index, columns, unique)| (*index, *columns, *unique))
            .expect("creator table must require a PRIMARY index");

        assert!(pending_index_satisfies_preflight(
            &absent_tables,
            creator,
            table,
            primary.0,
            primary.1,
            primary.2
        ));
        assert!(!pending_index_satisfies_preflight(
            &absent_tables,
            repair,
            table,
            primary.0,
            primary.1,
            primary.2
        ));
    }
}

#[test]
fn preflight_rejects_creator_owned_primary_for_existing_runtime_tables() {
    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RUST_RUNTIME_SCHEMA_VERSION)
        .expect("runtime creator migration must remain embedded");
    let primary = ("PRIMARY", &["id"][..], true);

    assert!(!pending_index_satisfies_preflight(
        &HashSet::new(),
        creator,
        "audit_log",
        primary.0,
        primary.1,
        primary.2
    ));
    assert!(!pending_index_satisfies_preflight(
        &HashSet::new(),
        creator,
        "pending_compensation",
        primary.0,
        primary.1,
        primary.2
    ));
}

#[test]
fn exact_runtime_contract_rejects_comments_quoted_tokens_and_changed_sql() {
    let comment_only = Migration::new(
        RUST_RUNTIME_SCHEMA_VERSION,
        "rust_runtime_schema".into(),
        sqlx::migrate::MigrationType::Simple,
        "-- CREATE TABLE IF NOT EXISTS audit_log (id BIGINT, PRIMARY KEY (id));\nSELECT 1;".into(),
        false,
    );
    assert!(!migration_defines_table(&comment_only, "audit_log"));
    assert!(!migration_defines_column(&comment_only, "audit_log", "id"));
    assert!(!migration_defines_index(
        &comment_only,
        "audit_log",
        "PRIMARY",
        &["id"],
        true
    ));

    let quoted_only = Migration::new(
        RUST_RUNTIME_SCHEMA_REPAIR_VERSION,
        "rust_runtime_schema_repair".into(),
        sqlx::migrate::MigrationType::Simple,
        "SET @sql = 'ALTER TABLE audit_log ADD INDEX PRIMARY (id)';".into(),
        false,
    );
    assert!(!migration_defines_existing_index(
        &quoted_only,
        "audit_log",
        "PRIMARY",
        &["id"],
        true
    ));
    assert!(!migration_defines_existing_column(
        &quoted_only,
        "audit_log",
        "user_id"
    ));

    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RUST_RUNTIME_SCHEMA_VERSION)
        .expect("runtime creator migration must remain embedded");
    let mut changed = creator.clone();
    changed.sql = format!("{}\n-- changed", creator.sql).into();
    assert!(!migration_defines_table(&changed, "audit_log"));
    assert!(!migration_defines_index(
        &changed,
        "audit_log",
        "PRIMARY",
        &["id"],
        true
    ));
}

#[test]
fn exact_quarantine_contract_rejects_comments_and_quoted_tokens() {
    let comment_only = Migration::new(
        AUDIT_QUARANTINE_SCHEMA_VERSION,
        "audit_quarantine".into(),
        sqlx::migrate::MigrationType::Simple,
        "-- CREATE TABLE IF NOT EXISTS audit_quarantine (id BIGINT);\nSELECT 1;".into(),
        false,
    );
    assert!(!migration_defines_table(&comment_only, "audit_quarantine"));
    assert!(!migration_defines_column(
        &comment_only,
        "audit_quarantine",
        "id"
    ));
    assert!(!migration_defines_index(
        &comment_only,
        "audit_quarantine",
        "PRIMARY",
        &["id"],
        true
    ));

    let quoted_only = Migration::new(
        QUARANTINE_REPLAY_HARDENING_VERSION,
        "quarantine_replay_hardening".into(),
        sqlx::migrate::MigrationType::Simple,
        "SET @sql = 'ALTER TABLE audit_quarantine ADD COLUMN replay_requested_at DATETIME';".into(),
        false,
    );
    assert!(!migration_defines_column(
        &quoted_only,
        "audit_quarantine",
        "replay_requested_at"
    ));
    assert!(!migration_defines_index(
        &quoted_only,
        "audit_quarantine",
        "idx_aq_replay_request",
        &["status", "replay_requested_at", "id"],
        false
    ));
}

#[test]
fn exact_quarantine_contract_rejects_changed_sql_even_when_artifacts_parse() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == AUDIT_QUARANTINE_SCHEMA_VERSION)
        .expect("audit quarantine creator migration must remain embedded");
    let mut changed = migration.clone();
    changed.sql = format!("{}\n-- changed", migration.sql).into();

    assert!(!migration_defines_table(&changed, "audit_quarantine"));
    assert!(!migration_defines_column(
        &changed,
        "audit_quarantine",
        "identity_key"
    ));
    assert!(!migration_defines_index(
        &changed,
        "audit_quarantine",
        "uk_aq_identity_key",
        &["identity_key"],
        true
    ));
}

#[test]
fn exact_quarantine_contract_covers_real_split_creator_and_hardening() {
    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == AUDIT_QUARANTINE_SCHEMA_VERSION)
        .expect("audit quarantine creator migration must remain embedded");
    let hardening = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == QUARANTINE_REPLAY_HARDENING_VERSION)
        .expect("quarantine hardening migration must remain embedded");
    let pending = [creator, hardening];

    let required_columns = REQUIRED_SCHEMA_COLUMNS
        .iter()
        .find(|(table, _)| *table == "audit_quarantine")
        .map(|(_, columns)| *columns)
        .expect("audit_quarantine columns must be registered");
    for column in required_columns {
        assert!(
            pending.iter().any(|migration| {
                pending_migration_defines_column(migration, "audit_quarantine", column)
            }),
            "split pending migrations must define audit_quarantine.{column}"
        );
    }
    for (table, index, columns, unique) in REQUIRED_SCHEMA_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table == "audit_quarantine")
    {
        assert!(
            pending.iter().any(|migration| {
                pending_migration_defines_index(migration, table, index, columns, *unique)
            }),
            "split pending migrations must define {table}.{index}"
        );
    }
}

#[test]
fn mysql8_compatibility_rewrites_only_the_known_historical_statements() {
    let migration = historical_auth_migration();
    let compatible_sql = historical_mysql8_compatible_sql(migration)
        .expect("known historical migration must match its compatibility contract");

    assert!(!compatible_sql.contains("ADD COLUMN IF NOT EXISTS session_state"));
    assert!(!compatible_sql.contains("ADD COLUMN IF NOT EXISTS session_version"));
    assert!(!compatible_sql.contains("ADD COLUMN IF NOT EXISTS session_epoch"));
    assert_eq!(compatible_sql.matches("SELECT 1;").count(), 3);
    assert_eq!(migration.version, AUTH_FAMILY_SCHEMA_CONTRACT_VERSION);
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        AUTH_FAMILY_SCHEMA_CONTRACT_SQL_SHA384
    );
    assert_eq!(
        migration.sql.matches("ADD COLUMN IF NOT EXISTS").count(),
        AUTH_FAMILY_INCOMPATIBLE_STATEMENTS.len()
    );
}

#[test]
fn auth_session_resilience_contract_pins_lf_hash_and_all_add_column_statements() {
    let migration = auth_session_resilience_migration();
    assert_eq!(migration.version, AUTH_SESSION_RESILIENCE_VERSION);
    let source = include_bytes!("../../migrations/20260728000001_auth_session_resilience.sql");
    let canonical_source = canonical_lf_bytes(source);
    assert!(!canonical_source.contains(&b'\r'));
    assert_eq!(
        canonical_sha384_hex(source),
        AUTH_SESSION_RESILIENCE_SQL_SHA384
    );
    assert_eq!(
        migration.sql.matches("ADD COLUMN IF NOT EXISTS").count(),
        AUTH_SESSION_RESILIENCE_INCOMPATIBLE_STATEMENTS.len()
    );
    assert_eq!(
        migration
            .sql
            .matches("ADD COLUMN IF NOT EXISTS session_state")
            .count(),
        1
    );
    assert_eq!(
        migration
            .sql
            .matches("ADD COLUMN IF NOT EXISTS session_version")
            .count(),
        1
    );
    assert_eq!(
        migration
            .sql
            .matches("ADD COLUMN IF NOT EXISTS session_epoch")
            .count(),
        1
    );
    let compatible = historical_mysql8_compatible_sql(migration).unwrap();
    assert_eq!(compatible.matches("SELECT 1;").count(), 3);
    assert!(!compatible.contains("ADD COLUMN IF NOT EXISTS"));
}

#[test]
fn tenant_school_cutover_contract_rewrites_exact_add_column_statements() {
    let migration = tenant_school_cutover_migration();
    assert_eq!(migration.version, TENANT_SCHOOL_CUTOVER_VERSION);
    let source = include_bytes!("../../migrations/20260729000001_tenant_school_cutover.sql");
    assert_eq!(
        canonical_sha384_hex(source),
        TENANT_SCHOOL_CUTOVER_SQL_SHA384
    );
    assert_eq!(
        migration.sql.matches("ADD COLUMN IF NOT EXISTS").count(),
        TENANT_SCHOOL_CUTOVER_INCOMPATIBLE_STATEMENTS.len()
    );

    let raw_checksum = migration.checksum.as_ref().to_vec();
    let compatible = historical_mysql8_compatible_sql(migration).unwrap();
    assert_eq!(compatible.matches("ADD COLUMN IF NOT EXISTS").count(), 0);
    assert_eq!(compatible.matches("SELECT 1;").count(), 13);
    assert_eq!(compatible.matches("ADD COLUMN").count(), 0);
    assert!(!compatible.contains("DEFAULT CHARSET=utf8mb4 COMMENT="));
    assert!(compatible.contains(
            "DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Schools to tenants migration audit mapping'"
        ));
    assert_eq!(migration.checksum.as_ref(), raw_checksum.as_slice());
    assert_eq!(
        canonical_sha384_hex(source),
        TENANT_SCHOOL_CUTOVER_SQL_SHA384
    );
    for statement in TENANT_SCHOOL_CUTOVER_INCOMPATIBLE_STATEMENTS {
        assert_eq!(compatible.matches(statement).count(), 0);
    }
    assert!(compatible.contains("CREATE TABLE IF NOT EXISTS school_tenant_migration"));
    for index in [
        "idx_school_members_tenant",
        "idx_user_profiles_tenant",
        "idx_leaderboards_tenant",
    ] {
        assert!(
            compatible.contains(index),
            "missing preserved index {index}"
        );
    }
}

#[test]
fn rollback_guard_rejects_unset_rehearsal_flag() {
    let script = include_str!("../../scripts/rollback-tenant-school-cutover.sql");
    assert!(script.contains("IF COALESCE(@ASTRAL_MIGRATION_REHEARSAL, '') <> '1'"));
    assert!(!script.contains("IF @ASTRAL_MIGRATION_REHEARSAL <> '1'"));
}

#[test]
fn tenant_school_cutover_contract_declares_all_thirteen_columns() {
    assert_eq!(TENANT_SCHOOL_CUTOVER_COLUMNS.len(), 13);
    let expected = [
        ("tenant", "org_id", "BIGINT", false, None, "settings_json"),
        ("tenant", "country", "VARCHAR(16)", false, None, "org_id"),
        ("tenant", "province", "VARCHAR(64)", false, None, "country"),
        ("tenant", "city", "VARCHAR(64)", false, None, "province"),
        ("tenant", "district", "VARCHAR(64)", false, None, "city"),
        ("tenant", "address", "VARCHAR(512)", false, None, "district"),
        (
            "tenant",
            "postal_code",
            "VARCHAR(32)",
            false,
            None,
            "address",
        ),
        (
            "tenant",
            "website",
            "VARCHAR(512)",
            false,
            None,
            "postal_code",
        ),
        ("tenant", "description", "TEXT", false, None, "website"),
        (
            "tenant",
            "verified",
            "TINYINT(1)",
            true,
            Some("0"),
            "description",
        ),
        (
            "school_members",
            "tenant_id",
            "BIGINT",
            false,
            None,
            "school_id",
        ),
        (
            "user_profiles",
            "tenant_id",
            "BIGINT",
            false,
            None,
            "school_id",
        ),
        (
            "leaderboards",
            "tenant_id",
            "BIGINT",
            false,
            None,
            "school_id",
        ),
    ];
    for (spec, expected) in TENANT_SCHOOL_CUTOVER_COLUMNS.iter().zip(expected) {
        assert_eq!(
            (
                spec.table,
                spec.name,
                spec.column_type,
                spec.not_null,
                spec.default,
                spec.after
            ),
            expected
        );
    }
    for spec in &TENANT_SCHOOL_CUTOVER_COLUMNS[1..9] {
        assert_eq!(spec.charset, Some(MYSQL_SCHEMA_CHARSET));
        assert_eq!(spec.collation, Some(MYSQL_MIGRATION_COLLATION));
    }
    for spec in TENANT_SCHOOL_CUTOVER_COLUMNS
        .iter()
        .filter(|spec| !is_character_type(spec.column_type))
    {
        assert_eq!(spec.charset, None);
        assert_eq!(spec.collation, None);
    }
}

#[test]
fn mysql8_compatibility_rejects_unknown_migration_or_changed_historical_sql() {
    let mut unknown = Migration::new(
        20260818009999,
        "unknown".into(),
        sqlx::migrate::MigrationType::Simple,
        "SELECT 1;".into(),
        false,
    );
    assert!(historical_mysql8_compatible_sql(&unknown).is_err());

    let historical = historical_auth_migration();
    unknown.version = historical.version;
    unknown.sql = historical.sql.replace("SELECT 1", "SELECT 2").into();
    assert!(historical_mysql8_compatible_sql(&unknown).is_err());

    let tenant = tenant_school_cutover_migration();
    unknown.version = tenant.version;
    unknown.sql = tenant.sql.replace("org_id BIGINT", "org_id INT").into();
    assert!(historical_mysql8_compatible_sql(&unknown).is_err());
}

#[test]
fn historical_column_matching_is_fail_closed_for_type_or_position_drift() {
    let expected = &AUTH_FAMILY_SESSION_COLUMNS[0];
    let expected_metadata = HistoricalColumnMetadata {
        column_type: expected.column_type.into(),
        nullable: "NO".into(),
        default: expected.default.map(Into::into),
        charset: Some(MYSQL_SCHEMA_CHARSET.into()),
        collation: Some(MYSQL_MIGRATION_COLLATION.into()),
        after: expected.after.into(),
        position_deferred: false,
        position_matches: true,
    };
    assert_eq!(
        historical_column_action(Some(&expected_metadata), expected),
        HistoricalColumnAction::Skip
    );
    assert_eq!(
        historical_column_action(None, expected),
        HistoricalColumnAction::Add
    );
    assert_eq!(
        historical_column_action(
            Some(&HistoricalColumnMetadata {
                after: "status".into(),
                ..expected_metadata.clone()
            }),
            expected
        ),
        HistoricalColumnAction::Fail
    );
    assert_eq!(
        historical_column_action(
            Some(&HistoricalColumnMetadata {
                column_type: "VARCHAR(255)".into(),
                ..expected_metadata.clone()
            }),
            expected
        ),
        HistoricalColumnAction::Fail
    );
}

#[test]
fn tenant_column_action_matrix_is_missing_add_matching_skip_drift_fail() {
    for expected in TENANT_SCHOOL_CUTOVER_COLUMNS {
        assert_eq!(
            historical_column_action(None, expected),
            HistoricalColumnAction::Add,
            "missing {}.{} must be added",
            expected.table,
            expected.name
        );
        let matching = HistoricalColumnMetadata {
            column_type: expected.column_type.into(),
            nullable: if expected.not_null { "NO" } else { "YES" }.into(),
            default: expected.default.map(Into::into),
            charset: expected.charset.map(Into::into),
            collation: expected.collation.map(Into::into),
            after: expected.after.into(),
            position_deferred: false,
            position_matches: true,
        };
        assert_eq!(
            historical_column_action(Some(&matching), expected),
            HistoricalColumnAction::Skip,
            "matching {}.{} must be skipped",
            expected.table,
            expected.name
        );
        assert_eq!(
            historical_column_action(
                Some(&HistoricalColumnMetadata {
                    column_type: "INT".into(),
                    ..matching.clone()
                }),
                expected
            ),
            HistoricalColumnAction::Fail,
            "drifted {}.{} must fail",
            expected.table,
            expected.name
        );
    }
}

#[test]
fn deferred_anchor_metadata_is_safe_only_until_final_position_reinspection() {
    let expected = &TENANT_SCHOOL_CUTOVER_COLUMNS[1];
    let deferred = HistoricalColumnMetadata {
        column_type: expected.column_type.into(),
        nullable: "YES".into(),
        default: None,
        charset: expected.charset.map(Into::into),
        collation: expected.collation.map(Into::into),
        after: String::new(),
        position_deferred: true,
        position_matches: true,
    };
    assert_eq!(
        historical_column_action(Some(&deferred), expected),
        HistoricalColumnAction::Deferred
    );
    assert!(matches!(
        historical_column_action(Some(&deferred), expected),
        HistoricalColumnAction::Deferred
    ));

    let incorrectly_ordered = HistoricalColumnMetadata {
        position_deferred: false,
        position_matches: true,
        after: "status".into(),
        ..deferred
    };
    assert_eq!(
        historical_column_action(Some(&incorrectly_ordered), expected),
        HistoricalColumnAction::Fail
    );
}

#[test]
fn ordered_column_contract_keeps_later_existing_columns_pending_until_anchor_exists() {
    let predecessor = &TENANT_SCHOOL_CUTOVER_COLUMNS[0];
    let later = &TENANT_SCHOOL_CUTOVER_COLUMNS[1];
    assert_eq!(predecessor.name, "org_id");
    assert_eq!(later.after, predecessor.name);

    let later_without_anchor = HistoricalColumnMetadata {
        column_type: later.column_type.into(),
        nullable: "YES".into(),
        default: None,
        charset: later.charset.map(Into::into),
        collation: later.collation.map(Into::into),
        after: String::new(),
        position_deferred: true,
        position_matches: true,
    };
    assert_eq!(
        historical_column_action(Some(&later_without_anchor), later),
        HistoricalColumnAction::Deferred
    );
    assert_eq!(
        historical_column_action(None, predecessor),
        HistoricalColumnAction::Add
    );

    let later_after_anchor = HistoricalColumnMetadata {
        after: predecessor.name.into(),
        position_deferred: false,
        position_matches: true,
        ..later_without_anchor
    };
    assert_eq!(
        historical_column_action(Some(&later_after_anchor), later),
        HistoricalColumnAction::Skip
    );
}

#[test]
fn recorded_cutover_state_distinguishes_complete_from_recoverable_data() {
    assert!(!SchoolTenantCutoverState::Complete.requires_replay());
    assert!(SchoolTenantCutoverState::Recoverable.requires_replay());
    assert_eq!(
        classify_school_tenant_cutover_state(0, 0, false).unwrap(),
        SchoolTenantCutoverState::Complete
    );
    assert_eq!(
        classify_school_tenant_cutover_state(0, 1, false).unwrap(),
        SchoolTenantCutoverState::Recoverable
    );
    assert_eq!(
        classify_school_tenant_cutover_state(0, 0, true).unwrap(),
        SchoolTenantCutoverState::Recoverable
    );
    assert!(classify_school_tenant_cutover_state(1, 0, false).is_err());
    assert!(SCHOOL_TENANT_BACKFILL_CONFLICTS
        .iter()
        .all(|(table, statement)| !table.is_empty() && statement.contains("tenant_id")));
}

#[test]
fn school_cutover_artifact_contract_matches_original_sql() {
    let source = &tenant_school_cutover_migration().sql;
    assert!(source.contains("ENGINE=InnoDB"));
    assert!(source.contains("DEFAULT CHARSET=utf8mb4"));
    assert!(source.contains("uk_school_tenant_migration_tenant"));
    assert!(source.contains("uk_school_tenant_migration_code"));
    assert!(source.contains("idx_school_tenant_migration_status"));
    for (table, constraint, column, referenced_table, referenced_column) in
        REQUIRED_SCHOOL_CUTOVER_FOREIGN_KEYS
    {
        assert!(source.contains(constraint));
        assert!(source.contains(&format!(
            "FOREIGN KEY ({column}) REFERENCES {referenced_table} ({referenced_column})"
        )));
        assert_eq!(*table, "school_tenant_migration");
    }
    assert!(SCHEMA_TABLE_ENGINE_CONTRACT_SQL.contains("CAST(t.ENGINE AS BINARY)"));
    assert!(SCHEMA_FOREIGN_KEY_CONTRACT_SQL.contains("COALESCE(SUM"));
    assert!(SCHEMA_FOREIGN_KEY_CONTRACT_SQL.contains("CAST(r.DELETE_RULE AS BINARY)"));
}

#[test]
fn school_cutover_contract_covers_original_artifacts_and_backfill_inputs() {
    assert_eq!(SCHOOL_TENANT_MIGRATION_COLUMN_CONTRACT.len(), 7);
    let required_indexes: Vec<(&str, &str, Vec<&str>, bool)> = REQUIRED_SCHOOL_CUTOVER_INDEXES
        .iter()
        .map(|(table, index, columns, unique)| (*table, *index, columns.to_vec(), *unique))
        .collect();
    assert_eq!(
        required_indexes,
        vec![
            (
                "school_tenant_migration",
                "PRIMARY",
                vec!["school_id"],
                true
            ),
            (
                "school_tenant_migration",
                "uk_school_tenant_migration_tenant",
                vec!["tenant_id"],
                true,
            ),
            (
                "school_tenant_migration",
                "uk_school_tenant_migration_code",
                vec!["tenant_code"],
                true,
            ),
            (
                "school_tenant_migration",
                "idx_school_tenant_migration_status",
                vec!["migration_status"],
                false,
            ),
            (
                "school_members",
                "idx_school_members_tenant",
                vec!["tenant_id"],
                false,
            ),
            (
                "user_profiles",
                "idx_user_profiles_tenant",
                vec!["tenant_id"],
                false,
            ),
            (
                "leaderboards",
                "idx_leaderboards_tenant",
                vec!["tenant_id"],
                false,
            ),
        ]
    );
    let source = &tenant_school_cutover_migration().sql;
    for required in [
        "CREATE TABLE IF NOT EXISTS school_tenant_migration",
        "migration_status VARCHAR(32) NOT NULL DEFAULT 'MIGRATED'",
        "migrated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        "verified_at DATETIME NULL",
        "rollback_note VARCHAR(512) NULL",
        "UPDATE schools s",
        "UPDATE school_members sm",
        "UPDATE user_profiles upf",
        "UPDATE leaderboards lb",
    ] {
        assert!(
            source.contains(required),
            "missing cutover artifact {required}"
        );
    }
}

#[test]
fn cutover_conflict_queries_refuse_existing_non_null_assignments() {
    for (table, statement) in SCHOOL_TENANT_BACKFILL_CONFLICTS {
        assert!(
            statement.contains("IS NOT NULL"),
            "{table} must check non-null assignments"
        );
        assert!(
            statement.contains("<>"),
            "{table} must check mismatched assignments"
        );
        assert!(
            statement.contains("CONCAT('SCHOOL-'"),
            "{table} must use deterministic codes"
        );
    }
}

#[test]
fn ordinary_startup_contract_does_not_require_school_cutover_columns() {
    assert!(!REQUIRED_SCHEMA_COLUMNS.iter().any(|(table, columns)| {
        (*table == "tenant" && columns.contains(&"org_id"))
            || (*table == "school_members" && columns.contains(&"tenant_id"))
            || (*table == "user_profiles" && columns.contains(&"tenant_id"))
            || (*table == "leaderboards" && columns.contains(&"tenant_id"))
    }));
    assert!(HISTORICAL_MIGRATION_COMPATIBILITY
        .iter()
        .any(|contract| contract.version == TENANT_SCHOOL_CUTOVER_VERSION));
}

fn baseline_versions() -> HashSet<i64> {
    MIGRATOR
        .migrations
        .iter()
        .filter(|migration| is_java_baseline_era(migration.version))
        .map(|migration| migration.version)
        .collect()
}

#[test]
fn character_metadata_validation_requires_mysql8_collation_for_text_types() {
    let expected = &AUTH_FAMILY_SESSION_COLUMNS[0];
    assert!(validate_character_metadata(
        "VARCHAR(32)",
        Some(MYSQL_SCHEMA_CHARSET),
        Some(MYSQL_MIGRATION_COLLATION),
        expected
    ));
    assert_eq!(
        expected_character_set_clause(expected),
        " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
    );
    for (charset, collation) in [
        (Some(MYSQL_SCHEMA_CHARSET), Some(MYSQL_SCHEMA_COLLATION)),
        (Some(MYSQL_SCHEMA_CHARSET), Some("utf8mb4_unknown_ci")),
        (Some(MYSQL_SCHEMA_CHARSET), None),
        (Some("binary"), Some("binary")),
    ] {
        assert!(!validate_character_metadata(
            "VARCHAR(32)",
            charset,
            collation,
            expected
        ));
    }
}

#[test]
fn non_character_metadata_requires_null_or_empty_names() {
    let expected = &AUTH_FAMILY_SESSION_COLUMNS[1];
    assert!(validate_character_metadata("BIGINT", None, None, expected));
    assert_eq!(expected_character_set_clause(expected), "");
    assert!(validate_character_metadata(
        "BIGINT",
        Some(""),
        Some(""),
        expected
    ));
    for (charset, collation) in [
        (Some(MYSQL_SCHEMA_CHARSET), None),
        (None, Some(MYSQL_MIGRATION_COLLATION)),
        (Some("binary"), Some("binary")),
        (Some("unknown"), Some("")),
    ] {
        assert!(!validate_character_metadata(
            "BIGINT", charset, collation, expected
        ));
    }
    assert!(!validate_character_metadata(
        "BINARY(32)",
        Some("binary"),
        None,
        expected
    ));
    assert!(!validate_character_metadata(
        "BLOB",
        None,
        Some("binary"),
        expected
    ));
}

#[test]
fn migration_and_service_connection_options_are_separate() {
    let database_url = "mysql://user:password@localhost/astral_test";
    let service_options = mysql_connection_options(database_url).expect("test URL must parse");
    let migration_options =
        mysql_migration_connection_options(database_url).expect("test URL must parse");

    assert!(mysql_pool_options().get_max_connections() >= 1);
    assert!(mysql_migration_pool_options().get_max_connections() >= 1);
    assert_eq!(service_options.get_charset(), MYSQL_SCHEMA_CHARSET);
    assert_eq!(
        service_options.get_collation(),
        Some(MYSQL_SCHEMA_COLLATION)
    );
    assert_eq!(migration_options.get_charset(), MYSQL_SCHEMA_CHARSET);
    assert_eq!(
        migration_options.get_collation(),
        Some(MYSQL_MIGRATION_COLLATION)
    );
    assert_ne!(
        service_options.get_collation(),
        migration_options.get_collation()
    );
}

#[test]
fn isolated_migration_gate_rejects_non_isolated_or_wrong_transport_targets() {
    std::env::set_var("ASTRAL_MIGRATION_ENV", ISOLATED_MIGRATION_ENV);
    assert!(
        ensure_isolated_migration_target("mysql://user:password@localhost:3308/astral_test")
            .is_ok()
    );
    assert!(ensure_isolated_migration_target(
        "mysql://user:password@127.0.0.1:3308/astral_rehearsal"
    )
    .is_ok());
    assert!(
        ensure_isolated_migration_target("mysql://user:password@[::1]:3308/astral_test").is_ok()
    );
    assert!(
        ensure_isolated_migration_target("mysql://user:password@[::1]:3308/astral_rehearsal")
            .is_ok()
    );
    assert!(ensure_isolated_migration_target(
        "mysql://user:password@localhost:3308/astral_production"
    )
    .is_err());
    assert!(ensure_isolated_migration_target("mysql://user:password@db:3308/astral_test").is_err());
    assert!(ensure_isolated_migration_target(
        "mysql://user:password@[2001:db8::1]:3308/astral_test"
    )
    .is_err());
    assert!(ensure_isolated_migration_target(
        "mysql://user:password@[::ffff:127.0.0.1]:3308/astral_test"
    )
    .is_err());
    assert!(
        ensure_isolated_migration_target("mysql://user:password@[::]:3308/astral_test").is_err()
    );
    assert!(
        ensure_isolated_migration_target("mysql://user:password@[::1]:3306/astral_test").is_err()
    );
    assert!(
        ensure_isolated_migration_target("mysql://user:password@localhost:3306/astral_test")
            .is_err()
    );
    assert!(
        ensure_isolated_migration_target("mysql://user:password@::1:3308/astral_test").is_err()
    );
    std::env::remove_var("ASTRAL_MIGRATION_ENV");
    assert!(
        ensure_isolated_migration_target("mysql://user:password@localhost:3308/astral_test")
            .is_err()
    );
}

#[test]
fn baseline_adoption_excludes_auth_family_compatibility_step() {
    // 默认拒绝结构：auth-family 是 Rust-owned 兼容步骤（2026 时代），
    // 基线采纳永不记录，必须保持 pending 由 SQLx 执行。
    assert!(!is_java_baseline_era(AUTH_FAMILY_SCHEMA_CONTRACT_VERSION));
    assert!(!baseline_versions().contains(&AUTH_FAMILY_SCHEMA_CONTRACT_VERSION));
}

#[test]
fn migration_session_contract_is_explicit_and_utc() {
    assert_eq!(
        MIGRATION_SET_NAMES_SQL,
        "SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci"
    );
    assert_eq!(
        MIGRATION_SET_COLLATION_CONNECTION_SQL,
        "SET collation_connection = 'utf8mb4_0900_ai_ci'"
    );
    assert_eq!(SET_UTC_TIME_ZONE_SQL, "SET time_zone = '+00:00'");
}

#[test]
fn historical_migration_checksum_source_remains_unchanged() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == 20260714000001)
        .expect("historical auth migration must remain embedded");

    assert!(migration
        .sql
        .contains("JOIN auth_token_family f ON CAST(s.family_id AS CHAR) = f.family_key"));
    assert!(!migration.sql.contains("SET NAMES"));
    let historical_sql =
        include_bytes!("../../migrations/20260714000001_auth_family_schema_contract.sql");
    assert_eq!(
        canonical_sha384_hex(historical_sql),
        AUTH_FAMILY_SCHEMA_CONTRACT_SQL_SHA384
    );
    assert_eq!(
        format!(
            "{:x}",
            sha2::Sha256::digest(canonical_lf_bytes(historical_sql))
        ),
        "1bca9d2da41eeed5c3e27e19a90fe0b7ddf431a7e6d5f6b7e46e08e5baafb4bf"
    );
}

#[test]
fn canonical_hash_is_identical_for_lf_and_crlf_source() {
    let lf = b"SELECT 1;\nSELECT 2;\n";
    let crlf = b"SELECT 1;\r\nSELECT 2;\r\n";
    assert_eq!(canonical_lf_bytes(lf), canonical_lf_bytes(crlf));
    assert_eq!(canonical_sha384_hex(lf), canonical_sha384_hex(crlf));
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(canonical_lf_bytes(lf))),
        format!("{:x}", sha2::Sha256::digest(canonical_lf_bytes(crlf)))
    );
}

#[test]
fn compatibility_rewrite_does_not_change_sqlx_source_checksum() {
    for migration in [
        historical_auth_migration(),
        auth_session_resilience_migration(),
        tenant_school_cutover_migration(),
    ] {
        let raw_checksum = migration.checksum.as_ref().to_vec();
        let compatible = historical_mysql8_compatible_sql(migration).unwrap();
        assert_ne!(compatible.as_bytes(), migration.sql.as_bytes());
        assert_eq!(migration.checksum.as_ref(), raw_checksum.as_slice());
        let contract = historical_migration_compatibility(migration.version).unwrap();
        assert_eq!(
            canonical_sha384_hex(migration.sql.as_bytes()),
            contract.source_sha384
        );
    }
}

#[test]
fn five_chain_migrations_are_pinned_and_own_only_declared_artifacts() {
    let expected: [(i64, &str, &str); 5] = [
        (
            IDENTITY_CREDENTIAL_FENCE_VERSION,
            IDENTITY_CREDENTIAL_FENCE_SQL_SHA384,
            IDENTITY_CREDENTIAL_FENCE_MIGRATION_SQL,
        ),
        (
            ASYNC_OPERATION_CORRELATION_VERSION,
            ASYNC_OPERATION_CORRELATION_SQL_SHA384,
            ASYNC_OPERATION_CORRELATION_MIGRATION_SQL,
        ),
        (
            REVIEW_SCHEMA_REPAIR_VERSION,
            REVIEW_SCHEMA_REPAIR_SQL_SHA384,
            REVIEW_SCHEMA_REPAIR_MIGRATION_SQL,
        ),
        (
            CHAT_DELIVERY_INTENT_VERSION,
            CHAT_DELIVERY_INTENT_SQL_SHA384,
            CHAT_DELIVERY_INTENT_MIGRATION_SQL,
        ),
        (
            LEARN_SYSTEM_ASSIGNMENT_VERSION,
            LEARN_SYSTEM_ASSIGNMENT_SQL_SHA384,
            LEARN_SYSTEM_ASSIGNMENT_MIGRATION_SQL,
        ),
    ];
    assert_eq!(REVIEW_SLICE_MIGRATION_VERSIONS.len(), expected.len());
    for (version, sha384, source) in expected {
        let migration = MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == version)
            .unwrap_or_else(|| panic!("migration {version} must remain embedded"));
        let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
            .iter()
            .find(|contract| contract.version == version)
            .unwrap_or_else(|| panic!("migration {version} needs exact artifact contract"));
        assert_eq!(canonical_sha384_hex(source.as_bytes()), sha384);
        assert_eq!(canonical_sha384_hex(migration.sql.as_bytes()), sha384);
        assert_eq!(contract.source_sha384, sha384);
        assert!(migration_matches_known_source(migration));
        assert!(exact_migration_artifact_contract(migration).is_some());
        assert!(!is_java_baseline_era(version));
        for table in contract.tables {
            assert!(
                migration_defines_table(migration, table),
                "{version} must own declared table {table}"
            );
        }
        for (table, column) in contract.columns {
            assert!(
                migration_defines_column(migration, table, column),
                "{version} must own declared column {table}.{column}"
            );
        }
        for (table, index, columns, unique) in contract.indexes {
            assert!(
                migration_defines_index(migration, table, index, columns, *unique),
                "{version} must own declared index {table}.{index}"
            );
        }
    }

    let identity = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == IDENTITY_CREDENTIAL_FENCE_VERSION)
        .unwrap();
    assert!(EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == IDENTITY_CREDENTIAL_FENCE_VERSION)
        .unwrap()
        .tables
        .is_empty());
    assert!(!pending_migration_can_create_table(
        &HashSet::new(),
        std::slice::from_ref(identity),
        "user_local_credential"
    ));
    assert!(pending_migration_can_own_column(
        &HashSet::new(),
        std::slice::from_ref(identity),
        "user_local_credential",
        "credential_version",
        false
    ));
    assert!(!pending_migration_can_own_column(
        &HashSet::new(),
        std::slice::from_ref(identity),
        "user_local_credential",
        "password_hash",
        false
    ));

    let repair = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == REVIEW_SCHEMA_REPAIR_VERSION)
        .unwrap();
    assert!(pending_migration_can_own_index(
        &HashSet::new(),
        std::slice::from_ref(repair),
        "org_scope_operation",
        "PRIMARY",
        &["operation_id"],
        true,
        false
    ));
    assert!(!pending_migration_can_own_index(
        &HashSet::new(),
        std::slice::from_ref(repair),
        "org_scope_operation",
        "idx_osop_tenant",
        &["tenant_id", "created_at"],
        false,
        false
    ));
    assert!(!pending_migration_can_create_table(
        &HashSet::new(),
        std::slice::from_ref(repair),
        "org_scope_operation"
    ));
    assert!(REVIEW_SCHEMA_REPAIR_MIGRATION_SQL.contains("INSERT INTO al_message_scope_counter"));
    assert!(REVIEW_SCHEMA_REPAIR_MIGRATION_SQL
        .contains("GREATEST(last_sequence, VALUES(last_sequence))"));
    assert!(!REVIEW_SCHEMA_REPAIR_MIGRATION_SQL.contains("DELETE FROM al_message_scope_counter"));

    let chat = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == CHAT_DELIVERY_INTENT_VERSION)
        .unwrap();
    for table in CHAT_DELIVERY_INTENT_TABLES {
        assert!(pending_migration_can_create_table(
            &HashSet::new(),
            std::slice::from_ref(chat),
            table
        ));
    }
    let mut chat_recorded = HashSet::new();
    chat_recorded.insert(CHAT_DELIVERY_INTENT_VERSION);
    assert!(!pending_migration_can_create_table(
        &chat_recorded,
        std::slice::from_ref(chat),
        CHAT_DELIVERY_INTENT_TABLES[0]
    ));
    assert!(!pending_migration_can_own_index(
        &chat_recorded,
        std::slice::from_ref(chat),
        "chat_delivery_intent",
        "uk_chat_delivery_intent_scope_client",
        &["scope_key_sha256", "client_msg_id"],
        true,
        false
    ));

    let proof_creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == CROSS_CITY_RUNTIME_PROOF_VERSION)
        .unwrap();
    let proof_table = CROSS_CITY_RUNTIME_PROOF_TABLES[0];
    assert!(pending_migration_can_create_table(
        &HashSet::new(),
        std::slice::from_ref(proof_creator),
        proof_table
    ));
    let mut proof_recorded = HashSet::new();
    proof_recorded.insert(CROSS_CITY_RUNTIME_PROOF_VERSION);
    assert!(!pending_migration_can_create_table(
        &proof_recorded,
        std::slice::from_ref(proof_creator),
        proof_table
    ));
}

#[test]
fn review_runtime_and_preflight_keep_optional_owners_separate() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let runtime = production
        .split("async fn validate_review_runtime_schema")
        .nth(1)
        .and_then(|body| body.split("fn review_migration_pending").next())
        .expect("review runtime validator");
    assert!(!runtime.contains("LEARN_SYSTEM_ASSIGNMENT"));
    assert!(!runtime.contains("CHAT_DELIVERY_INTENT"));
    assert!(!runtime.contains("ORG_SCOPE_OPERATION"));
    assert!(!runtime.contains("CROSS_CITY"));

    let schema = production
        .split("pub async fn validate_schema_contract")
        .nth(1)
        .and_then(|body| {
            body.split("async fn validate_decommissionable_snapshot_column_contracts")
                .next()
        })
        .expect("global schema validator");
    assert!(!schema.contains("CROSS_CITY_SCHEMA_INDEXES"));
    assert!(!schema.contains("LEARN_SYSTEM_ASSIGNMENT"));
    assert!(!schema.contains("CHAT_DELIVERY_INTENT"));
    assert!(schema.contains("validate_review_runtime_schema(pool).await?"));

    let cross_city = production
        .split("pub async fn validate_cross_city_runtime_schema")
        .nth(1)
        .and_then(|body| {
            body.split("async fn validate_cross_city_authority_scope_rows")
                .next()
        })
        .expect("cross-city enabled runtime validator");
    assert!(cross_city.contains("validate_cross_city_schema_contract(pool).await?"));
    assert!(cross_city.contains("validate_cross_city_runtime_proof_table_contract"));

    let preflight = production
        .split("async fn preflight_review_schema_contracts")
        .nth(1)
        .and_then(|body| body.split("pub async fn validate_schema_contract").next())
        .expect("review preflight validator");
    assert!(preflight.contains("LEARN_SYSTEM_ASSIGNMENT_COLUMNS"));
    assert!(preflight.contains("CHAT_DELIVERY_INTENT_TABLES"));
    assert!(preflight.contains("CROSS_CITY_RUNTIME_PROOF_TABLES"));
    assert!(preflight.contains("preflight_review_table"));
}

#[test]
fn learn_system_role_schema_contract_is_explicit_and_non_inferential() {
    let creator = LEARN_ASSIGNMENT_CREATOR_MIGRATION_SQL;
    assert!(creator.contains("CREATE TABLE IF NOT EXISTS learn_assignment"));
    assert!(!creator.contains("system_role"));

    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == LEARN_SYSTEM_ASSIGNMENT_VERSION)
        .expect("Learn marker migration must remain embedded");
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        LEARN_SYSTEM_ASSIGNMENT_SQL_SHA384
    );
    assert!(LEARN_SYSTEM_ASSIGNMENT_MIGRATION_SQL.contains(
        "system_role VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL"
    ));
    assert!(LEARN_SYSTEM_ASSIGNMENT_MIGRATION_SQL.contains(
        "ADD UNIQUE KEY uk_learn_assignment_course_system_role (course_id, system_role)"
    ));
    assert!(!LEARN_SYSTEM_ASSIGNMENT_MIGRATION_SQL.contains("UPDATE learn_assignment"));
    assert!(!LEARN_SYSTEM_ASSIGNMENT_MIGRATION_SQL.contains("DELETE FROM learn_assignment"));
    let creator = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == LEARN_ASSIGNMENT_CREATOR_VERSION)
        .expect("Learn assignment creator must remain embedded");
    assert!(pending_migration_can_create_table(
        &HashSet::new(),
        std::slice::from_ref(creator),
        "learn_assignment"
    ));
    let mut creator_recorded = HashSet::new();
    creator_recorded.insert(LEARN_ASSIGNMENT_CREATOR_VERSION);
    assert!(!pending_migration_can_create_table(
        &creator_recorded,
        std::slice::from_ref(creator),
        "learn_assignment"
    ));
    let marker = LEARN_SYSTEM_ASSIGNMENT_COLUMNS[0];
    assert_eq!(marker.table, "learn_assignment");
    assert_eq!(marker.name, "system_role");
    assert_eq!(marker.column_type, "VARCHAR(32)");
    assert!(!marker.not_null);
    assert_eq!(marker.default, None);
    assert_eq!(marker.collation, Some("utf8mb4_bin"));
    assert_eq!(
        LEARN_SYSTEM_ASSIGNMENT_INDEXES[0].2,
        &["course_id", "system_role"]
    );
    assert!(LEARN_SYSTEM_ASSIGNMENT_INDEXES[0].3);
    assert!(column_default_matches(None, None));
    const { assert!(LEARN_ASSIGNMENT_CREATOR_VERSION < LEARN_SYSTEM_ASSIGNMENT_VERSION) };
}

#[test]
fn column_default_normalization_accepts_mysql_expression_parentheses_only() {
    assert!(column_default_matches(
        Some("UNIX_TIMESTAMP()"),
        Some("(UNIX_TIMESTAMP())")
    ));
    assert!(column_default_matches(
        Some("(UNIX_TIMESTAMP())"),
        Some("UNIX_TIMESTAMP()")
    ));
    assert!(column_default_matches(
        Some("CURRENT_TIMESTAMP(6)"),
        Some("(CURRENT_TIMESTAMP(6))")
    ));
    assert!(column_default_matches(
        Some("(CURRENT_TIMESTAMP(6))"),
        Some("CURRENT_TIMESTAMP(6)")
    ));
    assert!(column_default_matches(
        Some("CURRENT_TIMESTAMP(6)"),
        Some("CURRENT_TIMESTAMP(6)")
    ));
    assert!(!column_default_matches(
        Some("CURRENT_TIMESTAMP(3)"),
        Some("CURRENT_TIMESTAMP(6)")
    ));
    assert!(!column_default_matches(Some("0"), Some("UNIX_TIMESTAMP()")));
    assert!(normalize_schema_source_default_contracts());
}

#[test]
fn review_preflight_and_destructive_gate_precede_history_writes_and_sqlx() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let apply = production
        .split("pub async fn apply_migrations(database_url")
        .nth(1)
        .and_then(|body| {
            body.split("pub async fn connect_and_validate_schema")
                .next()
        })
        .expect("migration apply body");
    let standby = apply
        .find("preflight_standby_migration_gate(&pool, &HashSet::new()")
        .expect("initial standby source/auth gate must run");
    let history_ddl = apply
        .find("CREATE TABLE IF NOT EXISTS _sqlx_migrations")
        .expect("migration history DDL");
    assert!(standby < history_ddl);
    let baseline_adoption = apply
        .find("preflight_before_baseline_adoption(&pool).await?")
        .expect("baseline preflight");
    let record_baseline = apply
        .find("record_verified_baseline(&pool, &recorded_versions).await?")
        .expect("baseline adoption");
    let sqlx_run = apply
        .find("apply_migrations_with_mysql8_compat(&pool).await?")
        .expect("SQLx migration run");
    assert!(history_ddl < baseline_adoption && baseline_adoption < record_baseline);
    assert!(record_baseline < sqlx_run);
    assert_eq!(
        DESTRUCTIVE_MIGRATION_ALLOWLIST_ENV,
        "ASTRAL_DESTRUCTIVE_MIGRATION_ALLOWLIST"
    );
    assert_eq!(
        DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ENV,
        "ASTRAL_DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ID"
    );
    assert_eq!(
        DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ENV,
        "ASTRAL_DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ID"
    );
    assert_eq!(
        DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ENV,
        "ASTRAL_DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ID"
    );
    assert!(DESTRUCTIVE_MIGRATION_DRAIN_SQL.contains("status = 'PENDING'"));
    assert!(DESTRUCTIVE_MIGRATION_DRAIN_SQL.contains("aggregate_type IN ('CARD', 'RULE_SET')"));
}

#[test]
fn empty_history_adopts_only_with_verified_baseline() {
    let empty = HashSet::new();

    assert_eq!(
        classify_migration_history(&empty),
        MigrationHistoryState::Empty
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::Empty, true),
        MigrationHistoryDecision::AdoptBaseline
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::Empty, false),
        MigrationHistoryDecision::FailClosed
    );
}

#[test]
fn complete_baseline_history_continues_without_replaying_baseline() {
    let complete = baseline_versions();

    assert_eq!(
        classify_migration_history(&complete),
        MigrationHistoryState::BaselineComplete
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::BaselineComplete, true),
        MigrationHistoryDecision::Continue
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::BaselineComplete, false),
        MigrationHistoryDecision::Continue
    );
}

#[test]
fn partial_history_fails_closed_instead_of_running_old_baseline_ddl() {
    let mut partial = baseline_versions();
    let missing = *partial.iter().next().expect("baseline must not be empty");
    partial.remove(&missing);

    assert_eq!(
        classify_migration_history(&partial),
        MigrationHistoryState::BaselineIncomplete
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::BaselineIncomplete, true),
        MigrationHistoryDecision::FailClosed
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::BaselineIncomplete, false),
        MigrationHistoryDecision::FailClosed
    );
}

#[test]
fn post_baseline_versions_remain_pending_after_baseline_adoption() {
    let recorded = baseline_versions();
    // 最新 Rust-owned 增量必须仍在基线集合之外（保持 pending，SQLx 执行）。
    let latest = MIGRATOR
        .migrations
        .iter()
        .map(|migration| migration.version)
        .max()
        .expect("embedded migrations must exist");
    assert!(
        !recorded.contains(&latest),
        "post-baseline migration {latest} must not be adopted"
    );
    for version in REVIEW_SLICE_MIGRATION_VERSIONS {
        assert!(!recorded.contains(version));
    }

    assert_eq!(
        classify_migration_history(&recorded),
        MigrationHistoryState::BaselineComplete
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::BaselineComplete, true),
        MigrationHistoryDecision::Continue
    );
}

/// 默认拒绝不变式：基线采纳的可记录集合**恰好**是 Java 基线时代（20240630
/// 系列）——所有 Rust-owned 增量（2026 系列）都不会被记为已应用，天然保持
/// pending 并由 SQLx 执行。
#[test]
fn verified_baseline_adoption_records_exactly_the_java_era() {
    let recorded = baseline_versions();
    let java_era: HashSet<i64> = MIGRATOR
        .migrations
        .iter()
        .map(|migration| migration.version)
        .filter(|version| is_java_baseline_era(*version))
        .collect();

    assert!(
        !java_era.is_empty(),
        "Java baseline era migrations must exist"
    );
    assert_eq!(recorded, java_era);
    for version in &java_era {
        assert_eq!(version / 1_000_000, 20240630, "era prefix drift: {version}");
    }
}

/// 基线采纳守卫（防再犯，20260831000001 教训）：`record_verified_baseline`
/// 必须保持默认拒绝结构——以 `!is_java_baseline_era` 门禁跳过 Rust-owned
/// 增量，绝不依据人工维护的允许清单扩大记录范围；清单漏登记曾使新鲜库上
/// 的新迁移被静默吞掉（记录成功、schema 缺增量、无任何报错）。
#[test]
fn record_verified_baseline_is_default_deny_for_post_baseline_migrations() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("test module must be separable");
    let body = production
        .split("async fn record_verified_baseline")
        .nth(1)
        .and_then(|rest| rest.split("async fn ").next())
        .expect("record_verified_baseline implementation must exist");
    assert!(
        body.contains("!is_java_baseline_era(migration.version)"),
        "baseline adoption must skip every non-Java-era migration by default; \
             a manually-maintained allowlist is what silently swallowed 20260831000001"
    );
    // 20260922000001 is the current chain tail: the org-scope authority
    // tables must not be silently omitted from the embedded migrator.
    // 20260929000001 is the AL-native local transport tail. It must remain
    // embedded and must never be adopted as part of the Java baseline.
    // 20261001000002 is the cross-city runtime-proof tail (node keys,
    // durable replay reservations, commit receipts, activation mint
    // records, authority scopes). It must remain embedded and must never
    // be adopted as part of the Java baseline either; the outbox pin
    // below therefore becomes a containment pin, and the exact tail pin
    // moves to the runtime-proof migration.
    // 20261001000005 is the current chain tail (invalidation scope
    // sequence, after the MQ consumer durable lease 000003 and the
    // invalidation inbox 000004 — the Redis-free runtime path's additive
    // tail). The exact tail pin therefore moves to the scope-sequence
    // migration; the runtime-proof pin below becomes a containment pin.
    assert!(
        MIGRATOR
            .migrations
            .iter()
            .map(|migration| migration.version)
            .max()
            .is_some_and(|tail| tail >= AL_MESSAGE_OUTBOX_VERSION),
        "the AL message outbox migration must remain embedded in the migrator"
    );
    assert!(!is_java_baseline_era(AL_MESSAGE_OUTBOX_VERSION));
    assert!(
        AL_MESSAGE_OUTBOX_MIGRATION_SQL.contains("CREATE TABLE IF NOT EXISTS al_message_outbox")
    );
    assert!(AL_MESSAGE_OUTBOX_MIGRATION_SQL.contains("uk_al_message_queue_message"));
    assert_eq!(
        MIGRATOR
            .migrations
            .iter()
            .map(|migration| migration.version)
            .max(),
        Some(20261005000001),
        "the SDK identity mapping migration is the current chain tail"
    );
    assert!(!is_java_baseline_era(20261005000001));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|m| m.version == REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION));
    assert!(!is_java_baseline_era(CROSS_CITY_RUNTIME_PROOF_VERSION));
    assert!(!is_java_baseline_era(RUNTIME_REDIS_FREE_TAIL_VERSION));
    assert!(
        MIGRATOR
            .migrations
            .iter()
            .map(|migration| migration.version)
            .max()
            .is_some_and(|tail| tail >= CROSS_CITY_RUNTIME_PROOF_VERSION),
        "the cross-city runtime-proof migration must remain embedded in the migrator"
    );
    assert!(MQ_IDEMPOTENCY_LEASE_MIGRATION_SQL.contains("mq_consumer_lease"));
    assert!(!RUNTIME_REDIS_FREE_TAIL_MIGRATION_SQL.is_empty());
    // 20261001000001..00005（Redis-free 运行路径 additive 切片）：除聚合尾
    // 钉之外，每个版本都必须单独保持 embedded 且绝不被 Java baseline 采纳
    // （防止聚合断言掩盖单个迁移被遗漏/静默吸收的回归）。
    for version in [
        AUTH_INTERNAL_REQUEST_GUARD_VERSION,
        CROSS_CITY_RUNTIME_PROOF_VERSION,
        MQ_IDEMPOTENCY_LEASE_VERSION,
        INVALIDATION_INBOX_VERSION,
        RUNTIME_REDIS_FREE_TAIL_VERSION,
    ] {
        assert!(
            MIGRATOR
                .migrations
                .iter()
                .any(|migration| migration.version == version),
            "migration {version} must remain embedded in the migrator"
        );
        assert!(
            !is_java_baseline_era(version),
            "migration {version} must never be adopted as part of the Java baseline"
        );
    }
    // 切片完整性：20261001000001..00005 必须全部存在、各出现一次
    // （sqlx::migrate! 按文件名嵌入，重复版本号会在编译期就失败，
    // 这里锚定五版本齐全且无漂移）。
    let mut embedded_20261001_slice: Vec<i64> = MIGRATOR
        .migrations
        .iter()
        .map(|migration| migration.version)
        .filter(|version| (20261001000001..=20261001000005).contains(version))
        .collect();
    embedded_20261001_slice.sort_unstable();
    assert_eq!(
        embedded_20261001_slice,
        vec![
            20261001000001,
            20261001000002,
            20261001000003,
            20261001000004,
            20261001000005,
        ],
        "the 20261001 Redis-free additive slice must be complete and unique"
    );
    assert!(AUTH_INTERNAL_REQUEST_GUARD_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS auth_internal_request_guard"));
    assert!(INVALIDATION_INBOX_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS authorization_invalidation_inbox"));
    assert!(RUNTIME_REDIS_FREE_TAIL_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS al_message_scope_counter"));
    assert!(CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS authorization_cross_city_node_key"));
    assert!(CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS authorization_cross_city_vote_reservation"));
    assert!(CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS authorization_cross_city_commit_receipt"));
    assert!(CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS authorization_cross_city_operation_activation"));
    assert!(CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL
        .contains("CREATE TABLE IF NOT EXISTS authorization_cross_city_authority_scope"));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == CROSS_CITY_RUNTIME_PROOF_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == CROSS_CITY_SCHEMA_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == HEAD_PROJECTION_STATUS_RETIREMENT_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == DELTA_CLAIM_GRANT_CHAIN_INDEX_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == AUTHORIZATION_PROJECTION_PARTITION_LEASE_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == ORG_SCOPE_AUTHORITY_VERSION));
}

#[test]
fn metadata_verification_never_decodes_information_schema_names_as_strings() {
    for query in [
        SCHEMA_TABLE_EXISTS_SQL,
        SCHEMA_COLUMN_EXISTS_SQL,
        SCHEMA_INDEX_STATS_SQL,
        SCHEMA_INDEX_COLUMN_EXISTS_SQL,
        SCHEMA_TABLE_CONTRACT_SQL,
        SCHEMA_KEY_COLUMN_CONTRACT_SQL,
    ] {
        assert!(query.contains("COUNT("));
        assert!(query.contains("CAST("));
    }
    assert!(SCHEMA_COLUMN_METADATA_SQL.contains("CAST(COLUMN_NAME AS BINARY)"));
    assert!(SCHEMA_COLUMN_METADATA_SQL.contains("CAST(COLUMN_TYPE AS BINARY)"));
    assert!(SCHEMA_COLUMN_METADATA_SQL.contains("CAST(COLUMN_DEFAULT AS BINARY)"));
    assert!(!SCHEMA_TABLE_EXISTS_SQL.contains("SELECT TABLE_NAME"));
    assert!(!SCHEMA_COLUMN_EXISTS_SQL.contains("SELECT COLUMN_NAME"));
    assert!(!SCHEMA_INDEX_COLUMN_EXISTS_SQL.contains("SELECT COLUMN_NAME"));
    assert!(HISTORICAL_COLUMN_METADATA_SQL.contains("AS BINARY"));
    assert!(HISTORICAL_COLUMN_POSITION_SQL.contains("AS BINARY"));
    assert!(MIGRATION_COLUMN_EXISTS_SQL.contains("AS BINARY"));
}

#[test]
fn verified_baseline_checks_every_java_table_contract_without_schema_shortcuts() {
    assert_eq!(VERIFIED_BASELINE_TABLES.len(), 16);
    for contract in VERIFIED_BASELINE_TABLES {
        assert!(!contract.table.is_empty());
        assert!(!contract.key_column.is_empty());
        assert_eq!(contract.key_type, "BIGINT");
        assert_eq!(contract.charset, "utf8mb4");
        assert!(contract.collation.starts_with("utf8mb4_"));
    }
    assert!(SCHEMA_TABLE_CONTRACT_SQL.contains("CAST(t.TABLE_TYPE AS BINARY)"));
    assert!(SCHEMA_TABLE_CONTRACT_SQL.contains("CAST(c.CHARACTER_SET_NAME AS BINARY)"));
    assert!(SCHEMA_TABLE_CONTRACT_SQL.contains("CAST(t.TABLE_COLLATION AS BINARY)"));
    assert!(SCHEMA_KEY_COLUMN_CONTRACT_SQL.contains("CAST(COLUMN_KEY AS BINARY)"));
    assert!(SCHEMA_KEY_COLUMN_CONTRACT_SQL.contains("CAST(IS_NULLABLE AS BINARY)"));
    assert!(SCHEMA_KEY_COLUMN_CONTRACT_SQL.contains("COLUMN_TYPE AS CHAR CHARACTER SET utf8mb4"));
}

#[test]
fn index_metadata_verification_preserves_exact_shape_and_uniqueness() {
    assert!(SCHEMA_INDEX_STATS_SQL.contains("MIN(NON_UNIQUE)"));
    assert!(SCHEMA_INDEX_STATS_SQL.contains("MAX(NON_UNIQUE)"));
    assert!(SCHEMA_INDEX_COLUMN_EXISTS_SQL.contains("SEQ_IN_INDEX = ?"));
    assert!(SCHEMA_INDEX_COLUMN_EXISTS_SQL.contains("CAST(COLUMN_NAME AS BINARY)"));
}

#[test]
fn metadata_bytes_decode_fail_closed_and_historical_contract_checks_charset() {
    assert!(metadata_text("COLUMN_TYPE", b"VARCHAR(32)", "t", "c").is_ok());
    assert!(metadata_text("COLUMN_TYPE", &[0xff], "t", "c").is_err());
    assert!(AUTH_FAMILY_SESSION_COLUMNS[0].charset.is_some());
    assert!(AUTH_FAMILY_SESSION_COLUMNS[0].collation.is_some());
    assert!(AUTH_FAMILY_SESSION_COLUMNS[1].charset.is_none());
    assert!(AUTH_FAMILY_SESSION_COLUMNS[1].collation.is_none());
}

#[test]
fn information_schema_numeric_metadata_uses_ordered_binary_bytes_and_strict_u64() {
    assert_eq!(
        metadata_u64(
            "ORDINAL_POSITION",
            b"18446744073709551615",
            "auth_device_session",
            "session_state"
        )
        .unwrap(),
        u64::MAX
    );
    for invalid in [b"".as_slice(), b"-1", b"1x", &[0xff]] {
        assert!(metadata_u64(
            "ORDINAL_POSITION",
            invalid,
            "auth_device_session",
            "session_state"
        )
        .is_err());
    }
    assert!(metadata_u64(
        "ORDINAL_POSITION",
        b"18446744073709551616",
        "auth_device_session",
        "session_state"
    )
    .is_err());

    assert_eq!(
        metadata_count(b"18446744073709551615".to_vec(), "count").unwrap(),
        u64::MAX
    );
    assert!(metadata_count(b"-1".to_vec(), "count").is_err());
    assert!(metadata_count(vec![0xff], "count").is_err());
    assert!(metadata_count(b"18446744073709551616".to_vec(), "count").is_err());

    assert!(HISTORICAL_COLUMN_METADATA_SQL.contains(
            "CAST(COLUMN_NAME AS BINARY), CAST(COLUMN_TYPE AS BINARY), CAST(IS_NULLABLE AS BINARY), CAST(COLUMN_DEFAULT AS BINARY), CAST(CHARACTER_SET_NAME AS BINARY), CAST(COLLATION_NAME AS BINARY), CAST(ORDINAL_POSITION AS BINARY)"
        ));
    assert!(HISTORICAL_COLUMN_POSITION_SQL.contains(
            "CAST(immediate_previous.COLUMN_NAME AS BINARY), CAST(immediate_previous.ORDINAL_POSITION AS BINARY), CAST(current_column.ORDINAL_POSITION AS BINARY), CAST(expected_previous.ORDINAL_POSITION AS BINARY)"
        ));
    for query in [
        SCHEMA_TABLE_EXISTS_SQL,
        SCHEMA_COLUMN_EXISTS_SQL,
        SCHEMA_INDEX_STATS_SQL,
        SCHEMA_INDEX_COLUMN_EXISTS_SQL,
        SCHEMA_TABLE_CONTRACT_SQL,
        SCHEMA_KEY_COLUMN_CONTRACT_SQL,
        MIGRATION_COLUMN_EXISTS_SQL,
    ] {
        assert!(query.contains("CAST(COUNT(*) AS BINARY)"));
    }
    assert!(SCHEMA_INDEX_STATS_SQL.contains("CAST(MIN(NON_UNIQUE) AS BINARY)"));
    assert!(SCHEMA_INDEX_STATS_SQL.contains("CAST(MAX(NON_UNIQUE) AS BINARY)"));
    assert!(SCHEMA_INDEX_COLUMN_EXISTS_SQL.contains("SEQ_IN_INDEX = ?"));
}

#[test]
fn incremental_projection_archive_migration_and_contract_are_exact() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == INCREMENTAL_PROJECTION_ARCHIVE_VERSION)
        .expect("incremental projection archive migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == INCREMENTAL_PROJECTION_ARCHIVE_VERSION)
        .expect("incremental projection archive artifact contract must remain registered");

    assert!(!contract.supports_existing_artifacts);
    assert_eq!(
        canonical_sha384_hex(INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL.as_bytes()),
        INCREMENTAL_PROJECTION_ARCHIVE_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        INCREMENTAL_PROJECTION_ARCHIVE_SQL_SHA384
    );
    assert_eq!(contract.tables, INCREMENTAL_PROJECTION_ARCHIVE_TABLES);
    assert_eq!(contract.columns, INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS);
    assert_eq!(contract.indexes, INCREMENTAL_PROJECTION_ARCHIVE_INDEXES);
    assert_eq!(INCREMENTAL_PROJECTION_ARCHIVE_TABLES.len(), 10);
    assert_eq!(
        INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL
            .matches("CREATE TABLE IF NOT EXISTS")
            .count(),
        INCREMENTAL_PROJECTION_ARCHIVE_TABLES.len()
    );
    assert!(!INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL.contains("ALTER TABLE"));
    assert!(!INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL.contains("DROP COLUMN"));
    assert!(!INCREMENTAL_PROJECTION_ARCHIVE_MIGRATION_SQL.contains("FOREIGN KEY"));
    assert_eq!(
        INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS.len(),
        INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS.len()
    );
    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        assert!(migration_defines_table(migration, table));
    }
    for (table, column) in INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS {
        assert!(migration_defines_column(migration, table, column));
        assert!(!migration_defines_existing_column(migration, table, column));
    }
    for (table, index, columns, unique) in INCREMENTAL_PROJECTION_ARCHIVE_INDEXES {
        assert!(migration_defines_index(
            migration, table, index, columns, *unique
        ));
        assert!(!migration_defines_existing_index(
            migration, table, index, columns, *unique
        ));
    }
}

#[test]
fn incremental_projection_archive_contract_covers_required_safety_fields() {
    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        assert!(INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
            .iter()
            .any(|column| column.table == *table));
    }
    for (table, column) in [
        ("authorization_grant_revision", "tenant_id"),
        ("authorization_grant_revision", "grant_id"),
        ("authorization_grant_revision", "revision_no"),
        ("authorization_grant_revision", "is_tombstone"),
        ("authorization_delta_event", "event_id"),
        ("authorization_delta_event", "base_version"),
        ("authorization_delta_event", "target_version"),
        ("authorization_delta_event", "before_digest"),
        ("authorization_delta_event", "lease_token_hash"),
        ("authorization_impact_plan", "target_generation"),
        ("authorization_projection_manifest", "manifest_digest"),
        ("authorization_projection_segment", "content_digest"),
        (
            "authorization_projection_manifest_segment",
            "segment_ordinal",
        ),
        ("authorization_projection_current", "current_generation"),
        ("authorization_archive_outbox", "operation_id"),
        ("authorization_archive_manifest", "archive_digest"),
    ] {
        assert!(INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
            .iter()
            .any(|expected| expected.table == table && expected.name == column));
    }
    for expected in INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS {
        assert!(schema_column_contract_matches(
            expected.name,
            expected.column_type,
            if expected.not_null { "NO" } else { "YES" },
            expected.default,
            expected.charset,
            expected.collation,
            expected,
        ));
    }
}

#[test]
fn cross_city_schema_migration_and_contract_are_exact() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == CROSS_CITY_SCHEMA_VERSION)
        .expect("cross-city schema migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == CROSS_CITY_SCHEMA_VERSION)
        .expect("cross-city schema artifact contract must remain registered");

    assert!(!contract.supports_existing_artifacts);
    assert_eq!(
        canonical_sha384_hex(CROSS_CITY_SCHEMA_MIGRATION_SQL.as_bytes()),
        CROSS_CITY_SCHEMA_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        CROSS_CITY_SCHEMA_SQL_SHA384
    );
    assert_eq!(contract.tables, CROSS_CITY_SCHEMA_TABLES);
    assert_eq!(contract.columns, CROSS_CITY_SCHEMA_COLUMNS);
    assert_eq!(contract.indexes, CROSS_CITY_SCHEMA_INDEXES);
    assert_eq!(CROSS_CITY_SCHEMA_TABLES.len(), 6);
    assert_eq!(
        CROSS_CITY_SCHEMA_MIGRATION_SQL
            .matches("CREATE TABLE IF NOT EXISTS")
            .count(),
        CROSS_CITY_SCHEMA_TABLES.len()
    );
    // Creator-only migration: every executable statement is a CREATE
    // TABLE. The rollback notes live in `--` comments that the statement
    // splitter skips, so no ALTER/DROP statement may reach the database.
    let statements = sql_statements(CROSS_CITY_SCHEMA_MIGRATION_SQL)
        .expect("cross-city schema migration must lex cleanly");
    assert_eq!(statements.len(), CROSS_CITY_SCHEMA_TABLES.len());
    for statement in &statements {
        assert!(
            normalized_sql_fragment(statement).starts_with("CREATE TABLE "),
            "cross-city schema migration must only create tables, found: {statement}"
        );
    }
    // No foreign keys (repository-enforced consistency, see migration
    // header) and no CHECK constraints (state machines stay in
    // astral-types; the database must not fake verification).
    assert!(!CROSS_CITY_SCHEMA_MIGRATION_SQL.contains("FOREIGN KEY"));
    assert!(!CROSS_CITY_SCHEMA_MIGRATION_SQL.contains("CHECK ("));
    assert!(!CROSS_CITY_SCHEMA_MIGRATION_SQL.contains("ON DELETE"));
    for table in CROSS_CITY_SCHEMA_TABLES {
        assert!(migration_defines_table(migration, table));
    }
    for (table, column) in CROSS_CITY_SCHEMA_COLUMNS {
        assert!(migration_defines_column(migration, table, column));
        assert!(!migration_defines_existing_column(migration, table, column));
    }
    for (table, index, columns, unique) in CROSS_CITY_SCHEMA_INDEXES {
        assert!(migration_defines_index(
            migration, table, index, columns, *unique
        ));
        assert!(!migration_defines_existing_index(
            migration, table, index, columns, *unique
        ));
    }
}

/// Cross-city runtime-proof slice (P4, default-off): the migration must
/// stay a set of five additive idempotent table creators — no destructive
/// statements, no foreign keys (repositories own consistency), no CHECK
/// constraints (state machines live in astral-types + repositories), and
/// it must remain embedded with its declared version.
#[test]
fn cross_city_runtime_proof_migration_is_additive_creators_only() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == CROSS_CITY_RUNTIME_PROOF_VERSION)
        .expect("cross-city runtime-proof migration must remain embedded");
    assert_eq!(
        migration.sql, CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL,
        "embedded migrator SQL must match the include_str! reference"
    );
    let statements = sql_statements(CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL)
        .expect("runtime-proof migration must lex cleanly");
    assert_eq!(statements.len(), 5, "exactly five table creators");
    for statement in &statements {
        assert!(
            normalized_sql_fragment(statement).starts_with("CREATE TABLE "),
            "runtime-proof migration must only create tables, found: {statement}"
        );
    }
    assert!(!CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL.contains("FOREIGN KEY"));
    assert!(!CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL.contains("CHECK ("));
    assert!(!CROSS_CITY_RUNTIME_PROOF_MIGRATION_SQL.contains("ON DELETE"));
    for table in [
        "authorization_cross_city_node_key",
        "authorization_cross_city_vote_reservation",
        "authorization_cross_city_commit_receipt",
        "authorization_cross_city_operation_activation",
        "authorization_cross_city_authority_scope",
    ] {
        assert!(migration_defines_table(migration, table));
    }
}

/// Delta claim sibling-ordering gate support index (10.D-2): the migration
/// must stay a single additive secondary-index ALTER — no destructive
/// statements, no new table, no column change. The claim statements in
/// grant_repository.rs reference this index by name.
#[test]
fn delta_claim_grant_chain_index_migration_is_single_additive_alter() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == DELTA_CLAIM_GRANT_CHAIN_INDEX_VERSION)
        .expect("delta claim grant-chain index migration must remain embedded");
    assert_eq!(
        migration.sql, DELTA_CLAIM_GRANT_CHAIN_INDEX_MIGRATION_SQL,
        "embedded migrator SQL must match the include_str! reference"
    );
    let statements = sql_statements(DELTA_CLAIM_GRANT_CHAIN_INDEX_MIGRATION_SQL)
        .expect("index migration must lex cleanly");
    assert_eq!(statements.len(), 1, "exactly one ALTER statement");
    let statement = normalized_sql_fragment(&statements[0]);
    assert!(statement.starts_with("ALTER TABLE AUTHORIZATION_DELTA_EVENT"));
    assert!(statement.contains("ADD KEY IDX_ADE_GRANT_CHAIN"));
    assert!(statement.contains("(TENANT_ID, GRANT_ID, STATUS, TARGET_VERSION)"));
    // Additive only: never drops/renames/modifies anything.
    for banned in ["DROP", "RENAME", "MODIFY", "CHANGE ", "DELETE FROM"] {
        assert!(
            !statement.contains(banned),
            "index migration must stay additive, found banned keyword: {banned}"
        );
    }
}

/// The post-creator index addition must stay consistent with both sides of
/// the resolver: the defining migration really creates the declared index,
/// and the creator contract never contains it (pending-tolerance premise).
#[test]
fn post_creator_index_addition_matches_its_migration_and_creator_disjoint() {
    assert_eq!(POST_CREATOR_INDEX_ADDITIONS.len(), 1);
    let (version, table, index, columns, unique) = POST_CREATOR_INDEX_ADDITIONS[0];
    assert_eq!(version, DELTA_CLAIM_GRANT_CHAIN_INDEX_VERSION);
    assert_eq!(table, "authorization_delta_event");
    assert_eq!(index, "idx_ade_grant_chain");
    assert_eq!(
        columns,
        ["tenant_id", "grant_id", "status", "target_version"]
    );
    assert!(!unique);
    // Creator contract stays verbatim: the addition is a later migration's
    // index, never folded into the creator shape.
    assert!(INCREMENTAL_PROJECTION_ARCHIVE_INDEXES
        .iter()
        .all(|(_, name, _, _)| *name != index));
    // The defining migration actually creates the declared index.
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == version)
        .expect("post-creator index migration must remain embedded");
    assert!(migration_defines_index(
        migration, table, index, columns, unique
    ));
}

#[test]
fn cross_city_column_lists_and_runtime_contracts_are_set_consistent() {
    // The pending-migration artifact list (CROSS_CITY_SCHEMA_COLUMNS) and
    // the runtime exact contracts (CROSS_CITY_SCHEMA_COLUMN_CONTRACTS)
    // must describe the exact same (table, column) set: sort both views
    // and compare them directly, so a column added to one list without
    // the other fails closed at test time.
    let mut columns: Vec<(&str, &str)> = CROSS_CITY_SCHEMA_COLUMNS.to_vec();
    columns.sort_unstable();
    let mut contracts: Vec<(&str, &str)> = CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
        .iter()
        .map(|expected| (expected.table, expected.name))
        .collect();
    contracts.sort_unstable();
    assert_eq!(columns, contracts);

    // Per-table column counts must agree between the two lists, and every
    // creator table must be covered by both.
    for table in CROSS_CITY_SCHEMA_TABLES {
        let column_count = CROSS_CITY_SCHEMA_COLUMNS
            .iter()
            .filter(|(column_table, _)| *column_table == *table)
            .count();
        let contract_count = CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
            .iter()
            .filter(|expected| expected.table == *table)
            .count();
        assert!(column_count > 0, "{table} has no columns listed");
        assert_eq!(column_count, contract_count, "{table}");
    }
}

#[test]
fn cross_city_schema_is_rust_owned_and_never_baseline_adopted() {
    // Fail-closed era rule: everything outside the 20240630 Java baseline
    // series is Rust-owned. A verified baseline is recorded as applied
    // without executing, so this creator must never be swallowed by
    // baseline adoption - it stays pending until SQLx really executes it.
    assert!(!is_java_baseline_era(CROSS_CITY_SCHEMA_VERSION));
    assert!(MIGRATOR
        .migrations
        .iter()
        .any(|migration| migration.version == CROSS_CITY_SCHEMA_VERSION));

    let baseline_versions: HashSet<i64> = MIGRATOR
        .migrations
        .iter()
        .filter(|migration| is_java_baseline_era(migration.version))
        .map(|migration| migration.version)
        .collect();
    assert_eq!(
        classify_migration_history(&baseline_versions),
        MigrationHistoryState::BaselineComplete
    );
    assert_eq!(
        migration_history_decision(classify_migration_history(&baseline_versions), true,),
        MigrationHistoryDecision::Continue
    );
    assert_eq!(
        migration_history_decision(MigrationHistoryState::Empty, true),
        MigrationHistoryDecision::AdoptBaseline
    );
    // Even with the recorded versions artificially claiming every
    // migration, adoption only ever records baseline-era versions; the
    // cross-city version itself is not baseline era and can never be in
    // that set.
    assert!(!baseline_versions.contains(&CROSS_CITY_SCHEMA_VERSION));
}

#[test]
fn cross_city_schema_contract_covers_required_safety_fields() {
    for table in CROSS_CITY_SCHEMA_TABLES {
        assert!(CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
            .iter()
            .any(|column| column.table == *table));
    }
    for (table, column) in [
        ("authorization_cross_city_operation", "operation_id"),
        ("authorization_cross_city_operation", "scope_digest"),
        ("authorization_cross_city_operation", "request_digest"),
        ("authorization_cross_city_operation", "mutation_digest"),
        ("authorization_cross_city_operation", "base_frontier_digest"),
        ("authorization_cross_city_operation", "target_generation"),
        ("authorization_cross_city_operation", "target_revoke_fence"),
        ("authorization_cross_city_operation", "proposal_digest"),
        ("authorization_cross_city_operation", "coordinator_epoch"),
        ("authorization_cross_city_operation", "agreement_digest"),
        ("authorization_cross_city_operation", "expires_at"),
        ("authorization_cross_city_vote", "decision"),
        ("authorization_cross_city_vote", "node_epoch"),
        ("authorization_cross_city_vote", "proposal_digest"),
        ("authorization_cross_city_vote", "frontier_digest"),
        ("authorization_cross_city_vote", "mutation_digest"),
        ("authorization_cross_city_vote", "evidence_digest"),
        ("authorization_cross_city_vote", "nonce"),
        ("authorization_cross_city_vote", "signature"),
        ("authorization_cross_city_vote", "expires_at"),
        ("authorization_cross_city_city_state", "phase"),
        ("authorization_cross_city_city_state", "local_base_digest"),
        ("authorization_cross_city_city_state", "commit_digest"),
        ("authorization_cross_city_city_state", "pointer_digest"),
        ("authorization_cross_city_city_state", "certificate_digest"),
        ("authorization_cross_city_city_state", "lease_owner"),
        ("authorization_cross_city_city_state", "lease_token_hash"),
        ("authorization_cross_city_city_state", "lease_expires_at"),
        ("authorization_cross_city_gate", "tenant_id"),
        ("authorization_cross_city_gate", "aggregate_type"),
        ("authorization_cross_city_gate", "aggregate_id"),
        ("authorization_cross_city_gate", "operation_id"),
        ("authorization_cross_city_gate", "certificate_digest"),
        ("authorization_cross_city_gate", "target_generation"),
        ("authorization_cross_city_gate", "revoke_fence"),
        ("authorization_cross_city_gate", "state"),
        ("authorization_cross_city_gate", "content_hash"),
        ("authorization_cross_city_outbox", "message_id"),
        ("authorization_cross_city_outbox", "source_city_id"),
        ("authorization_cross_city_outbox", "destination_city_id"),
        ("authorization_cross_city_outbox", "payload_digest"),
        ("authorization_cross_city_outbox", "payload"),
        ("authorization_cross_city_outbox", "status"),
        ("authorization_cross_city_outbox", "attempts"),
        ("authorization_cross_city_outbox", "lease_token_hash"),
        ("authorization_cross_city_inbox", "message_id"),
        ("authorization_cross_city_inbox", "payload_digest"),
        ("authorization_cross_city_inbox", "status"),
        ("authorization_cross_city_inbox", "attempts"),
        ("authorization_cross_city_inbox", "lease_token_hash"),
        ("authorization_cross_city_inbox", "received_at"),
        ("authorization_cross_city_inbox", "processed_at"),
    ] {
        assert!(
            CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
                .iter()
                .any(|expected| expected.table == table && expected.name == column),
            "cross-city column contract must cover {table}.{column}"
        );
    }
    // Scope uniqueness, per-node vote uniqueness, per-city state
    // uniqueness, and the lease-scan indexes are the schema-level durable
    // guarantees the repository relies on.
    for (table, index) in [
        ("authorization_cross_city_vote", "uk_accv_node"),
        ("authorization_cross_city_vote", "uk_accv_nonce"),
        (
            "authorization_cross_city_city_state",
            "uk_accc_operation_city",
        ),
        ("authorization_cross_city_gate", "uk_accg_scope"),
        ("authorization_cross_city_outbox", "idx_accob_lease"),
        ("authorization_cross_city_outbox", "idx_accob_source"),
        ("authorization_cross_city_outbox", "idx_accob_destination"),
        ("authorization_cross_city_inbox", "idx_accib_lease"),
    ] {
        assert!(
            CROSS_CITY_SCHEMA_INDEXES
                .iter()
                .any(
                    |(index_table, index_name, _, _)| *index_table == table && *index_name == index
                ),
            "cross-city index contract must cover {table}.{index}"
        );
    }
    // Fail-closed defaults: a gate is BLOCKED, an operation PROPOSED, work
    // items PENDING, and a recorded decision never carries an implicit
    // default; every digest column is BINARY(32).
    for expected in CROSS_CITY_SCHEMA_COLUMN_CONTRACTS {
        if expected.table == "authorization_cross_city_gate" && expected.name == "state" {
            assert_eq!(expected.default, Some("BLOCKED"));
        }
        if expected.table == "authorization_cross_city_operation" && expected.name == "state" {
            assert_eq!(expected.default, Some("PROPOSED"));
        }
        if expected.name == "status" {
            assert_eq!(expected.default, Some("PENDING"));
        }
        if expected.name == "decision" {
            assert_eq!(expected.default, None);
        }
        if expected.name.ends_with("_digest") || expected.name == "content_hash" {
            assert_eq!(
                expected.column_type, "BINARY(32)",
                "digest columns must store raw SHA-256 bytes: {}.{}",
                expected.table, expected.name
            );
        }
        if expected.name == "lease_token_hash" {
            assert_eq!(expected.column_type, "BINARY(32)");
        }
    }
}

#[test]
fn cross_city_outbox_routing_direction_is_explicit_and_indexed() {
    const OUTBOX: &str = "authorization_cross_city_outbox";
    let has_column = |column: &str| {
        CROSS_CITY_SCHEMA_COLUMNS
            .iter()
            .any(|(table, name)| *table == OUTBOX && *name == column)
    };

    // Durable routing evidence: both directions are first-class NOT NULL
    // columns; the ambiguous city_id must not come back through any
    // contract surface (column list, runtime contract, or SQL text).
    assert!(has_column("source_city_id"));
    assert!(has_column("destination_city_id"));
    assert!(!has_column("city_id"));

    for direction in ["source_city_id", "destination_city_id"] {
        let contract = CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
            .iter()
            .find(|expected| expected.table == OUTBOX && expected.name == direction)
            .unwrap_or_else(|| panic!("outbox {direction} column contract must exist"));
        assert_eq!(contract.column_type, "VARCHAR(191)", "{direction}");
        assert!(contract.not_null, "{direction}");
        assert_eq!(contract.default, None, "{direction}");
    }

    // Direction-scoped scan indexes back per-city send-queue and delivery
    // queries; together with the message-id primary key and the operation
    // index this covers routing without any ambiguous column.
    for (index, columns) in [
        ("idx_accob_source", &["source_city_id", "phase"][..]),
        (
            "idx_accob_destination",
            &["destination_city_id", "phase"][..],
        ),
    ] {
        assert!(CROSS_CITY_SCHEMA_INDEXES.iter().any(
            |(index_table, index_name, index_columns, unique)| {
                *index_table == OUTBOX
                    && *index_name == index
                    && **index_columns == *columns
                    && !*unique
            }
        ));
    }
    assert!(!CROSS_CITY_SCHEMA_INDEXES
        .iter()
        .any(|(index_table, index_name, _, _)| *index_table == OUTBOX
            && *index_name == "idx_accob_city"));

    // The embedded SQL itself must declare both direction columns as real
    // column definitions (comments cannot substitute columns). Stripping
    // the two direction names must leave no bare city_id token behind.
    let statements = sql_statements(CROSS_CITY_SCHEMA_MIGRATION_SQL)
        .expect("cross-city schema migration must lex cleanly");
    let outbox_statement = statements
        .iter()
        .find(|statement| {
            normalized_sql_fragment(statement)
                .starts_with("CREATE TABLE IF NOT EXISTS AUTHORIZATION_CROSS_CITY_OUTBOX ")
        })
        .expect("outbox creator statement must exist");
    for direction in ["source_city_id", "destination_city_id"] {
        let declared = format!("{} VARCHAR(191) NOT NULL", direction.to_ascii_uppercase());
        assert!(
            normalized_sql_fragment(outbox_statement).contains(&declared),
            "outbox must declare {direction} as a real NOT NULL VARCHAR(191) column"
        );
    }
    let stripped = outbox_statement
        .replace("source_city_id", "")
        .replace("destination_city_id", "");
    assert!(
        !stripped.contains("city_id"),
        "outbox statement must not declare an ambiguous city_id column"
    );
}

#[test]
fn cross_city_table_validator_enforces_exact_whole_shape() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("test module must be separable");
    let validator = production
        .split("async fn validate_cross_city_table_contract")
        .nth(1)
        .and_then(|body| body.split("async fn ").next())
        .expect("cross-city table validator must exist");

    // Both exact whole-shape checks must run inside the validator, after
    // the per-column/per-index validation: exhaustive ordered columns and
    // exhaustive index shape, not just presence.
    let columns_check = validator
        .find("schema_columns_match(pool, &columns)")
        .expect("exact whole-shape column check must exist");
    let indexes_check = validator
        .find("schema_indexes_match(pool, &indexes)")
        .expect("exact whole-shape index check must exist");
    let per_column = validator
        .find("validate_schema_columns(pool, &columns)")
        .expect("per-column validation must exist");
    let per_index = validator
        .find("validate_indexes(pool, &indexes)")
        .expect("per-index validation must exist");
    assert!(per_column < columns_check);
    assert!(per_index < indexes_check);

    // Each failed shape check must fail closed with explicit drift
    // wording; the validator must carry no automatic repair path.
    for wording in [
        "extra column drift",
        "unexpected extra indexes",
        "refusing automatic ALTER/DROP",
    ] {
        assert!(
            validator.contains(wording),
            "cross-city validator must fail closed on drift: must contain {wording:?}"
        );
    }
    // No automatic repair path may exist in the validator: no ALTER/DROP
    // statement forms of any kind.
    for repair_form in ["ALTER TABLE", "DROP TABLE", "DROP COLUMN", "ADD COLUMN"] {
        assert!(
            !validator.contains(repair_form),
            "cross-city validator must not attempt automatic repair: {repair_form:?}"
        );
    }

    // The six-table creator contract must remain exactly as registered:
    // every table keeps its runtime column contract and index contract.
    assert_eq!(
        CROSS_CITY_SCHEMA_TABLES,
        &[
            "authorization_cross_city_operation",
            "authorization_cross_city_vote",
            "authorization_cross_city_city_state",
            "authorization_cross_city_gate",
            "authorization_cross_city_outbox",
            "authorization_cross_city_inbox",
        ][..]
    );
    assert_eq!(CROSS_CITY_SCHEMA_TABLES.len(), 6);
    for table in CROSS_CITY_SCHEMA_TABLES {
        assert!(CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
            .iter()
            .any(|column| column.table == *table));
        assert!(CROSS_CITY_SCHEMA_INDEXES
            .iter()
            .any(|(index_table, _, _, _)| *index_table == *table));
    }
}

#[test]
fn authorization_projection_lineage_fence_migration_and_contract_are_exact() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION)
        .expect("lineage fence migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION)
        .expect("lineage fence artifact contract must remain registered");

    // Additive repair-style registration: no creator tables, only the six
    // appended tail columns that may already exist when it runs.
    assert!(contract.supports_existing_artifacts);
    assert!(contract.tables.is_empty());
    assert!(contract.indexes.is_empty());
    assert_eq!(
        canonical_sha384_hex(AUTHORIZATION_PROJECTION_LINEAGE_FENCE_MIGRATION_SQL.as_bytes()),
        AUTHORIZATION_PROJECTION_LINEAGE_FENCE_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        AUTHORIZATION_PROJECTION_LINEAGE_FENCE_SQL_SHA384
    );
    assert_eq!(
        contract.columns,
        AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMNS
    );
    assert_eq!(AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMNS.len(), 6);

    for (table, column) in AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMNS {
        assert!(migration_defines_column(migration, table, column));
        assert!(
            migration_defines_existing_column(migration, table, column),
            "lineage migration must define existing-artifact column {table}.{column}"
        );
    }
    // The lineage migration creates nothing and never declares indexes.
    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        assert!(!migration_defines_table(migration, table));
    }

    // Conditional, additive-only DDL: exactly one guarded ALTER per column,
    // appended at the tail (no AFTER clause), without DROP / FK / CHECK /
    // index or data-mutation statements.
    let sql = AUTHORIZATION_PROJECTION_LINEAGE_FENCE_MIGRATION_SQL;
    assert_eq!(
        sql.matches("PREPARE astral_stmt FROM @astral_sql").count(),
        6
    );
    assert_eq!(sql.matches("EXECUTE astral_stmt").count(), 6);
    assert_eq!(sql.matches("DEALLOCATE PREPARE astral_stmt").count(), 6);
    assert_eq!(sql.matches("information_schema.COLUMNS").count(), 6);
    assert_eq!(sql.matches("ADD COLUMN").count(), 6);
    for (table, column, definition) in [
        (
            "authorization_projection_manifest",
            "parent_manifest_id",
            "BIGINT NULL",
        ),
        (
            "authorization_projection_manifest",
            "revoke_fence",
            "BIGINT NOT NULL DEFAULT 0",
        ),
        (
            "authorization_projection_current",
            "revoke_fence",
            "BIGINT NOT NULL DEFAULT 0",
        ),
        (
            "authorization_projection_current",
            "revoke_fence_proven",
            "BIGINT NOT NULL DEFAULT 0",
        ),
        (
            "authorization_archive_outbox",
            "archived_revoke_fence",
            "BIGINT NOT NULL DEFAULT 0",
        ),
        (
            "authorization_archive_manifest",
            "archived_revoke_fence",
            "BIGINT NOT NULL DEFAULT 0",
        ),
    ] {
        assert!(
            sql.contains(&format!("AND TABLE_NAME = '{table}'")),
            "probe must inspect {table}"
        );
        assert!(
            sql.contains(&format!("AND COLUMN_NAME = '{column}'")),
            "probe must inspect {table}.{column}"
        );
        assert!(
            sql.contains(&format!(
                "'ALTER TABLE {table} ADD COLUMN {column} {definition}',"
            )),
            "conditional ALTER must append {table}.{column} {definition}"
        );
    }
    // Strip SQL comments before scanning for forbidden keywords so the
    // documentation prose (which legitimately mentions "foreign keys")
    // cannot mask real statement drift.
    let statement_sql = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<&str>>()
        .join("\n");
    let uppercase = statement_sql.to_ascii_uppercase();
    assert!(!uppercase.contains("DROP"));
    assert!(!uppercase.contains("FOREIGN KEY"));
    assert!(!uppercase.contains("CHECK ("));
    assert!(!uppercase.contains("DELETE FROM"));
    assert!(!uppercase.contains("UPDATE "));
    assert!(!uppercase.contains("INSERT INTO"));
    assert!(!uppercase.contains("ADD INDEX"));
    assert!(!uppercase.contains("ADD KEY"));
    assert!(!uppercase.contains("UNIQUE KEY"));
}

#[test]
fn delta_event_published_evidence_invalidation_migration_is_single_additive_alter() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION)
        .expect("delta event evidence-invalidation migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION)
        .expect("delta event evidence-invalidation artifact contract must remain registered");

    assert_eq!(
        migration.sql, DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_MIGRATION_SQL,
        "embedded migrator SQL must match the include_str! reference"
    );
    assert_eq!(
        canonical_sha384_hex(DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_MIGRATION_SQL.as_bytes()),
        DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_SQL_SHA384
    );
    assert!(contract.supports_existing_artifacts);
    assert!(contract.tables.is_empty());
    assert_eq!(
        contract.columns,
        DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMNS
    );
    assert!(contract.indexes.is_empty());
    assert_eq!(
        DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMNS,
        [(
            "authorization_delta_event",
            "invalidates_published_evidence"
        )]
    );
    assert_eq!(
        DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS,
        &[SchemaColumnContract {
            table: "authorization_delta_event",
            name: "invalidates_published_evidence",
            column_type: "TINYINT",
            not_null: true,
            default: Some("1"),
            charset: None,
            collation: None,
        }]
    );
    assert!(migration_defines_column(
        migration,
        "authorization_delta_event",
        "invalidates_published_evidence"
    ));
    assert!(migration_defines_existing_column(
        migration,
        "authorization_delta_event",
        "invalidates_published_evidence"
    ));

    let sql = DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_MIGRATION_SQL;
    assert_eq!(
        sql.matches("PREPARE astral_stmt FROM @astral_sql").count(),
        1
    );
    assert_eq!(sql.matches("EXECUTE astral_stmt").count(), 1);
    assert_eq!(sql.matches("DEALLOCATE PREPARE astral_stmt").count(), 1);
    assert_eq!(sql.matches("information_schema.COLUMNS").count(), 1);
    assert_eq!(sql.matches("ADD COLUMN").count(), 1);
    assert!(sql.contains(
            "'ALTER TABLE authorization_delta_event ADD COLUMN invalidates_published_evidence TINYINT NOT NULL DEFAULT 1',"
        ));
    let statement_sql = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<&str>>()
        .join("\n");
    let uppercase = statement_sql.to_ascii_uppercase();
    for banned in [
        "DROP",
        "DELETE FROM",
        "UPDATE ",
        "INSERT INTO",
        "RENAME",
        "MODIFY",
        "CHANGE ",
        "AFTER ",
        "ADD INDEX",
        "ADD KEY",
        "UNIQUE KEY",
        "FOREIGN KEY",
    ] {
        assert!(
            !uppercase.contains(banned),
            "migration must stay additive: {banned}"
        );
    }
}

#[test]
fn lineage_fence_columns_never_pollute_the_original_creator_contracts() {
    // The original 20260825000002 exact contract must stay verbatim so a
    // pending lineage migration can never look like creator-column drift.
    let archive_contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == INCREMENTAL_PROJECTION_ARCHIVE_VERSION)
        .expect("incremental projection archive artifact contract must remain registered");
    assert!(!archive_contract.supports_existing_artifacts);
    assert_eq!(
        archive_contract.columns,
        INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS
    );
    assert_eq!(
        archive_contract.tables,
        INCREMENTAL_PROJECTION_ARCHIVE_TABLES
    );
    assert_eq!(
        archive_contract.indexes,
        INCREMENTAL_PROJECTION_ARCHIVE_INDEXES
    );

    for (table, column) in AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMNS {
        assert!(
            !INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS
                .iter()
                .any(|(owner_table, owner_column)| *owner_table == *table
                    && *owner_column == *column),
            "creator column list must not contain {table}.{column}"
        );
        assert!(
            !INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
                .iter()
                .any(|expected| expected.table == *table && expected.name == *column),
            "creator strict contract must not contain {table}.{column}"
        );
    }
}

#[test]
fn legacy_snapshot_decommission_migration_is_pinned_and_decommission_only() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == LEGACY_SNAPSHOT_DECOMMISSION_VERSION)
        .expect("legacy snapshot decommission migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == LEGACY_SNAPSHOT_DECOMMISSION_VERSION)
        .expect("legacy snapshot decommission artifact contract must remain registered");

    // Decommission-only registration: it owns no artifact and only pins
    // the guarded DROP body.
    assert!(contract.supports_existing_artifacts);
    assert!(contract.tables.is_empty());
    assert!(contract.columns.is_empty());
    assert!(contract.indexes.is_empty());
    assert_eq!(
        canonical_sha384_hex(LEGACY_SNAPSHOT_DECOMMISSION_MIGRATION_SQL.as_bytes()),
        LEGACY_SNAPSHOT_DECOMMISSION_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        LEGACY_SNAPSHOT_DECOMMISSION_SQL_SHA384
    );

    // It must never be attributed as the creator of any table — in
    // particular not of the two tables it removes.
    for table in [
        "rule_set_snapshot",
        "permission_rule_snapshot",
        "rule_set_snapshot_manifest",
        "rule_set_projection_audit",
        "authorization_projection_head",
        "authorization_projection_outbox",
    ] {
        assert!(
            !migration_defines_table(migration, table),
            "decommission migration must not define {table}"
        );
    }

    // Active statements (comment block stripped): exactly three guarded
    // drops, one per legacy table.
    let sql = LEGACY_SNAPSHOT_DECOMMISSION_MIGRATION_SQL;
    let statement_sql = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert_eq!(
        statement_sql
            .matches("PREPARE astral_stmt FROM @astral_sql")
            .count(),
        3
    );
    assert_eq!(statement_sql.matches("EXECUTE astral_stmt").count(), 3);
    assert_eq!(
        statement_sql
            .matches("DEALLOCATE PREPARE astral_stmt")
            .count(),
        3
    );
    assert_eq!(
        statement_sql.matches("information_schema.TABLES").count(),
        3
    );
    assert!(statement_sql.contains("'DROP TABLE rule_set_snapshot'"));
    assert!(statement_sql.contains("'DROP TABLE permission_rule_snapshot'"));
    assert!(statement_sql.contains("'DROP TABLE rule_set_snapshot_manifest'"));
    // The dropped identifiers appear only inside the quoted guarded body,
    // never as an unguarded statement.
    assert_eq!(statement_sql.matches("DROP TABLE").count(), 3);

    // Exclusions: the writer-correlation and audit tables stay untouched.
    assert!(!statement_sql.contains("authorization_projection_head"));
    assert!(!statement_sql.contains("authorization_projection_outbox"));
    assert!(!statement_sql.contains("DROP TABLE rule_set_projection_audit"));

    // Idempotency guard: an absent table records a no-op instead of failing.
    assert_eq!(statement_sql.matches("SELECT 1 AS ").count(), 3);

    // Rollback block: commented structural rebuild covering the deployed
    // platform-v5 shape plus the Rust additive columns.
    let rollback = sql
        .split("===== ROLLBACK")
        .nth(1)
        .expect("decommission migration must document a rollback block");
    assert!(rollback.contains("CREATE TABLE IF NOT EXISTS rule_set_snapshot"));
    assert!(
        rollback.contains("CREATE TABLE IF NOT EXISTS permission_rule_snapshot"),
        "rollback must rebuild both legacy snapshot tables"
    );
    assert!(
        rollback.contains("CREATE TABLE IF NOT EXISTS rule_set_snapshot_manifest"),
        "rollback must rebuild the legacy RuleSet snapshot manifest table"
    );
    for fragment in [
        "projection_generation BIGINT NOT NULL DEFAULT 0",
        "valid_from DATETIME NULL",
        "valid_to DATETIME NULL",
        "uk_rule_set_snapshot (rule_set_id, resource_key, action_code)",
        "uk_permission_rule_snapshot (card_id, resource_key, action_code)",
        "REFERENCES rule_set (rule_set_id)",
        "PRIMARY KEY (rule_set_id, projection_generation)",
        "KEY idx_rssm_event (event_id)",
        "KEY idx_rssm_operation (operation_id)",
        "COMMENT='Rust-owned generation-bound empty/deleted RuleSet snapshot proof'",
    ] {
        assert!(
            rollback.contains(fragment),
            "rollback must restore {fragment}"
        );
    }
}

#[test]
fn identity_card_dual_card_separation_migration_is_pinned_and_decommission_only() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == IDENTITY_CARD_DUAL_CARD_SEPARATION_VERSION)
        .expect("identity card dual-card separation migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == IDENTITY_CARD_DUAL_CARD_SEPARATION_VERSION)
        .expect("dual-card separation artifact contract must remain registered");

    // Decommission-only registration: it owns no artifact and only pins
    // the guarded ALTER body.
    assert!(contract.supports_existing_artifacts);
    assert!(contract.tables.is_empty());
    assert!(contract.columns.is_empty());
    assert!(contract.indexes.is_empty());
    assert_eq!(
        canonical_sha384_hex(IDENTITY_CARD_DUAL_CARD_SEPARATION_MIGRATION_SQL.as_bytes()),
        IDENTITY_CARD_DUAL_CARD_SEPARATION_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        IDENTITY_CARD_DUAL_CARD_SEPARATION_SQL_SHA384
    );

    // It must never be attributed as the creator of any table — in
    // particular not of the table it trims or its dual-card counterpart.
    for table in ["identity_card", "user_card", "platform_domain"] {
        assert!(
            !migration_defines_table(migration, table),
            "dual-card separation migration must not define {table}"
        );
    }

    // Active statements (comment block stripped): exactly four guarded
    // ALTERs — FK first, then index, then the two tenancy columns.
    let sql = IDENTITY_CARD_DUAL_CARD_SEPARATION_MIGRATION_SQL;
    let statement_sql = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert_eq!(
        statement_sql
            .matches("PREPARE astral_stmt FROM @astral_sql")
            .count(),
        4
    );
    assert_eq!(statement_sql.matches("EXECUTE astral_stmt").count(), 4);
    assert_eq!(
        statement_sql
            .matches("DEALLOCATE PREPARE astral_stmt")
            .count(),
        4
    );
    assert_eq!(statement_sql.matches("DROP COLUMN").count(), 2);
    assert_eq!(statement_sql.matches("DROP FOREIGN KEY").count(), 1);
    assert_eq!(statement_sql.matches("DROP INDEX").count(), 1);
    assert!(statement_sql.contains("'ALTER TABLE identity_card DROP FOREIGN KEY fk_ic_domain'"));
    assert!(statement_sql.contains("'ALTER TABLE identity_card DROP INDEX idx_ic_domain'"));
    assert!(statement_sql.contains("'ALTER TABLE identity_card DROP COLUMN domain_id'"));
    assert!(statement_sql.contains("'ALTER TABLE identity_card DROP COLUMN tenant_id'"));
    // The guarded bodies must never name the auth columns or the dual-card
    // counterpart: only the tenancy artifacts are removed.
    assert!(!statement_sql.contains("token_version"));
    assert!(!statement_sql.contains("user_card"));
    assert!(!statement_sql.contains("platform_domain DROP"));
    // Exclusions: identity auth keys stay untouched.
    assert!(!statement_sql.contains("uk_ic_user"));
    assert!(!statement_sql.contains("fk_ic_user"));
    assert!(!statement_sql.contains("idx_ic_status"));

    // Idempotency guard: an absent artifact records a no-op, not a failure.
    assert_eq!(statement_sql.matches("SELECT 1 AS ").count(), 4);

    // Rollback block: commented forward-fix re-adding the legacy shapes.
    let rollback = sql
        .split("===== ROLLBACK")
        .nth(1)
        .expect("dual-card separation migration must document a rollback block");
    assert!(rollback.contains("ADD COLUMN domain_id BIGINT NULL"));
    assert!(rollback.contains("ADD COLUMN tenant_id BIGINT NULL"));
    assert!(rollback.contains("ADD INDEX idx_ic_domain (domain_id)"));
    assert!(rollback.contains("ADD CONSTRAINT fk_ic_domain FOREIGN KEY (domain_id)"));
}

#[test]
fn required_schema_contract_no_longer_requires_legacy_snapshot_tables() {
    // After 20260827000002 has dropped the legacy snapshot tables
    // (rule_set_snapshot / permission_rule_snapshot /
    // rule_set_snapshot_manifest) the startup/migration contract must not
    // demand them, otherwise every later connect_and_validate_schema would
    // fail closed on the dropped (decommissioned) schema.
    assert!(!REQUIRED_SCHEMA_COLUMNS.iter().any(|(table, _)| matches!(
        *table,
        "rule_set_snapshot" | "permission_rule_snapshot" | "rule_set_snapshot_manifest"
    )));
    assert!(!REQUIRED_SCHEMA_INDEXES
        .iter()
        .any(|(table, _, _, _)| matches!(
            *table,
            "rule_set_snapshot" | "permission_rule_snapshot" | "rule_set_snapshot_manifest"
        )));

    // Pre-drop enforcement is retained conditionally: the strict column
    // contracts still exist and the schema validator applies them exactly
    // when the table is still present.
    assert_eq!(
        RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT.table,
        "rule_set_snapshot"
    );
    for table in ["permission_rule_snapshot", "rule_set_snapshot"] {
        assert!(SNAPSHOT_VALIDITY_COLUMN_CONTRACTS
            .iter()
            .any(|expected| expected.table == table));
    }
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let validator = production_source
        .split("pub async fn validate_schema_contract")
        .nth(1)
        .and_then(|body| {
            body.split("async fn validate_decommissionable_snapshot_column_contracts")
                .next()
        })
        .expect("schema contract validator must exist");
    assert!(
        validator.contains("validate_decommissionable_snapshot_column_contracts(pool).await?"),
        "validator must route the legacy snapshot contracts through the table-presence guard"
    );
    assert!(
        !validator.contains(
            "validate_schema_column_exact(pool, &RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT)"
        ),
        "validator must not validate the legacy generation fence unconditionally"
    );
    assert!(
        validator.contains("schema_table_exists(pool, \"rule_set_snapshot_manifest\")"),
        "validator must guard the manifest contracts behind a table-presence check"
    );
    assert!(
        validator
            .contains("validate_schema_columns(pool, RULE_SET_SNAPSHOT_MANIFEST_COLUMN_CONTRACTS)")
            && validator.contains("validate_indexes(pool, RULE_SET_SNAPSHOT_MANIFEST_INDEXES)"),
        "validator must keep validating the manifest contract while the table is present"
    );
    assert!(
            !validator.contains(
                "validate_decommissionable_snapshot_column_contracts(pool).await?;\n    validate_schema_columns(pool, RULE_SET_SNAPSHOT_MANIFEST_COLUMN_CONTRACTS)"
            ),
            "manifest contract validation must no longer run unconditionally"
        );
    let helper = production_source
        .split("async fn validate_decommissionable_snapshot_column_contracts")
        .nth(1)
        .and_then(|body| {
            body.split("async fn validate_school_tenant_mapping_table_contract")
                .next()
        })
        .expect("decommissionable snapshot contract helper must exist");
    assert!(helper.contains(
        "schema_table_exists(pool, RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT.table)"
    ));
    assert!(helper.contains("schema_table_exists(pool, expected.table)"));
    assert!(helper.contains(
        "validate_schema_column_exact(pool, &RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT)"
    ));
}

#[test]
fn resolved_runtime_contract_layers_lineage_columns_after_creator_tail() {
    let mut affected_tables = std::collections::BTreeSet::new();
    let mut invalidation_tables = std::collections::BTreeSet::new();
    for expected in AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS {
        affected_tables.insert(expected.table);
        // Self-consistency: each contract accepts exactly its own spec and
        // refuses any type/null/default/charset drift.
        assert!(schema_column_contract_matches(
            expected.name,
            expected.column_type,
            if expected.not_null { "NO" } else { "YES" },
            expected.default,
            expected.charset,
            expected.collation,
            expected,
        ));
        assert!(!schema_column_contract_matches(
            expected.name,
            match expected.column_type {
                "BIGINT" => "BIGINT UNSIGNED",
                other => other,
            },
            if expected.not_null { "NO" } else { "YES" },
            expected.default,
            expected.charset,
            expected.collation,
            expected,
        ));
    }
    assert_eq!(affected_tables.len(), 4);
    for expected in DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS {
        invalidation_tables.insert(expected.table);
        assert!(schema_column_contract_matches(
            expected.name,
            expected.column_type,
            if expected.not_null { "NO" } else { "YES" },
            expected.default,
            expected.charset,
            expected.collation,
            expected,
        ));
        assert!(!schema_column_contract_matches(
            expected.name,
            "TINYINT UNSIGNED",
            if expected.not_null { "NO" } else { "YES" },
            expected.default,
            expected.charset,
            expected.collation,
            expected,
        ));
    }
    assert_eq!(
        invalidation_tables,
        ["authorization_delta_event"].into_iter().collect()
    );

    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        let base: Vec<SchemaColumnContract> = INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
            .iter()
            .filter(|expected| expected.table == *table)
            .copied()
            .collect();
        let resolved = incremental_projection_resolved_column_contract(table, &base);
        let declared_tail: Vec<SchemaColumnContract> =
            AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS
                .iter()
                .chain(DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS.iter())
                .filter(|expected| expected.table == *table)
                .copied()
                .collect();

        // Creator block is preserved element-wise at the head.
        assert_eq!(&resolved[..base.len()], base.as_slice());
        if !affected_tables.contains(*table) && !invalidation_tables.contains(*table) {
            assert!(
                declared_tail.is_empty(),
                "{table} must not declare additive tail columns"
            );
        }
        assert_eq!(resolved[base.len()..].len(), declared_tail.len());
        for (position, expected) in declared_tail.iter().enumerate() {
            assert_eq!(resolved[base.len() + position], *expected);
        }
        // Declared order inside the manifest table keeps parent before the
        // fence so byte-for-byte replay checks have a stable layout.
        if *table == "authorization_projection_manifest" {
            assert_eq!(declared_tail.len(), 2);
            assert_eq!(declared_tail[0].name, "parent_manifest_id");
            assert_eq!(declared_tail[1].name, "revoke_fence");
        }
        if *table == "authorization_delta_event" {
            assert_eq!(declared_tail.len(), 1);
            assert_eq!(declared_tail[0].name, "invalidates_published_evidence");
        }
    }

    // Shared BIGINT fence contracts line up with the SQL defaults.
    for expected in AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS {
        assert_eq!(expected.column_type, "BIGINT");
        assert!(expected.charset.is_none());
        assert!(expected.collation.is_none());
        match (expected.name, expected.not_null, expected.default) {
            ("parent_manifest_id", false, None) => {}
            (_, true, Some("0")) => {}
            other => panic!("unexpected lineage contract entry: {other:?}"),
        }
    }
}

#[test]
fn runtime_migration_and_contract_cover_distinct_rust_tables() {
    for table in ["audit_log", "mq_idempotent_log", "pending_compensation"] {
        assert!(RUNTIME_MIGRATION_SQL.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")));
        assert!(REQUIRED_SCHEMA_COLUMNS
            .iter()
            .any(|(required_table, _)| *required_table == table));
    }
    assert!(!RUNTIME_MIGRATION_SQL.contains("CREATE TABLE IF NOT EXISTS auth_audit_log"));
    assert!(RUNTIME_MIGRATION_SQL.contains("UNIQUE KEY uk_mq_msg"));
}

#[test]
fn monitor_repair_migration_covers_canonical_rust_tables_and_artifacts() {
    assert!(!is_java_baseline_era(MONITOR_SCHEMA_REPAIR_VERSION));
    assert_eq!(
        canonical_sha384_hex(MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.as_bytes()),
        MONITOR_SCHEMA_REPAIR_SQL_SHA384
    );
    for table in [
        "alert_rule",
        "notification_channel",
        "monitor_metric_snapshot",
        "monitor_alert_history",
        "monitor_activity_log",
    ] {
        assert!(MONITOR_SCHEMA_REPAIR_MIGRATION_SQL
            .contains(&format!("CREATE TABLE IF NOT EXISTS {table}")));
        assert!(migration_defines_table(
            MIGRATOR
                .migrations
                .iter()
                .find(|migration| migration.version == MONITOR_SCHEMA_REPAIR_VERSION)
                .expect("monitor repair migration must remain embedded"),
            table
        ));
    }
    assert!(!MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains("monitor_alert_rule"));
    assert!(!MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains("FOREIGN KEY"));
    for (table, columns) in REQUIRED_SCHEMA_COLUMNS.iter().filter(|(table, _)| {
        matches!(
            *table,
            "alert_rule"
                | "notification_channel"
                | "monitor_metric_snapshot"
                | "monitor_alert_history"
                | "monitor_activity_log"
        )
    }) {
        for column in *columns {
            assert!(
                MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains(column),
                "monitor repair must define {table}.{column}"
            );
        }
    }
    for (table, index, columns, unique) in
        REQUIRED_SCHEMA_INDEXES.iter().filter(|(table, _, _, _)| {
            matches!(
                *table,
                "alert_rule"
                    | "notification_channel"
                    | "monitor_metric_snapshot"
                    | "monitor_alert_history"
                    | "monitor_activity_log"
            )
        })
    {
        assert!(
            MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains(index) || *index == "PRIMARY",
            "monitor repair must define {table}.{index}"
        );
        for column in *columns {
            assert!(
                MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains(column),
                "monitor repair must define {table}.{index} column {column}"
            );
        }
        if *unique {
            assert!(
                MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains("PRIMARY KEY"),
                "monitor repair must preserve uniqueness for {table}.{index}"
            );
        }
    }
}

#[test]
fn monitor_repair_artifact_contract_matches_pending_migration() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == MONITOR_SCHEMA_REPAIR_VERSION)
        .expect("monitor repair migration must remain embedded");
    assert!(migration_defines_table(migration, "alert_rule"));
    assert!(migration_defines_index(
        migration,
        "monitor_metric_snapshot",
        "idx_mms_service_type",
        &["service_name", "metric_type"],
        false
    ));
    assert!(migration_defines_index(
        migration,
        "monitor_alert_history",
        "idx_mah_severity",
        &["severity"],
        false
    ));
    assert!(migration_defines_index(
        migration,
        "monitor_activity_log",
        "idx_mal_occurred",
        &["occurred_at"],
        false
    ));
    assert!(!migration_defines_existing_column(
        migration,
        "alert_rule",
        "name"
    ));
    assert!(!migration_defines_existing_index(
        migration,
        "notification_channel",
        "PRIMARY",
        &["id"],
        true
    ));
}

#[test]
fn monitor_schema_contract_covers_all_exact_metadata_and_rejects_drift() {
    assert_eq!(MONITOR_SCHEMA_TABLES.len(), 5);
    assert_eq!(MONITOR_SCHEMA_COLUMN_CONTRACT.len(), 39);
    for expected in MONITOR_SCHEMA_COLUMN_CONTRACT {
        assert!(schema_column_contract_matches(
            expected.name,
            expected.column_type,
            if expected.not_null { "NO" } else { "YES" },
            expected.default,
            expected.charset,
            expected.collation,
            expected,
        ));
    }

    let character_column = MONITOR_SCHEMA_COLUMN_CONTRACT
        .iter()
        .find(|column| column.table == "alert_rule" && column.name == "name")
        .expect("monitor character column contract");
    for (column_type, nullable, default, charset, collation) in [
        (
            "VARCHAR(128)",
            "NO",
            None,
            Some(MYSQL_SCHEMA_CHARSET),
            Some(MYSQL_SCHEMA_COLLATION),
        ),
        (
            "VARCHAR(255)",
            "YES",
            None,
            Some(MYSQL_SCHEMA_CHARSET),
            Some(MYSQL_SCHEMA_COLLATION),
        ),
        (
            "VARCHAR(255)",
            "NO",
            Some("drift"),
            Some(MYSQL_SCHEMA_CHARSET),
            Some(MYSQL_SCHEMA_COLLATION),
        ),
        (
            "VARCHAR(255)",
            "NO",
            None,
            Some(MYSQL_SCHEMA_CHARSET),
            Some("utf8mb4_general_ci"),
        ),
        (
            "VARCHAR(255)",
            "NO",
            None,
            Some("latin1"),
            Some("latin1_swedish_ci"),
        ),
    ] {
        assert!(!schema_column_contract_matches(
            character_column.name,
            column_type,
            nullable,
            default,
            charset,
            collation,
            character_column,
        ));
    }

    let numeric_column = MONITOR_SCHEMA_COLUMN_CONTRACT
        .iter()
        .find(|column| column.table == "alert_rule" && column.name == "threshold")
        .expect("monitor numeric column contract");
    assert!(!schema_column_contract_matches(
        numeric_column.name,
        "DOUBLE",
        "NO",
        None,
        Some(MYSQL_SCHEMA_CHARSET),
        Some(MYSQL_SCHEMA_COLLATION),
        numeric_column,
    ));
}

#[test]
fn monitor_schema_state_rejects_partial_creator_artifacts() {
    assert_eq!(
        classify_monitor_schema_state(0),
        MonitorSchemaState::Missing
    );
    assert_eq!(
        classify_monitor_schema_state(1),
        MonitorSchemaState::Partial
    );
    assert_eq!(
        classify_monitor_schema_state(MONITOR_SCHEMA_TABLES.len() - 1),
        MonitorSchemaState::Partial
    );
    assert_eq!(
        classify_monitor_schema_state(MONITOR_SCHEMA_TABLES.len()),
        MonitorSchemaState::Complete
    );
    assert!(!MONITOR_SCHEMA_TABLES.is_empty());
}

#[test]
fn monitor_creator_is_exact_and_never_claims_existing_artifact_repair() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == MONITOR_SCHEMA_REPAIR_VERSION)
        .expect("monitor creator migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == MONITOR_SCHEMA_REPAIR_VERSION)
        .expect("monitor creator contract must remain registered");

    assert!(!contract.supports_existing_artifacts);
    assert_eq!(
        canonical_sha384_hex(MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.as_bytes()),
        MONITOR_SCHEMA_REPAIR_SQL_SHA384
    );
    assert_eq!(
        MONITOR_SCHEMA_REPAIR_MIGRATION_SQL
            .matches("COLLATE=utf8mb4_unicode_ci")
            .count(),
        MONITOR_SCHEMA_TABLES.len()
    );
    for table in MONITOR_SCHEMA_TABLES {
        assert!(migration_defines_table(migration, table));
        assert!(!migration_defines_existing_column(migration, table, "id"));
        assert!(!migration_defines_existing_index(
            migration,
            table,
            "PRIMARY",
            &["id"],
            true
        ));
    }
    assert!(!MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains("ALTER TABLE"));
    assert!(!MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!MONITOR_SCHEMA_REPAIR_MIGRATION_SQL.contains("DROP COLUMN"));
}

#[test]
fn monitor_schema_validation_is_wired_before_sqlx_and_at_startup() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let apply_body = production_source
        .split("async fn apply_migrations_with_mysql8_compat")
        .nth(1)
        .and_then(|body| body.split("fn migration_matches_known_source").next())
        .expect("migration apply body must exist");
    let preflight = apply_body
        .find("preflight_schema_contract_before_sqlx(pool, &applied_versions")
        .expect("generic preflight must run before SQLx");
    let generic_preflight_body = production_source
        .split("async fn preflight_schema_contract_before_sqlx(")
        .nth(1)
        .and_then(|body| body.split("fn migration_matches_known_source").next())
        .expect("generic preflight body must exist");
    let monitor_preflight = generic_preflight_body
        .find("preflight_monitor_schema_contract(pool, applied_versions, migrations).await?")
        .expect("monitor preflight must be wired into generic preflight");
    let sqlx_run = apply_body
        .find("migrator\n        .run(pool)")
        .expect("SQLx run must exist");
    assert!(preflight < sqlx_run);
    assert!(monitor_preflight < generic_preflight_body.len());
    assert!(production_source.contains("validate_monitor_schema_contract(pool).await?"));
    assert!(production_source.contains("MonitorSchemaState::Partial"));
    assert!(production_source.contains("MigrationError::RecoveryRequired"));
}

#[test]
fn replay_lease_generation_contract_is_exact_and_unsigned() {
    let contract = AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT;
    assert_eq!(contract.table, "audit_quarantine");
    assert_eq!(contract.name, "replay_lease_generation");
    assert_eq!(contract.column_type, "BIGINT UNSIGNED");
    assert!(contract.not_null);
    assert_eq!(contract.default, Some("0"));
    assert!(contract.charset.is_none());
    assert!(contract.collation.is_none());

    assert!(schema_column_contract_matches(
        "replay_lease_generation",
        "BIGINT UNSIGNED",
        "NO",
        Some("0"),
        None,
        None,
        &contract,
    ));
}

#[test]
fn replay_lease_generation_contract_rejects_schema_drift() {
    let contract = AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT;
    let cases = [
        ("BIGINT", "NO", Some("0"), None, None),
        ("BIGINT UNSIGNED", "YES", Some("0"), None, None),
        ("BIGINT UNSIGNED", "NO", None, None, None),
        ("BIGINT UNSIGNED", "NO", Some("1"), None, None),
        ("BIGINT UNSIGNED", "NO", Some("0"), Some("utf8mb4"), None),
        (
            "BIGINT UNSIGNED",
            "NO",
            Some("0"),
            None,
            Some("utf8mb4_general_ci"),
        ),
    ];

    for (column_type, nullable, default, charset, collation) in cases {
        assert!(
                !schema_column_contract_matches(
                    "replay_lease_generation",
                    column_type,
                    nullable,
                    default,
                    charset,
                    collation,
                    &contract,
                ),
                "schema drift must be rejected for type={column_type}, nullable={nullable}, default={default:?}, charset={charset:?}, collation={collation:?}"
            );
    }
    assert!(!schema_column_contract_matches(
        "wrong_name",
        "BIGINT UNSIGNED",
        "NO",
        Some("0"),
        None,
        None,
        &contract,
    ));
}

#[test]
fn replay_lease_generation_contract_is_checked_before_sqlx_and_at_startup() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let preflight_call = production_source
        .find("preflight_schema_contract_before_sqlx(pool, &applied_versions")
        .expect("schema preflight call must exist");
    let sqlx_run = production_source
        .find("migrator\n        .run(pool)")
        .expect("SQLx run must exist");
    assert!(preflight_call < sqlx_run);

    let preflight_body = production_source
        .split("async fn preflight_schema_contract_before_sqlx(")
        .nth(1)
        .and_then(|body| body.split("fn migration_matches_known_source").next())
        .expect("schema preflight implementation must exist");
    assert!(preflight_body.contains("validate_schema_column_exact("));
    assert!(production_source.contains(
        "validate_schema_column_exact(pool, &AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT)"
    ));
    assert!(production_source.contains("refusing automatic ALTER/DROP"));
}

#[test]
fn audit_quarantine_migration_and_contract_match() {
    assert!(!is_java_baseline_era(20260818000003));
    assert!(!is_java_baseline_era(20260818000004));
    assert!(AUDIT_QUARANTINE_MIGRATION_SQL.contains("CREATE TABLE IF NOT EXISTS audit_quarantine"));
    assert!(QUARANTINE_HARDENING_MIGRATION_SQL.contains("replay_lease_token_hash"));
    assert!(QUARANTINE_HARDENING_MIGRATION_SQL
        .contains("replay_lease_generation BIGINT UNSIGNED NOT NULL DEFAULT 0"));
    assert!(QUARANTINE_HARDENING_MIGRATION_SQL.contains("REPLAY_REQUESTED"));
    assert!(AUDIT_QUARANTINE_MIGRATION_SQL.contains("identity_key             BINARY(32) NOT NULL"));
    assert!(AUDIT_QUARANTINE_MIGRATION_SQL.contains("UNIQUE KEY uk_aq_identity_key (identity_key)"));
    assert!(!AUDIT_QUARANTINE_MIGRATION_SQL.contains("CHECK ("));
    assert!(!AUDIT_QUARANTINE_MIGRATION_SQL.contains("(("));

    let required_columns = REQUIRED_SCHEMA_COLUMNS
        .iter()
        .find(|(table, _)| *table == "audit_quarantine")
        .map(|(_, columns)| *columns)
        .expect("audit_quarantine columns must be registered");
    for column in required_columns {
        assert!(
            AUDIT_QUARANTINE_MIGRATION_SQL.contains(column)
                || QUARANTINE_HARDENING_MIGRATION_SQL.contains(column),
            "migration must define audit_quarantine.{column}"
        );
    }

    for (table, index, columns, unique) in REQUIRED_SCHEMA_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table == "audit_quarantine")
    {
        assert!(
            AUDIT_QUARANTINE_MIGRATION_SQL.contains(index)
                || QUARANTINE_HARDENING_MIGRATION_SQL.contains(index),
            "migration must define {table}.{index}"
        );
        for column in *columns {
            assert!(
                AUDIT_QUARANTINE_MIGRATION_SQL.contains(column)
                    || QUARANTINE_HARDENING_MIGRATION_SQL.contains(column),
                "migration must define {table}.{index} column {column}"
            );
        }
        if *unique {
            assert!(
                AUDIT_QUARANTINE_MIGRATION_SQL.contains("UNIQUE KEY") || *index == "PRIMARY",
                "migration must preserve uniqueness for {table}.{index}"
            );
        }
    }
}

#[test]
fn audit_quarantine_pending_definitions_cover_split_creator_and_hardening_migrations() {
    let creator = Migration::new(
        20260818000003,
        "audit_quarantine".into(),
        sqlx::migrate::MigrationType::Simple,
        AUDIT_QUARANTINE_MIGRATION_SQL.into(),
        false,
    );
    let hardening = Migration::new(
        20260818000004,
        "quarantine_replay_hardening".into(),
        sqlx::migrate::MigrationType::Simple,
        QUARANTINE_HARDENING_MIGRATION_SQL.into(),
        false,
    );
    let pending = [&creator, &hardening];

    assert!(pending
        .iter()
        .any(|migration| migration_defines_table(migration, "audit_quarantine")));
    for column in REQUIRED_SCHEMA_COLUMNS
        .iter()
        .find(|(table, _)| *table == "audit_quarantine")
        .map(|(_, columns)| *columns)
        .expect("audit_quarantine columns must be registered")
    {
        assert!(
            pending.iter().any(|migration| {
                pending_migration_defines_column(migration, "audit_quarantine", column)
            }),
            "split pending migrations must define audit_quarantine.{column}"
        );
    }
    for (table, index, columns, unique) in REQUIRED_SCHEMA_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table == "audit_quarantine")
    {
        assert!(
            pending.iter().any(|migration| {
                pending_migration_defines_index(migration, table, index, columns, *unique)
            }),
            "split pending migrations must define {table}.{index}"
        );
    }
}

#[test]
fn baseline_ready_requires_no_foreign_keys_on_all_baseline_tables() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let baseline_ready_condition = source
        .split("let no_foreign_keys = schema_foreign_keys_match(pool, \"sod_violation\", &[])")
        .nth(1)
        .and_then(|body| {
            body.split("TrustgraphRuntimeSchemaState::BaselineReady")
                .next()
        })
        .expect("BaselineReady state condition must exist");
    assert!(baseline_ready_condition.contains("baseline_ready_indexes"));
    assert!(baseline_ready_condition.contains("other_tables_have_no_foreign_keys"));
    assert!(source.contains("schema_foreign_keys_match(pool, \"sod_policy\", &[])"));
    assert!(source.contains("schema_foreign_keys_match(pool, \"identity_global_admin\", &[])"));
}

#[test]
fn audit_quarantine_follows_existing_runtime_history_and_repair() {
    // 这些 Rust-only 迁移必须全部保持"由 SQLx 执行"（永不基线采纳）。
    for version in [
        RUST_RUNTIME_SCHEMA_VERSION,
        RUST_RUNTIME_SCHEMA_REPAIR_VERSION,
        AUDIT_QUARANTINE_SCHEMA_VERSION,
        QUARANTINE_REPLAY_HARDENING_VERSION,
        MONITOR_SCHEMA_REPAIR_VERSION,
        RULE_SET_PROJECTION_SCHEMA_REPAIR_VERSION,
        SNAPSHOT_VALIDITY_SCHEMA_VERSION,
        RULE_SET_SNAPSHOT_MANIFEST_VERSION,
        INCREMENTAL_PROJECTION_ARCHIVE_VERSION,
        AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION,
        LEGACY_SNAPSHOT_DECOMMISSION_VERSION,
        IDENTITY_CARD_DUAL_CARD_SEPARATION_VERSION,
        HEAD_PROJECTION_STATUS_RETIREMENT_VERSION,
    ] {
        assert!(
            !is_java_baseline_era(version),
            "Rust-only migration {version} must never be adopted as baseline"
        );
    }
    assert!(RUNTIME_MIGRATION_SQL.contains("CREATE TABLE IF NOT EXISTS"));
    assert!(RUNTIME_REPAIR_MIGRATION_SQL.contains("sqlx checksums are immutable"));
    assert!(!AUDIT_QUARANTINE_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!AUDIT_QUARANTINE_MIGRATION_SQL.contains("ALTER TABLE"));
}

#[test]
fn rule_set_projection_repair_artifact_contract_matches_pending_migration() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RULE_SET_PROJECTION_SCHEMA_REPAIR_VERSION)
        .expect("RuleSet projection repair migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == RULE_SET_PROJECTION_SCHEMA_REPAIR_VERSION)
        .expect("RuleSet projection repair artifact contract must remain registered");

    assert!(contract.supports_existing_artifacts);
    assert_eq!(
        canonical_sha384_hex(RULE_SET_PROJECTION_SCHEMA_REPAIR_MIGRATION_SQL.as_bytes()),
        RULE_SET_PROJECTION_SCHEMA_REPAIR_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        RULE_SET_PROJECTION_SCHEMA_REPAIR_SQL_SHA384
    );
    assert!(migration_defines_existing_column(
        migration,
        "rule_set_snapshot",
        "projection_generation"
    ));
    for (table, index, columns, unique) in RULE_SET_PROJECTION_REPAIR_INDEXES {
        assert!(
            migration_defines_existing_index(migration, table, index, columns, *unique),
            "repair must define {table}.{index}"
        );
    }
    assert!(!migration_defines_existing_index(
        migration,
        "rule_set",
        "PRIMARY",
        &["rule_set_id"],
        true
    ));
    assert!(RULE_SET_PROJECTION_SCHEMA_REPAIR_MIGRATION_SQL.contains(
        "ALTER TABLE rule_set_snapshot ADD COLUMN projection_generation BIGINT NOT NULL DEFAULT 0"
    ));
    assert!(RULE_SET_PROJECTION_SCHEMA_REPAIR_MIGRATION_SQL.contains("PREPARE astral_stmt"));
    assert!(!RULE_SET_PROJECTION_SCHEMA_REPAIR_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!RULE_SET_PROJECTION_SCHEMA_REPAIR_MIGRATION_SQL.contains("DROP COLUMN"));
}

#[test]
fn snapshot_validity_contract_requires_nullable_utc_datetimes() {
    assert_eq!(SNAPSHOT_VALIDITY_SCHEMA_COLUMNS.len(), 4);
    for contract in SNAPSHOT_VALIDITY_COLUMN_CONTRACTS {
        assert_eq!(contract.column_type, "DATETIME");
        assert!(!contract.not_null);
        assert_eq!(contract.default, None);
        assert!(schema_column_contract_matches(
            contract.name,
            "DATETIME",
            "YES",
            None,
            None,
            None,
            contract,
        ));
    }
}

#[test]
fn snapshot_validity_migration_artifact_contract_is_checksum_safe_and_additive() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == SNAPSHOT_VALIDITY_SCHEMA_VERSION)
        .expect("snapshot validity migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == SNAPSHOT_VALIDITY_SCHEMA_VERSION)
        .expect("snapshot validity artifact contract must remain registered");
    assert!(contract.supports_existing_artifacts);
    assert_eq!(
        canonical_sha384_hex(SNAPSHOT_VALIDITY_SCHEMA_MIGRATION_SQL.as_bytes()),
        SNAPSHOT_VALIDITY_SCHEMA_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        SNAPSHOT_VALIDITY_SCHEMA_SQL_SHA384
    );
    for (table, column) in SNAPSHOT_VALIDITY_SCHEMA_COLUMNS {
        assert!(migration_defines_existing_column(migration, table, column));
    }
    assert!(!SNAPSHOT_VALIDITY_SCHEMA_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!SNAPSHOT_VALIDITY_SCHEMA_MIGRATION_SQL.contains("DROP COLUMN"));
}

#[test]
fn rule_set_snapshot_manifest_artifact_contract_matches_pending_migration() {
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == RULE_SET_SNAPSHOT_MANIFEST_VERSION)
        .expect("RuleSet snapshot manifest migration must remain embedded");
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == RULE_SET_SNAPSHOT_MANIFEST_VERSION)
        .expect("RuleSet snapshot manifest artifact contract must remain registered");

    assert!(!contract.supports_existing_artifacts);
    assert_eq!(
        canonical_sha384_hex(RULE_SET_SNAPSHOT_MANIFEST_MIGRATION_SQL.as_bytes()),
        RULE_SET_SNAPSHOT_MANIFEST_SQL_SHA384
    );
    assert_eq!(
        canonical_sha384_hex(migration.sql.as_bytes()),
        RULE_SET_SNAPSHOT_MANIFEST_SQL_SHA384
    );
    assert!(migration_defines_table(
        migration,
        "rule_set_snapshot_manifest"
    ));
    for (table, column) in RULE_SET_SNAPSHOT_MANIFEST_COLUMNS {
        assert!(migration_defines_column(migration, table, column));
    }
    for (table, index, columns, unique) in RULE_SET_SNAPSHOT_MANIFEST_INDEXES {
        assert!(migration_defines_index(
            migration, table, index, columns, *unique
        ));
    }
    assert!(!migration_defines_existing_column(
        migration,
        "rule_set_snapshot_manifest",
        "rule_set_id"
    ));
    assert!(!migration_defines_existing_index(
        migration,
        "rule_set_snapshot_manifest",
        "PRIMARY",
        &["rule_set_id", "projection_generation"],
        true
    ));
    assert!(RULE_SET_SNAPSHOT_MANIFEST_MIGRATION_SQL
        .contains("COMMENT='Rust-owned generation-bound empty/deleted RuleSet snapshot proof'"));
    assert!(!RULE_SET_SNAPSHOT_MANIFEST_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!RULE_SET_SNAPSHOT_MANIFEST_MIGRATION_SQL.contains("DROP COLUMN"));
}

#[test]
fn rule_set_projection_generation_contract_rejects_schema_drift() {
    let contract = &RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT;
    assert_eq!(contract.table, "rule_set_snapshot");
    assert_eq!(contract.name, "projection_generation");
    assert_eq!(contract.column_type, "BIGINT");
    assert!(contract.not_null);
    assert_eq!(contract.default, Some("0"));
    assert!(contract.charset.is_none());
    assert!(contract.collation.is_none());
    assert!(schema_column_contract_matches(
        "projection_generation",
        "BIGINT",
        "NO",
        Some("0"),
        None,
        None,
        contract,
    ));
    for (column_type, nullable, default, charset, collation) in [
        ("BIGINT UNSIGNED", "NO", Some("0"), None, None),
        ("BIGINT", "YES", Some("0"), None, None),
        ("BIGINT", "NO", None, None, None),
        ("BIGINT", "NO", Some("1"), None, None),
        ("BIGINT", "NO", Some("0"), Some("utf8mb4"), None),
        ("BIGINT", "NO", Some("0"), None, Some("utf8mb4_general_ci")),
    ] {
        assert!(
                !schema_column_contract_matches(
                    "projection_generation",
                    column_type,
                    nullable,
                    default,
                    charset,
                    collation,
                    contract,
                ),
                "schema drift must be rejected for type={column_type}, nullable={nullable}, default={default:?}, charset={charset:?}, collation={collation:?}"
            );
    }
}

#[test]
fn rule_set_projection_aliases_match_exact_shapes() {
    assert_eq!(
        schema_index_candidates("rule_set_snapshot", "uk_rule_set_snapshot"),
        vec!["uk_rule_set_snapshot", "uk_snapshot"]
    );
    assert_eq!(
        schema_index_candidates("authorization_projection_head", "uk_aph_aggregate"),
        vec![
            "uk_aph_aggregate",
            "uk_test_projection_head",
            "uk_projection_head",
        ]
    );
    assert_eq!(
        schema_index_candidates("authorization_projection_outbox", "idx_apob_pending"),
        vec!["idx_apob_pending", "idx_test_apob_pending"]
    );
    assert_eq!(
        schema_index_candidates("authorization_projection_outbox", "idx_apob_lease"),
        vec!["idx_apob_lease", "idx_test_apob_lease"]
    );
    assert_eq!(
        schema_index_candidates("authorization_projection_outbox", "idx_apob_aggregate"),
        vec!["idx_apob_aggregate", "idx_test_apob_aggregate"]
    );
    assert_eq!(
        schema_index_candidates("rule_set", "uk_rule_set_code"),
        vec!["uk_rule_set_code"]
    );
}

#[test]
fn migration_backfill_payload_has_system_actor_and_deterministic_operation() {
    let first = migration_backfill_payload(42, Some(7), 3);
    let second = migration_backfill_payload(42, Some(7), 3);
    assert_eq!(first, second);
    assert_eq!(first["ruleSetId"], 42);
    assert_eq!(first["tenantId"], 7);
    assert_eq!(first["generation"], 3);
    assert_eq!(first["actorId"], astral_types::SYSTEM_ACTOR_ID);
    assert_eq!(
        first["operationId"],
        "migration-backfill:20260822000001:rule-set:42:generation:3"
    );
    assert!(!first["operationId"].as_str().unwrap_or_default().is_empty());
}

#[test]
fn malformed_or_mismatched_migration_marker_is_not_authoritative() {
    let payload = migration_backfill_payload(42, Some(7), 3);
    assert!(valid_migration_backfill_marker(&payload, 42, 3, 3, Some(7)));
    assert!(!valid_migration_backfill_marker(
        &payload,
        43,
        3,
        3,
        Some(7)
    ));
    assert!(!valid_migration_backfill_marker(
        &payload,
        42,
        4,
        3,
        Some(7)
    ));
    assert!(!valid_migration_backfill_marker(
        &payload,
        42,
        3,
        3,
        Some(8)
    ));
    assert!(!valid_migration_backfill_marker(
        &serde_json::json!({"migrationVersion": RULE_SET_PROJECTION_BACKFILL_MARKER}),
        42,
        3,
        3,
        Some(7),
    ));
}

#[test]
fn repairing_marker_metadata_preserves_event_identity_and_generation() {
    let payload = serde_json::json!({
        "ruleSetId": 42,
        "tenantId": 7,
        "generation": 3,
        "migrationVersion": RULE_SET_PROJECTION_BACKFILL_MARKER,
    });
    let repaired = repair_migration_backfill_payload(payload, 42, 3).unwrap();
    assert_eq!(repaired["actorId"], astral_types::SYSTEM_ACTOR_ID);
    assert_eq!(repaired["ruleSetId"], 42);
    assert_eq!(repaired["generation"], 3);
    assert_eq!(
        repaired["operationId"],
        "migration-backfill:20260822000001:rule-set:42:generation:3"
    );
}

#[test]
fn migration_backfill_status_columns_are_retired() {
    // 旧链状态列随迁移 20260831000001 退役：backfill 对 head 只维护
    // 代次/围栏/last_event_id，绝不写 projected_generation/projection_status。
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("test module must be separable");
    assert!(!production_source.contains("projection_status"));
    assert!(!production_source.contains("projected_generation = source_generation"));
}

#[test]
fn migration_backfill_retired_snapshot_proof_is_absent() {
    // 快照重建通道已随迁移 20260827000002 退役（snapshot 表已删除），旧
    // "零行快照 + manifest outbox 关联证明"谓词必须从 backfill 中缺席，
    // PROCESSED 标记即终态；防止重构时静默复活对已删表的 SQL 引用。
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let after_backfill = production_source
        .split("async fn backfill_rule_set_projection")
        .nth(1)
        .expect("backfill implementation must exist");
    // 只扫 backfill 函数体自身（后续函数的内嵌历史迁移 SQL 允许保留旧表名）。
    let backfill = &after_backfill
        .split("async fn ")
        .next()
        .expect("backfill body must be bounded");
    for retired in [
        "rule_set_snapshot_manifest",
        "empty_manifest_is_proven",
        "snapshot_row_count",
        "change_type = 'REBUILD_SNAPSHOT'",
    ] {
        assert!(
            !backfill.contains(retired),
            "backfill must not reference retired snapshot proof surface: {retired}"
        );
    }
}

#[test]
fn rule_set_projection_backfill_is_wired_after_sqlx_under_migration_lock() {
    let source = include_str!("../migration.rs").replace("\r\n", "\n");
    let production_source = source
        .split("#[cfg(test)]")
        .next()
        .expect("production source must precede tests");
    let apply_helper = production_source
        .split("async fn apply_migrations_with_mysql8_compat")
        .nth(1)
        .and_then(|body| body.split("fn migration_matches_known_source").next())
        .expect("migration apply helper must exist");
    let sqlx_run = apply_helper
        .find("migrator\n        .run(pool)")
        .expect("SQLx run must exist");
    let backfill = apply_helper
        .find("backfill_rule_set_projection(pool).await?")
        .expect("RuleSet projection backfill must be invoked");
    assert!(sqlx_run < backfill);
    let apply_entrypoint = production_source
        .split("pub async fn apply_migrations(database_url")
        .nth(1)
        .and_then(|body| {
            body.split("pub async fn connect_and_validate_schema")
                .next()
        })
        .expect("migration entrypoint must exist");
    let migration_scope = apply_entrypoint
        .find("let migration_result = async {")
        .expect("migration work must be scoped");
    let release_lock = apply_entrypoint
        .find("let cleanup_result = release_migration_lock(&mut lock_connection).await")
        .expect("migration lock cleanup must exist");
    assert!(migration_scope < release_lock);
    assert!(apply_helper.contains("SELECT COUNT(*) \\\n         FROM card_rule_set_ref"));
    let source_lock = production_source
        .find("SELECT rule_set_id, tenant_id FROM rule_set ORDER BY rule_set_id FOR UPDATE")
        .expect("RuleSet source rows must be locked in deterministic order");
    let source_load = production_source
        .find("let rule_sets: Vec<(i64, Option<i64>)>")
        .expect("RuleSet source rows must be loaded before reconciliation");
    let head_reconciliation = production_source
        .find("FROM authorization_projection_head")
        .expect("RuleSet projection head reconciliation must exist");
    assert!(source_load < source_lock);
    assert!(source_lock < head_reconciliation);
    assert!(production_source
        .contains("SELECT rule_set_id, tenant_id FROM rule_set ORDER BY rule_set_id FOR UPDATE"));
    assert!(production_source.contains("source_generation.checked_add(1)"));
    // 旧链状态列已退役：backfill 不再写 head 投影状态（见
    // migration_backfill_status_columns_are_retired）。
    assert!(!production_source.contains("projection_status = 'PENDING'"));
    assert!(production_source.contains("EVENT_TYPE_RULE_SET_UPDATE"));
    assert!(production_source.contains("RULE_SET_PROJECTION_BACKFILL_MARKER"));
    assert!(!production_source.contains("projected_generation = source_generation"));
}

#[test]
fn runtime_repair_is_conditional_and_covers_all_required_columns_and_indexes() {
    for table in ["audit_log", "mq_idempotent_log", "pending_compensation"] {
        assert!(RUNTIME_REPAIR_MIGRATION_SQL.contains(&format!(
                "information_schema.COLUMNS\n    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = '{table}'"
            )));
    }
    for (table, columns) in REQUIRED_SCHEMA_COLUMNS.iter().filter(|(table, _)| {
        matches!(
            *table,
            "audit_log" | "mq_idempotent_log" | "pending_compensation"
        )
    }) {
        for column in *columns {
            assert!(
                RUNTIME_REPAIR_MIGRATION_SQL.contains(&format!(
                    "TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'"
                )),
                "repair must inspect {table}.{column}"
            );
        }
    }
    for index in [
        "idx_al_user",
        "idx_al_action",
        "idx_al_created",
        "idx_al_event_type",
        "idx_al_tenant",
        "idx_al_card",
        "idx_al_decision",
        "uk_mq_msg",
        "idx_status",
        "idx_entity",
    ] {
        assert!(
            RUNTIME_REPAIR_MIGRATION_SQL.contains(&format!("INDEX_NAME = '{index}'")),
            "repair must inspect index {index}"
        );
    }
    for (table, index, columns, unique) in
        REQUIRED_SCHEMA_INDEXES.iter().filter(|(table, _, _, _)| {
            matches!(
                *table,
                "audit_log" | "mq_idempotent_log" | "pending_compensation"
            )
        })
    {
        assert!(
            RUNTIME_REPAIR_MIGRATION_SQL.contains(&format!("INDEX_NAME = '{index}'")),
            "repair must inspect index {table}.{index}"
        );
        for column in *columns {
            assert!(
                RUNTIME_REPAIR_MIGRATION_SQL.contains(&format!("COLUMN_NAME = '{column}'")),
                "repair must inspect {table}.{index} column {column}"
            );
        }
        if *unique {
            assert!(
                RUNTIME_REPAIR_MIGRATION_SQL.contains("NON_UNIQUE = 0") || *index == "PRIMARY",
                "repair must preserve uniqueness for {table}.{index}"
            );
        }
    }
    assert!(RUNTIME_REPAIR_MIGRATION_SQL.contains("PREPARE astral_stmt"));
    assert!(RUNTIME_REPAIR_MIGRATION_SQL.contains("THIS IS AN INTENTIONAL SCHEMA CONTRACT FAILURE"));
    assert!(!RUNTIME_REPAIR_MIGRATION_SQL.contains("DROP TABLE"));
    assert!(!RUNTIME_REPAIR_MIGRATION_SQL.contains("UPDATE audit_log"));
}

#[test]
fn repair_migration_is_rust_only_and_previous_sql_is_not_mutated() {
    assert!(!is_java_baseline_era(20260818000002));
    assert!(RUNTIME_REPAIR_MIGRATION_SQL.contains("sqlx checksums are immutable"));
    assert!(RUNTIME_REPAIR_MIGRATION_SQL.contains("MySQL 5.7-compatible"));
}
