//! 数据库迁移管理
//!
//! 通过 `sqlx::migrate!()` 宏在编译期嵌入迁移脚本。
//!
//! Rust is the sole owner of schema evolution. Production services only connect
//! to and validate an already migrated schema; the explicit `astral-migrate`
//! job is the only entry point allowed to execute DDL.
//!
//! DATETIME columns in the MySQL auth contract are UTC wall-clock values.  Rust
//! converts `OffsetDateTime::now_utc()` to `PrimitiveDateTime` at the boundary;
//! the database/session timezone must remain UTC.

use sha2::{Digest, Sha384};
use sqlx::migrate::{Migration, Migrator};
use sqlx::mysql::{MySqlConnectOptions, MySqlConnection, MySqlPoolOptions};
use sqlx::{Connection, MySqlPool};
use std::borrow::Cow;
use std::collections::HashSet;
use std::str::FromStr;

use astral_types::{ProjectionAggregate, EVENT_TYPE_RULE_SET_UPDATE};

const MIGRATION_LOCK_NAME: &str = "astral_light_rust_migrations";
const MYSQL_SCHEMA_CHARSET: &str = "utf8mb4";
const MYSQL_SCHEMA_COLLATION: &str = "utf8mb4_unicode_ci";
const MYSQL_MIGRATION_COLLATION: &str = "utf8mb4_0900_ai_ci";
const MIGRATION_SET_NAMES_SQL: &str = "SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci";
const MIGRATION_SET_COLLATION_CONNECTION_SQL: &str =
    "SET collation_connection = 'utf8mb4_0900_ai_ci'";
const SET_UTC_TIME_ZONE_SQL: &str = "SET time_zone = '+00:00'";
const AUTH_FAMILY_SCHEMA_CONTRACT_VERSION: i64 = 20260714000001;
const AUTH_SESSION_RESILIENCE_VERSION: i64 = 20260728000001;
const TENANT_SCHOOL_CUTOVER_VERSION: i64 = 20260729000001;
const TRUSTGRAPH_RUNTIME_TABLES_VERSION: i64 = 20260729000002;
// Each historical compatibility contract is pinned to the canonical LF hash
// of its original SQL. SQLx's raw-byte checksum remains untouched and is never
// rewritten when the execution SQL is adapted for MySQL 8.
const AUTH_FAMILY_SCHEMA_CONTRACT_SQL_SHA384: &str =
    "a0b65843ea3c3e34d687ff08f99f4f0d49b00ae198b4ea5b3aa1da24c7b1f66fcc11294aa81987ce7673a00c2c5c89ac";
const AUTH_SESSION_RESILIENCE_SQL_SHA384: &str =
    "fb9ea9c0f1361bb2065f26d3afccc9d87b4283d4bd7a30b92d034f5719aa721b253b36adf1efba9c954383e1805d3c0c";
const TENANT_SCHOOL_CUTOVER_SQL_SHA384: &str =
    "e467ca53a9e156e7c2f5b6ddc81d75fce923740513655c66c45bb9c6a81c3e920afdf9c66a70eac4577cf774d6d3e111";
const TRUSTGRAPH_RUNTIME_TABLES_SQL_SHA384: &str =
    "58209d46915f8754d226cd920c3a501ad21903158621e462dba93981b34b1be3fc411761975ecb51c7c00650f32db24c";
const AUDIT_QUARANTINE_SCHEMA_VERSION: i64 = 20260818000003;
const QUARANTINE_REPLAY_HARDENING_VERSION: i64 = 20260818000004;
const MONITOR_SCHEMA_REPAIR_VERSION: i64 = 20260820000001;
const RULE_SET_PROJECTION_SCHEMA_REPAIR_VERSION: i64 = 20260822000001;
const SNAPSHOT_VALIDITY_SCHEMA_VERSION: i64 = 20260822000002;
const RULE_SET_SNAPSHOT_MANIFEST_VERSION: i64 = 20260825000001;
const INCREMENTAL_PROJECTION_ARCHIVE_VERSION: i64 = 20260825000002;
const AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION: i64 = 20260827000001;
const LEGACY_SNAPSHOT_DECOMMISSION_VERSION: i64 = 20260827000002;
const IDENTITY_CARD_DUAL_CARD_SEPARATION_VERSION: i64 = 20260830000001;
const MONITOR_SCHEMA_TABLES: &[&str] = &[
    "alert_rule",
    "notification_channel",
    "monitor_metric_snapshot",
    "monitor_alert_history",
    "monitor_activity_log",
];
const RUST_RUNTIME_SCHEMA_VERSION: i64 = 20260818000001;
const RUST_RUNTIME_SCHEMA_REPAIR_VERSION: i64 = 20260818000002;
const AUDIT_QUARANTINE_SQL_SHA384: &str =
    "e0b993096c9908f3bdbdb2a6b825a6c9be3fbbbb8594f520db97622008254f8dad8371afc619ba72dae2d8cfa9f218f6";
const QUARANTINE_REPLAY_HARDENING_SQL_SHA384: &str =
    "69e7887a842572741e2c042ca9c32fff11afd2f19414392c675fc7b9933f855d188d64f07969bc3ec12025d1dc24f736";
const MONITOR_SCHEMA_REPAIR_SQL_SHA384: &str =
    "58562a70c59e5b859d7e0ba175099b80b60633fc30f6bba3bc69eda82f46917058e2b3b14d82b572650ee92cf7bec11e";
const RUST_RUNTIME_SCHEMA_SQL_SHA384: &str =
    "f3bdf8091a213ff5cdb566bed0cde6c62dba7ab7753c24311382e644f54e1ddecfd972deffc62eff429c9a8c1e137d42";
const RUST_RUNTIME_SCHEMA_REPAIR_SQL_SHA384: &str =
    "add51551b0a99c2350e15b79c0f03dd1afac3abef1411e59b53d214cc367f9bc2126a2d5d690a76aa1f2cd59cb4e0122";
const RULE_SET_PROJECTION_SCHEMA_REPAIR_SQL_SHA384: &str =
    "0464771a095e759c27c53c2c1b93561dd32e7ce0b4e5aaabdc251844903daffa7d3164041a3ed18f1fe203d55b0fe38b";
const SNAPSHOT_VALIDITY_SCHEMA_SQL_SHA384: &str =
    "88575f78f531eaad73fa4602e606e26f5977b1872f118fecaed1e3ae1bb2f38c0d875e6c407b9c5bdbc442525cd6a547";
const RULE_SET_SNAPSHOT_MANIFEST_SQL_SHA384: &str =
    "dbed86532f02105b9e5df65d07497fe5694019ac3c5109c746465c34354da1d925d7bc883e7ec4018d4d2d31b978a9cb";
const INCREMENTAL_PROJECTION_ARCHIVE_SQL_SHA384: &str =
    "57e22d0150171e5ee02da7be055b3a4122cf0d9c0386cd2c377a51ca67fc7926a854d1a668466ce44936061bd8ca174a";
const AUTHORIZATION_PROJECTION_LINEAGE_FENCE_SQL_SHA384: &str =
    "dc240529879fdb0786aa9e2683cef1997e9c79251b4925736682f8dfc49438706e1f6d7cab9d074b143794f4a38bfd0c";
const DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_SQL_SHA384: &str =
    "0274217b93daa77ed2c9a423598459b2e80887cbba28adec58134e67e9c6098dc2dcdae5bbf12db9bcafff090ba93ecb";
const LEGACY_SNAPSHOT_DECOMMISSION_SQL_SHA384: &str =
    "77fde4dd4244622075b6a266de5860c6bdb11481f3be26efbf738c8a61fd7987a93984bce198520a312c5bff770ac1c8";
const IDENTITY_CARD_DUAL_CARD_SEPARATION_SQL_SHA384: &str =
    "ffd92dc831cad445448f2408c6d2324cbfa37f84d4fd42c19e0e181cd97a4a0391f9294df95602c65e70b1f833828c4e";
// Cross-city durable schema (default-off subsystem): the creator migration only
// builds the six Rust-owned tables; no runtime path reads or writes them yet.
const CROSS_CITY_SCHEMA_VERSION: i64 = 20260831000002;
const LOCAL_SCOPE_SEQUENCE_VERSION: i64 = 20261001000005;
const LEGACY_SNAPSHOT_REQUIRED_DRAIN_TABLES: &[&str] = &["authorization_projection_outbox"];
/// Delta claim sibling-ordering gate support index (campaign finding 10.D-2):
/// introduces `idx_ade_grant_chain` on authorization_delta_event via
/// 20260903000001_delta_claim_grant_chain_index.sql.
const DELTA_CLAIM_GRANT_CHAIN_INDEX_VERSION: i64 = 20260903000001;
const DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION: i64 = 20260914000001;
const REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION: i64 = 20261004000001;
const REDUNDANT_ARCHIVE_INDEX_REMOVAL_SQL_SHA384: &str =
    "931864ec1052fda01a6a1ec59a4986b9e37644f193602b1277b4a3eae89cbcbe041a20af58844d426cd55ced754868b1";
const POST_CREATOR_INDEX_REMOVALS: &[(i64, &str, &str)] = &[
    (
        REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION,
        "authorization_impact_plan",
        "idx_aip_aggregate",
    ),
    (
        REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION,
        "authorization_projection_manifest",
        "idx_apm_aggregate",
    ),
];

/// Indexes appended to creator tables by LATER additive Rust migrations.
///
/// Mirrors the lineage-fence column-tail resolver: the creator contract
/// ([`INCREMENTAL_PROJECTION_ARCHIVE_INDEXES`] and the 20260825000002 artifact
/// contract) stays verbatim so a pending post-creator index migration can
/// never look like creator-shape drift. While the defining migration is
/// pending the addition is TOLERATED (excluded from the exact-shape set so a
/// fresh database converges); once it is durably recorded the index becomes
/// REQUIRED — a missing index is drift and fails closed.
const POST_CREATOR_INDEX_ADDITIONS: &[(i64, &str, &str, &[&str], bool)] = &[(
    DELTA_CLAIM_GRANT_CHAIN_INDEX_VERSION,
    "authorization_delta_event",
    "idx_ade_grant_chain",
    &["tenant_id", "grant_id", "status", "target_version"],
    false,
)];

/// Versions of post-creator index additions that are durably recorded as
/// successfully executed. A missing migration-history table means no explicit
/// migration run ever happened yet, so nothing counts as recorded.
async fn recorded_post_creator_index_versions(
    pool: &MySqlPool,
) -> Result<HashSet<i64>, MigrationError> {
    if !migration_history_table_exists(pool).await? {
        return Ok(HashSet::new());
    }
    let recorded = recorded_successful_versions(pool).await?;
    Ok(POST_CREATOR_INDEX_ADDITIONS
        .iter()
        .map(|(version, _, _, _, _)| *version)
        .chain(
            POST_CREATOR_INDEX_REMOVALS
                .iter()
                .map(|(version, _, _)| *version),
        )
        .filter(|version| recorded.contains(version))
        .collect())
}

/// Resolve creator indexes against recorded additions/removals. A pending
/// removal accepts only the exact old index or its absence after partial DDL.
async fn incremental_projection_resolved_index_contract(
    pool: &MySqlPool,
    table: &str,
) -> Result<Vec<(&'static str, &'static str, &'static [&'static str], bool)>, MigrationError> {
    let recorded = recorded_post_creator_index_versions(pool).await?;
    let migration = MIGRATOR
        .migrations
        .iter()
        .find(|migration| migration.version == REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION)
        .filter(|migration| exact_migration_artifact_contract(migration).is_some())
        .ok_or_else(|| {
            MigrationError::Failed(
                "redundant archive index removal artifact is missing or unverified".to_owned(),
            )
        })?;
    let mut present_removals = HashSet::new();
    if !recorded.contains(&migration.version) {
        for (_, index_table, index) in POST_CREATOR_INDEX_REMOVALS {
            if *index_table == table && schema_index_exists(pool, table, index).await? {
                present_removals.insert(*index);
            }
        }
    }
    Ok(resolve_archive_index_contract(
        table,
        &recorded,
        &present_removals,
    ))
}

fn resolve_archive_index_contract(
    table: &str,
    recorded: &HashSet<i64>,
    present_removals: &HashSet<&str>,
) -> Vec<(&'static str, &'static str, &'static [&'static str], bool)> {
    let mut resolved: Vec<_> = INCREMENTAL_PROJECTION_ARCHIVE_INDEXES
        .iter()
        .filter(|(index_table, index, _, _)| {
            *index_table == table
                && !POST_CREATOR_INDEX_REMOVALS.iter().any(
                    |(version, removal_table, removal_index)| {
                        removal_table == index_table
                            && removal_index == index
                            && (recorded.contains(version) || !present_removals.contains(index))
                    },
                )
        })
        .copied()
        .collect();
    for (version, index_table, index, columns, unique) in POST_CREATOR_INDEX_ADDITIONS {
        if *index_table == table && recorded.contains(version) {
            resolved.push((*index_table, *index, *columns, *unique));
        }
    }
    resolved
}
const CROSS_CITY_SCHEMA_SQL_SHA384: &str =
    "9d6b15dae4cf03ed45bfd2d342ef2a7238ff78a1bbc56e788c4f1cca8639a1659af3e12db6dc9b64e203a9996ef24f22";
const CROSS_CITY_RUNTIME_PROOF_VERSION: i64 = 20261001000002;
const REVIEW_SCHEMA_REPAIR_VERSION: i64 = 20261003000003;
const CROSS_CITY_RUNTIME_PROOF_SQL_SHA384: &str =
    "9f3a75003c2f7b0578ab4666e454bda5e842afc571736bf2e915ff85cf08b740c6f0c74421a1afe52f3af130e5abb02d";
const REVIEW_SCHEMA_REPAIR_SQL_SHA384: &str =
    "ef67f67303bc20bb9a82677550272d92892f43c0303629600d14b45aae054210546c196dcd818e54095c0a6e854420bd";
const IDENTITY_CREDENTIAL_FENCE_VERSION: i64 = 20261003000001;
const ASYNC_OPERATION_CORRELATION_VERSION: i64 = 20261003000002;
const CHAT_DELIVERY_INTENT_VERSION: i64 = 20261003000004;
const LEARN_SYSTEM_ASSIGNMENT_VERSION: i64 = 20261003000005;
const IDENTITY_CREDENTIAL_FENCE_COLUMNS: &[HistoricalColumnSpec] = &[
    HistoricalColumnSpec {
        table: "user_local_credential",
        name: "credential_version",
        column_type: "BIGINT",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
        after: "password_hash",
    },
    HistoricalColumnSpec {
        table: "user_mfa",
        name: "last_totp_counter",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
        after: "last_used_at",
    },
    HistoricalColumnSpec {
        table: "mfa_attempt_log",
        name: "attempt_code",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "mfa_type",
    },
    HistoricalColumnSpec {
        table: "mfa_attempt_log",
        name: "status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("UNKNOWN"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "attempt_code",
    },
    HistoricalColumnSpec {
        table: "mfa_attempt_log",
        name: "user_agent",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "ip",
    },
    HistoricalColumnSpec {
        table: "auth_device_session",
        name: "credential_version",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
        after: "session_epoch",
    },
];
const IDENTITY_CREDENTIAL_FENCE_COLUMNS_ARTIFACTS: &[(&str, &str)] = &[
    ("user_local_credential", "credential_version"),
    ("user_mfa", "last_totp_counter"),
    ("mfa_attempt_log", "attempt_code"),
    ("mfa_attempt_log", "status"),
    ("mfa_attempt_log", "user_agent"),
    ("auth_device_session", "credential_version"),
];
const IDENTITY_CREDENTIAL_FENCE_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "mfa_attempt_log",
        "uk_mal_attempt_code",
        &["attempt_code"],
        true,
    ),
    (
        "mfa_attempt_log",
        "idx_mal_user_attempt_status",
        &["user_id", "attempted_at", "success", "status"],
        false,
    ),
    (
        "auth_device_session",
        "idx_ads_user_credential_version",
        &["user_id", "credential_version", "status"],
        false,
    ),
];
const ASYNC_OPERATION_TABLES: &[&str] = &["async_operation", "async_operation_item"];
const ASYNC_OPERATION_COLUMNS_ARTIFACTS: &[(&str, &str)] = &[
    ("async_operation", "task_id"),
    ("async_operation", "task_type"),
    ("async_operation", "status"),
    ("async_operation", "requester_user_id"),
    ("async_operation", "requester_card_id"),
    ("async_operation", "requester_tenant_id"),
    ("async_operation", "requester_domain_id"),
    ("async_operation", "authorization_target_card_id"),
    ("async_operation", "authorization_target_tenant_id"),
    ("async_operation", "authorization_target_domain_id"),
    ("async_operation", "target_user_id"),
    ("async_operation", "total_items"),
    ("async_operation", "completed_items"),
    ("async_operation", "owner_instance_id"),
    ("async_operation", "error_message"),
    ("async_operation", "created_at"),
    ("async_operation", "updated_at"),
    ("async_operation_item", "task_id"),
    ("async_operation_item", "card_id"),
    ("async_operation_item", "tenant_id"),
    ("async_operation_item", "domain_id"),
    ("async_operation_item", "operation_id"),
    ("async_operation_item", "status"),
    ("async_operation_item", "error_message"),
    ("async_operation_item", "created_at"),
    ("async_operation_item", "updated_at"),
];
const CHAT_DELIVERY_INTENT_TABLES: &[&str] =
    &["chat_delivery_intent", "chat_delivery_intent_recipient"];
const ASYNC_OPERATION_COLUMNS: &[SchemaColumnContract] = &[
    incremental_text_column("async_operation", "task_id", "VARCHAR(64)", true, None),
    incremental_text_column("async_operation", "task_type", "VARCHAR(32)", true, None),
    incremental_text_column(
        "async_operation",
        "status",
        "VARCHAR(16)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column("async_operation", "requester_user_id", "BIGINT", true, None),
    incremental_scalar_column("async_operation", "requester_card_id", "BIGINT", true, None),
    incremental_scalar_column(
        "async_operation",
        "requester_tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "async_operation",
        "requester_domain_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "async_operation",
        "authorization_target_card_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "async_operation",
        "authorization_target_tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "async_operation",
        "authorization_target_domain_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column("async_operation", "target_user_id", "BIGINT", true, None),
    incremental_scalar_column("async_operation", "total_items", "INT UNSIGNED", true, None),
    incremental_scalar_column(
        "async_operation",
        "completed_items",
        "INT UNSIGNED",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "async_operation",
        "owner_instance_id",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "async_operation",
        "error_message",
        "VARCHAR(255)",
        false,
        None,
    ),
    incremental_scalar_column(
        "async_operation",
        "created_at",
        "BIGINT",
        true,
        Some("UNIX_TIMESTAMP()"),
    ),
    incremental_scalar_column(
        "async_operation",
        "updated_at",
        "BIGINT",
        true,
        Some("UNIX_TIMESTAMP()"),
    ),
    incremental_text_column("async_operation_item", "task_id", "VARCHAR(64)", true, None),
    incremental_scalar_column("async_operation_item", "card_id", "BIGINT", true, None),
    incremental_scalar_column("async_operation_item", "tenant_id", "BIGINT", true, None),
    incremental_scalar_column("async_operation_item", "domain_id", "BIGINT", true, None),
    incremental_text_column(
        "async_operation_item",
        "operation_id",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "async_operation_item",
        "status",
        "VARCHAR(16)",
        true,
        Some("PENDING"),
    ),
    incremental_text_column(
        "async_operation_item",
        "error_message",
        "VARCHAR(255)",
        false,
        None,
    ),
    incremental_scalar_column(
        "async_operation_item",
        "created_at",
        "BIGINT",
        true,
        Some("UNIX_TIMESTAMP()"),
    ),
    incremental_scalar_column(
        "async_operation_item",
        "updated_at",
        "BIGINT",
        true,
        Some("UNIX_TIMESTAMP()"),
    ),
];
const CHAT_DELIVERY_INTENT_COLUMNS: &[SchemaColumnContract] = &[
    incremental_text_column("chat_delivery_intent", "intent_id", "CHAR(36)", true, None),
    incremental_text_column(
        "chat_delivery_intent",
        "scope_key_sha256",
        "CHAR(64)",
        true,
        None,
    ),
    SchemaColumnContract {
        table: "chat_delivery_intent",
        name: "client_msg_id",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some("ascii"),
        collation: Some("ascii_bin"),
    },
    incremental_text_column(
        "chat_delivery_intent",
        "request_sha256",
        "CHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "chat_delivery_intent",
        "message_uuid",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_scalar_column("chat_delivery_intent", "message_id", "BIGINT", false, None),
    incremental_scalar_column(
        "chat_delivery_intent",
        "conversation_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column("chat_delivery_intent", "sender_id", "BIGINT", true, None),
    incremental_scalar_column(
        "chat_delivery_intent",
        "identity_card_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column("chat_delivery_intent", "user_card_id", "BIGINT", true, None),
    incremental_scalar_column("chat_delivery_intent", "tenant_id", "BIGINT", true, None),
    incremental_scalar_column("chat_delivery_intent", "domain_id", "BIGINT", true, None),
    incremental_text_column(
        "chat_delivery_intent",
        "payload_json",
        "MEDIUMTEXT",
        false,
        None,
    ),
    incremental_text_column(
        "chat_delivery_intent",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column("chat_delivery_intent", "attempts", "INT", true, Some("0")),
    incremental_scalar_column(
        "chat_delivery_intent",
        "next_attempt_at",
        "DATETIME(6)",
        false,
        None,
    ),
    incremental_text_column(
        "chat_delivery_intent",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent",
        "lease_generation",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "chat_delivery_intent",
        "lease_expires_at",
        "DATETIME(6)",
        false,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent",
        "published_at",
        "DATETIME(6)",
        false,
        None,
    ),
    incremental_text_column(
        "chat_delivery_intent",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent",
        "created_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
    incremental_scalar_column(
        "chat_delivery_intent",
        "updated_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
    incremental_text_column(
        "chat_delivery_intent_recipient",
        "intent_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent_recipient",
        "recipient_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent_recipient",
        "identity_card_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent_recipient",
        "user_card_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent_recipient",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent_recipient",
        "domain_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "chat_delivery_intent_recipient",
        "created_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
];
const CHAT_DELIVERY_INTENT_COLUMNS_ARTIFACTS: &[(&str, &str)] = &[
    ("chat_delivery_intent", "intent_id"),
    ("chat_delivery_intent", "scope_key_sha256"),
    ("chat_delivery_intent", "client_msg_id"),
    ("chat_delivery_intent", "request_sha256"),
    ("chat_delivery_intent", "message_uuid"),
    ("chat_delivery_intent", "message_id"),
    ("chat_delivery_intent", "conversation_id"),
    ("chat_delivery_intent", "sender_id"),
    ("chat_delivery_intent", "identity_card_id"),
    ("chat_delivery_intent", "user_card_id"),
    ("chat_delivery_intent", "tenant_id"),
    ("chat_delivery_intent", "domain_id"),
    ("chat_delivery_intent", "payload_json"),
    ("chat_delivery_intent", "status"),
    ("chat_delivery_intent", "attempts"),
    ("chat_delivery_intent", "next_attempt_at"),
    ("chat_delivery_intent", "lease_owner"),
    ("chat_delivery_intent", "lease_generation"),
    ("chat_delivery_intent", "lease_expires_at"),
    ("chat_delivery_intent", "published_at"),
    ("chat_delivery_intent", "last_error"),
    ("chat_delivery_intent", "created_at"),
    ("chat_delivery_intent", "updated_at"),
    ("chat_delivery_intent_recipient", "intent_id"),
    ("chat_delivery_intent_recipient", "recipient_id"),
    ("chat_delivery_intent_recipient", "identity_card_id"),
    ("chat_delivery_intent_recipient", "user_card_id"),
    ("chat_delivery_intent_recipient", "tenant_id"),
    ("chat_delivery_intent_recipient", "domain_id"),
    ("chat_delivery_intent_recipient", "created_at"),
];
const CHAT_DELIVERY_INTENT_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("chat_delivery_intent", "PRIMARY", &["intent_id"], true),
    (
        "chat_delivery_intent",
        "uk_chat_delivery_intent_scope_client",
        &["scope_key_sha256", "client_msg_id"],
        true,
    ),
    (
        "chat_delivery_intent",
        "uk_chat_delivery_intent_message_uuid",
        &["message_uuid"],
        true,
    ),
    (
        "chat_delivery_intent",
        "uk_chat_delivery_intent_message_id",
        &["message_id"],
        true,
    ),
    (
        "chat_delivery_intent",
        "idx_chat_delivery_intent_claim",
        &["status", "lease_expires_at", "created_at", "intent_id"],
        false,
    ),
    (
        "chat_delivery_intent",
        "idx_chat_delivery_intent_conversation",
        &["conversation_id", "created_at"],
        false,
    ),
    (
        "chat_delivery_intent_recipient",
        "PRIMARY",
        &[
            "intent_id",
            "recipient_id",
            "identity_card_id",
            "user_card_id",
        ],
        true,
    ),
    (
        "chat_delivery_intent_recipient",
        "idx_chat_delivery_intent_recipient_user",
        &["recipient_id", "created_at"],
        false,
    ),
];
const LEARN_SYSTEM_ASSIGNMENT_COLUMNS: &[SchemaColumnContract] = &[SchemaColumnContract {
    table: "learn_assignment",
    name: "system_role",
    column_type: "VARCHAR(32)",
    not_null: false,
    default: None,
    charset: Some("utf8mb4"),
    collation: Some("utf8mb4_bin"),
}];
const LEARN_SYSTEM_ASSIGNMENT_COLUMNS_ARTIFACTS: &[(&str, &str)] =
    &[("learn_assignment", "system_role")];
const LEARN_SYSTEM_ASSIGNMENT_INDEXES: &[(&str, &str, &[&str], bool)] = &[(
    "learn_assignment",
    "uk_learn_assignment_course_system_role",
    &["course_id", "system_role"],
    true,
)];
const IDENTITY_CREDENTIAL_FENCE_SQL_SHA384: &str =
    "67b0e206506af2e724d08951bcdeb8b297ca8a83f75c540c1ace98bfc18375b0167e40fbe10ea27ef6e0a7f3b71fdfda";
const ASYNC_OPERATION_CORRELATION_SQL_SHA384: &str =
    "9f923f7efe47307ca895eba96674384967e1e29317abd2661d07ca2f8be4fa92b543220d44e58354fc2fa5eeccef3089";
const CHAT_DELIVERY_INTENT_SQL_SHA384: &str =
    "9e54275dbd398508eb4daac9dcbb4c5f1a75902b66757e9110410d9e85e9abce82bbbb372a25c6591d0be2464f7620c7";
const LEARN_SYSTEM_ASSIGNMENT_SQL_SHA384: &str =
    "102705f5df0183e0bcd4fc4d39fe1c8e8ff994c66d198d0c7d738a992a3469cc9b453d9b52c7721d4bd48591ca2905de";
const REVIEW_SLICE_MIGRATION_VERSIONS: &[i64] = &[
    IDENTITY_CREDENTIAL_FENCE_VERSION,
    ASYNC_OPERATION_CORRELATION_VERSION,
    REVIEW_SCHEMA_REPAIR_VERSION,
    CHAT_DELIVERY_INTENT_VERSION,
    LEARN_SYSTEM_ASSIGNMENT_VERSION,
];
const LOCAL_SCOPE_SEQUENCE_MIGRATION_SQL: &str =
    include_str!("../migrations/20261001000005_invalidation_scope_sequence.sql");

const ISOLATED_MIGRATION_ENV: &str = "isolated";
const DESTRUCTIVE_MIGRATION_ALLOWLIST_ENV: &str = "ASTRAL_DESTRUCTIVE_MIGRATION_ALLOWLIST";
const DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ENV: &str = "ASTRAL_DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ID";
const DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ENV: &str = "ASTRAL_DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ID";
const DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ENV: &str =
    "ASTRAL_DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ID";
const DESTRUCTIVE_MIGRATION_DRAIN_SQL: &str = "SELECT 1 FROM authorization_projection_outbox WHERE status = 'PENDING' AND aggregate_type IN ('CARD', 'RULE_SET') LIMIT 1";
const ISOLATED_MIGRATION_DATABASES: &[&str] = &["astral_test", "astral_rehearsal"];
const ISOLATED_MIGRATION_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1"];
const ISOLATED_MIGRATION_PORT: u16 = 3308;
const AUTH_FAMILY_SESSION_TABLE: &str = "auth_device_session";
const AUTH_FAMILY_SESSION_STATE_COLUMN: &str = "session_state";
const AUTH_FAMILY_SESSION_VERSION_COLUMN: &str = "session_version";
const AUTH_FAMILY_SESSION_EPOCH_COLUMN: &str = "session_epoch";
const AUTH_FAMILY_SESSION_STATE_STATEMENT: &str = "ALTER TABLE auth_device_session\n    ADD COLUMN IF NOT EXISTS session_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' AFTER current_user_card_id;";
const AUTH_FAMILY_SESSION_VERSION_STATEMENT: &str = "ALTER TABLE auth_device_session\n    ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 1 AFTER session_state;";
const AUTH_FAMILY_SESSION_EPOCH_STATEMENT: &str = "ALTER TABLE auth_device_session\n    ADD COLUMN IF NOT EXISTS session_epoch BIGINT NOT NULL DEFAULT 1 AFTER session_version;";
const AUTH_SESSION_RESILIENCE_STATE_STATEMENT: &str = "ALTER TABLE auth_device_session\n    ADD COLUMN IF NOT EXISTS session_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'\n        AFTER current_user_card_id;";
const AUTH_SESSION_RESILIENCE_VERSION_STATEMENT: &str = "ALTER TABLE auth_device_session\n    ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 1\n        AFTER session_state;";
const AUTH_SESSION_RESILIENCE_EPOCH_STATEMENT: &str = "ALTER TABLE auth_device_session\n    ADD COLUMN IF NOT EXISTS session_epoch BIGINT NOT NULL DEFAULT 1\n        AFTER session_version;";
const TENANT_SCHOOL_CUTOVER_ORG_ID_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS org_id BIGINT NULL AFTER settings_json;";
const TENANT_SCHOOL_CUTOVER_COUNTRY_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS country VARCHAR(16) NULL AFTER org_id;";
const TENANT_SCHOOL_CUTOVER_PROVINCE_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS province VARCHAR(64) NULL AFTER country;";
const TENANT_SCHOOL_CUTOVER_CITY_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS city VARCHAR(64) NULL AFTER province;";
const TENANT_SCHOOL_CUTOVER_DISTRICT_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS district VARCHAR(64) NULL AFTER city;";
const TENANT_SCHOOL_CUTOVER_ADDRESS_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS address VARCHAR(512) NULL AFTER district;";
const TENANT_SCHOOL_CUTOVER_POSTAL_CODE_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS postal_code VARCHAR(32) NULL AFTER address;";
const TENANT_SCHOOL_CUTOVER_WEBSITE_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS website VARCHAR(512) NULL AFTER postal_code;";
const TENANT_SCHOOL_CUTOVER_DESCRIPTION_STATEMENT: &str =
    "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS description TEXT NULL AFTER website;";
const TENANT_SCHOOL_CUTOVER_VERIFIED_STATEMENT: &str = "ALTER TABLE tenant\n    ADD COLUMN IF NOT EXISTS verified TINYINT(1) NOT NULL DEFAULT 0 AFTER description;";
const TENANT_SCHOOL_CUTOVER_SCHOOL_MEMBERS_STATEMENT: &str = "ALTER TABLE school_members\n    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NULL AFTER school_id;";
const TENANT_SCHOOL_CUTOVER_USER_PROFILES_STATEMENT: &str = "ALTER TABLE user_profiles\n    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NULL AFTER school_id;";
const TENANT_SCHOOL_CUTOVER_LEADERBOARDS_STATEMENT: &str =
    "ALTER TABLE leaderboards\n    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NULL AFTER school_id;";
const TRUSTGRAPH_RUNTIME_SOD_POLICY_STATUS_STATEMENT: &str =
    "ALTER TABLE sod_policy\n    ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' AFTER condition_script;";
const TRUSTGRAPH_RUNTIME_INCOMPATIBLE_STATEMENTS: &[&str] =
    &[TRUSTGRAPH_RUNTIME_SOD_POLICY_STATUS_STATEMENT];

const TENANT_SCHOOL_CUTOVER_TABLE_DEFINITION: &str = "CREATE TABLE IF NOT EXISTS school_tenant_migration (\n    school_id BIGINT NOT NULL,\n    tenant_id BIGINT NOT NULL,\n    tenant_code VARCHAR(64) NOT NULL,\n    migration_status VARCHAR(32) NOT NULL DEFAULT 'MIGRATED',\n    migrated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    verified_at DATETIME NULL,\n    rollback_note VARCHAR(512) NULL,\n    PRIMARY KEY (school_id),\n    UNIQUE KEY uk_school_tenant_migration_tenant (tenant_id),\n    UNIQUE KEY uk_school_tenant_migration_code (tenant_code),\n    KEY idx_school_tenant_migration_status (migration_status),\n    CONSTRAINT fk_school_tenant_migration_school\n        FOREIGN KEY (school_id) REFERENCES schools (id) ON DELETE RESTRICT,\n    CONSTRAINT fk_school_tenant_migration_tenant\n        FOREIGN KEY (tenant_id) REFERENCES tenant (tenant_id) ON DELETE RESTRICT\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Schools to tenants migration audit mapping';";
const TENANT_SCHOOL_CUTOVER_TABLE_DEFINITION_MYSQL8: &str = "CREATE TABLE IF NOT EXISTS school_tenant_migration (\n    school_id BIGINT NOT NULL,\n    tenant_id BIGINT NOT NULL,\n    tenant_code VARCHAR(64) NOT NULL,\n    migration_status VARCHAR(32) NOT NULL DEFAULT 'MIGRATED',\n    migrated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    verified_at DATETIME NULL,\n    rollback_note VARCHAR(512) NULL,\n    PRIMARY KEY (school_id),\n    UNIQUE KEY uk_school_tenant_migration_tenant (tenant_id),\n    UNIQUE KEY uk_school_tenant_migration_code (tenant_code),\n    KEY idx_school_tenant_migration_status (migration_status),\n    CONSTRAINT fk_school_tenant_migration_school\n        FOREIGN KEY (school_id) REFERENCES schools (id) ON DELETE RESTRICT,\n    CONSTRAINT fk_school_tenant_migration_tenant\n        FOREIGN KEY (tenant_id) REFERENCES tenant (tenant_id) ON DELETE RESTRICT\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Schools to tenants migration audit mapping';";
const TENANT_SCHOOL_CUTOVER_EXACT_REWRITES: &[(&str, &str)] = &[(
    TENANT_SCHOOL_CUTOVER_TABLE_DEFINITION,
    TENANT_SCHOOL_CUTOVER_TABLE_DEFINITION_MYSQL8,
)];
const AUTH_FAMILY_INCOMPATIBLE_STATEMENTS: &[&str] = &[
    AUTH_FAMILY_SESSION_STATE_STATEMENT,
    AUTH_FAMILY_SESSION_VERSION_STATEMENT,
    AUTH_FAMILY_SESSION_EPOCH_STATEMENT,
];
const AUTH_SESSION_RESILIENCE_INCOMPATIBLE_STATEMENTS: &[&str] = &[
    AUTH_SESSION_RESILIENCE_STATE_STATEMENT,
    AUTH_SESSION_RESILIENCE_VERSION_STATEMENT,
    AUTH_SESSION_RESILIENCE_EPOCH_STATEMENT,
];
const TENANT_SCHOOL_CUTOVER_INCOMPATIBLE_STATEMENTS: &[&str] = &[
    TENANT_SCHOOL_CUTOVER_ORG_ID_STATEMENT,
    TENANT_SCHOOL_CUTOVER_COUNTRY_STATEMENT,
    TENANT_SCHOOL_CUTOVER_PROVINCE_STATEMENT,
    TENANT_SCHOOL_CUTOVER_CITY_STATEMENT,
    TENANT_SCHOOL_CUTOVER_DISTRICT_STATEMENT,
    TENANT_SCHOOL_CUTOVER_ADDRESS_STATEMENT,
    TENANT_SCHOOL_CUTOVER_POSTAL_CODE_STATEMENT,
    TENANT_SCHOOL_CUTOVER_WEBSITE_STATEMENT,
    TENANT_SCHOOL_CUTOVER_DESCRIPTION_STATEMENT,
    TENANT_SCHOOL_CUTOVER_VERIFIED_STATEMENT,
    TENANT_SCHOOL_CUTOVER_SCHOOL_MEMBERS_STATEMENT,
    TENANT_SCHOOL_CUTOVER_USER_PROFILES_STATEMENT,
    TENANT_SCHOOL_CUTOVER_LEADERBOARDS_STATEMENT,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HistoricalColumnSpec {
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
    not_null: bool,
    default: Option<&'static str>,
    charset: Option<&'static str>,
    collation: Option<&'static str>,
    after: &'static str,
}

const AUTH_FAMILY_SESSION_COLUMNS: &[HistoricalColumnSpec] = &[
    HistoricalColumnSpec {
        table: AUTH_FAMILY_SESSION_TABLE,
        name: AUTH_FAMILY_SESSION_STATE_COLUMN,
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("ACTIVE"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "current_user_card_id",
    },
    HistoricalColumnSpec {
        table: AUTH_FAMILY_SESSION_TABLE,
        name: AUTH_FAMILY_SESSION_VERSION_COLUMN,
        column_type: "BIGINT",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
        after: AUTH_FAMILY_SESSION_STATE_COLUMN,
    },
    HistoricalColumnSpec {
        table: AUTH_FAMILY_SESSION_TABLE,
        name: AUTH_FAMILY_SESSION_EPOCH_COLUMN,
        column_type: "BIGINT",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
        after: AUTH_FAMILY_SESSION_VERSION_COLUMN,
    },
];

const TENANT_SCHOOL_CUTOVER_COLUMNS: &[HistoricalColumnSpec] = &[
    HistoricalColumnSpec {
        table: "tenant",
        name: "org_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
        after: "settings_json",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "country",
        column_type: "VARCHAR(16)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "org_id",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "province",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "country",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "city",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "province",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "district",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "city",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "address",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "district",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "postal_code",
        column_type: "VARCHAR(32)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "address",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "website",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "postal_code",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "description",
        column_type: "TEXT",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
        after: "website",
    },
    HistoricalColumnSpec {
        table: "tenant",
        name: "verified",
        column_type: "TINYINT(1)",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
        after: "description",
    },
    HistoricalColumnSpec {
        table: "school_members",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
        after: "school_id",
    },
    HistoricalColumnSpec {
        table: "user_profiles",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
        after: "school_id",
    },
    HistoricalColumnSpec {
        table: "leaderboards",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
        after: "school_id",
    },
];

const TRUSTGRAPH_RUNTIME_COLUMNS: &[HistoricalColumnSpec] = &[HistoricalColumnSpec {
    table: "sod_policy",
    name: "status",
    column_type: "VARCHAR(16)",
    not_null: true,
    default: Some("ACTIVE"),
    charset: Some(MYSQL_SCHEMA_CHARSET),
    collation: Some(MYSQL_SCHEMA_COLLATION),
    after: "condition_script",
}];

const TRUSTGRAPH_RUNTIME_TABLES: &[BaselineTableContract] = &[
    BaselineTableContract {
        table: "sod_policy",
        key_column: "policy_id",
        key_type: "BIGINT",
        charset: MYSQL_SCHEMA_CHARSET,
        collation: MYSQL_SCHEMA_COLLATION,
    },
    BaselineTableContract {
        table: "sod_violation",
        key_column: "violation_id",
        key_type: "BIGINT",
        charset: MYSQL_SCHEMA_CHARSET,
        collation: MYSQL_SCHEMA_COLLATION,
    },
    BaselineTableContract {
        table: "identity_global_admin",
        key_column: "id",
        key_type: "BIGINT",
        charset: MYSQL_SCHEMA_CHARSET,
        collation: MYSQL_MIGRATION_COLLATION,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoricalMigrationRewrite {
    ReplaceWithSelect1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HistoricalMigrationCompatibility {
    version: i64,
    source_sha384: &'static str,
    incompatible_statements: &'static [&'static str],
    exact_rewrites: &'static [(&'static str, &'static str)],
    rewrite: HistoricalMigrationRewrite,
    columns: &'static [HistoricalColumnSpec],
}

const HISTORICAL_MIGRATION_COMPATIBILITY: &[HistoricalMigrationCompatibility] = &[
    HistoricalMigrationCompatibility {
        version: AUTH_FAMILY_SCHEMA_CONTRACT_VERSION,
        source_sha384: AUTH_FAMILY_SCHEMA_CONTRACT_SQL_SHA384,
        incompatible_statements: AUTH_FAMILY_INCOMPATIBLE_STATEMENTS,
        exact_rewrites: &[],
        rewrite: HistoricalMigrationRewrite::ReplaceWithSelect1,
        columns: AUTH_FAMILY_SESSION_COLUMNS,
    },
    HistoricalMigrationCompatibility {
        version: AUTH_SESSION_RESILIENCE_VERSION,
        source_sha384: AUTH_SESSION_RESILIENCE_SQL_SHA384,
        incompatible_statements: AUTH_SESSION_RESILIENCE_INCOMPATIBLE_STATEMENTS,
        exact_rewrites: &[],
        rewrite: HistoricalMigrationRewrite::ReplaceWithSelect1,
        columns: AUTH_FAMILY_SESSION_COLUMNS,
    },
    HistoricalMigrationCompatibility {
        version: TENANT_SCHOOL_CUTOVER_VERSION,
        source_sha384: TENANT_SCHOOL_CUTOVER_SQL_SHA384,
        incompatible_statements: TENANT_SCHOOL_CUTOVER_INCOMPATIBLE_STATEMENTS,
        exact_rewrites: TENANT_SCHOOL_CUTOVER_EXACT_REWRITES,
        rewrite: HistoricalMigrationRewrite::ReplaceWithSelect1,
        columns: TENANT_SCHOOL_CUTOVER_COLUMNS,
    },
    HistoricalMigrationCompatibility {
        version: TRUSTGRAPH_RUNTIME_TABLES_VERSION,
        source_sha384: TRUSTGRAPH_RUNTIME_TABLES_SQL_SHA384,
        incompatible_statements: TRUSTGRAPH_RUNTIME_INCOMPATIBLE_STATEMENTS,
        exact_rewrites: &[],
        rewrite: HistoricalMigrationRewrite::ReplaceWithSelect1,
        columns: TRUSTGRAPH_RUNTIME_COLUMNS,
    },
];

fn mysql_connection_options(database_url: &str) -> Result<MySqlConnectOptions, MigrationError> {
    MySqlConnectOptions::from_str(database_url)
        .map(|options| {
            options
                .charset(MYSQL_SCHEMA_CHARSET)
                .collation(MYSQL_SCHEMA_COLLATION)
        })
        .map_err(|e| MigrationError::Failed(format!("parse database URL: {e}")))
}

fn mysql_migration_connection_options(
    database_url: &str,
) -> Result<MySqlConnectOptions, MigrationError> {
    MySqlConnectOptions::from_str(database_url)
        .map(|options| {
            options
                .charset(MYSQL_SCHEMA_CHARSET)
                .collation(MYSQL_MIGRATION_COLLATION)
        })
        .map_err(|e| MigrationError::Failed(format!("parse migration database URL: {e}")))
}

fn destructive_migration_authorization(
    allowlist: Option<&str>,
    backup_proof: Option<&str>,
    drain_proof: Option<&str>,
    cutover_proof: Option<&str>,
) -> Result<(), MigrationError> {
    let authorized = allowlist.is_some_and(|allowlist| {
        allowlist
            .split(',')
            .map(str::trim)
            .any(|entry| entry.parse::<i64>().ok() == Some(LEGACY_SNAPSHOT_DECOMMISSION_VERSION))
    });
    if !authorized {
        return Err(MigrationError::Failed(format!(
            "pending standby migration {LEGACY_SNAPSHOT_DECOMMISSION_VERSION} is destructive and refused by default; set {DESTRUCTIVE_MIGRATION_ALLOWLIST_ENV} to its exact version with approved backup/drain/cutover proof references"
        )));
    }
    for (field, value) in [
        (DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ENV, backup_proof),
        (DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ENV, drain_proof),
        (DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ENV, cutover_proof),
    ] {
        if value.is_none_or(|value| !is_valid_destructive_proof_reference(value)) {
            return Err(MigrationError::Failed(format!(
                "pending standby migration {LEGACY_SNAPSHOT_DECOMMISSION_VERSION} requires a non-empty approved evidence reference in {field}"
            )));
        }
    }
    Ok(())
}

fn is_valid_destructive_proof_reference(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn ensure_isolated_migration_target(database_url: &str) -> Result<(), MigrationError> {
    if std::env::var("ASTRAL_MIGRATION_ENV").as_deref() != Ok(ISOLATED_MIGRATION_ENV) {
        return Err(MigrationError::Failed(
            "ASTRAL_MIGRATION_ENV=isolated is required for schema migrations".into(),
        ));
    }

    let options = MySqlConnectOptions::from_str(database_url)
        .map_err(|e| MigrationError::Failed(format!("parse migration database URL: {e}")))?;
    let database = options.get_database().ok_or_else(|| {
        MigrationError::Failed("migration DATABASE_URL must select a database".into())
    })?;
    if !ISOLATED_MIGRATION_DATABASES
        .iter()
        .any(|allowed| database.eq_ignore_ascii_case(allowed))
    {
        return Err(MigrationError::Failed(format!(
            "refusing migration for database {database:?}; only astral_test or astral_rehearsal are isolated"
        )));
    }
    let host = options.get_host().trim_matches(['[', ']']);
    if !ISOLATED_MIGRATION_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
        || options.get_port() != ISOLATED_MIGRATION_PORT
    {
        return Err(MigrationError::Failed(format!(
            "refusing migration target {}:{}; isolated migrations require localhost/127.0.0.1/[::1]:{}",
            options.get_host(),
            options.get_port(),
            ISOLATED_MIGRATION_PORT
        )));
    }
    Ok(())
}

fn canonical_lf_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' {
            if bytes.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
            canonical.push(b'\n');
        } else {
            canonical.push(bytes[index]);
        }
        index += 1;
    }
    canonical
}

fn canonical_sha384_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha384::digest(canonical_lf_bytes(bytes)))
}

fn mysql_pool_options() -> MySqlPoolOptions {
    MySqlPoolOptions::new()
        .max_connections(5)
        // 关闭 acquire 前 PING 探活：每次从池取连接的 PING 是一个纯网络往返，
        // 在查询密集路径上与业务查询 1:1 放大。安全性不变：失效连接的首条查询
        // 以错误失败并向调用方传播，授权链按依赖失败走 PENDING/DENY（fail-closed），
        // 不存在以旧状态或旧连接数据放行的路径。
        .test_before_acquire(false)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query(SET_UTC_TIME_ZONE_SQL)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
}

fn mysql_migration_pool_options() -> MySqlPoolOptions {
    MySqlPoolOptions::new()
        .max_connections(5)
        .after_connect(|connection, _| {
            Box::pin(async move { configure_migration_session(connection).await })
        })
}

async fn configure_migration_session(connection: &mut MySqlConnection) -> Result<(), sqlx::Error> {
    sqlx::query(MIGRATION_SET_NAMES_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::query(MIGRATION_SET_COLLATION_CONNECTION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::query(SET_UTC_TIME_ZONE_SQL)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// Create a MySQL pool with the schema's historical UTF-8 collation contract.
///
/// `MySqlConnectOptions` emits `SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci`
/// for every physical service connection. Migration connections deliberately
/// use a separate pool and session contract for historical Java-compatible DDL.
pub async fn connect_configured_pool(database_url: &str) -> Result<MySqlPool, sqlx::Error> {
    let options = mysql_connection_options(database_url).map_err(|error| {
        sqlx::Error::Configuration(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            error.to_string(),
        )))
    })?;
    mysql_pool_options().connect_with(options).await
}

// MySQL 8 exposes information_schema text columns as VARBINARY in some sqlx
// result paths. Keep existence/index checks numeric and compare identifiers as
// binary values; metadata that must be inspected is explicitly cast to BINARY
// and decoded from Vec<u8> below. A failed decode is always fail-closed.
// MySQL 5.7 and 8 expose information_schema numeric fields as unsigned
// integers. Cast every selected numeric field to binary text and parse it
// strictly below, avoiding sqlx signed/unsigned type metadata differences.
const SCHEMA_TABLE_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.TABLES \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(TABLE_TYPE AS BINARY) = CAST('BASE TABLE' AS BINARY)";
const SCHEMA_COLUMN_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.COLUMNS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_INDEX_STATS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY), CAST(MIN(NON_UNIQUE) AS BINARY), CAST(MAX(NON_UNIQUE) AS BINARY) \
     FROM information_schema.STATISTICS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(INDEX_NAME AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_INDEX_COLUMN_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.STATISTICS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(INDEX_NAME AS BINARY) = CAST(? AS BINARY) \
       AND SEQ_IN_INDEX = ? \
       AND SUB_PART IS NULL \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_TABLE_CONTRACT_SQL: &str = "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.TABLES AS t JOIN information_schema.COLLATION_CHARACTER_SET_APPLICABILITY AS c ON CAST(c.COLLATION_NAME AS BINARY) = CAST(t.TABLE_COLLATION AS BINARY) WHERE CAST(t.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) AND CAST(t.TABLE_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(t.TABLE_TYPE AS BINARY) = CAST('BASE TABLE' AS BINARY) AND CAST(c.CHARACTER_SET_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(t.TABLE_COLLATION AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_TABLE_ENGINE_CONTRACT_SQL: &str = "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.TABLES AS t WHERE CAST(t.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) AND CAST(t.TABLE_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(t.TABLE_TYPE AS BINARY) = CAST('BASE TABLE' AS BINARY) AND CAST(t.ENGINE AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_KEY_COLUMN_CONTRACT_SQL: &str = "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.COLUMNS WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY) AND UPPER(CAST(COLUMN_TYPE AS CHAR CHARACTER SET utf8mb4)) = CAST(? AS CHAR CHARACTER SET utf8mb4) AND CAST(IS_NULLABLE AS BINARY) = CAST('NO' AS BINARY) AND CAST(COLUMN_KEY AS BINARY) = CAST('PRI' AS BINARY)";
const SCHEMA_FOREIGN_KEY_CONTRACT_SQL: &str = "SELECT CAST(COUNT(*) AS BINARY), CAST(COALESCE(SUM(CASE WHEN CAST(k.COLUMN_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(k.REFERENCED_TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) AND CAST(k.REFERENCED_TABLE_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(k.REFERENCED_COLUMN_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(r.DELETE_RULE AS BINARY) = CAST(? AS BINARY) THEN 1 ELSE 0 END), 0) AS BINARY) FROM information_schema.KEY_COLUMN_USAGE AS k JOIN information_schema.REFERENTIAL_CONSTRAINTS AS r ON CAST(r.CONSTRAINT_SCHEMA AS BINARY) = CAST(k.CONSTRAINT_SCHEMA AS BINARY) AND CAST(r.TABLE_NAME AS BINARY) = CAST(k.TABLE_NAME AS BINARY) AND CAST(r.CONSTRAINT_NAME AS BINARY) = CAST(k.CONSTRAINT_NAME AS BINARY) WHERE CAST(k.CONSTRAINT_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) AND CAST(k.TABLE_NAME AS BINARY) = CAST(? AS BINARY) AND CAST(k.CONSTRAINT_NAME AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_COLUMN_METADATA_SQL: &str = "SELECT CAST(COLUMN_NAME AS BINARY), CAST(COLUMN_TYPE AS BINARY), CAST(IS_NULLABLE AS BINARY), CAST(COLUMN_DEFAULT AS BINARY), CAST(CHARACTER_SET_NAME AS BINARY), CAST(COLLATION_NAME AS BINARY) \
     FROM information_schema.COLUMNS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";
const HISTORICAL_COLUMN_METADATA_SQL: &str = "SELECT CAST(COLUMN_NAME AS BINARY), CAST(COLUMN_TYPE AS BINARY), CAST(IS_NULLABLE AS BINARY), CAST(COLUMN_DEFAULT AS BINARY), CAST(CHARACTER_SET_NAME AS BINARY), CAST(COLLATION_NAME AS BINARY), CAST(ORDINAL_POSITION AS BINARY) \
     FROM information_schema.COLUMNS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";
const HISTORICAL_COLUMN_POSITION_SQL: &str = "SELECT CAST(immediate_previous.COLUMN_NAME AS BINARY), CAST(immediate_previous.ORDINAL_POSITION AS BINARY), CAST(current_column.ORDINAL_POSITION AS BINARY), CAST(expected_previous.ORDINAL_POSITION AS BINARY) \
     FROM information_schema.COLUMNS AS current_column \
     LEFT JOIN information_schema.COLUMNS AS immediate_previous \
       ON CAST(immediate_previous.TABLE_SCHEMA AS BINARY) = CAST(current_column.TABLE_SCHEMA AS BINARY) \
      AND CAST(immediate_previous.TABLE_NAME AS BINARY) = CAST(current_column.TABLE_NAME AS BINARY) \
      AND immediate_previous.ORDINAL_POSITION = current_column.ORDINAL_POSITION - 1 \
     LEFT JOIN information_schema.COLUMNS AS expected_previous \
       ON CAST(expected_previous.TABLE_SCHEMA AS BINARY) = CAST(current_column.TABLE_SCHEMA AS BINARY) \
      AND CAST(expected_previous.TABLE_NAME AS BINARY) = CAST(current_column.TABLE_NAME AS BINARY) \
      AND CAST(expected_previous.COLUMN_NAME AS BINARY) = CAST(? AS BINARY) \
     WHERE CAST(current_column.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(current_column.TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(current_column.COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";
const SCHEMA_COLUMN_ORDER_SQL: &str =
    "SELECT CAST(COLUMN_NAME AS BINARY), CAST(ORDINAL_POSITION AS BINARY) \
     FROM information_schema.COLUMNS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
     ORDER BY ORDINAL_POSITION";
const SCHEMA_INDEX_METADATA_SQL: &str = "SELECT CAST(INDEX_NAME AS BINARY), CAST(NON_UNIQUE AS BINARY), CAST(SEQ_IN_INDEX AS BINARY), CAST(COLUMN_NAME AS BINARY), CAST(SUB_PART AS BINARY), CAST(EXPRESSION AS BINARY) \
     FROM information_schema.STATISTICS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
     ORDER BY INDEX_NAME, SEQ_IN_INDEX";
const SCHEMA_FOREIGN_KEY_LIST_SQL: &str = "SELECT CAST(k.CONSTRAINT_NAME AS BINARY), CAST(k.COLUMN_NAME AS BINARY), CAST(k.REFERENCED_TABLE_NAME AS BINARY), CAST(k.REFERENCED_COLUMN_NAME AS BINARY), CAST(r.DELETE_RULE AS BINARY) \
     FROM information_schema.KEY_COLUMN_USAGE AS k \
     JOIN information_schema.REFERENTIAL_CONSTRAINTS AS r \
       ON CAST(r.CONSTRAINT_SCHEMA AS BINARY) = CAST(k.CONSTRAINT_SCHEMA AS BINARY) \
      AND CAST(r.TABLE_NAME AS BINARY) = CAST(k.TABLE_NAME AS BINARY) \
      AND CAST(r.CONSTRAINT_NAME AS BINARY) = CAST(k.CONSTRAINT_NAME AS BINARY) \
     WHERE CAST(k.CONSTRAINT_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(k.TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
     ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION";
const TRUSTGRAPH_BASELINE_RUNTIME_NULLS_SQL: &str = "SELECT CAST((SELECT COUNT(*) FROM sod_policy WHERE status IS NULL) + (SELECT COUNT(*) FROM sod_violation WHERE policy_name IS NULL OR card_id IS NULL) AS BINARY)";
const MIGRATION_COLUMN_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.COLUMNS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST('_sqlx_migrations' AS BINARY) \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";

/// 迁移错误
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("Migration failed: {0}")]
    Failed(String),
    #[error("migration recovery required: {reason}")]
    RecoveryRequired { reason: String },
}

/// 编译期嵌入的迁移
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Java 基线时代（20240630 系列）迁移判定：这批迁移的 DDL 已被
/// `full_schema_v4.sql` 固化，verified-baseline 采纳时可以**记为已应用而不执行**。
///
/// 除此之外的一切迁移都是 Rust-owned 增量，基线采纳绝不记录——它们保持
/// pending 并由 SQLx 真实执行。这是默认拒绝（fail-closed）结构：新增迁移
/// 无需登记任何清单，天然不会被基线采纳吞掉（20260831000001 曾因依赖人工
/// 维护的 `RUST_ONLY_MIGRATIONS` 允许清单漏登记，在新鲜库上被静默跳过）。
fn is_java_baseline_era(version: i64) -> bool {
    version / 1_000_000 == 20240630
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationHistoryState {
    Empty,
    BaselineIncomplete,
    BaselineComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationHistoryDecision {
    AdoptBaseline,
    Continue,
    FailClosed,
}

fn classify_migration_history(recorded_versions: &HashSet<i64>) -> MigrationHistoryState {
    if recorded_versions.is_empty() {
        return MigrationHistoryState::Empty;
    }

    let baseline_complete = MIGRATOR
        .migrations
        .iter()
        .filter(|migration| is_java_baseline_era(migration.version))
        .all(|migration| recorded_versions.contains(&migration.version));

    if baseline_complete {
        MigrationHistoryState::BaselineComplete
    } else {
        MigrationHistoryState::BaselineIncomplete
    }
}

fn migration_history_decision(
    state: MigrationHistoryState,
    baseline_is_verified: bool,
) -> MigrationHistoryDecision {
    match (state, baseline_is_verified) {
        (MigrationHistoryState::Empty, true) => MigrationHistoryDecision::AdoptBaseline,
        (MigrationHistoryState::Empty, false)
        | (MigrationHistoryState::BaselineIncomplete, true) => MigrationHistoryDecision::FailClosed,
        (MigrationHistoryState::BaselineIncomplete, false) => MigrationHistoryDecision::FailClosed,
        (MigrationHistoryState::BaselineComplete, _) => MigrationHistoryDecision::Continue,
    }
}

/// Java-managed baseline table contracts that must be verified before Rust
/// adopts baseline history.  Table names alone are not evidence: every
/// contract checks a stable primary-key column/type and the table's
/// charset/collation.  An empty schema is therefore never treated as Java
/// ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BaselineTableContract {
    table: &'static str,
    key_column: &'static str,
    key_type: &'static str,
    charset: &'static str,
    collation: &'static str,
}

const VERIFIED_BASELINE_TABLES: &[BaselineTableContract] = &[
    BaselineTableContract {
        table: "platform_user",
        key_column: "user_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "user_local_credential",
        key_column: "credential_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "identity_card",
        key_column: "card_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "user_card",
        key_column: "card_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "auth_token_family",
        key_column: "family_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "auth_device_session",
        key_column: "session_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "tenant",
        key_column: "tenant_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "tenant_domain_map",
        key_column: "id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "identity_level_template",
        key_column: "template_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "identity_global_admin",
        key_column: "id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "sod_policy",
        key_column: "policy_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_unicode_ci",
    },
    BaselineTableContract {
        table: "sod_violation",
        key_column: "violation_id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_unicode_ci",
    },
    BaselineTableContract {
        table: "schools",
        key_column: "id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "school_members",
        key_column: "id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "user_profiles",
        key_column: "id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
    BaselineTableContract {
        table: "leaderboards",
        key_column: "id",
        key_type: "BIGINT",
        charset: "utf8mb4",
        collation: "utf8mb4_0900_ai_ci",
    },
];

const REQUIRED_SCHEMA_COLUMNS: &[(&str, &[&str])] = &[
    ("platform_domain", &["domain_id", "status"]),
    (
        "tenant",
        &[
            "tenant_id",
            "tenant_code",
            "tenant_name",
            "tenant_type",
            "status",
        ],
    ),
    ("tenant_domain_map", &["tenant_id", "domain_id", "status"]),
    (
        "identity_card",
        &[
            "card_id",
            "user_id",
            "status",
            "token_version",
            "expires_at",
            "disabled_reason",
            "last_used_at",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "user_card",
        &[
            "card_id",
            "user_id",
            "domain_id",
            "card_type",
            "card_status",
            "template_id",
            "level_id",
            "valid_from",
            "valid_until",
            "tenant_id",
        ],
    ),
    (
        "user_card_template",
        &[
            "template_id",
            "domain_id",
            "tenant_id",
            "template_code",
            "template_name",
            "card_type",
            "template_scope",
            "version_no",
            "default_priority",
            "default_roles_json",
            "resource_scope_json",
            "status",
        ],
    ),
    (
        "identity_level_template",
        &[
            "template_id",
            "template_code",
            "domain_id",
            "principal_type",
            "grant_type",
            "level_no",
            "user_card_template_id",
            "status",
            "version_no",
            "force_cover",
        ],
    ),
    ("identity_global_admin", &["id", "user_id", "status"]),
    (
        "permission_request",
        &[
            "request_id",
            "user_id",
            "request_type",
            "request_content",
            "status",
            "approver_id",
            "approved_at",
            "approve_comment",
            "created_at",
        ],
    ),
    (
        "permission_rule",
        &[
            "rule_id",
            "card_id",
            "tenant_id",
            "resource_type",
            "resource_id",
            "action_code",
            "effect",
            "condition_json",
            "priority",
            "source_type",
            "source_id",
            "valid_from",
            "valid_to",
            "enabled",
        ],
    ),
    // AL-native local message outbox. It is a transport queue for events that
    // do not already have an aggregate-specific durable outbox.
    (
        "al_message_outbox",
        &[
            "message_id",
            "operation_id",
            "message_type",
            "queue_name",
            "ordering_key",
            "tenant_id",
            "origin_region",
            "target_region",
            "schema_version",
            "payload_json",
            "headers_json",
            "payload_sha256",
            "status",
            "attempts",
            "next_attempt_at",
            "lease_owner",
            "lease_expires_at",
            "processed_at",
            "last_error",
            "created_at",
            "updated_at",
            "scope_sequence",
        ],
    ),
    (
        "async_operation",
        &[
            "task_id",
            "task_type",
            "status",
            "requester_user_id",
            "requester_card_id",
            "requester_tenant_id",
            "requester_domain_id",
            "authorization_target_card_id",
            "authorization_target_tenant_id",
            "authorization_target_domain_id",
            "target_user_id",
            "total_items",
            "completed_items",
            "owner_instance_id",
            "error_message",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "async_operation_item",
        &[
            "task_id",
            "card_id",
            "tenant_id",
            "domain_id",
            "operation_id",
            "status",
            "error_message",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "permission_rule_template",
        &[
            "template_rule_id",
            "template_id",
            "resource_type",
            "resource_id",
            "action_code",
            "effect",
            "condition_json",
            "priority",
            "enabled",
        ],
    ),
    (
        "rule_set",
        &[
            "rule_set_id",
            "name",
            "code",
            "source_type",
            "source_id",
            "enabled",
            "tenant_id",
        ],
    ),
    (
        "rule_set_entry",
        &[
            "entry_id",
            "rule_set_id",
            "resource_type",
            "resource_id",
            "action_code",
            "effect",
            "condition_json",
            "priority",
            "enabled",
            "valid_from",
            "valid_to",
            "tenant_id",
        ],
    ),
    (
        "rule_set_projection_audit",
        &[
            "audit_id",
            "rule_set_id",
            "entry_id",
            "changed_by",
            "change_type",
            "old_value_json",
            "new_value_json",
            "changed_at",
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "event_id",
            "source_generation",
            "operation_id",
        ],
    ),
    (
        "card_rule_set_ref",
        &["id", "card_id", "rule_set_id", "ref_type", "tenant_id"],
    ),
    (
        "auth_token_family",
        &["family_id", "family_key", "user_id", "status"],
    ),
    (
        "auth_device_session",
        &[
            "session_id",
            "family_id",
            "user_id",
            "current_user_card_id",
            "session_state",
            "session_version",
            "session_epoch",
        ],
    ),
    (
        "authorization_projection_head",
        &[
            "head_id",
            "aggregate_type",
            "aggregate_id",
            "source_generation",
            "revoke_fence",
            "last_event_id",
            "last_error",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "authorization_projection_outbox",
        &[
            "outbox_id",
            "event_id",
            "aggregate_type",
            "aggregate_id",
            "tenant_id",
            "event_type",
            "source_generation",
            "sequence_number",
            "revoke_fence",
            "payload_json",
            "status",
            "attempts",
            "next_attempt_at",
            "lease_owner",
            "lease_expires_at",
            "processed_at",
            "processed_by",
            "terminal_transitions",
            "last_error",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "authorization_delta_event",
        &["invalidates_published_evidence"],
    ),
    (
        "auth_session_operation",
        &[
            "operation_id",
            "session_id",
            "user_id",
            "operation_type",
            "idempotency_key_hash",
            "request_hash",
            "refresh_token_hash",
            "target_card_id",
            "status",
            "response_ciphertext",
            "response_expires_at",
            "completed_at",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "auth_session_outbox",
        &[
            "outbox_id",
            "operation_id",
            "session_id",
            "event_type",
            "sequence_number",
            "projection_key",
            "payload_json",
            "status",
            "attempts",
            "next_attempt_at",
            "lease_owner",
            "lease_expires_at",
            "processed_at",
            "processed_by",
            "terminal_transitions",
            "last_error",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "auth_session_jti_index",
        &[
            "jti_id",
            "session_id",
            "jti",
            "user_id",
            "session_epoch",
            "status",
            "issued_at",
            "expires_at",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "audit_log",
        &[
            "id",
            "user_id",
            "action",
            "resource",
            "decision",
            "reason",
            "card_id",
            "event_type",
            "source_ip",
            "request_id",
            "domain_id",
            "tenant_id",
            "detail",
            "created_at",
        ],
    ),
    (
        "mq_idempotent_log",
        &["id", "message_type", "message_id", "status", "created_at"],
    ),
    (
        "pending_compensation",
        &[
            "id",
            "entity_id",
            "op_type",
            "error_msg",
            "status",
            "retry_count",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "audit_quarantine",
        &[
            "id",
            "identity_key",
            "message_id",
            "message_type",
            "raw_payload",
            "source_queue",
            "source_exchange",
            "source_routing_key",
            "retry_count",
            "attempts",
            "replay_attempts",
            "failure_reason",
            "status",
            "replay_lease_owner",
            "replay_lease_token",
            "replay_lease_token_hash",
            "replay_lease_generation",
            "replay_operation_id_hash",
            "replay_requested_by",
            "replay_requested_at",
            "replay_lease_expires_at",
            "first_failed_at",
            "last_failed_at",
            "quarantined_at",
            "replayed_at",
        ],
    ),
    (
        "alert_rule",
        &[
            "id",
            "name",
            "metric",
            "condition_op",
            "threshold",
            "duration_seconds",
            "severity",
            "enabled",
            "created_at",
        ],
    ),
    (
        "notification_channel",
        &[
            "id",
            "name",
            "channel_type",
            "config",
            "enabled",
            "created_at",
        ],
    ),
    (
        "monitor_metric_snapshot",
        &[
            "id",
            "service_name",
            "metric_type",
            "metric_value",
            "collected_at",
            "created_at",
        ],
    ),
    (
        "monitor_alert_history",
        &[
            "id",
            "rule_id",
            "rule_name",
            "metric_type",
            "actual_value",
            "severity",
            "status",
            "triggered_at",
            "resolved_at",
            "created_at",
        ],
    ),
    (
        "monitor_activity_log",
        &[
            "id",
            "event_type",
            "title",
            "detail",
            "level",
            "source_service",
            "occurred_at",
            "created_at",
        ],
    ),
];

const REQUIRED_SCHEMA_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("al_message_outbox", "PRIMARY", &["message_id"], true),
    (
        "al_message_outbox",
        "uk_al_message_queue_message",
        &["queue_name", "message_id"],
        true,
    ),
    (
        "al_message_outbox",
        "idx_al_message_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "al_message_outbox",
        "idx_al_message_lease",
        &["status", "lease_expires_at", "message_id"],
        false,
    ),
    (
        "al_message_outbox",
        "idx_al_message_ordering",
        &["queue_name", "ordering_key", "status", "created_at"],
        false,
    ),
    (
        "al_message_outbox",
        "idx_al_message_operation",
        &["operation_id", "message_type"],
        false,
    ),
    (
        "al_message_outbox",
        "idx_al_message_tenant",
        &["tenant_id", "queue_name", "created_at"],
        false,
    ),
    ("audit_log", "PRIMARY", &["id"], true),
    ("audit_log", "idx_al_user", &["user_id"], false),
    ("audit_log", "idx_al_action", &["action"], false),
    ("audit_log", "idx_al_created", &["created_at"], false),
    ("audit_log", "idx_al_event_type", &["event_type"], false),
    ("audit_log", "idx_al_tenant", &["tenant_id"], false),
    ("audit_log", "idx_al_card", &["card_id"], false),
    ("audit_log", "idx_al_decision", &["decision"], false),
    ("mq_idempotent_log", "PRIMARY", &["id"], true),
    (
        "mq_idempotent_log",
        "uk_mq_msg",
        &["message_type", "message_id"],
        true,
    ),
    ("pending_compensation", "PRIMARY", &["id"], true),
    ("pending_compensation", "idx_status", &["status"], false),
    ("pending_compensation", "idx_entity", &["entity_id"], false),
    ("rule_set", "PRIMARY", &["rule_set_id"], true),
    ("rule_set", "uk_rule_set_code", &["code"], true),
    (
        "rule_set",
        "idx_rule_set_source",
        &["source_type", "source_id"],
        false,
    ),
    ("rule_set_entry", "PRIMARY", &["entry_id"], true),
    (
        "rule_set_entry",
        "idx_rule_set_entry",
        &["rule_set_id", "enabled", "priority"],
        false,
    ),
    // rule_set_snapshot PRIMARY/uk/idx entries were removed together with the
    // REQUIRED_SCHEMA_COLUMNS entry: the table is decommissionable via
    // 20260827000002 and must not be required after the drop.
    ("rule_set_projection_audit", "PRIMARY", &["audit_id"], true),
    (
        "rule_set_projection_audit",
        "uk_rsp_audit_event_generation",
        &["event_id", "source_generation", "change_type"],
        true,
    ),
    (
        "rule_set_projection_audit",
        "idx_rsp_audit_rule_set_generation",
        &["rule_set_id", "source_generation"],
        false,
    ),
    (
        "rule_set_projection_audit",
        "idx_rsp_audit_operation",
        &["operation_id"],
        false,
    ),
    // rule_set_snapshot_manifest PRIMARY/idx entries were removed together with
    // the REQUIRED_SCHEMA_COLUMNS entry: the table is decommissionable via
    // 20260827000002 and must not be required after the drop.
    ("card_rule_set_ref", "PRIMARY", &["id"], true),
    (
        "card_rule_set_ref",
        "uk_card_rule_set",
        &["card_id", "rule_set_id"],
        true,
    ),
    ("card_rule_set_ref", "idx_crsr_card", &["card_id"], false),
    (
        "card_rule_set_ref",
        "idx_crsr_rule_set",
        &["rule_set_id"],
        false,
    ),
    (
        "authorization_projection_head",
        "PRIMARY",
        &["head_id"],
        true,
    ),
    (
        "authorization_projection_head",
        "uk_aph_aggregate",
        &["aggregate_type", "aggregate_id"],
        true,
    ),
    (
        "authorization_projection_outbox",
        "PRIMARY",
        &["outbox_id"],
        true,
    ),
    (
        "authorization_projection_outbox",
        "uk_apob_event",
        &["event_id"],
        true,
    ),
    (
        "authorization_projection_outbox",
        "uk_apob_generation_sequence",
        &[
            "aggregate_type",
            "aggregate_id",
            "source_generation",
            "sequence_number",
        ],
        true,
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_lease",
        &["status", "lease_expires_at", "outbox_id"],
        false,
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_aggregate",
        &["aggregate_type", "aggregate_id", "source_generation"],
        false,
    ),
    ("audit_quarantine", "PRIMARY", &["id"], true),
    (
        "audit_quarantine",
        "uk_aq_identity_key",
        &["identity_key"],
        true,
    ),
    (
        "audit_quarantine",
        "idx_aq_status",
        &["status", "quarantined_at", "id"],
        false,
    ),
    (
        "audit_quarantine",
        "idx_aq_replay_lease",
        &["status", "replay_lease_expires_at", "id"],
        false,
    ),
    (
        "audit_quarantine",
        "idx_aq_replay_request",
        &["status", "replay_requested_at", "id"],
        false,
    ),
    ("alert_rule", "PRIMARY", &["id"], true),
    ("notification_channel", "PRIMARY", &["id"], true),
    ("monitor_metric_snapshot", "PRIMARY", &["id"], true),
    (
        "monitor_metric_snapshot",
        "idx_mms_service",
        &["service_name"],
        false,
    ),
    (
        "monitor_metric_snapshot",
        "idx_mms_type",
        &["metric_type"],
        false,
    ),
    (
        "monitor_metric_snapshot",
        "idx_mms_collected",
        &["collected_at"],
        false,
    ),
    (
        "monitor_metric_snapshot",
        "idx_mms_service_type",
        &["service_name", "metric_type"],
        false,
    ),
    ("monitor_alert_history", "PRIMARY", &["id"], true),
    ("monitor_alert_history", "idx_mah_rule", &["rule_id"], false),
    (
        "monitor_alert_history",
        "idx_mah_status",
        &["status"],
        false,
    ),
    (
        "monitor_alert_history",
        "idx_mah_severity",
        &["severity"],
        false,
    ),
    (
        "monitor_alert_history",
        "idx_mah_triggered",
        &["triggered_at"],
        false,
    ),
    ("monitor_activity_log", "PRIMARY", &["id"], true),
    (
        "monitor_activity_log",
        "idx_mal_event_type",
        &["event_type"],
        false,
    ),
    ("monitor_activity_log", "idx_mal_level", &["level"], false),
    (
        "monitor_activity_log",
        "idx_mal_source",
        &["source_service"],
        false,
    ),
    (
        "monitor_activity_log",
        "idx_mal_occurred",
        &["occurred_at"],
        false,
    ),
];

const REQUIRED_SCHEMA_INDEX_ALIASES: &[(&str, &str, &str)] = &[
    ("rule_set_snapshot", "uk_rule_set_snapshot", "uk_snapshot"),
    (
        "authorization_projection_head",
        "uk_aph_aggregate",
        "uk_test_projection_head",
    ),
    (
        "authorization_projection_head",
        "uk_aph_aggregate",
        "uk_projection_head",
    ),
    (
        "authorization_projection_outbox",
        "uk_apob_event",
        "uk_test_apob_event",
    ),
    (
        "authorization_projection_outbox",
        "uk_apob_generation_sequence",
        "uk_test_apob_generation_sequence",
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_pending",
        "idx_test_apob_pending",
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_lease",
        "idx_test_apob_lease",
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_aggregate",
        "idx_test_apob_aggregate",
    ),
];

fn schema_index_candidates(table: &str, index: &str) -> Vec<String> {
    let mut candidates = vec![index.to_owned()];
    for (alias_table, canonical, alias) in REQUIRED_SCHEMA_INDEX_ALIASES {
        if *alias_table == table && *canonical == index {
            candidates.push((*alias).to_owned());
        }
    }
    candidates
}

const REQUIRED_SCHOOL_CUTOVER_COLUMNS: &[(&str, &[&str])] = &[
    (
        "school_tenant_migration",
        &[
            "school_id",
            "tenant_id",
            "tenant_code",
            "migration_status",
            "migrated_at",
            "verified_at",
            "rollback_note",
        ],
    ),
    ("schools", &["id", "status", "tenant_id"]),
    ("school_members", &["school_id", "user_id", "tenant_id"]),
    ("user_profiles", &["school_id", "tenant_id"]),
    ("leaderboards", &["school_id", "tenant_id"]),
];

const REQUIRED_SCHOOL_CUTOVER_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("school_tenant_migration", "PRIMARY", &["school_id"], true),
    (
        "school_tenant_migration",
        "uk_school_tenant_migration_tenant",
        &["tenant_id"],
        true,
    ),
    (
        "school_tenant_migration",
        "uk_school_tenant_migration_code",
        &["tenant_code"],
        true,
    ),
    (
        "school_tenant_migration",
        "idx_school_tenant_migration_status",
        &["migration_status"],
        false,
    ),
    (
        "school_members",
        "idx_school_members_tenant",
        &["tenant_id"],
        false,
    ),
    (
        "user_profiles",
        "idx_user_profiles_tenant",
        &["tenant_id"],
        false,
    ),
    (
        "leaderboards",
        "idx_leaderboards_tenant",
        &["tenant_id"],
        false,
    ),
];

const REQUIRED_SCHOOL_CUTOVER_FOREIGN_KEYS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "school_tenant_migration",
        "fk_school_tenant_migration_school",
        "school_id",
        "schools",
        "id",
    ),
    (
        "school_tenant_migration",
        "fk_school_tenant_migration_tenant",
        "tenant_id",
        "tenant",
        "tenant_id",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchoolTenantCutoverState {
    Complete,
    Recoverable,
}

impl SchoolTenantCutoverState {
    fn requires_replay(self) -> bool {
        matches!(self, Self::Recoverable)
    }
}

const SCHOOL_TENANT_BACKFILL_CONFLICTS: &[(&str, &str)] = &[
    (
        "schools",
        "SELECT COUNT(*) FROM schools s \
         LEFT JOIN tenant t ON t.tenant_code = CONCAT('SCHOOL-', s.id) \
         WHERE s.tenant_id IS NOT NULL \
           AND (t.tenant_id IS NULL OR s.tenant_id <> t.tenant_id)",
    ),
    (
        "school_members",
        "SELECT COUNT(*) FROM school_members sm \
         LEFT JOIN tenant t ON t.tenant_code = CONCAT('SCHOOL-', sm.school_id) \
         WHERE sm.school_id IS NOT NULL AND sm.tenant_id IS NOT NULL \
           AND (t.tenant_id IS NULL OR sm.tenant_id <> t.tenant_id)",
    ),
    (
        "user_profiles",
        "SELECT COUNT(*) FROM user_profiles upf \
         LEFT JOIN tenant t ON t.tenant_code = CONCAT('SCHOOL-', upf.school_id) \
         WHERE upf.school_id IS NOT NULL AND upf.tenant_id IS NOT NULL \
           AND (t.tenant_id IS NULL OR upf.tenant_id <> t.tenant_id)",
    ),
    (
        "leaderboards",
        "SELECT COUNT(*) FROM leaderboards lb \
         LEFT JOIN tenant t ON t.tenant_code = CONCAT('SCHOOL-', lb.school_id) \
         WHERE lb.school_id IS NOT NULL AND lb.tenant_id IS NOT NULL \
           AND (t.tenant_id IS NULL OR lb.tenant_id <> t.tenant_id)",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemaColumnContract {
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
    not_null: bool,
    default: Option<&'static str>,
    charset: Option<&'static str>,
    collation: Option<&'static str>,
}

const fn incremental_scalar_column(
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
    not_null: bool,
    default: Option<&'static str>,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name,
        column_type,
        not_null,
        default,
        charset: None,
        collation: None,
    }
}

const fn incremental_text_column(
    table: &'static str,
    name: &'static str,
    column_type: &'static str,
    not_null: bool,
    default: Option<&'static str>,
) -> SchemaColumnContract {
    SchemaColumnContract {
        table,
        name,
        column_type,
        not_null,
        default,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    }
}

const MONITOR_SCHEMA_COLUMN_CONTRACT: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "alert_rule",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "name",
        column_type: "VARCHAR(255)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "metric",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "condition_op",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: Some(">="),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "threshold",
        column_type: "DOUBLE",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "duration_seconds",
        column_type: "INT",
        not_null: true,
        default: Some("60"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "severity",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("WARNING"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "enabled",
        column_type: "TINYINT",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "alert_rule",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "notification_channel",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "notification_channel",
        name: "name",
        column_type: "VARCHAR(255)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "notification_channel",
        name: "channel_type",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("EMAIL"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "notification_channel",
        name: "config",
        column_type: "JSON",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "notification_channel",
        name: "enabled",
        column_type: "TINYINT",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "notification_channel",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_metric_snapshot",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_metric_snapshot",
        name: "service_name",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_metric_snapshot",
        name: "metric_type",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_metric_snapshot",
        name: "metric_value",
        column_type: "DOUBLE",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_metric_snapshot",
        name: "collected_at",
        column_type: "TIMESTAMP",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_metric_snapshot",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "rule_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "rule_name",
        column_type: "VARCHAR(255)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "metric_type",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "actual_value",
        column_type: "DOUBLE",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "severity",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("WARNING"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("triggered"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "triggered_at",
        column_type: "TIMESTAMP",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "resolved_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_alert_history",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "event_type",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "title",
        column_type: "VARCHAR(255)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "detail",
        column_type: "TEXT",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "level",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: Some("info"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "source_service",
        column_type: "VARCHAR(128)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "occurred_at",
        column_type: "TIMESTAMP",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "monitor_activity_log",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
];

const AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT: SchemaColumnContract =
    SchemaColumnContract {
        table: "audit_quarantine",
        name: "replay_lease_generation",
        column_type: "BIGINT UNSIGNED",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    };

const RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT: SchemaColumnContract =
    SchemaColumnContract {
        table: "rule_set_snapshot",
        name: "projection_generation",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    };

const SNAPSHOT_VALIDITY_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "permission_rule_snapshot",
        name: "valid_from",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "permission_rule_snapshot",
        name: "valid_to",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "rule_set_snapshot",
        name: "valid_from",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "rule_set_snapshot",
        name: "valid_to",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
];

// These columns participate in durable projection uniqueness or in the
// generation gate. Presence-only checks are insufficient here: a nullable
// outbox key would make MySQL UNIQUE indexes permit duplicate events containing
// NULL, and a nullable generation would let an old snapshot look comparable to
// a proven head. Other baseline columns intentionally retain their historical
// compatibility-only contracts below.
const RULE_SET_PROJECTION_EVENT_KEY_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "authorization_projection_head",
        name: "aggregate_type",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_projection_head",
        name: "aggregate_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_head",
        name: "source_generation",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_head",
        name: "revoke_fence",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_outbox",
        name: "event_id",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_projection_outbox",
        name: "aggregate_type",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_projection_outbox",
        name: "aggregate_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_outbox",
        name: "source_generation",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_outbox",
        name: "sequence_number",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
];

fn rule_set_projection_strict_column_contract(
    table: &str,
    column: &str,
) -> Option<&'static SchemaColumnContract> {
    RULE_SET_PROJECTION_EVENT_KEY_COLUMN_CONTRACTS
        .iter()
        .find(|expected| expected.table == table && expected.name == column)
        .or_else(|| {
            (RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT.table == table
                && RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT.name == column)
                .then_some(&RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT)
        })
        .or_else(|| {
            SNAPSHOT_VALIDITY_COLUMN_CONTRACTS
                .iter()
                .find(|expected| expected.table == table && expected.name == column)
        })
        .or_else(|| {
            RULE_SET_SNAPSHOT_MANIFEST_COLUMN_CONTRACTS
                .iter()
                .find(|expected| expected.table == table && expected.name == column)
        })
}

// These contracts intentionally mirror the two supported TrustGraph shapes:
// the immutable full_schema_v4 baseline and the Rust migration's CREATE shape.
// Existing tables are never rewritten between the two shapes.
const TRUSTGRAPH_BASELINE_COLUMN_CONTRACT: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "sod_policy",
        name: "policy_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "policy_name",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "description",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "conflict_type",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "resource_type",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "action_code",
        column_type: "VARCHAR(32)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "permission_a",
        column_type: "VARCHAR(128)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "permission_b",
        column_type: "VARCHAR(128)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "condition_script",
        column_type: "VARCHAR(1024)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "limit_count",
        column_type: "INT",
        not_null: false,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "limit_window",
        column_type: "VARCHAR(32)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "status",
        column_type: "VARCHAR(16)",
        not_null: false,
        default: Some("ACTIVE"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "created_at",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "updated_at",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "violation_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "policy_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "policy_name",
        column_type: "VARCHAR(128)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "card_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "user_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "operator_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "violation_type",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "details_json",
        column_type: "JSON",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "blocked",
        column_type: "TINYINT(1)",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "created_at",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "user_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("ACTIVE"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "granted_by",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "granted_reason",
        column_type: "VARCHAR(255)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "created_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "updated_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
];

const TRUSTGRAPH_SOURCE_COLUMN_CONTRACT: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "sod_policy",
        name: "policy_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "policy_name",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "description",
        column_type: "TEXT",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "conflict_type",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: Some("STATIC"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "resource_type",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "action_code",
        column_type: "VARCHAR(64)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "permission_a",
        column_type: "VARCHAR(256)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "permission_b",
        column_type: "VARCHAR(256)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "condition_script",
        column_type: "TEXT",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "status",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: Some("ACTIVE"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "limit_count",
        column_type: "INT",
        not_null: false,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "limit_window",
        column_type: "VARCHAR(32)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_policy",
        name: "updated_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "violation_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "policy_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "policy_name",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "card_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "user_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "operator_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "violation_type",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: Some("STATIC"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "details_json",
        column_type: "TEXT",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "blocked",
        column_type: "TINYINT(1)",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "sod_violation",
        name: "created_at",
        column_type: "TIMESTAMP",
        not_null: false,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "user_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("ACTIVE"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "granted_by",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "granted_reason",
        column_type: "VARCHAR(255)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "created_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "identity_global_admin",
        name: "updated_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
];

const TRUSTGRAPH_BASELINE_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("sod_policy", "PRIMARY", &["policy_id"], true),
    ("sod_policy", "uk_policy_name", &["policy_name"], true),
    ("sod_policy", "idx_conflict_type", &["conflict_type"], false),
    ("sod_violation", "PRIMARY", &["violation_id"], true),
    ("sod_violation", "idx_policy", &["policy_id"], false),
    ("sod_violation", "idx_card", &["card_id"], false),
    ("sod_violation", "idx_user", &["user_id"], false),
    ("identity_global_admin", "PRIMARY", &["id"], true),
    (
        "identity_global_admin",
        "uk_identity_global_admin_user_id",
        &["user_id"],
        true,
    ),
    (
        "identity_global_admin",
        "idx_identity_global_admin_status",
        &["status"],
        false,
    ),
];

const TRUSTGRAPH_BASELINE_READY_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("sod_policy", "PRIMARY", &["policy_id"], true),
    ("sod_policy", "uk_policy_name", &["policy_name"], true),
    ("sod_policy", "idx_conflict_type", &["conflict_type"], false),
    ("sod_policy", "idx_sod_status", &["status"], false),
    ("sod_violation", "PRIMARY", &["violation_id"], true),
    ("sod_violation", "idx_policy", &["policy_id"], false),
    ("sod_violation", "idx_card", &["card_id"], false),
    ("sod_violation", "idx_user", &["user_id"], false),
    ("identity_global_admin", "PRIMARY", &["id"], true),
    (
        "identity_global_admin",
        "uk_identity_global_admin_user_id",
        &["user_id"],
        true,
    ),
    (
        "identity_global_admin",
        "idx_identity_global_admin_status",
        &["status"],
        false,
    ),
];

const TRUSTGRAPH_SOURCE_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("sod_policy", "PRIMARY", &["policy_id"], true),
    ("sod_policy", "idx_sod_type", &["conflict_type"], false),
    ("sod_policy", "idx_sod_status", &["status"], false),
    ("sod_violation", "PRIMARY", &["violation_id"], true),
    ("sod_violation", "idx_sv_policy", &["policy_id"], false),
    ("sod_violation", "idx_sv_card", &["card_id"], false),
    ("identity_global_admin", "PRIMARY", &["id"], true),
    (
        "identity_global_admin",
        "uk_identity_global_admin_user_id",
        &["user_id"],
        true,
    ),
    (
        "identity_global_admin",
        "idx_identity_global_admin_status",
        &["status"],
        false,
    ),
];

const TRUSTGRAPH_SOURCE_FOREIGN_KEYS: &[(&str, &str, &str, &str, &str, &str)] = &[(
    "sod_violation",
    "fk_sod_violation_policy",
    "policy_id",
    "sod_policy",
    "policy_id",
    "CASCADE",
)];

const SCHOOL_TENANT_MIGRATION_COLUMN_CONTRACT: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "school_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "tenant_code",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "migration_status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("MIGRATED"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "migrated_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "verified_at",
        column_type: "DATETIME",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "school_tenant_migration",
        name: "rollback_note",
        column_type: "VARCHAR(512)",
        not_null: false,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_MIGRATION_COLLATION),
    },
];

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct SchoolTenantCutoverReport {
    pub mapped_schools: i64,
    pub active_schools_without_mapping: i64,
    pub school_members_without_tenant: i64,
    pub user_profiles_without_tenant: i64,
    pub leaderboards_without_tenant: i64,
}

/// Apply all pending migrations through the explicit Rust migration job.
///
/// The `_sqlx_migrations` DDL is intentionally byte-for-byte compatible with
/// sqlx 0.8.6's MySQL migrator. Setup, baseline verification, history repair,
/// and migration execution all fail closed: a security-sensitive service must
/// not start against an unknown or partially initialized schema.
pub async fn apply_migrations(database_url: &str) -> Result<MySqlPool, MigrationError> {
    ensure_isolated_migration_target(database_url)?;

    let pool = mysql_migration_pool_options()
        .connect_with(mysql_migration_connection_options(database_url)?)
        .await
        .map_err(|e| MigrationError::Failed(format!("connect migration pool: {e}")))?;
    let lock_options = mysql_migration_connection_options(database_url)?;
    let mut lock_connection = MySqlConnection::connect_with(&lock_options)
        .await
        .map_err(|e| MigrationError::Failed(format!("connect migration lock: {e}")))?;
    configure_migration_session(&mut lock_connection)
        .await
        .map_err(|e| MigrationError::Failed(format!("configure migration lock session: {e}")))?;
    acquire_migration_lock(&mut lock_connection).await?;

    let migration_result = async {
        // Inspect pinned standby source and destructive-operation authorization
        // before creating or normalizing migration history, baseline adoption,
        // or handing any pending statement to SQLx. Absence of history means no
        // successful migration has been durably recorded yet.
        preflight_standby_migration_gate(&pool, &HashSet::new(), MIGRATOR.migrations.as_ref()).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _sqlx_migrations (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL,
                checksum BLOB NOT NULL,
                execution_time BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("create migration history: {e}")))?;
        normalize_migration_history_schema(&pool).await?;

        let failed_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = 0")
                .fetch_one(&pool)
                .await
                .map_err(|e| MigrationError::Failed(format!("inspect failed migrations: {e}")))?;
        if failed_count.0 != 0 {
            return Err(MigrationError::Failed(format!(
                "migration history contains {} failed migration record(s)",
                failed_count.0
            )));
        }

        let recorded_versions = recorded_successful_versions(&pool).await?;
        preflight_standby_migration_gate(&pool, &recorded_versions, MIGRATOR.migrations.as_ref()).await?;
        let history_state = classify_migration_history(&recorded_versions);
        let baseline_is_verified = verified_baseline(&pool).await?;

        match migration_history_decision(history_state, baseline_is_verified) {
            MigrationHistoryDecision::AdoptBaseline => {
                preflight_before_baseline_adoption(&pool).await?;
                tracing::info!(
                    "verified Java baseline found; recording baseline migrations as applied"
                );
                record_verified_baseline(&pool, &recorded_versions).await?;
            }
            MigrationHistoryDecision::Continue => {}
            MigrationHistoryDecision::FailClosed => {
                let reason = match (history_state, baseline_is_verified) {
                    (MigrationHistoryState::Empty, false) => {
                        "migration history is empty and verified Java baseline is absent"
                    }
                    (MigrationHistoryState::BaselineIncomplete, true) => {
                        "verified Java baseline exists but Rust migration history is incomplete; refusing to guess baseline ownership"
                    }
                    (MigrationHistoryState::BaselineIncomplete, false) => {
                        "Rust migration history is incomplete and verified Java baseline is absent; refusing to rerun unknown historical DDL"
                    }
                    _ => "migration history cannot be safely adopted",
                };
                return Err(MigrationError::Failed(reason.into()));
            }
        }

        // A checksum mismatch is only repairable for a verified Java baseline. Rust
        // migrations are immutable and must never be silently deleted/replayed.
        for mig in MIGRATOR.migrations.iter() {
            let existing: Option<(Vec<u8>,)> = sqlx::query_as(
                "SELECT checksum FROM _sqlx_migrations WHERE version = ? AND success = 1",
            )
            .bind(mig.version)
            .fetch_optional(&pool)
            .await
            .map_err(|e| MigrationError::Failed(format!("inspect migration history: {e}")))?;

            if let Some((old_checksum,)) = existing {
                if old_checksum != mig.checksum.as_ref().to_vec() {
                    // A verified schema proves structure, not that an arbitrary
                    // history row is authentic.  Never overwrite mismatch rows:
                    // the mismatch itself is tamper/ownership evidence.
                    return Err(MigrationError::Failed(format!(
                        "checksum mismatch for migration {}{}",
                        mig.version,
                        if !is_java_baseline_era(mig.version) {
                            " (Rust-owned or compatibility migration)"
                        } else if baseline_is_verified {
                            " (baseline checksum mismatch; refusing silent repair)"
                        } else {
                            " (baseline is not verified)"
                        }
                    )));
                }
            }
        }

        apply_migrations_with_mysql8_compat(&pool).await?;

        // SQLx records success before returning from `run`. Keep the explicit
        // migration lock while checking the final contract so an unexpected
        // postcondition failure is reported as recovery-required, never as a
        // completed migration run. The preflight below makes this branch
        // unreachable for any schema state produced by the embedded migrations.
        validate_schema_contract(&pool).await.map_err(|error| {
            MigrationError::RecoveryRequired {
                reason: format!(
                    "SQLx may have recorded a successful migration before schema contract validation failed: {error}"
                ),
            }
        })?;
        tracing::info!("database migrations completed and schema contract verified");
        Ok(())
    }
    .await;

    let cleanup_result = release_migration_lock(&mut lock_connection).await;
    match resolve_migration_result(migration_result, cleanup_result) {
        Ok(()) => Ok(pool),
        Err(error) => Err(error),
    }
}

async fn preflight_standby_migration_gate(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<(), MigrationError> {
    let migration = migrations
        .iter()
        .find(|migration| migration.version == LEGACY_SNAPSHOT_DECOMMISSION_VERSION)
        .ok_or_else(|| {
            MigrationError::Failed(format!(
                "standby migration {LEGACY_SNAPSHOT_DECOMMISSION_VERSION} is missing from the embedded migrator"
            ))
        })?;
    if !migration_matches_known_source(migration) {
        return Err(MigrationError::Failed(format!(
            "standby migration {} is not the checksum-pinned canonical source",
            LEGACY_SNAPSHOT_DECOMMISSION_VERSION
        )));
    }
    if applied_versions.contains(&LEGACY_SNAPSHOT_DECOMMISSION_VERSION) {
        return Ok(());
    }

    let is_pending = MIGRATOR
        .migrations
        .iter()
        .find(|embedded| embedded.version == LEGACY_SNAPSHOT_DECOMMISSION_VERSION)
        .is_some_and(|embedded| !applied_versions.contains(&embedded.version));
    if !is_pending {
        return Ok(());
    }

    let authorization = destructive_migration_authorization(
        std::env::var(DESTRUCTIVE_MIGRATION_ALLOWLIST_ENV)
            .ok()
            .as_deref(),
        std::env::var(DESTRUCTIVE_MIGRATION_BACKUP_PROOF_ENV)
            .ok()
            .as_deref(),
        std::env::var(DESTRUCTIVE_MIGRATION_DRAIN_PROOF_ENV)
            .ok()
            .as_deref(),
        std::env::var(DESTRUCTIVE_MIGRATION_CUTOVER_PROOF_ENV)
            .ok()
            .as_deref(),
    );
    authorization?;

    let table_present = schema_table_exists(pool, LEGACY_SNAPSHOT_REQUIRED_DRAIN_TABLES[0]).await?;
    if table_present {
        let pending_legacy_work: Option<(i64,)> = sqlx::query_as(DESTRUCTIVE_MIGRATION_DRAIN_SQL)
            .fetch_optional(pool)
            .await
            .map_err(|error| {
                MigrationError::Failed(format!(
                    "read-only standby migration drain preflight failed: {error}"
                ))
            })?;
        if pending_legacy_work.is_some() {
            return Err(MigrationError::Failed(format!(
                "standby migration {} refused while CARD/RULE_SET projection outbox work remains PENDING",
                LEGACY_SNAPSHOT_DECOMMISSION_VERSION
            )));
        }
    }
    Ok(())
}

async fn preflight_before_baseline_adoption(pool: &MySqlPool) -> Result<(), MigrationError> {
    preflight_standby_migration_gate(pool, &HashSet::new(), MIGRATOR.migrations.as_ref()).await?;
    for contract in HISTORICAL_MIGRATION_COMPATIBILITY {
        if !is_java_baseline_era(contract.version)
            && contract.version != TRUSTGRAPH_RUNTIME_TABLES_VERSION
        {
            continue;
        }
        let migration = MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == contract.version)
            .ok_or_else(|| {
                MigrationError::Failed(format!(
                    "known historical migration {} is missing from the embedded migrator",
                    contract.version
                ))
            })?;
        let migration_pending = contract.version == TRUSTGRAPH_RUNTIME_TABLES_VERSION;
        preflight_historical_migration_schema_contract(pool, migration, migration_pending, true)
            .await?;
        if contract.version == TENANT_SCHOOL_CUTOVER_VERSION {
            validate_school_tenant_cutover_pre_data_contract(pool).await?;
            validate_school_tenant_backfill_source_conflicts(pool).await?;
            if school_tenant_cutover_table_exists(pool).await? {
                validate_school_tenant_backfill_conflicts(pool).await?;
            }
        }
    }
    Ok(())
}

///
/// This is intentionally the normal application-startup path. Missing tables
/// or columns are a deployment error and must be corrected by `astral-migrate`.
pub async fn connect_and_validate_schema(database_url: &str) -> Result<MySqlPool, MigrationError> {
    let pool = mysql_pool_options()
        .connect_with(mysql_connection_options(database_url)?)
        .await
        .map_err(|e| MigrationError::Failed(format!("connect: {e}")))?;

    // A successful history row is not proof that either historical auth
    // migration completed its fence-column contract. Services never execute
    // DDL here, but they must apply the same strict type/null/default/position
    // preflight and fail closed on drift. The school cutover is an explicit
    // migration/report contract and is intentionally outside ordinary startup.
    for contract in HISTORICAL_MIGRATION_COMPATIBILITY
        .iter()
        .filter(|contract| contract.version != TENANT_SCHOOL_CUTOVER_VERSION)
    {
        let migration = MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == contract.version)
            .ok_or_else(|| {
                MigrationError::Failed(format!(
                    "known historical migration {} is missing from the embedded migrator",
                    contract.version
                ))
            })?;
        preflight_historical_migration_schema_contract(&pool, migration, false, false).await?;
    }
    validate_schema_contract(&pool).await?;
    Ok(pool)
}

async fn apply_migrations_with_mysql8_compat(pool: &MySqlPool) -> Result<(), MigrationError> {
    let applied_versions = recorded_successful_versions(pool).await?;
    let mut migrations = MIGRATOR.migrations.to_vec();
    let mut replay_recorded_cutover = false;

    for contract in HISTORICAL_MIGRATION_COMPATIBILITY {
        let migration_pending = !applied_versions.contains(&contract.version);
        let migration = migrations
            .iter()
            .find(|migration| migration.version == contract.version)
            .ok_or_else(|| {
                MigrationError::Failed(format!(
                    "known historical migration {} is missing from the embedded migrator",
                    contract.version
                ))
            })?;

        // Run the exact schema preflight on every apply, including when the
        // history row already exists. A recorded version is not evidence that
        // its three-column fence contract was ever completed.
        preflight_historical_migration_schema_contract(pool, migration, migration_pending, true)
            .await?;

        if contract.version == TENANT_SCHOOL_CUTOVER_VERSION {
            if migration_pending {
                // The canonical SQL creates the mapping table before its
                // mapping insert, so validate any existing artifacts before
                // checking conflicts and executing its data statements.
                validate_school_tenant_cutover_pre_data_contract(pool).await?;
                // The canonical SQL creates the mapping table before its
                // mapping insert, so only existing source assignments can be
                // checked before SQLx applies this pending migration.
                validate_school_tenant_backfill_source_conflicts(pool).await?;
                if school_tenant_cutover_table_exists(pool).await? {
                    validate_school_tenant_backfill_conflicts(pool).await?;
                }
            } else {
                validate_school_tenant_cutover_contract(pool).await?;
                let cutover_state = school_tenant_cutover_state(pool).await?;
                if cutover_state.requires_replay() {
                    validate_school_tenant_backfill_conflicts(pool).await?;
                    replay_recorded_cutover = true;
                }
            }
        }

        if migration_pending {
            let migration = migrations
                .iter_mut()
                .find(|migration| migration.version == contract.version)
                .expect("historical migration was found immediately before adaptation");
            migration.sql = historical_mysql8_compatible_sql(migration)?;
        }
    }

    // Keep SQLx responsible for ordering, history rows, checksums, dirty-state
    // handling, and execution of every pending migration. Only the verified
    // historical SQL bodies above are adapted; each original checksum remains
    // untouched.
    let migrator = Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: MIGRATOR.ignore_missing,
        locking: false,
        no_tx: MIGRATOR.no_tx,
    };
    preflight_schema_contract_before_sqlx(pool, &applied_versions, &migrator.migrations).await?;
    migrator
        .run(pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("migrate: {e}")))?;
    validate_archive_index_removal_postcondition(pool).await?;

    // SQLx records a successful migration before returning. This idempotent
    // data backfill therefore runs on every explicit migration invocation,
    // including recovery runs after a post-SQLx backfill failure, while the
    // caller still owns MIGRATION_LOCK_NAME.
    backfill_rule_set_projection(pool).await?;

    if replay_recorded_cutover {
        // The rollback rehearsal intentionally leaves the successful SQLx row
        // in place. Replay only the canonical, checksum-pinned cutover body;
        // raw_sql is explicit-job-only and does not touch migration history.
        let migration = MIGRATOR
            .migrations
            .iter()
            .find(|migration| migration.version == TENANT_SCHOOL_CUTOVER_VERSION)
            .ok_or_else(|| {
                MigrationError::Failed(format!(
                    "known historical migration {} is missing from the embedded migrator",
                    TENANT_SCHOOL_CUTOVER_VERSION
                ))
            })?;
        let replay_sql = historical_mysql8_compatible_sql(migration)?;
        sqlx::raw_sql(replay_sql.as_ref())
            .execute(pool)
            .await
            .map_err(|e| {
                MigrationError::RecoveryRequired {
                    reason: format!(
                        "replay recorded school tenant cutover after rollback failed; migration history was preserved and explicit recovery is required: {e}"
                    ),
                }
            })?;
    }

    validate_school_tenant_cutover_complete(pool)
        .await
        .map_err(|error| MigrationError::RecoveryRequired {
            reason: format!(
                "school tenant cutover post-validation failed after SQLx migration execution; explicit recovery is required: {error}"
            ),
        })
}

const RULE_SET_PROJECTION_BACKFILL_MARKER: &str = "20260822000001";
const RULE_SET_MIGRATION_BACKFILL_CHANGE_TYPE: &str = "MIGRATION_BACKFILL";

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationBackfillMarker {
    event_id: String,
    source_generation: i64,
    status: String,
    tenant_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct MigrationMarkerEvent {
    event_id: String,
    source_generation: i64,
    sequence_number: i64,
    tenant_id: Option<i64>,
    payload_json: Option<String>,
    status: String,
}

fn migration_backfill_operation_id(rule_set_id: i64, generation: i64) -> String {
    format!(
        "migration-backfill:{RULE_SET_PROJECTION_BACKFILL_MARKER}:rule-set:{rule_set_id}:generation:{generation}"
    )
}

fn nullable_json_i64(value: &serde_json::Value) -> Option<Option<i64>> {
    if value.is_null() {
        Some(None)
    } else {
        value.as_i64().map(Some)
    }
}

fn valid_migration_backfill_marker(
    payload: &serde_json::Value,
    rule_set_id: i64,
    event_source_generation: i64,
    sequence_number: i64,
    event_tenant_id: Option<i64>,
) -> bool {
    payload
        .get("migrationVersion")
        .and_then(serde_json::Value::as_str)
        == Some(RULE_SET_PROJECTION_BACKFILL_MARKER)
        && payload.get("ruleSetId").and_then(serde_json::Value::as_i64) == Some(rule_set_id)
        && payload
            .get("generation")
            .and_then(serde_json::Value::as_i64)
            == Some(event_source_generation)
        && event_source_generation > 0
        && event_source_generation == sequence_number
        && payload.get("tenantId").and_then(nullable_json_i64) == Some(event_tenant_id)
}

fn repair_migration_backfill_payload(
    mut payload: serde_json::Value,
    rule_set_id: i64,
    generation: i64,
) -> Option<serde_json::Value> {
    let object = payload.as_object_mut()?;
    object.insert(
        "actorId".into(),
        serde_json::json!(astral_types::SYSTEM_ACTOR_ID),
    );
    object.insert(
        "operationId".into(),
        serde_json::Value::String(migration_backfill_operation_id(rule_set_id, generation)),
    );
    Some(payload)
}

fn migration_backfill_payload(
    rule_set_id: i64,
    tenant_id: Option<i64>,
    generation: i64,
) -> serde_json::Value {
    serde_json::json!({
        "ruleSetId": rule_set_id,
        "tenantId": tenant_id,
        "generation": generation,
        "migrationVersion": RULE_SET_PROJECTION_BACKFILL_MARKER,
        "actorId": astral_types::SYSTEM_ACTOR_ID,
        "operationId": migration_backfill_operation_id(rule_set_id, generation),
    })
}

async fn insert_migration_backfill_audit_in_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    tenant_id: Option<i64>,
    event_id: &str,
    generation: i64,
    operation_id: &str,
    payload_json: &str,
) -> Result<(), MigrationError> {
    sqlx::query(
        "INSERT INTO rule_set_projection_audit \
         (rule_set_id, entry_id, changed_by, change_type, old_value_json, new_value_json, \
          changed_at, tenant_id, aggregate_type, aggregate_id, event_id, source_generation, operation_id) \
         VALUES (?, NULL, ?, ?, NULL, ?, UTC_TIMESTAMP(), ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             changed_by = VALUES(changed_by), operation_id = VALUES(operation_id), \
             tenant_id = VALUES(tenant_id), new_value_json = VALUES(new_value_json)",
    )
    .bind(rule_set_id)
    .bind(astral_types::SYSTEM_ACTOR_ID)
    .bind(RULE_SET_MIGRATION_BACKFILL_CHANGE_TYPE)
    .bind(payload_json)
    .bind(tenant_id)
    .bind(ProjectionAggregate::RuleSet.as_str())
    .bind(rule_set_id)
    .bind(event_id)
    .bind(generation)
    .bind(operation_id)
    .execute(&mut **transaction)
    .await
    .map_err(|e| MigrationError::Failed(format!("write RuleSet migration audit evidence: {e}")))?;
    Ok(())
}

async fn backfill_rule_set_projection(pool: &MySqlPool) -> Result<(), MigrationError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| MigrationError::Failed(format!("begin RuleSet projection backfill: {e}")))?;

    let orphan_references: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) \
         FROM card_rule_set_ref crs \
         LEFT JOIN rule_set rs ON rs.rule_set_id = crs.rule_set_id \
         WHERE rs.rule_set_id IS NULL",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|e| MigrationError::Failed(format!("inspect orphan RuleSet references: {e}")))?;
    if orphan_references != 0 {
        return Err(MigrationError::Failed(format!(
            "RuleSet projection backfill found {orphan_references} orphan card_rule_set_ref row(s); refusing to create unverifiable projection heads"
        )));
    }

    let rule_sets: Vec<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT rule_set_id, tenant_id FROM rule_set ORDER BY rule_set_id FOR UPDATE",
    )
    .fetch_all(&mut *transaction)
    .await
    .map_err(|e| MigrationError::Failed(format!("load RuleSets for projection backfill: {e}")))?;

    for (rule_set_id, tenant_id) in rule_sets {
        let head: Option<(i64, i64)> = sqlx::query_as(
            "SELECT source_generation, revoke_fence \
             FROM authorization_projection_head \
             WHERE aggregate_type = ? AND aggregate_id = ? \
             FOR UPDATE",
        )
        .bind(ProjectionAggregate::RuleSet.as_str())
        .bind(rule_set_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!("lock RuleSet projection head {rule_set_id}: {e}"))
        })?;

        // Lock every candidate marker while repairing metadata/audit. The
        // newest valid marker controls whether a new generation is required,
        // but older valid rows also need durable evidence for convergence.
        let marker_events: Vec<MigrationMarkerEvent> = sqlx::query_as(
            "SELECT event_id, source_generation, sequence_number, tenant_id, payload_json, status \
                 FROM authorization_projection_outbox \
                 WHERE aggregate_type = ? AND aggregate_id = ? AND event_type = ? \
                 ORDER BY outbox_id DESC FOR UPDATE",
        )
        .bind(ProjectionAggregate::RuleSet.as_str())
        .bind(rule_set_id)
        .bind(EVENT_TYPE_RULE_SET_UPDATE)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!(
                "inspect RuleSet projection backfill marker {rule_set_id}: {e}"
            ))
        })?;

        let mut valid_markers = Vec::new();
        for marker in &marker_events {
            let Some(payload_value) = marker
                .payload_json
                .as_deref()
                .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
            else {
                continue;
            };
            if marker.tenant_id != tenant_id
                || !valid_migration_backfill_marker(
                    &payload_value,
                    rule_set_id,
                    marker.source_generation,
                    marker.sequence_number,
                    marker.tenant_id,
                )
            {
                continue;
            }

            let repaired_payload = repair_migration_backfill_payload(
                payload_value.clone(),
                rule_set_id,
                marker.source_generation,
            )
            .ok_or_else(|| {
                MigrationError::Failed(format!(
                    "RuleSet migration marker {} payload is not a JSON object",
                    marker.event_id
                ))
            })?;
            let repaired_payload_json = repaired_payload.to_string();
            if marker.payload_json.as_deref() != Some(repaired_payload_json.as_str()) {
                sqlx::query(
                    "UPDATE authorization_projection_outbox SET payload_json = ? \
                     WHERE event_id = ? AND aggregate_type = ? AND aggregate_id = ?",
                )
                .bind(&repaired_payload_json)
                .bind(&marker.event_id)
                .bind(ProjectionAggregate::RuleSet.as_str())
                .bind(rule_set_id)
                .execute(&mut *transaction)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "repair RuleSet migration marker metadata {}: {e}",
                        marker.event_id
                    ))
                })?;
            }

            let operation_id =
                migration_backfill_operation_id(rule_set_id, marker.source_generation);
            insert_migration_backfill_audit_in_tx(
                &mut transaction,
                rule_set_id,
                marker.tenant_id,
                &marker.event_id,
                marker.source_generation,
                &operation_id,
                &repaired_payload_json,
            )
            .await?;
            valid_markers.push(MigrationBackfillMarker {
                event_id: marker.event_id.clone(),
                source_generation: marker.source_generation,
                status: marker.status.clone(),
                tenant_id: marker.tenant_id,
            });
        }

        let (source_generation, revoke_fence) = match head.as_ref() {
            Some((source, fence)) => {
                if *source < 0 || *fence < 0 {
                    return Err(MigrationError::Failed(format!(
                        "RuleSet projection head {rule_set_id} has invalid generation state source={source}, revoke_fence={fence}"
                    )));
                }
                (*source, *fence)
            }
            None => (0, 0),
        };

        if let Some(marker) = valid_markers.first() {
            if head.is_none() || source_generation < marker.source_generation {
                return Err(MigrationError::Failed(format!(
                    "RuleSet projection head {rule_set_id} is missing or behind its durable backfill event at generation {}",
                    marker.source_generation
                )));
            }
            if source_generation > marker.source_generation {
                // A later source event already superseded the migration event;
                // repair evidence above but do not add an unrelated generation.
                continue;
            }
            match marker.status.as_str() {
                // A pending marker must remain pending. In particular, this
                // repair never infers READY from metadata/audit presence.
                "PENDING" => continue,
                "PROCESSED" => {
                    // 快照重建通道已整体退役（迁移 20260827000002 删除旧
                    // 快照表；worker 对 RULE_SET 事件只做终态
                    // mark_processed）：旧快照证据复核既不可行也不再必要，
                    // PROCESSED 即终态。
                    continue;
                }
                "SUPERSEDED_BY_NEWER_GENERATION" => {}
                _ => {
                    return Err(MigrationError::Failed(format!(
                        "RuleSet projection backfill found unknown marker status {:?} for {rule_set_id}",
                        marker.status
                    )));
                }
            }
        }

        let next_generation = source_generation.checked_add(1).ok_or_else(|| {
            MigrationError::Failed(format!(
                "RuleSet projection generation overflow for {rule_set_id}"
            ))
        })?;
        let event_id = uuid::Uuid::new_v4().to_string();
        let payload = migration_backfill_payload(rule_set_id, tenant_id, next_generation);
        let payload_json = payload.to_string();
        let operation_id = migration_backfill_operation_id(rule_set_id, next_generation);

        match head.is_some() {
            true => {
                sqlx::query(
                    "UPDATE authorization_projection_head \
                     SET source_generation = ?, revoke_fence = ?, \
                         last_event_id = ?, updated_at = NOW() \
                     WHERE aggregate_type = ? AND aggregate_id = ?",
                )
                .bind(next_generation)
                .bind(revoke_fence)
                .bind(&event_id)
                .bind(ProjectionAggregate::RuleSet.as_str())
                .bind(rule_set_id)
                .execute(&mut *transaction)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "reset RuleSet projection head {rule_set_id}: {e}"
                    ))
                })?;
            }
            false => {
                sqlx::query(
                    "INSERT INTO authorization_projection_head \
                     (aggregate_type, aggregate_id, source_generation, \
                      revoke_fence, last_event_id) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(ProjectionAggregate::RuleSet.as_str())
                .bind(rule_set_id)
                .bind(next_generation)
                .bind(revoke_fence)
                .bind(&event_id)
                .execute(&mut *transaction)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "create RuleSet projection head {rule_set_id}: {e}"
                    ))
                })?;
            }
        }

        sqlx::query(
            "INSERT INTO authorization_projection_outbox \
             (event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
              sequence_number, revoke_fence, payload_json, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')",
        )
        .bind(&event_id)
        .bind(ProjectionAggregate::RuleSet.as_str())
        .bind(rule_set_id)
        .bind(tenant_id)
        .bind(EVENT_TYPE_RULE_SET_UPDATE)
        .bind(next_generation)
        .bind(next_generation)
        .bind(revoke_fence)
        .bind(&payload_json)
        .execute(&mut *transaction)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!(
                "create RuleSet projection rebuild event {rule_set_id}/{next_generation}: {e}"
            ))
        })?;

        // Source evidence and the head/outbox event share this transaction. A
        // database failure rolls back all three artifacts and leaves the head
        // non-READY for the next locked migration attempt.
        insert_migration_backfill_audit_in_tx(
            &mut transaction,
            rule_set_id,
            tenant_id,
            &event_id,
            next_generation,
            &operation_id,
            &payload_json,
        )
        .await?;
    }

    transaction
        .commit()
        .await
        .map_err(|e| MigrationError::Failed(format!("commit RuleSet projection backfill: {e}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorSchemaState {
    Missing,
    Partial,
    Complete,
}

fn classify_monitor_schema_state(present_tables: usize) -> MonitorSchemaState {
    match present_tables {
        0 => MonitorSchemaState::Missing,
        present if present == MONITOR_SCHEMA_TABLES.len() => MonitorSchemaState::Complete,
        _ => MonitorSchemaState::Partial,
    }
}

async fn inspect_monitor_schema_state(
    pool: &MySqlPool,
) -> Result<MonitorSchemaState, MigrationError> {
    let mut present_tables = 0_usize;
    for table in MONITOR_SCHEMA_TABLES {
        let table_count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_EXISTS_SQL)
                .bind(table)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!("inspect monitor schema table {table}: {e}"))
                })?,
            "inspect monitor schema table",
        )?;
        if table_count > 1 {
            return Err(MigrationError::Failed(format!(
                "monitor schema table {table} has ambiguous metadata"
            )));
        }
        present_tables += table_count as usize;
    }
    Ok(classify_monitor_schema_state(present_tables))
}

async fn validate_monitor_schema_contract(pool: &MySqlPool) -> Result<(), MigrationError> {
    for table in MONITOR_SCHEMA_TABLES {
        validate_table_contract(
            pool,
            table,
            MYSQL_SCHEMA_CHARSET,
            MYSQL_SCHEMA_COLLATION,
            Some("InnoDB"),
        )
        .await?;
    }
    validate_schema_columns(pool, MONITOR_SCHEMA_COLUMN_CONTRACT).await?;
    validate_indexes(pool, MONITOR_SCHEMA_REPAIR_INDEXES).await?;

    if !schema_columns_match(pool, MONITOR_SCHEMA_COLUMN_CONTRACT).await? {
        return Err(MigrationError::Failed(
            "monitor schema has incompatible column order or unexpected columns; refusing automatic ALTER/DROP"
                .into(),
        ));
    }
    if !schema_indexes_match(pool, MONITOR_SCHEMA_REPAIR_INDEXES).await? {
        return Err(MigrationError::Failed(
            "monitor schema has incompatible index shape or unexpected indexes; refusing automatic ALTER/DROP"
                .into(),
        ));
    }
    Ok(())
}

async fn preflight_monitor_schema_contract(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<(), MigrationError> {
    let migration = migrations
        .iter()
        .find(|migration| migration.version == MONITOR_SCHEMA_REPAIR_VERSION)
        .ok_or_else(|| {
            MigrationError::Failed(format!(
                "monitor schema migration {} is missing from the embedded migrator",
                MONITOR_SCHEMA_REPAIR_VERSION
            ))
        })?;
    let migration_pending = !applied_versions.contains(&MONITOR_SCHEMA_REPAIR_VERSION);

    match inspect_monitor_schema_state(pool).await? {
        MonitorSchemaState::Missing => {
            if !migration_pending {
                return Err(MigrationError::Failed(
                    "monitor schema migration is recorded but all canonical monitor tables are missing; refusing to replay or recreate recorded history"
                        .into(),
                ));
            }
            if !MONITOR_SCHEMA_TABLES
                .iter()
                .all(|table| migration_defines_table(migration, table))
            {
                return Err(MigrationError::Failed(
                    "pending monitor schema migration is not the exact creator for all canonical monitor tables"
                        .into(),
                ));
            }
            // The creator migration is the only permitted DDL path for an
            // entirely absent monitor schema. Its exact contract is checked
            // above; do not treat it as an ALTER/repair migration.
        }
        MonitorSchemaState::Partial => {
            return Err(MigrationError::Failed(
                "monitor schema is partially present; refusing to mix creator migration with existing monitor tables; restore the exact canonical schema explicitly before rerunning"
                    .into(),
            ));
        }
        MonitorSchemaState::Complete => {
            validate_monitor_schema_contract(pool).await?;
        }
    }
    Ok(())
}

async fn validate_incremental_projection_archive_table_contract(
    pool: &MySqlPool,
    table: &str,
    lineage_recorded: Option<bool>,
    invalidation_recorded: Option<bool>,
) -> Result<(), MigrationError> {
    let columns: Vec<SchemaColumnContract> = INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
        .iter()
        .filter(|expected| expected.table == table)
        .copied()
        .collect();
    let indexes = incremental_projection_resolved_index_contract(pool, table).await?;
    if columns.is_empty() || indexes.is_empty() {
        return Err(MigrationError::Failed(format!(
            "incremental projection archive contract has no complete definition for table {table}"
        )));
    }

    validate_table_contract(
        pool,
        table,
        MYSQL_SCHEMA_CHARSET,
        MYSQL_SCHEMA_COLLATION,
        Some("InnoDB"),
    )
    .await?;
    // Exact per-column type/null/default validation of the original creator
    // columns; the additive tail is layered on top by the resolver below.
    validate_schema_columns(pool, &columns).await?;
    validate_indexes(pool, &indexes).await?;

    // Resolved runtime contract: creator columns first, then each additive tail
    // in migration order. A missing tail is tolerated only while its migration
    // is pending; once recorded, the exact column is required.
    if !schema_columns_match(
        pool,
        &incremental_projection_resolved_column_contract(table, &columns),
    )
    .await?
    {
        validate_lineage_fence_tail_state(
            pool,
            table,
            &columns,
            lineage_recorded,
            invalidation_recorded,
        )
        .await?;
    }
    if !schema_indexes_match(pool, &indexes).await? {
        return Err(MigrationError::Failed(format!(
            "incremental projection archive table {table} has incompatible index shape or unexpected indexes; refusing automatic ALTER/DROP"
        )));
    }
    Ok(())
}

/// Build the runtime-resolved column contract for one archive table: creator
/// columns first, then additive columns in migration order. Each additive
/// migration owns its own tail; the final runtime shape includes both tails.
fn incremental_projection_resolved_column_contract(
    table: &str,
    base_columns: &[SchemaColumnContract],
) -> Vec<SchemaColumnContract> {
    let mut resolved = Vec::with_capacity(base_columns.len() + 7);
    resolved.extend_from_slice(base_columns);
    for expected in AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS {
        if expected.table == table {
            resolved.push(*expected);
        }
    }
    for expected in DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS {
        if expected.table == table {
            resolved.push(*expected);
        }
    }
    resolved
}

/// Ordered actual column names of one table (`information_schema.COLUMNS`
/// ordered by `ORDINAL_POSITION`, binary-decoded).
async fn ordered_table_column_names(
    pool: &MySqlPool,
    table: &str,
) -> Result<Vec<String>, MigrationError> {
    let rows: Vec<SchemaColumnOrderRow> = sqlx::query_as(SCHEMA_COLUMN_ORDER_SQL)
        .bind(table)
        .fetch_all(pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("inspect schema column order {table}: {e}")))?;
    rows.into_iter()
        .map(|(name, ordinal)| {
            let name = metadata_text("COLUMN_NAME", &name, table, "<order>")?;
            let _ = metadata_u64("ORDINAL_POSITION", &ordinal, table, &name)?;
            Ok(name)
        })
        .collect()
}

/// Fail-closed state resolution for additive archive tails. The creator column
/// block must remain intact; each declared tail may be absent only while its
/// migration is pending, and any present tail must have the exact declared
/// order/type/default. Unknown or reordered tail columns are never repaired.
async fn validate_lineage_fence_tail_state(
    pool: &MySqlPool,
    table: &str,
    base_columns: &[SchemaColumnContract],
    lineage_recorded: Option<bool>,
    invalidation_recorded: Option<bool>,
) -> Result<(), MigrationError> {
    let lineage_tail: Vec<&SchemaColumnContract> =
        AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS
            .iter()
            .filter(|expected| expected.table == table)
            .collect();
    let invalidation_tail: Vec<&SchemaColumnContract> =
        DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS
            .iter()
            .filter(|expected| expected.table == table)
            .collect();
    let declared_tail: Vec<&SchemaColumnContract> = lineage_tail
        .iter()
        .chain(invalidation_tail.iter())
        .copied()
        .collect();
    let actual = ordered_table_column_names(pool, table).await?;

    if actual.len() < base_columns.len()
        || actual[..base_columns.len()]
            .iter()
            .zip(base_columns)
            .any(|(name, expected)| name != expected.name)
    {
        return Err(MigrationError::Failed(format!(
            "incremental projection archive table {table} has incompatible column order or unexpected columns; refusing automatic ALTER/DROP"
        )));
    }
    let tail = &actual[base_columns.len()..];
    for (position, name) in tail.iter().enumerate() {
        let Some(expected) = declared_tail.get(position) else {
            return Err(MigrationError::Failed(format!(
                "incremental projection archive table {table} has incompatible column order or unexpected columns; refusing automatic ALTER/DROP"
            )));
        };
        if name != expected.name {
            return Err(MigrationError::Failed(format!(
                "incremental projection archive table {table} has incompatible column order or unexpected columns; refusing automatic ALTER/DROP"
            )));
        }
        validate_schema_column_exact(pool, expected).await?;
    }
    if tail.len() > declared_tail.len() {
        return Err(MigrationError::Failed(format!(
            "incremental projection archive table {table} has more columns than the resolved additive contract allows; refusing automatic ALTER/DROP"
        )));
    }
    if lineage_recorded == Some(true) && tail.len() < lineage_tail.len() {
        return Err(MigrationError::Failed(format!(
            "migration 20260827000001 is recorded but table {table} lacks its declared lineage/revoke-fence columns; refusing to replay or recreate recorded history"
        )));
    }
    if invalidation_recorded == Some(true)
        && tail.len() < lineage_tail.len() + invalidation_tail.len()
    {
        return Err(MigrationError::Failed(format!(
            "migration 20260914000001 is recorded but table {table} lacks its declared invalidation column; refusing to replay or recreate recorded history"
        )));
    }
    Ok(())
}

async fn validate_incremental_projection_archive_schema_contract(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    let lineage_recorded = Some(authorization_projection_lineage_fence_recorded(pool).await?);
    let invalidation_recorded =
        Some(delta_event_published_evidence_invalidation_recorded(pool).await?);
    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        validate_incremental_projection_archive_table_contract(
            pool,
            table,
            lineage_recorded,
            invalidation_recorded,
        )
        .await?;
    }
    Ok(())
}

/// Whether 20260827000001 is durably recorded as successfully executed.
///
/// A missing migration-history table means no explicit migration run ever
/// happened yet, so the version is simply not recorded (`false`); absent rows
/// must never be invented from schema shape alone.
async fn authorization_projection_lineage_fence_recorded(
    pool: &MySqlPool,
) -> Result<bool, MigrationError> {
    if !migration_history_table_exists(pool).await? {
        return Ok(false);
    }
    Ok(recorded_successful_versions(pool)
        .await?
        .contains(&AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION))
}

async fn delta_event_published_evidence_invalidation_recorded(
    pool: &MySqlPool,
) -> Result<bool, MigrationError> {
    if !migration_history_table_exists(pool).await? {
        return Ok(false);
    }
    Ok(recorded_successful_versions(pool)
        .await?
        .contains(&DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION))
}

async fn migration_history_table_exists(pool: &MySqlPool) -> Result<bool, MigrationError> {
    let value: Vec<u8> = sqlx::query_scalar(SCHEMA_TABLE_EXISTS_SQL)
        .bind("_sqlx_migrations")
        .fetch_one(pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("inspect migration history table: {e}")))?;
    Ok(metadata_count(value, "inspect migration history table")? == 1)
}

async fn preflight_incremental_projection_archive_schema_contract(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let migration = migrations
        .iter()
        .find(|migration| migration.version == INCREMENTAL_PROJECTION_ARCHIVE_VERSION)
        .ok_or_else(|| {
            MigrationError::Failed(format!(
                "incremental projection archive migration {} is missing from the embedded migrator",
                INCREMENTAL_PROJECTION_ARCHIVE_VERSION
            ))
        })?;
    let removal_migration = migrations.iter()
        .find(|migration| migration.version == REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION)
        .filter(|migration| exact_migration_artifact_contract(migration).is_some())
        .ok_or_else(|| MigrationError::Failed("redundant archive index removal migration is missing or unverified in the execution plan".to_owned()))?;
    if applied_versions.contains(&removal_migration.version)
        && !recorded_post_creator_index_versions(pool)
            .await?
            .contains(&removal_migration.version)
    {
        return Err(MigrationError::Failed(
            "redundant archive index removal history disagrees with the execution plan".to_owned(),
        ));
    }
    let migration_pending = !applied_versions.contains(&INCREMENTAL_PROJECTION_ARCHIVE_VERSION);
    let lineage_recorded = authorization_projection_lineage_fence_recorded(pool).await?;
    let invalidation_recorded = delta_event_published_evidence_invalidation_recorded(pool).await?;
    let mut complete = true;

    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        if !schema_table_exists(pool, table).await? {
            complete = false;
            if !migration_pending {
                return Err(MigrationError::Failed(format!(
                    "incremental projection archive migration is recorded but table {table} is missing; refusing to replay or recreate recorded history"
                )));
            }
            if !migration_defines_table(migration, table) {
                return Err(MigrationError::Failed(format!(
                    "pending incremental projection archive migration does not define creator table {table}"
                )));
            }
            for expected in INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS
                .iter()
                .filter(|expected| expected.table == *table)
            {
                if !migration_defines_column(migration, table, expected.name) {
                    return Err(MigrationError::Failed(format!(
                        "pending incremental projection archive migration does not define {table}.{}",
                        expected.name
                    )));
                }
            }
            for (index_table, index, columns, unique) in INCREMENTAL_PROJECTION_ARCHIVE_INDEXES
                .iter()
                .filter(|(index_table, _, _, _)| *index_table == *table)
            {
                if !pending_migration_defines_index(migration, index_table, index, columns, *unique)
                {
                    return Err(MigrationError::Failed(format!(
                        "pending incremental projection archive migration does not define {table}.{index}"
                    )));
                }
            }
        } else {
            // A partially executed creator migration may be retried, but any
            // table that already exists must already be the exact Rust contract.
            // CREATE IF NOT EXISTS cannot repair drift and must not hide it.
            validate_incremental_projection_archive_table_contract(
                pool,
                table,
                Some(lineage_recorded),
                Some(invalidation_recorded),
            )
            .await?;
        }
    }

    // The additive lineage/revoke-fence migration: when it is still pending it
    // must be able to define every declared tail column on the four affected
    // tables; once recorded, a missing column is handled by the exact
    // table-contract validator above (fail-closed, never replayed). The
    // `complete` flag deliberately tracks only creator-table presence so the
    // generic post-loop validator keeps running exactly as before; its
    // archive section applies the same resolved-tail semantics.
    let lineage_migration = migrations
        .iter()
        .find(|migration| migration.version == AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION)
        .ok_or_else(|| {
            MigrationError::Failed(format!(
                "authorization projection lineage fence migration {} is missing from the embedded migrator",
                AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION
            ))
        })?;
    if !applied_versions.contains(&AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION)
        && !authorization_projection_lineage_fence_recorded(pool).await?
    {
        for expected in AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS {
            if !migration_defines_existing_column(lineage_migration, expected.table, expected.name)
            {
                return Err(MigrationError::Failed(format!(
                    "pending authorization projection lineage fence migration does not define {}.{}",
                    expected.table, expected.name
                )));
            }
        }
    }

    // The additive invalidation migration follows the lineage migration. It
    // owns one tail column on authorization_delta_event and is tolerated only
    // while its own migration remains pending.
    let invalidation_migration = migrations
        .iter()
        .find(|migration| migration.version == DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION)
        .ok_or_else(|| {
            MigrationError::Failed(format!(
                "delta event evidence-invalidation migration {} is missing from the embedded migrator",
                DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION
            ))
        })?;
    if !applied_versions.contains(&DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION)
        && !delta_event_published_evidence_invalidation_recorded(pool).await?
    {
        for expected in DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS {
            if !migration_defines_existing_column(
                invalidation_migration,
                expected.table,
                expected.name,
            ) {
                return Err(MigrationError::Failed(format!(
                    "pending delta event evidence-invalidation migration does not define {}.{}",
                    expected.table, expected.name
                )));
            }
        }
    }
    Ok(complete)
}

async fn validate_archive_index_removal_postcondition(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    let recorded = recorded_post_creator_index_versions(pool).await?;
    if !recorded.contains(&REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION) {
        return Err(MigrationError::RecoveryRequired {
            reason:
                "redundant archive index removal has no successful history row after SQLx execution"
                    .to_owned(),
        });
    }
    for (_, table, _) in POST_CREATOR_INDEX_REMOVALS {
        validate_incremental_projection_archive_table_contract(pool, table, None, None)
            .await
            .map_err(|error| MigrationError::RecoveryRequired {
                reason: format!(
                    "redundant archive index removal postcondition failed for {table}: {error}"
                ),
            })?;
    }
    Ok(())
}

async fn validate_cross_city_table_contract(
    pool: &MySqlPool,
    table: &str,
) -> Result<(), MigrationError> {
    let columns: Vec<SchemaColumnContract> = CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
        .iter()
        .filter(|expected| expected.table == table)
        .copied()
        .collect();
    let indexes: Vec<(&str, &str, &[&str], bool)> = CROSS_CITY_SCHEMA_INDEXES
        .iter()
        .filter(|(index_table, _, _, _)| *index_table == table)
        .copied()
        .collect();
    if columns.is_empty() || indexes.is_empty() {
        return Err(MigrationError::Failed(format!(
            "cross-city schema contract has no complete definition for table {table}"
        )));
    }

    validate_table_contract(
        pool,
        table,
        MYSQL_SCHEMA_CHARSET,
        MYSQL_SCHEMA_COLLATION,
        Some("InnoDB"),
    )
    .await?;
    validate_schema_columns(pool, &columns).await?;
    validate_indexes(pool, &indexes).await?;
    // Exact whole-shape check on top of the per-column/per-index validation:
    // the live table must match the creator contract exhaustively and in
    // declared order - extra unknown columns, extra unexpected indexes,
    // reordered columns, or any shape drift refuse outright. CREATE IF NOT
    // EXISTS cannot repair drift, so no automatic ALTER/DROP is attempted
    // here; recovery is an explicit, reviewed migration-recovery action.
    if !schema_columns_match(pool, &columns).await? {
        return Err(MigrationError::Failed(format!(
            "cross-city table {table} has incompatible or extra column drift (unknown columns, unexpected order, or shape drift); refusing automatic ALTER/DROP"
        )));
    }
    if !schema_indexes_match(pool, &indexes).await? {
        return Err(MigrationError::Failed(format!(
            "cross-city table {table} has incompatible index shape or unexpected extra indexes; refusing automatic ALTER/DROP"
        )));
    }
    Ok(())
}

async fn validate_cross_city_schema_contract(pool: &MySqlPool) -> Result<(), MigrationError> {
    for table in CROSS_CITY_SCHEMA_TABLES {
        validate_cross_city_table_contract(pool, table).await?;
    }
    Ok(())
}

/// Validate the opt-in Chat runtime's pinned durable send-intent tables.
/// This is a read-only gate and never creates or repairs missing proof tables.
pub async fn validate_chat_delivery_intent_schema(pool: &MySqlPool) -> Result<(), MigrationError> {
    for table in CHAT_DELIVERY_INTENT_TABLES {
        validate_chat_delivery_intent_table_contract(pool, table).await?;
    }
    Ok(())
}

async fn validate_chat_delivery_intent_table_contract(
    pool: &MySqlPool,
    table: &str,
) -> Result<(), MigrationError> {
    let columns: Vec<SchemaColumnContract> = CHAT_DELIVERY_INTENT_COLUMNS
        .iter()
        .filter(|expected| expected.table == table)
        .copied()
        .collect();
    let indexes: Vec<(&str, &str, &[&str], bool)> = CHAT_DELIVERY_INTENT_INDEXES
        .iter()
        .filter(|(index_table, _, _, _)| *index_table == table)
        .copied()
        .collect();
    if columns.is_empty() || indexes.is_empty() {
        return Err(MigrationError::Failed(format!(
            "Chat delivery-intent contract has no complete definition for table {table}"
        )));
    }
    validate_table_contract(
        pool,
        table,
        MYSQL_SCHEMA_CHARSET,
        MYSQL_SCHEMA_COLLATION,
        Some("InnoDB"),
    )
    .await?;
    validate_schema_columns(pool, &columns).await?;
    validate_indexes(pool, &indexes).await?;
    if !schema_columns_match(pool, &columns).await? || !schema_indexes_match(pool, &indexes).await?
    {
        return Err(MigrationError::Failed(format!(
            "Chat delivery-intent table {table} has incompatible extra or reordered metadata; refusing automatic ALTER/DROP"
        )));
    }
    Ok(())
}

async fn validate_cross_city_runtime_proof_table_contract(
    pool: &MySqlPool,
    table: &str,
) -> Result<(), MigrationError> {
    let columns: Vec<SchemaColumnContract> = CROSS_CITY_RUNTIME_PROOF_COLUMNS
        .iter()
        .filter(|expected| expected.table == table)
        .copied()
        .collect();
    let indexes: Vec<(&str, &str, &[&str], bool)> = CROSS_CITY_RUNTIME_PROOF_INDEXES
        .iter()
        .filter(|(index_table, _, _, _)| *index_table == table)
        .copied()
        .collect();
    if columns.is_empty() || indexes.is_empty() {
        return Err(MigrationError::Failed(format!(
            "cross-city runtime proof contract has no complete definition for table {table}"
        )));
    }
    validate_table_contract(
        pool,
        table,
        MYSQL_SCHEMA_CHARSET,
        MYSQL_SCHEMA_COLLATION,
        Some("InnoDB"),
    )
    .await?;
    validate_schema_columns(pool, &columns).await?;
    validate_indexes(pool, &indexes).await?;
    if !schema_columns_match(pool, &columns).await? {
        return Err(MigrationError::Failed(format!(
            "cross-city runtime proof table {table} has incompatible or extra column drift; refusing automatic ALTER/DROP"
        )));
    }
    if !schema_indexes_match(pool, &indexes).await? {
        return Err(MigrationError::Failed(format!(
            "cross-city runtime proof table {table} has incompatible or extra index drift; refusing automatic ALTER/DROP"
        )));
    }
    Ok(())
}

/// Enabled-only cross-city schema and durable authority preflight. Default-off
/// deployments remain unaffected; an enabled runtime calls this before it loads
/// keys, scopes, or starts workers. A flag outside {0,1}, an empty authority
/// registry, or missing proof evidence is a startup refusal.
pub async fn validate_cross_city_runtime_schema(pool: &MySqlPool) -> Result<(), MigrationError> {
    // This public validator is called only after the default-off runtime gate
    // has resolved to Enabled. Keep both durable creator slices together here;
    // ordinary service schema validation must not touch either optional slice.
    validate_cross_city_schema_contract(pool).await?;
    for table in CROSS_CITY_RUNTIME_PROOF_TABLES {
        validate_cross_city_runtime_proof_table_contract(pool, table).await?;
    }

    validate_cross_city_authority_scope_rows(pool).await?;
    Ok(())
}

async fn validate_cross_city_authority_scope_rows(pool: &MySqlPool) -> Result<(), MigrationError> {
    let invalid_flag = sqlx::query(
        "SELECT 1 FROM authorization_cross_city_authority_scope \
         WHERE authoritative NOT IN (0, 1) OR authoritative IS NULL LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        MigrationError::Failed(format!(
            "validate cross-city authority-scope row flags: {error}"
        ))
    })?;
    if invalid_flag.is_some() {
        return Err(MigrationError::Failed(
            "cross-city authority scope contains an authoritative flag outside {0,1}".into(),
        ));
    }
    let authoritative_row = sqlx::query(
        "SELECT 1 FROM authorization_cross_city_authority_scope \
         WHERE authoritative = 1 LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        MigrationError::Failed(format!(
            "inspect cross-city authoritative scope registry: {error}"
        ))
    })?;
    if authoritative_row.is_none() {
        return Err(MigrationError::Failed(
            "cross-city runtime has no explicitly authoritative scope rows".into(),
        ));
    }
    Ok(())
}

/// Cross-city creator preflight (fail-closed, same shape as the incremental
/// projection archive preflight): while 20260831000002 is pending, every
/// missing table must be defined by the pending migration (table, columns,
/// indexes); any table that already exists must already match the exact Rust
/// contract because CREATE IF NOT EXISTS cannot repair drift. Returns whether
/// the creator schema is fully present.
async fn preflight_cross_city_schema_contract(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let migration = migrations
        .iter()
        .find(|migration| migration.version == CROSS_CITY_SCHEMA_VERSION)
        .ok_or_else(|| {
            MigrationError::Failed(format!(
                "cross-city schema migration {} is missing from the embedded migrator",
                CROSS_CITY_SCHEMA_VERSION
            ))
        })?;
    let migration_pending = !applied_versions.contains(&CROSS_CITY_SCHEMA_VERSION);
    let mut complete = true;

    for table in CROSS_CITY_SCHEMA_TABLES {
        if !schema_table_exists(pool, table).await? {
            complete = false;
            if !migration_pending {
                return Err(MigrationError::Failed(format!(
                    "cross-city schema migration is recorded but table {table} is missing; refusing to replay or recreate recorded history"
                )));
            }
            if !migration_defines_table(migration, table) {
                return Err(MigrationError::Failed(format!(
                    "pending cross-city schema migration does not define creator table {table}"
                )));
            }
            for expected in CROSS_CITY_SCHEMA_COLUMN_CONTRACTS
                .iter()
                .filter(|expected| expected.table == *table)
            {
                if !migration_defines_column(migration, table, expected.name) {
                    return Err(MigrationError::Failed(format!(
                        "pending cross-city schema migration does not define {table}.{}",
                        expected.name
                    )));
                }
            }
            for (index_table, index, columns, unique) in CROSS_CITY_SCHEMA_INDEXES
                .iter()
                .filter(|(index_table, _, _, _)| *index_table == *table)
            {
                if !pending_migration_defines_index(migration, index_table, index, columns, *unique)
                {
                    return Err(MigrationError::Failed(format!(
                        "pending cross-city schema migration does not define {table}.{index}"
                    )));
                }
            }
        } else {
            // A partially executed creator migration may be retried, but any
            // table that already exists must already be the exact Rust contract.
            // CREATE IF NOT EXISTS cannot repair drift and must not hide it.
            validate_cross_city_table_contract(pool, table).await?;
        }
    }

    Ok(complete)
}

async fn preflight_schema_contract_before_sqlx(
    pool: &MySqlPool,
    applied_versions: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<(), MigrationError> {
    preflight_standby_migration_gate(pool, applied_versions, migrations).await?;
    let review_schema_complete =
        preflight_review_schema_contracts(pool, applied_versions, migrations).await?;
    preflight_monitor_schema_contract(pool, applied_versions, migrations).await?;
    let incremental_archive_complete = preflight_incremental_projection_archive_schema_contract(
        pool,
        applied_versions,
        migrations,
    )
    .await?;
    let cross_city_schema_complete =
        preflight_cross_city_schema_contract(pool, applied_versions, migrations).await?;
    let pending_migrations: Vec<&Migration> = migrations
        .iter()
        .filter(|migration| !applied_versions.contains(&migration.version))
        .collect();

    let mut all_required_artifacts_present =
        incremental_archive_complete && cross_city_schema_complete && review_schema_complete;
    let mut absent_tables = HashSet::new();
    for (table, columns) in REQUIRED_SCHEMA_COLUMNS {
        let table_exists = schema_table_exists(pool, table).await?;
        if !table_exists {
            all_required_artifacts_present = false;
            absent_tables.insert(*table);
            if !pending_migrations
                .iter()
                .any(|migration| migration_defines_table(migration, table))
            {
                return Err(MigrationError::Failed(format!(
                    "schema contract preflight found missing table {table} with no pending migration that can create it"
                )));
            }
            for column in *columns {
                if !pending_migrations
                    .iter()
                    .any(|migration| pending_migration_defines_column(migration, table, column))
                {
                    return Err(MigrationError::Failed(format!(
                        "schema contract preflight found missing table {table} whose pending migrations do not define column {column}"
                    )));
                }
            }
            for (index_table, index, columns, unique) in REQUIRED_SCHEMA_INDEXES
                .iter()
                .filter(|(index_table, _, _, _)| *index_table == *table)
            {
                if !pending_migrations.iter().any(|migration| {
                    pending_migration_defines_index(migration, index_table, index, columns, *unique)
                }) {
                    return Err(MigrationError::Failed(format!(
                        "schema contract preflight found missing table {table} whose pending migrations do not define index {index}"
                    )));
                }
            }
            continue;
        }

        for column in *columns {
            if schema_column_exists(pool, table, column).await? {
                if let Some(expected) = rule_set_projection_strict_column_contract(table, column) {
                    validate_schema_column_exact(pool, expected).await?;
                } else if *table == AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT.table
                    && *column == AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT.name
                {
                    validate_schema_column_exact(
                        pool,
                        &AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT,
                    )
                    .await?;
                }
                continue;
            }
            all_required_artifacts_present = false;
            if !pending_migrations
                .iter()
                .any(|migration| migration_defines_existing_column(migration, table, column))
            {
                return Err(MigrationError::Failed(format!(
                    "schema contract preflight found missing column {table}.{column} with no pending migration that can create it"
                )));
            }
        }
    }

    for (table, index, columns, unique) in REQUIRED_SCHEMA_INDEXES {
        if schema_index_exists(pool, table, index).await? {
            validate_indexes(pool, &[(*table, *index, *columns, *unique)]).await?;
            continue;
        }
        all_required_artifacts_present = false;
        if !pending_migrations.iter().any(|migration| {
            pending_index_satisfies_preflight(
                &absent_tables,
                migration,
                table,
                index,
                columns,
                *unique,
            )
        }) {
            return Err(MigrationError::Failed(format!(
                "schema contract preflight found missing index {table}.{index} with no pending migration that can create it"
            )));
        }
    }

    // When all required artifacts already exist, run the exact validator before
    // SQLx. This catches incompatible metadata before SQLx can record a new
    // success row. A pending migration may still add missing artifacts below;
    // its pinned SQL and the final validator then cover that additive path.
    if all_required_artifacts_present {
        validate_schema_contract(pool).await?;
    }
    Ok(())
}

fn migration_matches_known_source(migration: &Migration) -> bool {
    let Some(known) = MIGRATOR
        .migrations
        .iter()
        .find(|known| known.version == migration.version)
    else {
        return false;
    };

    // Artifact ownership is only accepted for the exact embedded migration
    // body and SQLx checksum. Historical MySQL-8 rewrites are derived from the
    // checksum-pinned source contract. Newly registered 20261003 review-slice
    // sources are also pinned to canonical LF SHA-384 so the helper remains
    // closed even while sibling files arrive on the branch.
    if migration.checksum.as_ref() != known.checksum.as_ref() {
        return false;
    }
    if migration.sql.as_ref() == known.sql.as_ref() {
        if REVIEW_SLICE_MIGRATION_VERSIONS.contains(&migration.version) {
            return EXACT_MIGRATION_ARTIFACT_CONTRACTS
                .iter()
                .find(|contract| contract.version == migration.version)
                .is_some_and(|contract| {
                    canonical_sha384_hex(migration.sql.as_bytes()) == contract.source_sha384
                });
        }
        if migration.version == CROSS_CITY_RUNTIME_PROOF_VERSION {
            return canonical_sha384_hex(migration.sql.as_bytes())
                == CROSS_CITY_RUNTIME_PROOF_SQL_SHA384;
        }
        if migration.version == LOCAL_SCOPE_SEQUENCE_VERSION {
            return migration.sql.as_ref() == LOCAL_SCOPE_SEQUENCE_MIGRATION_SQL;
        }
        return true;
    }

    historical_migration_compatibility(migration.version)
        .and_then(|_| historical_mysql8_compatible_sql(known).ok())
        .is_some_and(|compatible| compatible.as_ref() == migration.sql.as_ref())
}

fn normalized_sql_fragment(fragment: &str) -> String {
    let mut normalized = String::with_capacity(fragment.len());
    let mut pending_space = false;
    for character in fragment.chars() {
        if character.is_ascii_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        if character != '`' {
            normalized.push(character.to_ascii_uppercase());
        }
    }
    normalized
}

fn sql_statements(sql: &str) -> Option<Vec<String>> {
    let bytes = sql.as_bytes();
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut index = 0;
    let mut quote: Option<u8> = None;
    let mut block_comment = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if block_comment {
            if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if let Some(delimiter) = quote {
            current.push(byte as char);
            if byte == b'\\' {
                if let Some(escaped) = bytes.get(index + 1) {
                    current.push(*escaped as char);
                    index += 2;
                    continue;
                }
                return None;
            }
            if byte == delimiter {
                if bytes.get(index + 1) == Some(&delimiter) {
                    current.push(delimiter as char);
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }

        if byte == b'\'' || byte == b'"' || byte == b'`' {
            quote = Some(byte);
            current.push(byte as char);
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            block_comment = true;
            index += 2;
            continue;
        }
        if byte == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'-'
            && bytes.get(index + 1) == Some(&b'-')
            && bytes
                .get(index + 2)
                .is_some_and(|next| next.is_ascii_whitespace())
        {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b';' {
            if !current.trim().is_empty() {
                statements.push(std::mem::take(&mut current));
            }
            index += 1;
            continue;
        }
        current.push(byte as char);
        index += 1;
    }

    if quote.is_some() || block_comment {
        return None;
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    Some(statements)
}

fn split_top_level_items(fragment: &str) -> Option<Vec<&str>> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut depth = 0_u32;
    let mut quote: Option<char> = None;
    let characters: Vec<char> = fragment.chars().collect();
    let mut index = 0;

    while index < characters.len() {
        let character = characters[index];
        if let Some(delimiter) = quote {
            if character == '\\' {
                index += 2;
                continue;
            }
            if character == delimiter {
                if characters.get(index + 1) == Some(&delimiter) {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '(' {
            depth += 1;
        } else if character == ')' {
            if depth == 0 {
                return None;
            }
            depth -= 1;
        } else if character == ',' && depth == 0 {
            items.push(&fragment[start..character_indices(fragment, index)]);
            start = character_indices(fragment, index) + character.len_utf8();
        }
        index += 1;
    }
    if quote.is_some() || depth != 0 {
        return None;
    }
    items.push(&fragment[start..]);
    Some(items)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationArtifactKind {
    Table,
    CreateColumn,
    CreateIndex,
    AddColumn,
    AddIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationArtifact {
    kind: MigrationArtifactKind,
    table: String,
    name: String,
    columns: Vec<String>,
    unique: bool,
}

#[derive(Debug, Clone, Copy)]
struct ExactMigrationArtifactContract {
    version: i64,
    source_sha384: &'static str,
    supports_existing_artifacts: bool,
    tables: &'static [&'static str],
    columns: &'static [(&'static str, &'static str)],
    indexes: &'static [(&'static str, &'static str, &'static [&'static str], bool)],
}

const AUDIT_QUARANTINE_CREATOR_COLUMNS: &[(&str, &str)] = &[
    ("audit_quarantine", "id"),
    ("audit_quarantine", "identity_key"),
    ("audit_quarantine", "message_id"),
    ("audit_quarantine", "message_type"),
    ("audit_quarantine", "raw_payload"),
    ("audit_quarantine", "source_queue"),
    ("audit_quarantine", "source_exchange"),
    ("audit_quarantine", "source_routing_key"),
    ("audit_quarantine", "retry_count"),
    ("audit_quarantine", "attempts"),
    ("audit_quarantine", "replay_attempts"),
    ("audit_quarantine", "failure_reason"),
    ("audit_quarantine", "status"),
    ("audit_quarantine", "replay_lease_owner"),
    ("audit_quarantine", "replay_lease_token"),
    ("audit_quarantine", "replay_lease_expires_at"),
    ("audit_quarantine", "first_failed_at"),
    ("audit_quarantine", "last_failed_at"),
    ("audit_quarantine", "quarantined_at"),
    ("audit_quarantine", "replayed_at"),
];

const AUDIT_QUARANTINE_HARDENING_COLUMNS: &[(&str, &str)] = &[
    ("audit_quarantine", "replay_lease_token_hash"),
    ("audit_quarantine", "replay_lease_generation"),
    ("audit_quarantine", "replay_operation_id_hash"),
    ("audit_quarantine", "replay_requested_by"),
    ("audit_quarantine", "replay_requested_at"),
];

const AUDIT_QUARANTINE_CREATOR_STATUS_INDEX_COLUMNS: &[&str] = &["status", "quarantined_at", "id"];
const AUDIT_QUARANTINE_CREATOR_LEASE_INDEX_COLUMNS: &[&str] =
    &["status", "replay_lease_expires_at", "id"];
const AUDIT_QUARANTINE_HARDENING_REQUEST_INDEX_COLUMNS: &[&str] =
    &["status", "replay_requested_at", "id"];

const RUST_RUNTIME_CREATOR_COLUMNS: &[(&str, &str)] = &[
    ("audit_log", "id"),
    ("audit_log", "user_id"),
    ("audit_log", "action"),
    ("audit_log", "resource"),
    ("audit_log", "decision"),
    ("audit_log", "reason"),
    ("audit_log", "card_id"),
    ("audit_log", "detail"),
    ("audit_log", "created_at"),
    ("audit_log", "event_type"),
    ("audit_log", "source_ip"),
    ("audit_log", "request_id"),
    ("audit_log", "domain_id"),
    ("audit_log", "tenant_id"),
    ("mq_idempotent_log", "id"),
    ("mq_idempotent_log", "message_type"),
    ("mq_idempotent_log", "message_id"),
    ("mq_idempotent_log", "status"),
    ("mq_idempotent_log", "created_at"),
    ("pending_compensation", "id"),
    ("pending_compensation", "entity_id"),
    ("pending_compensation", "op_type"),
    ("pending_compensation", "error_msg"),
    ("pending_compensation", "status"),
    ("pending_compensation", "retry_count"),
    ("pending_compensation", "created_at"),
    ("pending_compensation", "updated_at"),
];

const RUST_RUNTIME_REPAIR_COLUMNS: &[(&str, &str)] = &[
    ("audit_log", "user_id"),
    ("audit_log", "action"),
    ("audit_log", "resource"),
    ("audit_log", "decision"),
    ("audit_log", "reason"),
    ("audit_log", "card_id"),
    ("audit_log", "detail"),
    ("audit_log", "created_at"),
    ("audit_log", "event_type"),
    ("audit_log", "source_ip"),
    ("audit_log", "request_id"),
    ("audit_log", "domain_id"),
    ("audit_log", "tenant_id"),
    ("mq_idempotent_log", "message_type"),
    ("mq_idempotent_log", "message_id"),
    ("mq_idempotent_log", "status"),
    ("mq_idempotent_log", "created_at"),
    ("pending_compensation", "entity_id"),
    ("pending_compensation", "op_type"),
    ("pending_compensation", "error_msg"),
    ("pending_compensation", "status"),
    ("pending_compensation", "retry_count"),
    ("pending_compensation", "created_at"),
    ("pending_compensation", "updated_at"),
];

const RUST_RUNTIME_CREATOR_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("audit_log", "PRIMARY", &["id"], true),
    ("audit_log", "idx_al_user", &["user_id"], false),
    ("audit_log", "idx_al_action", &["action"], false),
    ("audit_log", "idx_al_created", &["created_at"], false),
    ("audit_log", "idx_al_event_type", &["event_type"], false),
    ("audit_log", "idx_al_tenant", &["tenant_id"], false),
    ("audit_log", "idx_al_card", &["card_id"], false),
    ("audit_log", "idx_al_decision", &["decision"], false),
    ("mq_idempotent_log", "PRIMARY", &["id"], true),
    (
        "mq_idempotent_log",
        "uk_mq_msg",
        &["message_type", "message_id"],
        true,
    ),
    ("pending_compensation", "PRIMARY", &["id"], true),
    ("pending_compensation", "idx_status", &["status"], false),
    ("pending_compensation", "idx_entity", &["entity_id"], false),
];

const RUST_RUNTIME_REPAIR_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("audit_log", "idx_al_user", &["user_id"], false),
    ("audit_log", "idx_al_action", &["action"], false),
    ("audit_log", "idx_al_created", &["created_at"], false),
    ("audit_log", "idx_al_event_type", &["event_type"], false),
    ("audit_log", "idx_al_tenant", &["tenant_id"], false),
    ("audit_log", "idx_al_card", &["card_id"], false),
    ("audit_log", "idx_al_decision", &["decision"], false),
    (
        "mq_idempotent_log",
        "uk_mq_msg",
        &["message_type", "message_id"],
        true,
    ),
    ("pending_compensation", "idx_status", &["status"], false),
    ("pending_compensation", "idx_entity", &["entity_id"], false),
];

const AUDIT_QUARANTINE_CREATOR_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("audit_quarantine", "PRIMARY", &["id"], true),
    (
        "audit_quarantine",
        "uk_aq_identity_key",
        &["identity_key"],
        true,
    ),
    (
        "audit_quarantine",
        "idx_aq_status",
        AUDIT_QUARANTINE_CREATOR_STATUS_INDEX_COLUMNS,
        false,
    ),
    (
        "audit_quarantine",
        "idx_aq_replay_lease",
        AUDIT_QUARANTINE_CREATOR_LEASE_INDEX_COLUMNS,
        false,
    ),
];

const AUDIT_QUARANTINE_HARDENING_INDEXES: &[(&str, &str, &[&str], bool)] = &[(
    "audit_quarantine",
    "idx_aq_replay_request",
    AUDIT_QUARANTINE_HARDENING_REQUEST_INDEX_COLUMNS,
    false,
)];

const MONITOR_SCHEMA_REPAIR_COLUMNS: &[(&str, &str)] = &[
    ("alert_rule", "id"),
    ("alert_rule", "name"),
    ("alert_rule", "metric"),
    ("alert_rule", "condition_op"),
    ("alert_rule", "threshold"),
    ("alert_rule", "duration_seconds"),
    ("alert_rule", "severity"),
    ("alert_rule", "enabled"),
    ("alert_rule", "created_at"),
    ("notification_channel", "id"),
    ("notification_channel", "name"),
    ("notification_channel", "channel_type"),
    ("notification_channel", "config"),
    ("notification_channel", "enabled"),
    ("notification_channel", "created_at"),
    ("monitor_metric_snapshot", "id"),
    ("monitor_metric_snapshot", "service_name"),
    ("monitor_metric_snapshot", "metric_type"),
    ("monitor_metric_snapshot", "metric_value"),
    ("monitor_metric_snapshot", "collected_at"),
    ("monitor_metric_snapshot", "created_at"),
    ("monitor_alert_history", "id"),
    ("monitor_alert_history", "rule_id"),
    ("monitor_alert_history", "rule_name"),
    ("monitor_alert_history", "metric_type"),
    ("monitor_alert_history", "actual_value"),
    ("monitor_alert_history", "severity"),
    ("monitor_alert_history", "status"),
    ("monitor_alert_history", "triggered_at"),
    ("monitor_alert_history", "resolved_at"),
    ("monitor_alert_history", "created_at"),
    ("monitor_activity_log", "id"),
    ("monitor_activity_log", "event_type"),
    ("monitor_activity_log", "title"),
    ("monitor_activity_log", "detail"),
    ("monitor_activity_log", "level"),
    ("monitor_activity_log", "source_service"),
    ("monitor_activity_log", "occurred_at"),
    ("monitor_activity_log", "created_at"),
];

const MONITOR_SCHEMA_REPAIR_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("alert_rule", "PRIMARY", &["id"], true),
    ("notification_channel", "PRIMARY", &["id"], true),
    ("monitor_metric_snapshot", "PRIMARY", &["id"], true),
    (
        "monitor_metric_snapshot",
        "idx_mms_service",
        &["service_name"],
        false,
    ),
    (
        "monitor_metric_snapshot",
        "idx_mms_type",
        &["metric_type"],
        false,
    ),
    (
        "monitor_metric_snapshot",
        "idx_mms_collected",
        &["collected_at"],
        false,
    ),
    (
        "monitor_metric_snapshot",
        "idx_mms_service_type",
        &["service_name", "metric_type"],
        false,
    ),
    ("monitor_alert_history", "PRIMARY", &["id"], true),
    ("monitor_alert_history", "idx_mah_rule", &["rule_id"], false),
    (
        "monitor_alert_history",
        "idx_mah_status",
        &["status"],
        false,
    ),
    (
        "monitor_alert_history",
        "idx_mah_severity",
        &["severity"],
        false,
    ),
    (
        "monitor_alert_history",
        "idx_mah_triggered",
        &["triggered_at"],
        false,
    ),
    ("monitor_activity_log", "PRIMARY", &["id"], true),
    (
        "monitor_activity_log",
        "idx_mal_event_type",
        &["event_type"],
        false,
    ),
    ("monitor_activity_log", "idx_mal_level", &["level"], false),
    (
        "monitor_activity_log",
        "idx_mal_source",
        &["source_service"],
        false,
    ),
    (
        "monitor_activity_log",
        "idx_mal_occurred",
        &["occurred_at"],
        false,
    ),
];

const RULE_SET_PROJECTION_REPAIR_COLUMNS: &[(&str, &str)] =
    &[("rule_set_snapshot", "projection_generation")];

const SNAPSHOT_VALIDITY_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("permission_rule_snapshot", "valid_from"),
    ("permission_rule_snapshot", "valid_to"),
    ("rule_set_snapshot", "valid_from"),
    ("rule_set_snapshot", "valid_to"),
];

const RULE_SET_SNAPSHOT_MANIFEST_COLUMNS: &[(&str, &str)] = &[
    ("rule_set_snapshot_manifest", "rule_set_id"),
    ("rule_set_snapshot_manifest", "projection_generation"),
    ("rule_set_snapshot_manifest", "status"),
    ("rule_set_snapshot_manifest", "tenant_id"),
    ("rule_set_snapshot_manifest", "event_id"),
    ("rule_set_snapshot_manifest", "operation_id"),
    ("rule_set_snapshot_manifest", "committed_at"),
];

const RULE_SET_SNAPSHOT_MANIFEST_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "rule_set_snapshot_manifest",
        "PRIMARY",
        &["rule_set_id", "projection_generation"],
        true,
    ),
    (
        "rule_set_snapshot_manifest",
        "idx_rssm_event",
        &["event_id"],
        false,
    ),
    (
        "rule_set_snapshot_manifest",
        "idx_rssm_operation",
        &["operation_id"],
        false,
    ),
];

const INCREMENTAL_PROJECTION_ARCHIVE_TABLES: &[&str] = &[
    "authorization_grant_revision",
    "authorization_delta_event",
    "authorization_impact_plan",
    "authorization_impact_plan_item",
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
    "authorization_archive_outbox",
    "authorization_archive_manifest",
];

const INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS: &[(&str, &str)] = &[
    ("authorization_grant_revision", "revision_id"),
    ("authorization_grant_revision", "tenant_id"),
    ("authorization_grant_revision", "card_id"),
    ("authorization_grant_revision", "aggregate_type"),
    ("authorization_grant_revision", "aggregate_id"),
    ("authorization_grant_revision", "grant_id"),
    ("authorization_grant_revision", "revision_no"),
    ("authorization_grant_revision", "operation_id"),
    ("authorization_grant_revision", "event_id"),
    ("authorization_grant_revision", "status"),
    ("authorization_grant_revision", "is_tombstone"),
    ("authorization_grant_revision", "grant_payload"),
    ("authorization_grant_revision", "semantic_hash"),
    ("authorization_grant_revision", "dependency_hash"),
    ("authorization_grant_revision", "compiler_version"),
    ("authorization_grant_revision", "created_at"),
    ("authorization_grant_revision", "updated_at"),
    ("authorization_delta_event", "delta_event_id"),
    ("authorization_delta_event", "tenant_id"),
    ("authorization_delta_event", "card_id"),
    ("authorization_delta_event", "aggregate_type"),
    ("authorization_delta_event", "aggregate_id"),
    ("authorization_delta_event", "grant_id"),
    ("authorization_delta_event", "event_id"),
    ("authorization_delta_event", "operation_id"),
    ("authorization_delta_event", "event_type"),
    ("authorization_delta_event", "base_version"),
    ("authorization_delta_event", "target_version"),
    ("authorization_delta_event", "source_generation"),
    ("authorization_delta_event", "revoke_fence"),
    ("authorization_delta_event", "before_image_json"),
    ("authorization_delta_event", "before_digest"),
    ("authorization_delta_event", "delta_json"),
    ("authorization_delta_event", "semantic_hash"),
    ("authorization_delta_event", "dependency_hash"),
    ("authorization_delta_event", "compiler_version"),
    ("authorization_delta_event", "status"),
    ("authorization_delta_event", "attempts"),
    ("authorization_delta_event", "next_attempt_at"),
    ("authorization_delta_event", "lease_owner"),
    ("authorization_delta_event", "lease_token_hash"),
    ("authorization_delta_event", "lease_expires_at"),
    ("authorization_delta_event", "cas_version"),
    ("authorization_delta_event", "last_error"),
    ("authorization_delta_event", "created_at"),
    ("authorization_delta_event", "updated_at"),
    ("authorization_impact_plan", "plan_id"),
    ("authorization_impact_plan", "tenant_id"),
    ("authorization_impact_plan", "card_id"),
    ("authorization_impact_plan", "aggregate_type"),
    ("authorization_impact_plan", "aggregate_id"),
    ("authorization_impact_plan", "event_id"),
    ("authorization_impact_plan", "operation_id"),
    ("authorization_impact_plan", "base_generation"),
    ("authorization_impact_plan", "target_generation"),
    ("authorization_impact_plan", "base_version"),
    ("authorization_impact_plan", "target_version"),
    ("authorization_impact_plan", "semantic_hash"),
    ("authorization_impact_plan", "dependency_hash"),
    ("authorization_impact_plan", "compiler_version"),
    ("authorization_impact_plan", "status"),
    ("authorization_impact_plan", "attempts"),
    ("authorization_impact_plan", "next_attempt_at"),
    ("authorization_impact_plan", "lease_owner"),
    ("authorization_impact_plan", "lease_token_hash"),
    ("authorization_impact_plan", "lease_expires_at"),
    ("authorization_impact_plan", "cas_version"),
    ("authorization_impact_plan", "last_error"),
    ("authorization_impact_plan", "created_at"),
    ("authorization_impact_plan", "updated_at"),
    ("authorization_impact_plan_item", "item_id"),
    ("authorization_impact_plan_item", "plan_id"),
    ("authorization_impact_plan_item", "tenant_id"),
    ("authorization_impact_plan_item", "card_id"),
    ("authorization_impact_plan_item", "aggregate_type"),
    ("authorization_impact_plan_item", "aggregate_id"),
    ("authorization_impact_plan_item", "event_id"),
    ("authorization_impact_plan_item", "operation_id"),
    ("authorization_impact_plan_item", "projection_key"),
    ("authorization_impact_plan_item", "item_type"),
    ("authorization_impact_plan_item", "grant_id"),
    ("authorization_impact_plan_item", "base_version"),
    ("authorization_impact_plan_item", "target_version"),
    ("authorization_impact_plan_item", "before_digest"),
    ("authorization_impact_plan_item", "after_digest"),
    ("authorization_impact_plan_item", "dependency_hash"),
    ("authorization_impact_plan_item", "status"),
    ("authorization_impact_plan_item", "cas_version"),
    ("authorization_impact_plan_item", "last_error"),
    ("authorization_impact_plan_item", "created_at"),
    ("authorization_impact_plan_item", "updated_at"),
    ("authorization_projection_manifest", "manifest_id"),
    ("authorization_projection_manifest", "tenant_id"),
    ("authorization_projection_manifest", "card_id"),
    ("authorization_projection_manifest", "aggregate_type"),
    ("authorization_projection_manifest", "aggregate_id"),
    ("authorization_projection_manifest", "generation"),
    ("authorization_projection_manifest", "source_generation"),
    ("authorization_projection_manifest", "projected_generation"),
    ("authorization_projection_manifest", "event_id"),
    ("authorization_projection_manifest", "operation_id"),
    ("authorization_projection_manifest", "semantic_hash"),
    ("authorization_projection_manifest", "dependency_hash"),
    ("authorization_projection_manifest", "compiler_version"),
    ("authorization_projection_manifest", "manifest_digest"),
    ("authorization_projection_manifest", "status"),
    ("authorization_projection_manifest", "cas_version"),
    ("authorization_projection_manifest", "lease_owner"),
    ("authorization_projection_manifest", "lease_token_hash"),
    ("authorization_projection_manifest", "lease_expires_at"),
    ("authorization_projection_manifest", "last_error"),
    ("authorization_projection_manifest", "created_at"),
    ("authorization_projection_manifest", "updated_at"),
    ("authorization_projection_segment", "segment_id"),
    ("authorization_projection_segment", "tenant_id"),
    ("authorization_projection_segment", "card_id"),
    ("authorization_projection_segment", "aggregate_type"),
    ("authorization_projection_segment", "aggregate_id"),
    ("authorization_projection_segment", "content_digest"),
    ("authorization_projection_segment", "semantic_hash"),
    ("authorization_projection_segment", "dependency_hash"),
    ("authorization_projection_segment", "compiler_version"),
    ("authorization_projection_segment", "segment_format"),
    ("authorization_projection_segment", "row_count"),
    ("authorization_projection_segment", "byte_size"),
    ("authorization_projection_segment", "segment_payload"),
    ("authorization_projection_segment", "status"),
    ("authorization_projection_segment", "cas_version"),
    ("authorization_projection_segment", "created_at"),
    ("authorization_projection_segment", "updated_at"),
    ("authorization_projection_manifest_segment", "reference_id"),
    ("authorization_projection_manifest_segment", "manifest_id"),
    ("authorization_projection_manifest_segment", "segment_id"),
    ("authorization_projection_manifest_segment", "tenant_id"),
    ("authorization_projection_manifest_segment", "card_id"),
    (
        "authorization_projection_manifest_segment",
        "aggregate_type",
    ),
    ("authorization_projection_manifest_segment", "aggregate_id"),
    ("authorization_projection_manifest_segment", "generation"),
    (
        "authorization_projection_manifest_segment",
        "segment_ordinal",
    ),
    (
        "authorization_projection_manifest_segment",
        "content_digest",
    ),
    ("authorization_projection_manifest_segment", "event_id"),
    ("authorization_projection_manifest_segment", "operation_id"),
    ("authorization_projection_manifest_segment", "status"),
    ("authorization_projection_manifest_segment", "created_at"),
    ("authorization_projection_current", "pointer_id"),
    ("authorization_projection_current", "tenant_id"),
    ("authorization_projection_current", "card_id"),
    ("authorization_projection_current", "aggregate_type"),
    ("authorization_projection_current", "aggregate_id"),
    ("authorization_projection_current", "current_generation"),
    ("authorization_projection_current", "manifest_id"),
    ("authorization_projection_current", "event_id"),
    ("authorization_projection_current", "operation_id"),
    ("authorization_projection_current", "semantic_hash"),
    ("authorization_projection_current", "dependency_hash"),
    ("authorization_projection_current", "compiler_version"),
    ("authorization_projection_current", "status"),
    ("authorization_projection_current", "cas_version"),
    ("authorization_projection_current", "last_error"),
    ("authorization_projection_current", "created_at"),
    ("authorization_projection_current", "updated_at"),
    ("authorization_archive_outbox", "archive_outbox_id"),
    ("authorization_archive_outbox", "tenant_id"),
    ("authorization_archive_outbox", "card_id"),
    ("authorization_archive_outbox", "aggregate_type"),
    ("authorization_archive_outbox", "aggregate_id"),
    ("authorization_archive_outbox", "manifest_id"),
    ("authorization_archive_outbox", "generation"),
    ("authorization_archive_outbox", "event_id"),
    ("authorization_archive_outbox", "operation_id"),
    ("authorization_archive_outbox", "archive_key"),
    ("authorization_archive_outbox", "semantic_hash"),
    ("authorization_archive_outbox", "dependency_hash"),
    ("authorization_archive_outbox", "compiler_version"),
    ("authorization_archive_outbox", "status"),
    ("authorization_archive_outbox", "attempts"),
    ("authorization_archive_outbox", "next_attempt_at"),
    ("authorization_archive_outbox", "lease_owner"),
    ("authorization_archive_outbox", "lease_token_hash"),
    ("authorization_archive_outbox", "lease_expires_at"),
    ("authorization_archive_outbox", "cas_version"),
    ("authorization_archive_outbox", "archived_at"),
    ("authorization_archive_outbox", "last_error"),
    ("authorization_archive_outbox", "created_at"),
    ("authorization_archive_outbox", "updated_at"),
    ("authorization_archive_manifest", "archive_manifest_id"),
    ("authorization_archive_manifest", "tenant_id"),
    ("authorization_archive_manifest", "card_id"),
    ("authorization_archive_manifest", "aggregate_type"),
    ("authorization_archive_manifest", "aggregate_id"),
    ("authorization_archive_manifest", "manifest_id"),
    ("authorization_archive_manifest", "generation"),
    ("authorization_archive_manifest", "event_id"),
    ("authorization_archive_manifest", "operation_id"),
    ("authorization_archive_manifest", "archive_key"),
    ("authorization_archive_manifest", "archive_digest"),
    ("authorization_archive_manifest", "semantic_hash"),
    ("authorization_archive_manifest", "dependency_hash"),
    ("authorization_archive_manifest", "compiler_version"),
    ("authorization_archive_manifest", "status"),
    ("authorization_archive_manifest", "cas_version"),
    ("authorization_archive_manifest", "archived_at"),
    ("authorization_archive_manifest", "last_error"),
    ("authorization_archive_manifest", "created_at"),
    ("authorization_archive_manifest", "updated_at"),
];

const INCREMENTAL_PROJECTION_ARCHIVE_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "authorization_grant_revision",
        "PRIMARY",
        &["revision_id"],
        true,
    ),
    (
        "authorization_grant_revision",
        "uk_agr_revision_version",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "grant_id",
            "revision_no",
        ],
        true,
    ),
    (
        "authorization_grant_revision",
        "idx_agr_revision_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id", "revision_no"],
        false,
    ),
    (
        "authorization_grant_revision",
        "idx_agr_revision_card",
        &["tenant_id", "card_id", "revision_no"],
        false,
    ),
    (
        "authorization_grant_revision",
        "idx_agr_revision_tombstone",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "is_tombstone",
            "revision_no",
        ],
        false,
    ),
    (
        "authorization_grant_revision",
        "idx_agr_revision_event",
        &["event_id"],
        false,
    ),
    (
        "authorization_grant_revision",
        "idx_agr_revision_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_delta_event",
        "PRIMARY",
        &["delta_event_id"],
        true,
    ),
    (
        "authorization_delta_event",
        "uk_ade_event",
        &["event_id"],
        true,
    ),
    (
        "authorization_delta_event",
        "uk_ade_target_version",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "grant_id",
            "target_version",
        ],
        true,
    ),
    (
        "authorization_delta_event",
        "idx_ade_aggregate",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "target_version",
        ],
        false,
    ),
    (
        "authorization_delta_event",
        "idx_ade_card",
        &["tenant_id", "card_id", "target_version"],
        false,
    ),
    (
        "authorization_delta_event",
        "idx_ade_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "authorization_delta_event",
        "idx_ade_lease",
        &["status", "lease_expires_at", "delta_event_id"],
        false,
    ),
    (
        "authorization_delta_event",
        "idx_ade_operation",
        &["operation_id"],
        false,
    ),
    ("authorization_impact_plan", "PRIMARY", &["plan_id"], true),
    (
        "authorization_impact_plan",
        "uk_aip_event",
        &["event_id"],
        true,
    ),
    (
        "authorization_impact_plan",
        "uk_aip_target_generation",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "target_generation",
        ],
        true,
    ),
    (
        "authorization_impact_plan",
        "idx_aip_aggregate",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "target_generation",
        ],
        false,
    ),
    (
        "authorization_impact_plan",
        "idx_aip_card",
        &["tenant_id", "card_id", "target_generation"],
        false,
    ),
    (
        "authorization_impact_plan",
        "idx_aip_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "authorization_impact_plan",
        "idx_aip_lease",
        &["status", "lease_expires_at", "plan_id"],
        false,
    ),
    (
        "authorization_impact_plan",
        "idx_aip_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_impact_plan_item",
        "PRIMARY",
        &["item_id"],
        true,
    ),
    (
        "authorization_impact_plan_item",
        "uk_aipi_plan_key",
        &["plan_id", "projection_key"],
        true,
    ),
    (
        "authorization_impact_plan_item",
        "idx_aipi_plan_status",
        &["plan_id", "status", "item_id"],
        false,
    ),
    (
        "authorization_impact_plan_item",
        "idx_aipi_aggregate",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "target_version",
        ],
        false,
    ),
    (
        "authorization_impact_plan_item",
        "idx_aipi_card",
        &["tenant_id", "card_id", "target_version"],
        false,
    ),
    (
        "authorization_impact_plan_item",
        "idx_aipi_event",
        &["event_id"],
        false,
    ),
    (
        "authorization_impact_plan_item",
        "idx_aipi_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_projection_manifest",
        "PRIMARY",
        &["manifest_id"],
        true,
    ),
    (
        "authorization_projection_manifest",
        "uk_apm_generation",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        true,
    ),
    (
        "authorization_projection_manifest",
        "uk_apm_digest",
        &["tenant_id", "manifest_digest"],
        true,
    ),
    (
        "authorization_projection_manifest",
        "idx_apm_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        false,
    ),
    (
        "authorization_projection_manifest",
        "idx_apm_card",
        &["tenant_id", "card_id", "generation"],
        false,
    ),
    (
        "authorization_projection_manifest",
        "idx_apm_status",
        &["status", "lease_expires_at", "manifest_id"],
        false,
    ),
    (
        "authorization_projection_manifest",
        "idx_apm_event",
        &["event_id"],
        false,
    ),
    (
        "authorization_projection_manifest",
        "idx_apm_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_projection_segment",
        "PRIMARY",
        &["segment_id"],
        true,
    ),
    (
        "authorization_projection_segment",
        "uk_aps_content",
        &["tenant_id", "content_digest"],
        true,
    ),
    (
        "authorization_projection_segment",
        "idx_aps_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id", "segment_id"],
        false,
    ),
    (
        "authorization_projection_segment",
        "idx_aps_card",
        &["tenant_id", "card_id", "segment_id"],
        false,
    ),
    (
        "authorization_projection_segment",
        "idx_aps_semantic",
        &["tenant_id", "semantic_hash", "compiler_version"],
        false,
    ),
    (
        "authorization_projection_segment",
        "idx_aps_status",
        &["status", "segment_id"],
        false,
    ),
    (
        "authorization_projection_manifest_segment",
        "PRIMARY",
        &["reference_id"],
        true,
    ),
    (
        "authorization_projection_manifest_segment",
        "uk_apms_ordinal",
        &["manifest_id", "segment_ordinal"],
        true,
    ),
    (
        "authorization_projection_manifest_segment",
        "uk_apms_segment",
        &["manifest_id", "segment_id"],
        true,
    ),
    (
        "authorization_projection_manifest_segment",
        "idx_apms_manifest",
        &["tenant_id", "manifest_id", "generation"],
        false,
    ),
    (
        "authorization_projection_manifest_segment",
        "idx_apms_segment",
        &["tenant_id", "segment_id"],
        false,
    ),
    (
        "authorization_projection_manifest_segment",
        "idx_apms_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        false,
    ),
    (
        "authorization_projection_manifest_segment",
        "idx_apms_event",
        &["event_id"],
        false,
    ),
    (
        "authorization_projection_manifest_segment",
        "idx_apms_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_projection_current",
        "PRIMARY",
        &["pointer_id"],
        true,
    ),
    (
        "authorization_projection_current",
        "uk_apc_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id"],
        true,
    ),
    (
        "authorization_projection_current",
        "idx_apc_generation",
        &[
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "current_generation",
        ],
        false,
    ),
    (
        "authorization_projection_current",
        "idx_apc_card",
        &["tenant_id", "card_id", "current_generation"],
        false,
    ),
    (
        "authorization_projection_current",
        "idx_apc_manifest",
        &["manifest_id"],
        false,
    ),
    (
        "authorization_projection_current",
        "idx_apc_event",
        &["event_id"],
        false,
    ),
    (
        "authorization_projection_current",
        "idx_apc_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_archive_outbox",
        "PRIMARY",
        &["archive_outbox_id"],
        true,
    ),
    (
        "authorization_archive_outbox",
        "uk_aao_event",
        &["event_id"],
        true,
    ),
    (
        "authorization_archive_outbox",
        "uk_aao_generation",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        true,
    ),
    (
        "authorization_archive_outbox",
        "idx_aao_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        false,
    ),
    (
        "authorization_archive_outbox",
        "idx_aao_card",
        &["tenant_id", "card_id", "generation"],
        false,
    ),
    (
        "authorization_archive_outbox",
        "idx_aao_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "authorization_archive_outbox",
        "idx_aao_lease",
        &["status", "lease_expires_at", "archive_outbox_id"],
        false,
    ),
    (
        "authorization_archive_outbox",
        "idx_aao_manifest",
        &["manifest_id"],
        false,
    ),
    (
        "authorization_archive_outbox",
        "idx_aao_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_archive_manifest",
        "PRIMARY",
        &["archive_manifest_id"],
        true,
    ),
    (
        "authorization_archive_manifest",
        "uk_aam_generation",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        true,
    ),
    (
        "authorization_archive_manifest",
        "uk_aam_archive_digest",
        &["tenant_id", "archive_digest"],
        true,
    ),
    (
        "authorization_archive_manifest",
        "idx_aam_aggregate",
        &["tenant_id", "aggregate_type", "aggregate_id", "generation"],
        false,
    ),
    (
        "authorization_archive_manifest",
        "idx_aam_card",
        &["tenant_id", "card_id", "generation"],
        false,
    ),
    (
        "authorization_archive_manifest",
        "idx_aam_status",
        &["status", "archived_at", "archive_manifest_id"],
        false,
    ),
    (
        "authorization_archive_manifest",
        "idx_aam_manifest",
        &["manifest_id"],
        false,
    ),
    (
        "authorization_archive_manifest",
        "idx_aam_event",
        &["event_id"],
        false,
    ),
    (
        "authorization_archive_manifest",
        "idx_aam_operation",
        &["operation_id"],
        false,
    ),
];

const INCREMENTAL_PROJECTION_ARCHIVE_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "revision_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "card_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "aggregate_type",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "aggregate_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "grant_id",
        // Canonical text form of a typed GrantId UUID (lowercase hyphenated).
        column_type: "CHAR(36)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "revision_no",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "operation_id",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "event_id",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "status",
        column_type: "VARCHAR(32)",
        not_null: true,
        default: Some("ACTIVE"),
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "is_tombstone",
        column_type: "TINYINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "grant_payload",
        column_type: "JSON",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "semantic_hash",
        column_type: "BINARY(32)",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "dependency_hash",
        column_type: "BINARY(32)",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "compiler_version",
        column_type: "VARCHAR(64)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "created_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_grant_revision",
        name: "updated_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
    incremental_scalar_column(
        "authorization_delta_event",
        "delta_event_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "grant_id",
        // Canonical text form of a typed GrantId UUID (lowercase hyphenated).
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "event_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "base_version",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "target_version",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "source_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "revoke_fence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "before_image_json",
        "JSON",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "before_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "delta_json",
        "JSON",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "attempts",
        "INT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "next_attempt_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_delta_event",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_delta_event",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_delta_event",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column("authorization_impact_plan", "plan_id", "BIGINT", true, None),
    incremental_scalar_column(
        "authorization_impact_plan",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "base_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "target_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "base_version",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "target_version",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "attempts",
        "INT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "next_attempt_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_impact_plan",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_impact_plan",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "item_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "plan_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "projection_key",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "item_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "grant_id",
        // Canonical text form of a typed GrantId UUID (lowercase hyphenated).
        "CHAR(36)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "base_version",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "target_version",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "before_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "after_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_impact_plan_item",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_impact_plan_item",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "manifest_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "source_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "projected_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "manifest_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "status",
        "VARCHAR(32)",
        true,
        Some("BUILDING"),
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_manifest",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "segment_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_projection_segment",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "content_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_segment",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_segment",
        "segment_format",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "row_count",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "byte_size",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "segment_payload",
        "MEDIUMBLOB",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_segment",
        "status",
        "VARCHAR(32)",
        true,
        Some("READY"),
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_segment",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "reference_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "manifest_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "segment_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest_segment",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "segment_ordinal",
        "INT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "content_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest_segment",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest_segment",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_manifest_segment",
        "status",
        "VARCHAR(32)",
        true,
        Some("READY"),
    ),
    incremental_scalar_column(
        "authorization_projection_manifest_segment",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "pointer_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_projection_current",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "current_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "manifest_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_current",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_current",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_current",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_projection_current",
        "status",
        "VARCHAR(32)",
        true,
        Some("READY"),
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_projection_current",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_projection_current",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "archive_outbox_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "manifest_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "archive_key",
        "VARCHAR(512)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "attempts",
        "INT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "next_attempt_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "archived_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_archive_outbox",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_archive_outbox",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "archive_manifest_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "card_id",
        "BIGINT",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "manifest_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "event_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "archive_key",
        "VARCHAR(512)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "archive_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "semantic_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "dependency_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "status",
        "VARCHAR(32)",
        true,
        Some("STAGED"),
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "cas_version",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "archived_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_archive_manifest",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_archive_manifest",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// Lineage/revoke-fence additive contract (20260827000001)
//
// The lineage-fence migration appends exactly six columns to the tail of four
// creator tables. It is a Rust-owned repair-style migration: it may run while
// the tables already exist, so its artifact contract supports existing
// artifacts, and every statement is a conditional ALTER that never drops,
// backfills or rewrites data. The numeric fence value alone — zero or
// positive — never identifies unproven history:
// `authorization_projection_current.revoke_fence_proven` is the sole durable
// proof latch. A row whose latch is still `0` is unproven history and fails
// closed regardless of its numeric fence (fail-closed to an explicit
// backfill/rehearsal requirement instead of inference); a proven zero (latch
// `1`, fence `0`) is a valid, authoritative state that may later advance to a
// positive fence. The affected tables are exactly the distinct `table` values
// inside AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS below.
const AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMNS: &[(&str, &str)] = &[
    ("authorization_projection_manifest", "parent_manifest_id"),
    ("authorization_projection_manifest", "revoke_fence"),
    ("authorization_projection_current", "revoke_fence"),
    ("authorization_projection_current", "revoke_fence_proven"),
    ("authorization_archive_outbox", "archived_revoke_fence"),
    ("authorization_archive_manifest", "archived_revoke_fence"),
];

const DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMNS: &[(&str, &str)] = &[(
    "authorization_delta_event",
    "invalidates_published_evidence",
)];

const AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "authorization_projection_manifest",
        name: "parent_manifest_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_manifest",
        name: "revoke_fence",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_current",
        name: "revoke_fence",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_projection_current",
        name: "revoke_fence_proven",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_archive_outbox",
        name: "archived_revoke_fence",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "authorization_archive_manifest",
        name: "archived_revoke_fence",
        column_type: "BIGINT",
        not_null: true,
        default: Some("0"),
        charset: None,
        collation: None,
    },
];

const DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMN_CONTRACTS: &[SchemaColumnContract] =
    &[SchemaColumnContract {
        table: "authorization_delta_event",
        name: "invalidates_published_evidence",
        column_type: "TINYINT",
        not_null: true,
        default: Some("1"),
        charset: None,
        collation: None,
    }];

const RULE_SET_SNAPSHOT_MANIFEST_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "rule_set_id",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "projection_generation",
        column_type: "BIGINT",
        not_null: true,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "status",
        column_type: "VARCHAR(16)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "tenant_id",
        column_type: "BIGINT",
        not_null: false,
        default: None,
        charset: None,
        collation: None,
    },
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "event_id",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "operation_id",
        column_type: "VARCHAR(128)",
        not_null: true,
        default: None,
        charset: Some(MYSQL_SCHEMA_CHARSET),
        collation: Some(MYSQL_SCHEMA_COLLATION),
    },
    SchemaColumnContract {
        table: "rule_set_snapshot_manifest",
        name: "committed_at",
        column_type: "DATETIME",
        not_null: true,
        default: Some("CURRENT_TIMESTAMP"),
        charset: None,
        collation: None,
    },
];

const RULE_SET_PROJECTION_AUDIT_COLUMNS: &[(&str, &str)] = &[
    ("rule_set_projection_audit", "audit_id"),
    ("rule_set_projection_audit", "rule_set_id"),
    ("rule_set_projection_audit", "entry_id"),
    ("rule_set_projection_audit", "changed_by"),
    ("rule_set_projection_audit", "change_type"),
    ("rule_set_projection_audit", "old_value_json"),
    ("rule_set_projection_audit", "new_value_json"),
    ("rule_set_projection_audit", "changed_at"),
    ("rule_set_projection_audit", "tenant_id"),
    ("rule_set_projection_audit", "aggregate_type"),
    ("rule_set_projection_audit", "aggregate_id"),
    ("rule_set_projection_audit", "event_id"),
    ("rule_set_projection_audit", "source_generation"),
    ("rule_set_projection_audit", "operation_id"),
];

const RULE_SET_PROJECTION_AUDIT_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("rule_set_projection_audit", "PRIMARY", &["audit_id"], true),
    (
        "rule_set_projection_audit",
        "uk_rsp_audit_event_generation",
        &["event_id", "source_generation", "change_type"],
        true,
    ),
    (
        "rule_set_projection_audit",
        "idx_rsp_audit_rule_set_generation",
        &["rule_set_id", "source_generation"],
        false,
    ),
    (
        "rule_set_projection_audit",
        "idx_rsp_audit_operation",
        &["operation_id"],
        false,
    ),
];

const RULE_SET_PROJECTION_REPAIR_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("rule_set", "uk_rule_set_code", &["code"], true),
    (
        "rule_set",
        "idx_rule_set_source",
        &["source_type", "source_id"],
        false,
    ),
    (
        "rule_set_entry",
        "idx_rule_set_entry",
        &["rule_set_id", "enabled", "priority"],
        false,
    ),
    (
        "card_rule_set_ref",
        "uk_card_rule_set",
        &["card_id", "rule_set_id"],
        true,
    ),
    ("card_rule_set_ref", "idx_crsr_card", &["card_id"], false),
    (
        "card_rule_set_ref",
        "idx_crsr_rule_set",
        &["rule_set_id"],
        false,
    ),
    (
        "rule_set_snapshot",
        "uk_rule_set_snapshot",
        &["rule_set_id", "resource_key", "action_code"],
        true,
    ),
    (
        "rule_set_snapshot",
        "idx_rss_rule_set",
        &["rule_set_id", "action_code"],
        false,
    ),
    (
        "authorization_projection_head",
        "uk_aph_aggregate",
        &["aggregate_type", "aggregate_id"],
        true,
    ),
    (
        "authorization_projection_outbox",
        "uk_apob_event",
        &["event_id"],
        true,
    ),
    (
        "authorization_projection_outbox",
        "uk_apob_generation_sequence",
        &[
            "aggregate_type",
            "aggregate_id",
            "source_generation",
            "sequence_number",
        ],
        true,
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_lease",
        &["status", "lease_expires_at", "outbox_id"],
        false,
    ),
    (
        "authorization_projection_outbox",
        "idx_apob_aggregate",
        &["aggregate_type", "aggregate_id", "source_generation"],
        false,
    ),
];

// Cross-city durable schema (20260831000002): Rust-owned creator tables for
// the default-off cross-city subsystem. The schema stores only durable state;
// the operation/vote/city-state/gate state machines, the closed decision set,
// and every transition rule stay owned by the astral-types cross_city
// contracts - the database intentionally carries no CHECK constraints for
// them. Foreign keys are intentionally omitted (see the migration header):
// cross-city evidence must stay queryable after related rows expire, and the
// future repository enforces consistency via its own transactions plus
// generation/token fences instead of cascading DDL.
const CROSS_CITY_SCHEMA_TABLES: &[&str] = &[
    "authorization_cross_city_operation",
    "authorization_cross_city_vote",
    "authorization_cross_city_city_state",
    "authorization_cross_city_gate",
    "authorization_cross_city_outbox",
    "authorization_cross_city_inbox",
];

const CROSS_CITY_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("authorization_cross_city_operation", "operation_id"),
    ("authorization_cross_city_operation", "scope_digest"),
    ("authorization_cross_city_operation", "request_digest"),
    ("authorization_cross_city_operation", "mutation_digest"),
    ("authorization_cross_city_operation", "base_frontier_digest"),
    (
        "authorization_cross_city_operation",
        "base_source_generation",
    ),
    ("authorization_cross_city_operation", "base_revoke_fence"),
    ("authorization_cross_city_operation", "target_generation"),
    ("authorization_cross_city_operation", "target_revoke_fence"),
    ("authorization_cross_city_operation", "proposal_digest"),
    ("authorization_cross_city_operation", "compiler_version"),
    ("authorization_cross_city_operation", "policy_version"),
    ("authorization_cross_city_operation", "home_city"),
    ("authorization_cross_city_operation", "coordinator_epoch"),
    ("authorization_cross_city_operation", "state"),
    ("authorization_cross_city_operation", "agreement_digest"),
    ("authorization_cross_city_operation", "expires_at"),
    ("authorization_cross_city_operation", "last_error"),
    ("authorization_cross_city_operation", "created_at"),
    ("authorization_cross_city_operation", "updated_at"),
    ("authorization_cross_city_vote", "vote_id"),
    ("authorization_cross_city_vote", "operation_id"),
    ("authorization_cross_city_vote", "city_id"),
    ("authorization_cross_city_vote", "node_id"),
    ("authorization_cross_city_vote", "node_epoch"),
    ("authorization_cross_city_vote", "decision"),
    ("authorization_cross_city_vote", "proposal_digest"),
    ("authorization_cross_city_vote", "frontier_digest"),
    ("authorization_cross_city_vote", "mutation_digest"),
    ("authorization_cross_city_vote", "evidence_digest"),
    ("authorization_cross_city_vote", "nonce"),
    ("authorization_cross_city_vote", "signature"),
    ("authorization_cross_city_vote", "expires_at"),
    ("authorization_cross_city_vote", "observed_at"),
    ("authorization_cross_city_city_state", "state_id"),
    ("authorization_cross_city_city_state", "operation_id"),
    ("authorization_cross_city_city_state", "city_id"),
    ("authorization_cross_city_city_state", "phase"),
    ("authorization_cross_city_city_state", "local_base_digest"),
    ("authorization_cross_city_city_state", "commit_digest"),
    ("authorization_cross_city_city_state", "pointer_digest"),
    ("authorization_cross_city_city_state", "certificate_digest"),
    ("authorization_cross_city_city_state", "lease_owner"),
    ("authorization_cross_city_city_state", "lease_token_hash"),
    ("authorization_cross_city_city_state", "lease_expires_at"),
    ("authorization_cross_city_city_state", "last_error"),
    ("authorization_cross_city_city_state", "created_at"),
    ("authorization_cross_city_city_state", "updated_at"),
    ("authorization_cross_city_gate", "gate_id"),
    ("authorization_cross_city_gate", "tenant_id"),
    ("authorization_cross_city_gate", "aggregate_type"),
    ("authorization_cross_city_gate", "aggregate_id"),
    ("authorization_cross_city_gate", "operation_id"),
    ("authorization_cross_city_gate", "certificate_digest"),
    ("authorization_cross_city_gate", "target_generation"),
    ("authorization_cross_city_gate", "revoke_fence"),
    ("authorization_cross_city_gate", "state"),
    ("authorization_cross_city_gate", "content_hash"),
    ("authorization_cross_city_gate", "created_at"),
    ("authorization_cross_city_gate", "updated_at"),
    ("authorization_cross_city_outbox", "message_id"),
    ("authorization_cross_city_outbox", "operation_id"),
    ("authorization_cross_city_outbox", "source_city_id"),
    ("authorization_cross_city_outbox", "destination_city_id"),
    ("authorization_cross_city_outbox", "phase"),
    ("authorization_cross_city_outbox", "payload_digest"),
    ("authorization_cross_city_outbox", "payload"),
    ("authorization_cross_city_outbox", "status"),
    ("authorization_cross_city_outbox", "attempts"),
    ("authorization_cross_city_outbox", "next_attempt_at"),
    ("authorization_cross_city_outbox", "lease_owner"),
    ("authorization_cross_city_outbox", "lease_token_hash"),
    ("authorization_cross_city_outbox", "lease_expires_at"),
    ("authorization_cross_city_outbox", "last_error"),
    ("authorization_cross_city_outbox", "created_at"),
    ("authorization_cross_city_outbox", "updated_at"),
    ("authorization_cross_city_inbox", "message_id"),
    ("authorization_cross_city_inbox", "operation_id"),
    ("authorization_cross_city_inbox", "source_city_id"),
    ("authorization_cross_city_inbox", "phase"),
    ("authorization_cross_city_inbox", "payload_digest"),
    ("authorization_cross_city_inbox", "status"),
    ("authorization_cross_city_inbox", "attempts"),
    ("authorization_cross_city_inbox", "lease_owner"),
    ("authorization_cross_city_inbox", "lease_token_hash"),
    ("authorization_cross_city_inbox", "lease_expires_at"),
    ("authorization_cross_city_inbox", "received_at"),
    ("authorization_cross_city_inbox", "processed_at"),
    ("authorization_cross_city_inbox", "last_error"),
    ("authorization_cross_city_inbox", "updated_at"),
];

const CROSS_CITY_SCHEMA_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "authorization_cross_city_operation",
        "PRIMARY",
        &["operation_id"],
        true,
    ),
    (
        "authorization_cross_city_operation",
        "idx_acco_state_expiry",
        &["state", "expires_at", "operation_id"],
        false,
    ),
    (
        "authorization_cross_city_operation",
        "idx_acco_home_city",
        &["home_city", "state", "operation_id"],
        false,
    ),
    (
        "authorization_cross_city_operation",
        "idx_acco_scope_target",
        &["scope_digest", "target_generation"],
        false,
    ),
    (
        "authorization_cross_city_vote",
        "PRIMARY",
        &["vote_id"],
        true,
    ),
    (
        "authorization_cross_city_vote",
        "uk_accv_node",
        &["operation_id", "city_id", "node_id"],
        true,
    ),
    (
        "authorization_cross_city_vote",
        "uk_accv_nonce",
        &["operation_id", "nonce"],
        true,
    ),
    (
        "authorization_cross_city_vote",
        "idx_accv_decision",
        &["operation_id", "decision", "city_id"],
        false,
    ),
    (
        "authorization_cross_city_city_state",
        "PRIMARY",
        &["state_id"],
        true,
    ),
    (
        "authorization_cross_city_city_state",
        "uk_accc_operation_city",
        &["operation_id", "city_id"],
        true,
    ),
    (
        "authorization_cross_city_city_state",
        "idx_accc_phase_lease",
        &["phase", "lease_expires_at", "state_id"],
        false,
    ),
    (
        "authorization_cross_city_city_state",
        "idx_accc_city",
        &["city_id", "operation_id"],
        false,
    ),
    (
        "authorization_cross_city_gate",
        "PRIMARY",
        &["gate_id"],
        true,
    ),
    (
        "authorization_cross_city_gate",
        "uk_accg_scope",
        &["tenant_id", "aggregate_type", "aggregate_id"],
        true,
    ),
    (
        "authorization_cross_city_gate",
        "idx_accg_state",
        &["state", "updated_at", "gate_id"],
        false,
    ),
    (
        "authorization_cross_city_gate",
        "idx_accg_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_cross_city_outbox",
        "PRIMARY",
        &["message_id"],
        true,
    ),
    (
        "authorization_cross_city_outbox",
        "idx_accob_pending",
        &["status", "next_attempt_at", "created_at"],
        false,
    ),
    (
        "authorization_cross_city_outbox",
        "idx_accob_lease",
        &["status", "lease_expires_at", "message_id"],
        false,
    ),
    (
        "authorization_cross_city_outbox",
        "idx_accob_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_cross_city_outbox",
        "idx_accob_source",
        &["source_city_id", "phase"],
        false,
    ),
    (
        "authorization_cross_city_outbox",
        "idx_accob_destination",
        &["destination_city_id", "phase"],
        false,
    ),
    (
        "authorization_cross_city_inbox",
        "PRIMARY",
        &["message_id"],
        true,
    ),
    (
        "authorization_cross_city_inbox",
        "idx_accib_lease",
        &["status", "lease_expires_at", "message_id"],
        false,
    ),
    (
        "authorization_cross_city_inbox",
        "idx_accib_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_cross_city_inbox",
        "idx_accib_source",
        &["source_city_id", "phase"],
        false,
    ),
];

/// Exact runtime column contracts for the six cross-city creator tables. The
/// closed operation-state / decision / gate vocabularies, the two-city
/// agreement rule, and all signature verification stay in astral-types; these
/// contracts pin only the durable column shapes the repository relies on.
const CROSS_CITY_RUNTIME_PROOF_TABLES: &[&str] = &[
    "authorization_cross_city_node_key",
    "authorization_cross_city_vote_reservation",
    "authorization_cross_city_commit_receipt",
    "authorization_cross_city_operation_activation",
    "authorization_cross_city_authority_scope",
];

const CROSS_CITY_RUNTIME_PROOF_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "authorization_cross_city_node_key",
        "PRIMARY",
        &["node_key_id"],
        true,
    ),
    (
        "authorization_cross_city_node_key",
        "uk_accnk_identity",
        &["city_id", "node_id", "node_epoch"],
        true,
    ),
    (
        "authorization_cross_city_node_key",
        "idx_accnk_revoked",
        &["revoked", "node_key_id"],
        false,
    ),
    (
        "authorization_cross_city_vote_reservation",
        "PRIMARY",
        &["reservation_id"],
        true,
    ),
    (
        "authorization_cross_city_vote_reservation",
        "uk_accvr_replay_key",
        &[
            "city_id",
            "node_id",
            "node_epoch",
            "nonce",
            "evidence_digest",
        ],
        true,
    ),
    (
        "authorization_cross_city_vote_reservation",
        "idx_accvr_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "PRIMARY",
        &["receipt_id"],
        true,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "uk_acccr_node",
        &["operation_id", "city_id", "node_id"],
        true,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "uk_acccr_nonce",
        &["operation_id", "nonce"],
        true,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "idx_acccr_operation_city",
        &["operation_id", "city_id", "decision"],
        false,
    ),
    (
        "authorization_cross_city_operation_activation",
        "PRIMARY",
        &["operation_id"],
        true,
    ),
    (
        "authorization_cross_city_authority_scope",
        "PRIMARY",
        &["scope_id"],
        true,
    ),
    (
        "authorization_cross_city_authority_scope",
        "uk_accas_city_scope",
        &["city_id", "scope_digest"],
        true,
    ),
    (
        "authorization_cross_city_authority_scope",
        "idx_accas_scope",
        &["scope_digest", "authoritative"],
        false,
    ),
];

const CROSS_CITY_RUNTIME_PROOF_COLUMNS: &[SchemaColumnContract] = &[
    incremental_scalar_column(
        "authorization_cross_city_node_key",
        "node_key_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_node_key",
        "city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_node_key",
        "node_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_node_key",
        "node_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_node_key",
        "public_key",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_node_key",
        "revoked",
        "TINYINT(1)",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_node_key",
        "registered_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_node_key",
        "revoked_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_node_key",
        "revoked_reason",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote_reservation",
        "reservation_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote_reservation",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote_reservation",
        "city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote_reservation",
        "node_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote_reservation",
        "node_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote_reservation",
        "nonce",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote_reservation",
        "evidence_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote_reservation",
        "reserved_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "receipt_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_commit_receipt",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_commit_receipt",
        "city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_commit_receipt",
        "node_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "node_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_commit_receipt",
        "decision",
        "VARCHAR(16)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "proposal_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "evidence_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "target_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "revoke_fence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "coordinator_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_commit_receipt",
        "nonce",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_commit_receipt",
        "signature",
        "VARCHAR(4096)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_commit_receipt",
        "observed_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_text_column(
        "authorization_cross_city_operation_activation",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "agreement_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "commit_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "scope_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "target_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "revoke_fence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "coordinator_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation_activation",
        "minted_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_authority_scope",
        "scope_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_authority_scope",
        "city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_authority_scope",
        "scope_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_authority_scope",
        "authoritative",
        "TINYINT(1)",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_authority_scope",
        "registered_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
];

const ASYNC_OPERATION_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("async_operation", "PRIMARY", &["task_id"], true),
    (
        "async_operation",
        "idx_async_operation_owner_status",
        &["requester_user_id", "status", "updated_at"],
        false,
    ),
    (
        "async_operation",
        "idx_async_operation_anchor",
        &["authorization_target_card_id", "task_id"],
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

const LOCAL_SCOPE_SEQUENCE_COLUMN_CONTRACT: SchemaColumnContract =
    incremental_scalar_column("al_message_outbox", "scope_sequence", "BIGINT", false, None);

const LOCAL_SCOPE_COUNTER_COLUMNS: &[SchemaColumnContract] = &[
    incremental_text_column(
        "al_message_scope_counter",
        "scope_key",
        "VARCHAR(400)",
        true,
        None,
    ),
    incremental_scalar_column(
        "al_message_scope_counter",
        "last_sequence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "al_message_scope_counter",
        "updated_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
];

const LOCAL_SCOPE_COUNTER_INDEXES: &[(&str, &str, &[&str], bool)] =
    &[("al_message_scope_counter", "PRIMARY", &["scope_key"], true)];

const ORG_SCOPE_OPERATION_COLUMNS: &[SchemaColumnContract] = &[
    incremental_text_column(
        "org_scope_operation",
        "operation_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "org_scope_operation",
        "operation_kind",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column("org_scope_operation", "tenant_id", "BIGINT", true, None),
    incremental_scalar_column(
        "org_scope_operation",
        "input_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "org_scope_operation",
        "outcome_json",
        "MEDIUMTEXT",
        false,
        None,
    ),
    incremental_scalar_column(
        "org_scope_operation",
        "created_at",
        "DATETIME(6)",
        true,
        Some("CURRENT_TIMESTAMP(6)"),
    ),
];

const ORG_SCOPE_OPERATION_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    ("org_scope_operation", "PRIMARY", &["operation_id"], true),
    (
        "org_scope_operation",
        "idx_osop_tenant",
        &["tenant_id", "created_at"],
        false,
    ),
];

const REVIEW_SCHEMA_REPAIR_COLUMNS: &[(&str, &str)] = &[
    ("al_message_outbox", "scope_sequence"),
    ("al_message_scope_counter", "scope_key"),
    ("al_message_scope_counter", "last_sequence"),
    ("al_message_scope_counter", "updated_at"),
];

const REVIEW_SCHEMA_REPAIR_INDEXES: &[(&str, &str, &[&str], bool)] = &[
    (
        "al_message_outbox",
        "idx_al_message_scope_order",
        &["queue_name", "ordering_key", "scope_sequence"],
        false,
    ),
    ("al_message_scope_counter", "PRIMARY", &["scope_key"], true),
    ("org_scope_operation", "PRIMARY", &["operation_id"], true),
    // Existing indexes are reasserted here because 20261003000003 may repair a
    // same-name missing index after its creator has already been recorded.
    (
        "authorization_cross_city_node_key",
        "PRIMARY",
        &["node_key_id"],
        true,
    ),
    (
        "authorization_cross_city_node_key",
        "uk_accnk_identity",
        &["city_id", "node_id", "node_epoch"],
        true,
    ),
    (
        "authorization_cross_city_node_key",
        "idx_accnk_revoked",
        &["revoked", "node_key_id"],
        false,
    ),
    (
        "authorization_cross_city_vote_reservation",
        "PRIMARY",
        &["reservation_id"],
        true,
    ),
    (
        "authorization_cross_city_vote_reservation",
        "uk_accvr_replay_key",
        &[
            "city_id",
            "node_id",
            "node_epoch",
            "nonce",
            "evidence_digest",
        ],
        true,
    ),
    (
        "authorization_cross_city_vote_reservation",
        "idx_accvr_operation",
        &["operation_id"],
        false,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "PRIMARY",
        &["receipt_id"],
        true,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "uk_acccr_node",
        &["operation_id", "city_id", "node_id"],
        true,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "uk_acccr_nonce",
        &["operation_id", "nonce"],
        true,
    ),
    (
        "authorization_cross_city_commit_receipt",
        "idx_acccr_operation_city",
        &["operation_id", "city_id", "decision"],
        false,
    ),
    (
        "authorization_cross_city_operation_activation",
        "PRIMARY",
        &["operation_id"],
        true,
    ),
    (
        "authorization_cross_city_authority_scope",
        "PRIMARY",
        &["scope_id"],
        true,
    ),
    (
        "authorization_cross_city_authority_scope",
        "uk_accas_city_scope",
        &["city_id", "scope_digest"],
        true,
    ),
    (
        "authorization_cross_city_authority_scope",
        "idx_accas_scope",
        &["scope_digest", "authoritative"],
        false,
    ),
];

const CROSS_CITY_SCHEMA_COLUMN_CONTRACTS: &[SchemaColumnContract] = &[
    // authorization_cross_city_operation
    incremental_text_column(
        "authorization_cross_city_operation",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "scope_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "request_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "mutation_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "base_frontier_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "base_source_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "base_revoke_fence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "target_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "target_revoke_fence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "proposal_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_operation",
        "compiler_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_operation",
        "policy_version",
        "VARCHAR(64)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_operation",
        "home_city",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "coordinator_epoch",
        "BIGINT",
        true,
        Some("1"),
    ),
    incremental_text_column(
        "authorization_cross_city_operation",
        "state",
        "VARCHAR(32)",
        true,
        Some("PROPOSED"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "agreement_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "expires_at",
        "DATETIME",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_operation",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_operation",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // authorization_cross_city_vote
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "vote_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote",
        "city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote",
        "node_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "node_epoch",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote",
        "decision",
        "VARCHAR(16)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "proposal_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "frontier_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "mutation_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "evidence_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote",
        "nonce",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_vote",
        "signature",
        "VARCHAR(4096)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "expires_at",
        "DATETIME",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_vote",
        "observed_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // authorization_cross_city_city_state
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "state_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_city_state",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_city_state",
        "city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_city_state",
        "phase",
        "VARCHAR(32)",
        true,
        Some("PROPOSED"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "local_base_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "commit_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "pointer_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "certificate_digest",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_city_state",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_city_state",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_city_state",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // authorization_cross_city_gate
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "gate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "tenant_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_gate",
        "aggregate_type",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "aggregate_id",
        "BIGINT",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_gate",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "certificate_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "target_generation",
        "BIGINT",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "revoke_fence",
        "BIGINT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_cross_city_gate",
        "state",
        "VARCHAR(32)",
        true,
        Some("BLOCKED"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "content_hash",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_gate",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // authorization_cross_city_outbox
    incremental_text_column(
        "authorization_cross_city_outbox",
        "message_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "source_city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "destination_city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "phase",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "payload_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "payload",
        "MEDIUMBLOB",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "attempts",
        "INT",
        true,
        Some("0"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "next_attempt_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_outbox",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "created_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_outbox",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    // authorization_cross_city_inbox
    incremental_text_column(
        "authorization_cross_city_inbox",
        "message_id",
        "VARCHAR(128)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_inbox",
        "operation_id",
        "CHAR(36)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_inbox",
        "source_city_id",
        "VARCHAR(191)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_inbox",
        "phase",
        "VARCHAR(32)",
        true,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "payload_digest",
        "BINARY(32)",
        true,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_inbox",
        "status",
        "VARCHAR(32)",
        true,
        Some("PENDING"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "attempts",
        "INT",
        true,
        Some("0"),
    ),
    incremental_text_column(
        "authorization_cross_city_inbox",
        "lease_owner",
        "VARCHAR(128)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "lease_token_hash",
        "BINARY(32)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "lease_expires_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "received_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "processed_at",
        "DATETIME",
        false,
        None,
    ),
    incremental_text_column(
        "authorization_cross_city_inbox",
        "last_error",
        "VARCHAR(512)",
        false,
        None,
    ),
    incremental_scalar_column(
        "authorization_cross_city_inbox",
        "updated_at",
        "DATETIME",
        true,
        Some("CURRENT_TIMESTAMP"),
    ),
];

const EXACT_MIGRATION_ARTIFACT_CONTRACTS: &[ExactMigrationArtifactContract] = &[
    ExactMigrationArtifactContract {
        version: REDUNDANT_ARCHIVE_INDEX_REMOVAL_VERSION,
        source_sha384: REDUNDANT_ARCHIVE_INDEX_REMOVAL_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: &[],
        indexes: &[],
    },
    ExactMigrationArtifactContract {
        version: RUST_RUNTIME_SCHEMA_VERSION,
        source_sha384: RUST_RUNTIME_SCHEMA_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: &["audit_log", "mq_idempotent_log", "pending_compensation"],
        columns: RUST_RUNTIME_CREATOR_COLUMNS,
        indexes: RUST_RUNTIME_CREATOR_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: RUST_RUNTIME_SCHEMA_REPAIR_VERSION,
        source_sha384: RUST_RUNTIME_SCHEMA_REPAIR_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: RUST_RUNTIME_REPAIR_COLUMNS,
        indexes: RUST_RUNTIME_REPAIR_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: AUDIT_QUARANTINE_SCHEMA_VERSION,
        source_sha384: AUDIT_QUARANTINE_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: &["audit_quarantine"],
        columns: AUDIT_QUARANTINE_CREATOR_COLUMNS,
        indexes: AUDIT_QUARANTINE_CREATOR_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: QUARANTINE_REPLAY_HARDENING_VERSION,
        source_sha384: QUARANTINE_REPLAY_HARDENING_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: AUDIT_QUARANTINE_HARDENING_COLUMNS,
        indexes: AUDIT_QUARANTINE_HARDENING_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: MONITOR_SCHEMA_REPAIR_VERSION,
        source_sha384: MONITOR_SCHEMA_REPAIR_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: &[
            "alert_rule",
            "notification_channel",
            "monitor_metric_snapshot",
            "monitor_alert_history",
            "monitor_activity_log",
        ],
        columns: MONITOR_SCHEMA_REPAIR_COLUMNS,
        indexes: MONITOR_SCHEMA_REPAIR_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: RULE_SET_PROJECTION_SCHEMA_REPAIR_VERSION,
        source_sha384: RULE_SET_PROJECTION_SCHEMA_REPAIR_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &["rule_set_projection_audit"],
        columns: &[
            RULE_SET_PROJECTION_REPAIR_COLUMNS[0],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[0],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[1],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[2],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[3],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[4],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[5],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[6],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[7],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[8],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[9],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[10],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[11],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[12],
            RULE_SET_PROJECTION_AUDIT_COLUMNS[13],
        ],
        indexes: &[
            RULE_SET_PROJECTION_REPAIR_INDEXES[0],
            RULE_SET_PROJECTION_REPAIR_INDEXES[1],
            RULE_SET_PROJECTION_REPAIR_INDEXES[2],
            RULE_SET_PROJECTION_REPAIR_INDEXES[3],
            RULE_SET_PROJECTION_REPAIR_INDEXES[4],
            RULE_SET_PROJECTION_REPAIR_INDEXES[5],
            RULE_SET_PROJECTION_REPAIR_INDEXES[6],
            RULE_SET_PROJECTION_REPAIR_INDEXES[7],
            RULE_SET_PROJECTION_REPAIR_INDEXES[8],
            RULE_SET_PROJECTION_REPAIR_INDEXES[9],
            RULE_SET_PROJECTION_REPAIR_INDEXES[10],
            RULE_SET_PROJECTION_REPAIR_INDEXES[11],
            RULE_SET_PROJECTION_REPAIR_INDEXES[12],
            RULE_SET_PROJECTION_REPAIR_INDEXES[13],
            RULE_SET_PROJECTION_AUDIT_INDEXES[0],
            RULE_SET_PROJECTION_AUDIT_INDEXES[1],
            RULE_SET_PROJECTION_AUDIT_INDEXES[2],
            RULE_SET_PROJECTION_AUDIT_INDEXES[3],
        ],
    },
    ExactMigrationArtifactContract {
        version: SNAPSHOT_VALIDITY_SCHEMA_VERSION,
        source_sha384: SNAPSHOT_VALIDITY_SCHEMA_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: &[
            SNAPSHOT_VALIDITY_SCHEMA_COLUMNS[0],
            SNAPSHOT_VALIDITY_SCHEMA_COLUMNS[1],
            SNAPSHOT_VALIDITY_SCHEMA_COLUMNS[2],
            SNAPSHOT_VALIDITY_SCHEMA_COLUMNS[3],
        ],
        indexes: &[],
    },
    ExactMigrationArtifactContract {
        version: RULE_SET_SNAPSHOT_MANIFEST_VERSION,
        source_sha384: RULE_SET_SNAPSHOT_MANIFEST_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: &["rule_set_snapshot_manifest"],
        columns: &[
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[0],
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[1],
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[2],
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[3],
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[4],
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[5],
            RULE_SET_SNAPSHOT_MANIFEST_COLUMNS[6],
        ],
        indexes: &[
            RULE_SET_SNAPSHOT_MANIFEST_INDEXES[0],
            RULE_SET_SNAPSHOT_MANIFEST_INDEXES[1],
            RULE_SET_SNAPSHOT_MANIFEST_INDEXES[2],
        ],
    },
    ExactMigrationArtifactContract {
        version: INCREMENTAL_PROJECTION_ARCHIVE_VERSION,
        source_sha384: INCREMENTAL_PROJECTION_ARCHIVE_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: INCREMENTAL_PROJECTION_ARCHIVE_TABLES,
        columns: INCREMENTAL_PROJECTION_ARCHIVE_COLUMNS,
        indexes: INCREMENTAL_PROJECTION_ARCHIVE_INDEXES,
    },
    // Additive lineage/revoke-fence migration: runs against tables that
    // already exist, so it declares only the six appended tail columns and no
    // creator tables or indexes. The original 20260825000002 creator contract
    // above stays verbatim; the appended columns are NOT folded into it so a
    // pending lineage migration can never look like creator-column drift.
    ExactMigrationArtifactContract {
        version: AUTHORIZATION_PROJECTION_LINEAGE_FENCE_VERSION,
        source_sha384: AUTHORIZATION_PROJECTION_LINEAGE_FENCE_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: AUTHORIZATION_PROJECTION_LINEAGE_FENCE_COLUMNS,
        indexes: &[],
    },
    ExactMigrationArtifactContract {
        version: DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_VERSION,
        source_sha384: DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: DELTA_EVENT_PUBLISHED_EVIDENCE_INVALIDATION_COLUMNS,
        indexes: &[],
    },
    // Decommission-only migration (20260827000002): it creates no tables,
    // columns, or indexes — it removes the legacy snapshot tables
    // (rule_set_snapshot / permission_rule_snapshot / rule_set_snapshot_manifest)
    // after the versioned projection chain cutover. The empty artifact lists are
    // load-bearing: artifact-ownership lookups must never attribute the
    // dropped tables to a creator path, and the pin keeps the guarded DROP
    // body byte-exact. supports_existing_artifacts stays true because the
    // guarded drop runs against pre-existing tables (or converges to a no-op
    // when they are already absent).
    ExactMigrationArtifactContract {
        version: LEGACY_SNAPSHOT_DECOMMISSION_VERSION,
        source_sha384: LEGACY_SNAPSHOT_DECOMMISSION_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: &[],
        indexes: &[],
    },
    // Decommission-only migration (20260830000001): it creates no tables,
    // columns, or indexes — it removes the legacy identity_card tenancy
    // artifacts (domain_id / tenant_id columns, idx_ic_domain, fk_ic_domain)
    // to enforce the dual-card separation contract (tenant/domain belong to
    // user_card). The empty artifact lists are load-bearing: artifact-
    // ownership lookups must never attribute the dropped artifacts to a
    // creator path, and the pin keeps the guarded ALTER body byte-exact.
    // supports_existing_artifacts stays true because the guarded drops run
    // against pre-existing artifacts (or converge to a no-op when the v5
    // shape is already in place).
    ExactMigrationArtifactContract {
        version: IDENTITY_CARD_DUAL_CARD_SEPARATION_VERSION,
        source_sha384: IDENTITY_CARD_DUAL_CARD_SEPARATION_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: &[],
        indexes: &[],
    },
    // Creator-only migration (20260831000002): builds the six Rust-owned
    // cross-city tables for the default-off subsystem. No runtime path reads
    // or writes them yet, so the schema must never look like an enablement:
    // fail-closed defaults (gate BLOCKED, operation PROPOSED, work PENDING)
    // and the closed state/decision vocabularies stay owned by astral-types.
    // supports_existing_artifacts stays false: a creator either creates every
    // declared artifact or must not converge silently over drift.
    ExactMigrationArtifactContract {
        version: CROSS_CITY_SCHEMA_VERSION,
        source_sha384: CROSS_CITY_SCHEMA_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: CROSS_CITY_SCHEMA_TABLES,
        columns: CROSS_CITY_SCHEMA_COLUMNS,
        indexes: CROSS_CITY_SCHEMA_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: CROSS_CITY_RUNTIME_PROOF_VERSION,
        source_sha384: CROSS_CITY_RUNTIME_PROOF_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: CROSS_CITY_RUNTIME_PROOF_TABLES,
        columns: &[
            ("authorization_cross_city_node_key", "node_key_id"),
            ("authorization_cross_city_node_key", "city_id"),
            ("authorization_cross_city_node_key", "node_id"),
            ("authorization_cross_city_node_key", "node_epoch"),
            ("authorization_cross_city_node_key", "public_key"),
            ("authorization_cross_city_node_key", "revoked"),
            ("authorization_cross_city_node_key", "registered_at"),
            ("authorization_cross_city_node_key", "revoked_at"),
            ("authorization_cross_city_node_key", "revoked_reason"),
            (
                "authorization_cross_city_vote_reservation",
                "reservation_id",
            ),
            ("authorization_cross_city_vote_reservation", "operation_id"),
            ("authorization_cross_city_vote_reservation", "city_id"),
            ("authorization_cross_city_vote_reservation", "node_id"),
            ("authorization_cross_city_vote_reservation", "node_epoch"),
            ("authorization_cross_city_vote_reservation", "nonce"),
            (
                "authorization_cross_city_vote_reservation",
                "evidence_digest",
            ),
            ("authorization_cross_city_vote_reservation", "reserved_at"),
            ("authorization_cross_city_commit_receipt", "receipt_id"),
            ("authorization_cross_city_commit_receipt", "operation_id"),
            ("authorization_cross_city_commit_receipt", "city_id"),
            ("authorization_cross_city_commit_receipt", "node_id"),
            ("authorization_cross_city_commit_receipt", "node_epoch"),
            ("authorization_cross_city_commit_receipt", "decision"),
            ("authorization_cross_city_commit_receipt", "proposal_digest"),
            ("authorization_cross_city_commit_receipt", "evidence_digest"),
            (
                "authorization_cross_city_commit_receipt",
                "target_generation",
            ),
            ("authorization_cross_city_commit_receipt", "revoke_fence"),
            (
                "authorization_cross_city_commit_receipt",
                "coordinator_epoch",
            ),
            ("authorization_cross_city_commit_receipt", "nonce"),
            ("authorization_cross_city_commit_receipt", "signature"),
            ("authorization_cross_city_commit_receipt", "observed_at"),
            (
                "authorization_cross_city_operation_activation",
                "operation_id",
            ),
            (
                "authorization_cross_city_operation_activation",
                "agreement_digest",
            ),
            (
                "authorization_cross_city_operation_activation",
                "commit_digest",
            ),
            (
                "authorization_cross_city_operation_activation",
                "scope_digest",
            ),
            (
                "authorization_cross_city_operation_activation",
                "target_generation",
            ),
            (
                "authorization_cross_city_operation_activation",
                "revoke_fence",
            ),
            (
                "authorization_cross_city_operation_activation",
                "coordinator_epoch",
            ),
            ("authorization_cross_city_operation_activation", "minted_at"),
            ("authorization_cross_city_authority_scope", "scope_id"),
            ("authorization_cross_city_authority_scope", "city_id"),
            ("authorization_cross_city_authority_scope", "scope_digest"),
            ("authorization_cross_city_authority_scope", "authoritative"),
            ("authorization_cross_city_authority_scope", "registered_at"),
        ],
        indexes: CROSS_CITY_RUNTIME_PROOF_INDEXES,
    },
    ExactMigrationArtifactContract {
        version: REVIEW_SCHEMA_REPAIR_VERSION,
        source_sha384: REVIEW_SCHEMA_REPAIR_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &["al_message_scope_counter"],
        columns: REVIEW_SCHEMA_REPAIR_COLUMNS,
        indexes: REVIEW_SCHEMA_REPAIR_INDEXES,
    },
    // Identity's 00001 migration only alters established Identity tables; it
    // cannot create missing base tables. Its source owner is verified by the
    // checked-in LF pin before artifact ownership can be used.
    ExactMigrationArtifactContract {
        version: IDENTITY_CREDENTIAL_FENCE_VERSION,
        source_sha384: IDENTITY_CREDENTIAL_FENCE_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: IDENTITY_CREDENTIAL_FENCE_COLUMNS_ARTIFACTS,
        indexes: IDENTITY_CREDENTIAL_FENCE_INDEXES,
    },
    // Async-operation creator. Requester scope and item operation identity are
    // both written by the service in the same source transaction.
    ExactMigrationArtifactContract {
        version: ASYNC_OPERATION_CORRELATION_VERSION,
        source_sha384: ASYNC_OPERATION_CORRELATION_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: ASYNC_OPERATION_TABLES,
        columns: ASYNC_OPERATION_COLUMNS_ARTIFACTS,
        indexes: ASYNC_OPERATION_INDEXES,
    },
    // Chat send-intent creator; exact physical validation is repeated by Chat's
    // private startup gate when the subsystem is enabled.
    ExactMigrationArtifactContract {
        version: CHAT_DELIVERY_INTENT_VERSION,
        source_sha384: CHAT_DELIVERY_INTENT_SQL_SHA384,
        supports_existing_artifacts: false,
        tables: CHAT_DELIVERY_INTENT_TABLES,
        columns: CHAT_DELIVERY_INTENT_COLUMNS_ARTIFACTS,
        indexes: CHAT_DELIVERY_INTENT_INDEXES,
    },
    // Learn adds one exact nullable marker + course-scoped uniqueness to the
    // existing learn_assignment creator; the history is intentionally untouched.
    ExactMigrationArtifactContract {
        version: LEARN_SYSTEM_ASSIGNMENT_VERSION,
        source_sha384: LEARN_SYSTEM_ASSIGNMENT_SQL_SHA384,
        supports_existing_artifacts: true,
        tables: &[],
        columns: LEARN_SYSTEM_ASSIGNMENT_COLUMNS_ARTIFACTS,
        indexes: LEARN_SYSTEM_ASSIGNMENT_INDEXES,
    },
];

fn character_indices(value: &str, character_index: usize) -> usize {
    value
        .char_indices()
        .nth(character_index)
        .map_or(value.len(), |(byte_index, _)| byte_index)
}

fn matching_parenthesis(value: &str, open: usize) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut depth = 0_u32;
    let mut index = open;
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == delimiter {
                if bytes.get(index + 1) == Some(&delimiter) {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
        } else if byte == b'(' {
            depth += 1;
        } else if byte == b')' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn first_sql_word(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let end = value
        .find(|character: char| character.is_ascii_whitespace() || character == '(')
        .unwrap_or(value.len());
    if end == 0 {
        None
    } else {
        Some((&value[..end], &value[end..]))
    }
}

fn normalized_identifier(value: &str) -> String {
    value.trim().trim_matches('`').to_ascii_uppercase()
}

fn index_columns(value: &str) -> Option<Vec<String>> {
    let open = value.find('(')?;
    let close = matching_parenthesis(value, open)?;
    let columns = split_top_level_items(&value[open + 1..close])?;
    Some(
        columns
            .into_iter()
            .map(|column| {
                first_sql_word(column)
                    .map(|(word, _)| normalized_identifier(word))
                    .unwrap_or_default()
            })
            .collect(),
    )
}

fn parse_create_table(statement: &str) -> Option<Vec<MigrationArtifact>> {
    let statement = normalized_sql_fragment(statement);
    let remainder = statement
        .strip_prefix("CREATE TABLE IF NOT EXISTS ")
        .or_else(|| statement.strip_prefix("CREATE TABLE "))?;
    let (table, _) = first_sql_word(remainder)?;
    let table = normalized_identifier(table);
    let open = statement.find('(')?;
    let close = matching_parenthesis(&statement, open)?;
    let body = &statement[open + 1..close];
    let mut artifacts = vec![MigrationArtifact {
        kind: MigrationArtifactKind::Table,
        table: table.clone(),
        name: table.clone(),
        columns: Vec::new(),
        unique: false,
    }];
    for item in split_top_level_items(body)? {
        let item = item.trim();
        if item.is_empty() {
            return None;
        }
        let upper = item.to_ascii_uppercase();
        if upper.starts_with("PRIMARY KEY") {
            artifacts.push(MigrationArtifact {
                kind: MigrationArtifactKind::CreateIndex,
                table: table.clone(),
                name: "PRIMARY".to_owned(),
                columns: index_columns(item)?,
                unique: true,
            });
        } else if upper.starts_with("UNIQUE KEY ") || upper.starts_with("UNIQUE INDEX ") {
            let remainder = item
                .strip_prefix("UNIQUE KEY ")
                .or_else(|| item.strip_prefix("UNIQUE INDEX "))?;
            let (name, _) = first_sql_word(remainder)?;
            artifacts.push(MigrationArtifact {
                kind: MigrationArtifactKind::CreateIndex,
                table: table.clone(),
                name: normalized_identifier(name),
                columns: index_columns(item)?,
                unique: true,
            });
        } else if upper.starts_with("KEY ") || upper.starts_with("INDEX ") {
            let remainder = item
                .strip_prefix("KEY ")
                .or_else(|| item.strip_prefix("INDEX "))?;
            let (name, _) = first_sql_word(remainder)?;
            artifacts.push(MigrationArtifact {
                kind: MigrationArtifactKind::CreateIndex,
                table: table.clone(),
                name: normalized_identifier(name),
                columns: index_columns(item)?,
                unique: false,
            });
        } else {
            let (name, _) = first_sql_word(item)?;
            artifacts.push(MigrationArtifact {
                kind: MigrationArtifactKind::CreateColumn,
                table: table.clone(),
                name: normalized_identifier(name),
                columns: Vec::new(),
                unique: false,
            });
        }
    }
    Some(artifacts)
}

fn parse_alter_table(statement: &str) -> Option<Vec<MigrationArtifact>> {
    let statement = normalized_sql_fragment(statement);
    let remainder = statement.strip_prefix("ALTER TABLE ")?;
    let (table, actions) = first_sql_word(remainder)?;
    let table = normalized_identifier(table);
    let mut artifacts = Vec::new();
    for action in split_top_level_items(actions)? {
        let action = action.trim();
        let column = action
            .strip_prefix("ADD COLUMN IF NOT EXISTS ")
            .or_else(|| action.strip_prefix("ADD COLUMN "));
        if let Some(column) = column {
            let (name, _) = first_sql_word(column)?;
            artifacts.push(MigrationArtifact {
                kind: MigrationArtifactKind::AddColumn,
                table: table.clone(),
                name: normalized_identifier(name),
                columns: Vec::new(),
                unique: false,
            });
            continue;
        }

        let index_action = action
            .strip_prefix("ADD PRIMARY KEY ")
            .map(|value| ("PRIMARY", value, true))
            .or_else(|| {
                action
                    .strip_prefix("ADD UNIQUE KEY ")
                    .or_else(|| action.strip_prefix("ADD UNIQUE INDEX "))
                    .and_then(|value| {
                        let (name, _) = first_sql_word(value)?;
                        Some((name, value, true))
                    })
            })
            .or_else(|| {
                action
                    .strip_prefix("ADD KEY ")
                    .or_else(|| action.strip_prefix("ADD INDEX "))
                    .and_then(|value| {
                        let (name, _) = first_sql_word(value)?;
                        Some((name, value, false))
                    })
            });
        if let Some((name, index, unique)) = index_action {
            artifacts.push(MigrationArtifact {
                kind: MigrationArtifactKind::AddIndex,
                table: table.clone(),
                name: normalized_identifier(name),
                columns: index_columns(index)?,
                unique,
            });
            continue;
        }
        return Some(Vec::new());
    }
    Some(artifacts)
}

fn sql_string_literals(statement: &str) -> Option<Vec<String>> {
    let bytes = statement.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\'' {
            index += 1;
            continue;
        }
        index += 1;
        let mut literal = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' {
                let escaped = *bytes.get(index + 1)?;
                literal.push(escaped as char);
                index += 2;
            } else if byte == b'\'' {
                if bytes.get(index + 1) == Some(&b'\'') {
                    literal.push('\'');
                    index += 2;
                } else {
                    index += 1;
                    break;
                }
            } else {
                literal.push(byte as char);
                index += 1;
            }
        }
        if index > bytes.len() || (index == bytes.len() && bytes[index - 1] != b'\'') {
            return None;
        }
        literals.push(literal);
    }
    Some(literals)
}

fn exact_migration_artifact_contract(
    migration: &Migration,
) -> Option<&'static ExactMigrationArtifactContract> {
    let contract = EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .find(|contract| contract.version == migration.version)?;

    // The SQLx checksum protects the exact checked-in bytes. The canonical hash
    // additionally pins the LF-normalized source contract used by this table.
    if !migration_matches_known_source(migration)
        || canonical_sha384_hex(migration.sql.as_bytes()) != contract.source_sha384
    {
        return None;
    }
    if REVIEW_SLICE_MIGRATION_VERSIONS.contains(&migration.version) {
        let artifacts = parsed_migration_artifacts(migration)?;
        if !exact_contract_artifacts_match_source(contract, &artifacts) {
            return None;
        }
    }
    Some(contract)
}

fn exact_contract_artifacts_match_source(
    contract: &ExactMigrationArtifactContract,
    artifacts: &[MigrationArtifact],
) -> bool {
    let source_has_table = |table: &str| {
        artifacts.iter().any(|artifact| {
            artifact.kind == MigrationArtifactKind::Table
                && artifact.name.eq_ignore_ascii_case(table)
        })
    };
    let source_has_column = |table: &str, column: &str| {
        artifacts.iter().any(|artifact| {
            matches!(
                artifact.kind,
                MigrationArtifactKind::CreateColumn | MigrationArtifactKind::AddColumn
            ) && artifact.table.eq_ignore_ascii_case(table)
                && artifact.name.eq_ignore_ascii_case(column)
        })
    };
    let source_has_index = |table: &str, index: &str, columns: &[&str], unique: bool| {
        artifacts.iter().any(|artifact| {
            matches!(
                artifact.kind,
                MigrationArtifactKind::CreateIndex | MigrationArtifactKind::AddIndex
            ) && artifact.table.eq_ignore_ascii_case(table)
                && artifact.name.eq_ignore_ascii_case(index)
                && artifact.unique == unique
                && artifact.columns.len() == columns.len()
                && artifact
                    .columns
                    .iter()
                    .zip(columns)
                    .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        })
    };
    let artifact_is_declared = |artifact: &MigrationArtifact| match artifact.kind {
        MigrationArtifactKind::Table => exact_contract_defines_table(contract, &artifact.name),
        MigrationArtifactKind::CreateColumn | MigrationArtifactKind::AddColumn => {
            exact_contract_defines_column(contract, &artifact.table, &artifact.name)
        }
        MigrationArtifactKind::CreateIndex | MigrationArtifactKind::AddIndex => {
            let columns: Vec<&str> = artifact.columns.iter().map(String::as_str).collect();
            exact_contract_defines_index(
                contract,
                &artifact.table,
                &artifact.name,
                &columns,
                artifact.unique,
            )
        }
    };
    artifacts.iter().all(artifact_is_declared)
        && contract.tables.iter().all(|table| source_has_table(table))
        && contract
            .columns
            .iter()
            .all(|(table, column)| source_has_column(table, column))
        && contract
            .indexes
            .iter()
            .all(|(table, index, columns, unique)| source_has_index(table, index, columns, *unique))
}

fn exact_contract_defines_table(contract: &ExactMigrationArtifactContract, table: &str) -> bool {
    contract
        .tables
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(table))
}

fn exact_contract_defines_column(
    contract: &ExactMigrationArtifactContract,
    table: &str,
    column: &str,
) -> bool {
    contract.columns.iter().any(|(owner_table, owner_column)| {
        owner_table.eq_ignore_ascii_case(table) && owner_column.eq_ignore_ascii_case(column)
    })
}

fn exact_contract_defines_index(
    contract: &ExactMigrationArtifactContract,
    table: &str,
    index: &str,
    columns: &[&str],
    unique: bool,
) -> bool {
    contract
        .indexes
        .iter()
        .any(|(owner_table, owner_index, owner_columns, owner_unique)| {
            owner_table.eq_ignore_ascii_case(table)
                && owner_index.eq_ignore_ascii_case(index)
                && *owner_unique == unique
                && owner_columns.len() == columns.len()
                && owner_columns
                    .iter()
                    .zip(columns)
                    .all(|(owner_column, column)| owner_column.eq_ignore_ascii_case(column))
        })
}

fn parsed_migration_artifacts(migration: &Migration) -> Option<Vec<MigrationArtifact>> {
    if !migration_matches_known_source(migration) {
        return None;
    }
    let mut artifacts = Vec::new();
    for statement in sql_statements(migration.sql.as_ref())? {
        let normalized = normalized_sql_fragment(&statement);
        if normalized.starts_with("CREATE TABLE ") {
            if let Some(parsed) = parse_create_table(&statement) {
                artifacts.extend(parsed);
            }
        } else if normalized.starts_with("ALTER TABLE ") {
            if let Some(parsed) = parse_alter_table(&statement) {
                artifacts.extend(parsed);
            }
        } else if normalized.starts_with("SET ") && normalized.contains("IF") {
            for literal in sql_string_literals(&statement)? {
                if normalized_sql_fragment(&literal).starts_with("ALTER TABLE ") {
                    if let Some(parsed) = parse_alter_table(&literal) {
                        artifacts.extend(parsed);
                    }
                }
            }
        }
    }
    Some(artifacts)
}

fn migration_defines_table(migration: &Migration, table: &str) -> bool {
    if EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .any(|contract| contract.version == migration.version)
    {
        return exact_migration_artifact_contract(migration)
            .is_some_and(|contract| exact_contract_defines_table(contract, table));
    }

    let table = normalized_identifier(table);
    parsed_migration_artifacts(migration).is_some_and(|artifacts| {
        artifacts
            .iter()
            .any(|artifact| artifact.kind == MigrationArtifactKind::Table && artifact.name == table)
    })
}

fn migration_defines_column(migration: &Migration, table: &str, column: &str) -> bool {
    if EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .any(|contract| contract.version == migration.version)
    {
        return exact_migration_artifact_contract(migration)
            .is_some_and(|contract| exact_contract_defines_column(contract, table, column));
    }

    let table = normalized_identifier(table);
    let column = normalized_identifier(column);
    parsed_migration_artifacts(migration).is_some_and(|artifacts| {
        artifacts.iter().any(|artifact| {
            matches!(
                artifact.kind,
                MigrationArtifactKind::CreateColumn | MigrationArtifactKind::AddColumn
            ) && artifact.table == table
                && artifact.name == column
        })
    })
}

fn migration_defines_index(
    migration: &Migration,
    table: &str,
    index: &str,
    columns: &[&str],
    unique: bool,
) -> bool {
    if EXACT_MIGRATION_ARTIFACT_CONTRACTS
        .iter()
        .any(|contract| contract.version == migration.version)
    {
        return exact_migration_artifact_contract(migration).is_some_and(|contract| {
            exact_contract_defines_index(contract, table, index, columns, unique)
        });
    }

    let table = normalized_identifier(table);
    let index = normalized_identifier(index);
    let columns: Vec<String> = columns
        .iter()
        .map(|column| normalized_identifier(column))
        .collect();
    parsed_migration_artifacts(migration).is_some_and(|artifacts| {
        artifacts.iter().any(|artifact| {
            matches!(
                artifact.kind,
                MigrationArtifactKind::CreateIndex | MigrationArtifactKind::AddIndex
            ) && artifact.table == table
                && artifact.name == index
                && artifact.columns == columns
                && artifact.unique == unique
        })
    })
}

fn pending_migration_defines_column(migration: &Migration, table: &str, column: &str) -> bool {
    migration_defines_column(migration, table, column)
        || migration_defines_existing_column(migration, table, column)
}

fn pending_migration_defines_index(
    migration: &Migration,
    table: &str,
    index: &str,
    columns: &[&str],
    unique: bool,
) -> bool {
    migration_defines_index(migration, table, index, columns, unique)
        || migration_defines_existing_index(migration, table, index, columns, unique)
}

fn pending_index_satisfies_preflight(
    absent_tables: &HashSet<&str>,
    migration: &Migration,
    table: &str,
    index: &str,
    columns: &[&str],
    unique: bool,
) -> bool {
    if absent_tables.contains(table) {
        pending_migration_defines_index(migration, table, index, columns, unique)
    } else {
        migration_defines_existing_index(migration, table, index, columns, unique)
    }
}

fn migration_defines_existing_column(migration: &Migration, table: &str, column: &str) -> bool {
    let table = normalized_identifier(table);
    let column = normalized_identifier(column);
    parsed_migration_artifacts(migration).is_some_and(|artifacts| {
        let declared = EXACT_MIGRATION_ARTIFACT_CONTRACTS
            .iter()
            .find(|contract| contract.version == migration.version)
            .is_none_or(|contract| {
                contract.supports_existing_artifacts
                    && exact_contract_defines_column(contract, &table, &column)
            });
        declared
            && artifacts.iter().any(|artifact| {
                artifact.kind == MigrationArtifactKind::AddColumn
                    && artifact.table == table
                    && artifact.name == column
            })
    })
}

fn migration_defines_existing_index(
    migration: &Migration,
    table: &str,
    index: &str,
    columns: &[&str],
    unique: bool,
) -> bool {
    let table = normalized_identifier(table);
    let index = normalized_identifier(index);
    let columns: Vec<String> = columns
        .iter()
        .map(|column| normalized_identifier(column))
        .collect();
    parsed_migration_artifacts(migration).is_some_and(|artifacts| {
        let declared = EXACT_MIGRATION_ARTIFACT_CONTRACTS
            .iter()
            .find(|contract| contract.version == migration.version)
            .is_none_or(|contract| {
                contract.supports_existing_artifacts
                    && exact_contract_defines_index(
                        contract,
                        &table,
                        &index,
                        &columns.iter().map(String::as_str).collect::<Vec<_>>(),
                        unique,
                    )
            });
        declared
            && artifacts.iter().any(|artifact| {
                artifact.kind == MigrationArtifactKind::AddIndex
                    && artifact.table == table
                    && artifact.name == index
                    && artifact.columns == columns
                    && artifact.unique == unique
            })
    })
}

async fn schema_table_exists(pool: &MySqlPool, table: &str) -> Result<bool, MigrationError> {
    let count = metadata_count(
        sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_EXISTS_SQL)
            .bind(table)
            .fetch_one(pool)
            .await
            .map_err(|e| MigrationError::Failed(format!("inspect schema table {table}: {e}")))?,
        "inspect schema table preflight",
    )?;
    Ok(count == 1)
}

async fn schema_column_exists(
    pool: &MySqlPool,
    table: &str,
    column: &str,
) -> Result<bool, MigrationError> {
    let count = metadata_count(
        sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_COLUMN_EXISTS_SQL)
            .bind(table)
            .bind(column)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!(
                    "inspect schema column {table}.{column} preflight: {e}"
                ))
            })?,
        "inspect schema column preflight",
    )?;
    Ok(count == 1)
}

fn historical_migration_compatibility(
    version: i64,
) -> Option<&'static HistoricalMigrationCompatibility> {
    HISTORICAL_MIGRATION_COMPATIBILITY
        .iter()
        .find(|contract| contract.version == version)
}

fn historical_mysql8_compatible_sql(
    migration: &Migration,
) -> Result<Cow<'static, str>, MigrationError> {
    let contract = historical_migration_compatibility(migration.version).ok_or_else(|| {
        MigrationError::Failed(format!(
            "migration {} is not an approved historical compatibility migration",
            migration.version
        ))
    })?;
    validate_historical_migration_compatibility(migration, contract)?;

    // Execute a canonical LF copy only. The source file is pinned to LF by
    // .gitattributes; normalization also makes this path independent of a
    // pre-existing Windows worktree checkout.
    let mut compatible_sql = migration.sql.replace("\r\n", "\n");
    for statement in contract.incompatible_statements {
        let normalized_statement = statement.replace("\r\n", "\n");
        let replacement = match contract.rewrite {
            HistoricalMigrationRewrite::ReplaceWithSelect1 => "SELECT 1;".to_owned(),
        };
        compatible_sql = compatible_sql.replace(&normalized_statement, &replacement);
    }
    for (source, replacement) in contract.exact_rewrites {
        let normalized_source = source.replace("\r\n", "\n");
        let normalized_replacement = replacement.replace("\r\n", "\n");
        compatible_sql = compatible_sql.replace(&normalized_source, &normalized_replacement);
    }
    Ok(Cow::Owned(compatible_sql))
}

fn validate_historical_migration_compatibility(
    migration: &Migration,
    contract: &HistoricalMigrationCompatibility,
) -> Result<(), MigrationError> {
    if migration.version != contract.version {
        return Err(MigrationError::Failed(
            "historical migration compatibility version mismatch".into(),
        ));
    }

    let actual_checksum = canonical_sha384_hex(migration.sql.as_bytes());
    if actual_checksum != contract.source_sha384 {
        return Err(MigrationError::Failed(format!(
            "migration {} embedded SQL checksum does not match the historical compatibility contract",
            migration.version
        )));
    }

    if !historical_sql_has_known_incompatible_statements(migration, contract) {
        return Err(MigrationError::Failed(format!(
            "migration {} historical compatibility statement contract does not match embedded SQL",
            migration.version
        )));
    }
    if !historical_sql_has_known_exact_rewrites(migration, contract) {
        return Err(MigrationError::Failed(format!(
            "migration {} historical compatibility exact rewrite contract does not match embedded SQL",
            migration.version
        )));
    }
    Ok(())
}

async fn preflight_historical_migration_schema_contract(
    pool: &MySqlPool,
    migration: &Migration,
    migration_pending: bool,
    explicit_apply: bool,
) -> Result<(), MigrationError> {
    let contract = historical_migration_compatibility(migration.version).ok_or_else(|| {
        MigrationError::Failed(format!(
            "migration {} is not an approved historical compatibility migration",
            migration.version
        ))
    })?;
    validate_historical_migration_compatibility(migration, contract)?;

    if migration.version == TRUSTGRAPH_RUNTIME_TABLES_VERSION {
        return preflight_trustgraph_runtime_schema_contract(
            pool,
            migration,
            migration_pending,
            explicit_apply,
        )
        .await;
    }

    let mut table_names = HashSet::new();
    for column in contract.columns {
        table_names.insert(column.table);
    }
    for table in table_names {
        let table_count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_EXISTS_SQL)
                .bind(table)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "inspect historical migration table {table}: {e}"
                    ))
                })?,
            "inspect historical migration table",
        )?;
        if table_count != 1 {
            return Err(MigrationError::Failed(format!(
                "historical migration {} preflight requires {table} table",
                migration.version
            )));
        }
    }

    if migration_pending {
        // Process the declaration in order. A missing column is added before
        // inspecting the next column, so a later existing column can defer its
        // position check until its missing predecessor becomes an anchor.
        for column in contract.columns {
            let metadata = inspect_historical_column(pool, column).await?;
            let action = historical_column_action(metadata.as_ref(), column);
            if action == HistoricalColumnAction::Fail {
                let existing = metadata
                    .as_ref()
                    .expect("non-empty metadata for fail action");
                return Err(MigrationError::Failed(format!(
                    "historical migration column {}.{} is incompatible: expected {} {} DEFAULT {} AFTER {}, found {} AFTER {}",
                    column.table,
                    column.name,
                    column.column_type,
                    if column.not_null { "NOT NULL" } else { "NULL" },
                    column.default.map_or_else(|| "NULL".into(), sql_literal),
                    column.after,
                    historical_column_definition(existing),
                    existing.after
                )));
            }
            if action != HistoricalColumnAction::Add {
                continue;
            }

            let statement = format!(
                "ALTER TABLE `{}` ADD COLUMN `{}` {}{} {}{} AFTER `{}`",
                column.table,
                column.name,
                column.column_type,
                expected_character_set_clause(column),
                if column.not_null { "NOT NULL" } else { "NULL" },
                column.default.map_or_else(String::new, |default| format!(
                    " DEFAULT {}",
                    sql_literal(default)
                )),
                column.after
            );
            sqlx::query(&statement).execute(pool).await.map_err(|e| {
                MigrationError::Failed(format!(
                    "add historical migration column {}.{} (partial DDL may remain; rerun will revalidate all columns): {e}",
                    column.table, column.name
                ))
            })?;
        }

        // Re-inspect after all ordered additions. Deferred columns must now
        // have an exact immediate predecessor; otherwise the migration fails.
        for column in contract.columns {
            let metadata = inspect_historical_column(pool, column).await?;
            if historical_column_action(metadata.as_ref(), column) != HistoricalColumnAction::Skip {
                return Err(MigrationError::Failed(format!(
                    "historical migration {} pending preflight did not settle column {}.{} into its exact contract",
                    migration.version, column.table, column.name
                )));
            }
        }
    } else {
        for column in contract.columns {
            let metadata = inspect_historical_column(pool, column).await?;
            let action = historical_column_action(metadata.as_ref(), column);
            if action != HistoricalColumnAction::Skip {
                return Err(MigrationError::Failed(format!(
                    "historical migration {} is recorded but column {}.{} is missing or not exactly ordered; refusing historical ALTER",
                    migration.version, column.table, column.name
                )));
            }
        }
    }
    Ok(())
}

async fn preflight_trustgraph_runtime_schema_contract(
    pool: &MySqlPool,
    _migration: &Migration,
    migration_pending: bool,
    explicit_apply: bool,
) -> Result<(), MigrationError> {
    let state = inspect_trustgraph_runtime_schema(pool).await?;
    match state {
        TrustgraphRuntimeSchemaState::Missing => {
            if !explicit_apply {
                return Err(MigrationError::Failed(
                    "TrustGraph runtime tables are missing; ordinary startup cannot execute DDL; run the explicit Rust migration job".into(),
                ));
            }
            if !migration_pending {
                return Err(MigrationError::Failed(
                    "TrustGraph runtime migration is recorded but all runtime tables are missing; restore the exact supported baseline or remove the stale history only through the approved migration recovery procedure".into(),
                ));
            }
            // The checksum-pinned source body is the sole DDL owner for an
            // entirely new Rust schema. Let SQLx execute it once so a failure
            // remains represented by its normal success=0 history row.
        }
        TrustgraphRuntimeSchemaState::Partial => {
            return Err(MigrationError::Failed(
                "TrustGraph runtime schema is partially present; refusing to mix full_schema_v4 and Rust-created tables; restore the exact baseline or remove the incomplete runtime tables before rerunning the explicit migration".into(),
            ));
        }
        TrustgraphRuntimeSchemaState::Baseline {
            status_index_present,
        } => {
            if !status_index_present {
                if !explicit_apply {
                    return Err(MigrationError::Failed(
                        "full_schema_v4 TrustGraph baseline is missing sod_policy.idx_sod_status; run the explicit Rust migration job".into(),
                    ));
                }
                sqlx::query("ALTER TABLE `sod_policy` ADD KEY `idx_sod_status` (`status`)")
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        MigrationError::Failed(format!(
                            "add required full_schema_v4 runtime index sod_policy.idx_sod_status: {e}"
                        ))
                    })?;
            }
            ensure_trustgraph_runtime_baseline_ready(pool).await?;
        }
        TrustgraphRuntimeSchemaState::BaselineReady => {
            // The status index is already present, but readiness still requires
            // the runtime data/null checks. Index existence is not data validity.
            ensure_trustgraph_runtime_baseline_ready(pool).await?;
        }
        TrustgraphRuntimeSchemaState::Source => {}
        TrustgraphRuntimeSchemaState::Unsupported => {
            return Err(MigrationError::Failed(
                "TrustGraph runtime schema does not match the supported full_schema_v4 baseline or Rust-created source contract; no destructive convergence is attempted".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustgraphRuntimeSchemaState {
    Missing,
    Partial,
    Baseline { status_index_present: bool },
    BaselineReady,
    Source,
    Unsupported,
}

async fn inspect_trustgraph_runtime_schema(
    pool: &MySqlPool,
) -> Result<TrustgraphRuntimeSchemaState, MigrationError> {
    let mut present = 0_u8;
    for table in TRUSTGRAPH_RUNTIME_TABLES {
        let count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_EXISTS_SQL)
                .bind(table.table)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "inspect TrustGraph runtime table {}: {e}",
                        table.table
                    ))
                })?,
            "inspect TrustGraph runtime table",
        )?;
        if count > 1 {
            return Err(MigrationError::Failed(format!(
                "TrustGraph runtime table {} has ambiguous metadata",
                table.table
            )));
        }
        present += count as u8;
    }
    if present == 0 {
        return Ok(TrustgraphRuntimeSchemaState::Missing);
    }
    if present != TRUSTGRAPH_RUNTIME_TABLES.len() as u8 {
        return Ok(TrustgraphRuntimeSchemaState::Partial);
    }

    for table in TRUSTGRAPH_RUNTIME_TABLES {
        validate_table_contract(
            pool,
            table.table,
            table.charset,
            table.collation,
            Some("InnoDB"),
        )
        .await?;
    }

    let baseline_columns = schema_columns_match(pool, TRUSTGRAPH_BASELINE_COLUMN_CONTRACT).await?;
    let source_columns = schema_columns_match(pool, TRUSTGRAPH_SOURCE_COLUMN_CONTRACT).await?;
    let baseline_indexes = schema_indexes_match(pool, TRUSTGRAPH_BASELINE_INDEXES).await?;
    let baseline_ready_indexes =
        schema_indexes_match(pool, TRUSTGRAPH_BASELINE_READY_INDEXES).await?;
    let source_indexes = schema_indexes_match(pool, TRUSTGRAPH_SOURCE_INDEXES).await?;
    let no_foreign_keys = schema_foreign_keys_match(pool, "sod_violation", &[]).await?;
    let source_foreign_keys =
        schema_foreign_keys_match(pool, "sod_violation", TRUSTGRAPH_SOURCE_FOREIGN_KEYS).await?;
    let other_tables_have_no_foreign_keys = schema_foreign_keys_match(pool, "sod_policy", &[])
        .await?
        && schema_foreign_keys_match(pool, "identity_global_admin", &[]).await?;

    if baseline_columns && no_foreign_keys && other_tables_have_no_foreign_keys && baseline_indexes
    {
        return Ok(TrustgraphRuntimeSchemaState::Baseline {
            status_index_present: false,
        });
    }
    if baseline_columns
        && no_foreign_keys
        && other_tables_have_no_foreign_keys
        && baseline_ready_indexes
    {
        return Ok(TrustgraphRuntimeSchemaState::BaselineReady);
    }
    if source_columns && source_indexes && source_foreign_keys && other_tables_have_no_foreign_keys
    {
        return Ok(TrustgraphRuntimeSchemaState::Source);
    }
    Ok(TrustgraphRuntimeSchemaState::Unsupported)
}

async fn ensure_trustgraph_runtime_baseline_ready(pool: &MySqlPool) -> Result<(), MigrationError> {
    if inspect_trustgraph_runtime_schema(pool).await? != TrustgraphRuntimeSchemaState::BaselineReady
    {
        return Err(MigrationError::Failed(
            "full_schema_v4 TrustGraph baseline repair did not produce the exact supported ready contract".into(),
        ));
    }
    let null_rows = metadata_count(
        sqlx::query_scalar::<_, Vec<u8>>(TRUSTGRAPH_BASELINE_RUNTIME_NULLS_SQL)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!(
                    "inspect TrustGraph baseline runtime nullability: {e}"
                ))
            })?,
        "inspect TrustGraph baseline runtime nullability",
    )?;
    if null_rows != 0 {
        return Err(MigrationError::Failed(format!(
            "full_schema_v4 TrustGraph baseline contains {null_rows} NULL value(s) in fields required by Rust runtime decoding; repair the data explicitly before rerunning"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoricalColumnMetadata {
    column_type: String,
    nullable: String,
    default: Option<String>,
    charset: Option<String>,
    collation: Option<String>,
    after: String,
    position_deferred: bool,
    position_matches: bool,
}

// Tuple order is the SELECT projection order in
// HISTORICAL_COLUMN_METADATA_SQL: name, type, nullability, default,
// character set, collation, ordinal position. Keep numeric metadata as bytes;
// MySQL 5.7/8 may report different signedness for information_schema fields.
type HistoricalColumnMetadataRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
);

type HistoricalColumnPositionRow = (Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>);

impl HistoricalColumnMetadata {
    fn action(&self, expected: &HistoricalColumnSpec) -> HistoricalColumnAction {
        let type_matches = normalize_column_definition(&self.column_type)
            == normalize_column_definition(expected.column_type);
        let nullable_matches =
            self.nullable
                .eq_ignore_ascii_case(if expected.not_null { "NO" } else { "YES" });
        let default_matches = column_default_matches(self.default.as_deref(), expected.default);
        let character_metadata_matches = validate_character_metadata(
            &self.column_type,
            self.charset.as_deref(),
            self.collation.as_deref(),
            expected,
        );
        if !type_matches || !nullable_matches || !default_matches || !character_metadata_matches {
            HistoricalColumnAction::Fail
        } else if self.position_deferred {
            HistoricalColumnAction::Deferred
        } else if !self.position_matches || !self.after.eq_ignore_ascii_case(expected.after) {
            HistoricalColumnAction::Fail
        } else {
            HistoricalColumnAction::Skip
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoricalColumnAction {
    Add,
    Skip,
    Deferred,
    Fail,
}

fn historical_column_action(
    metadata: Option<&HistoricalColumnMetadata>,
    expected: &HistoricalColumnSpec,
) -> HistoricalColumnAction {
    metadata.map_or(HistoricalColumnAction::Add, |metadata| {
        metadata.action(expected)
    })
}

fn sql_literal(value: &str) -> String {
    if value.chars().all(|character| character.is_ascii_digit()) {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "''"))
    }
}

fn expected_character_set_clause(expected: &HistoricalColumnSpec) -> String {
    match (expected.charset, expected.collation) {
        (Some(charset), Some(collation)) => {
            format!(" CHARACTER SET {charset} COLLATE {collation}")
        }
        (None, None) => String::new(),
        _ => String::new(),
    }
}

fn historical_column_definition(metadata: &HistoricalColumnMetadata) -> String {
    format!(
        "{} {} DEFAULT {}",
        metadata.column_type,
        if metadata.nullable.eq_ignore_ascii_case("YES") {
            "NULL"
        } else {
            "NOT NULL"
        },
        metadata
            .default
            .as_deref()
            .map_or_else(|| "NULL".into(), sql_literal)
    )
}

fn is_character_type(column_type: &str) -> bool {
    let type_name = column_type
        .split(['(', ' ', '\t'])
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        type_name.as_str(),
        "CHAR" | "VARCHAR" | "TINYTEXT" | "TEXT" | "MEDIUMTEXT" | "LONGTEXT" | "ENUM" | "SET"
    )
}

fn metadata_name_is_present(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn validate_character_metadata(
    column_type: &str,
    charset: Option<&str>,
    collation: Option<&str>,
    expected: &HistoricalColumnSpec,
) -> bool {
    if is_character_type(column_type) {
        charset == expected.charset && collation == expected.collation
    } else {
        !metadata_name_is_present(charset) && !metadata_name_is_present(collation)
    }
}

fn historical_sql_has_known_incompatible_statements(
    migration: &Migration,
    contract: &HistoricalMigrationCompatibility,
) -> bool {
    if migration.version != contract.version {
        return false;
    }

    let normalized_sql = migration.sql.replace("\r\n", "\n");
    let known_statements_match = contract
        .incompatible_statements
        .iter()
        .map(|statement| statement.replace("\r\n", "\n"))
        .all(|statement| normalized_sql.matches(&statement).count() == 1);
    let add_column_statement_count = normalized_sql.matches("ADD COLUMN IF NOT EXISTS").count();

    known_statements_match && add_column_statement_count == contract.incompatible_statements.len()
}

fn historical_sql_has_known_exact_rewrites(
    migration: &Migration,
    contract: &HistoricalMigrationCompatibility,
) -> bool {
    if migration.version != contract.version {
        return false;
    }

    let normalized_sql = migration.sql.replace("\r\n", "\n");
    contract.exact_rewrites.iter().all(|(source, _)| {
        let normalized_source = source.replace("\r\n", "\n");
        normalized_sql.matches(&normalized_source).count() == 1
    })
}

fn normalize_column_definition(definition: &str) -> String {
    definition
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

fn metadata_text(
    field: &str,
    value: &[u8],
    table: &str,
    column: &str,
) -> Result<String, MigrationError> {
    String::from_utf8(value.to_vec()).map_err(|_| {
        MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: failed to decode {field} metadata"
        ))
    })
}

fn metadata_optional_name(
    field: &str,
    value: Option<&[u8]>,
    table: &str,
    column: &str,
) -> Result<Option<String>, MigrationError> {
    value
        .map(|value| metadata_text(field, value, table, column))
        .transpose()
        .map(|value| value.filter(|value| !value.is_empty()))
}

fn metadata_u64(
    field: &str,
    value: &[u8],
    table: &str,
    column: &str,
) -> Result<u64, MigrationError> {
    let text = metadata_text(field, value, table, column)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: invalid {field} numeric metadata"
        )));
    }
    text.parse::<u64>().map_err(|_| {
        MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: {field} numeric metadata overflows u64"
        ))
    })
}

fn metadata_count(value: Vec<u8>, context: &str) -> Result<u64, MigrationError> {
    let text = String::from_utf8(value).map_err(|_| {
        MigrationError::Failed(format!("{context}: failed to decode numeric metadata"))
    })?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MigrationError::Failed(format!(
            "{context}: invalid numeric metadata"
        )));
    }
    text.parse::<u64>()
        .map_err(|_| MigrationError::Failed(format!("{context}: numeric metadata overflows u64")))
}

fn metadata_optional_u64(
    value: Option<Vec<u8>>,
    context: &str,
) -> Result<Option<u64>, MigrationError> {
    value
        .map(|value| metadata_count(value, context))
        .transpose()
}

async fn inspect_historical_column(
    pool: &MySqlPool,
    expected: &HistoricalColumnSpec,
) -> Result<Option<HistoricalColumnMetadata>, MigrationError> {
    let table = expected.table;
    let column = expected.name;
    let row: Option<HistoricalColumnMetadataRow> = sqlx::query_as(HISTORICAL_COLUMN_METADATA_SQL)
        .bind(table)
        .bind(column)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!("inspect historical column {table}.{column}: {e}"))
        })?;

    let Some((name, column_type, nullable, default, charset, collation, ordinal_position)) = row
    else {
        return Ok(None);
    };
    let ordinal_position = metadata_u64("ORDINAL_POSITION", &ordinal_position, table, column)?;
    let name = metadata_text("COLUMN_NAME", &name, table, column)?;
    let column_type = metadata_text("COLUMN_TYPE", &column_type, table, column)?;
    let nullable = metadata_text("IS_NULLABLE", &nullable, table, column)?;
    if !nullable.eq_ignore_ascii_case("YES") && !nullable.eq_ignore_ascii_case("NO") {
        return Err(MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: unknown IS_NULLABLE metadata"
        )));
    }
    let default = default
        .as_deref()
        .map(|value| metadata_text("COLUMN_DEFAULT", value, table, column))
        .transpose()?;
    let charset = metadata_optional_name("CHARACTER_SET_NAME", charset.as_deref(), table, column)?;
    let collation = metadata_optional_name("COLLATION_NAME", collation.as_deref(), table, column)?;

    if name != column {
        return Err(MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: metadata name mismatch"
        )));
    }
    if !validate_character_metadata(
        &column_type,
        charset.as_deref(),
        collation.as_deref(),
        expected,
    ) {
        return Err(MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: character metadata is unknown or incompatible"
        )));
    }

    let previous_row: Option<HistoricalColumnPositionRow> =
        sqlx::query_as(HISTORICAL_COLUMN_POSITION_SQL)
            .bind(expected.after)
            .bind(table)
            .bind(column)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!(
                    "inspect historical column position {table}.{column}: {e}"
                ))
            })?;
    let (previous_name, previous_position, current_position, expected_position) =
        previous_row.ok_or_else(|| {
            MigrationError::Failed(format!(
                "inspect historical column position {table}.{column}: metadata is missing or incompatible"
            ))
        })?;
    let previous_name = previous_name
        .as_deref()
        .map(|value| metadata_text("COLUMN_NAME", value, table, column))
        .transpose()?
        .unwrap_or_default();
    let previous_position = metadata_optional_u64(
        previous_position,
        &format!("inspect historical column {table}.{column}: previous ORDINAL_POSITION"),
    )?;
    let expected_position = metadata_optional_u64(
        expected_position,
        &format!("inspect historical column {table}.{column}: expected ORDINAL_POSITION"),
    )?;
    let current_position =
        metadata_u64("current ORDINAL_POSITION", &current_position, table, column)?;
    if current_position == 0 {
        return Err(MigrationError::Failed(format!(
            "inspect historical column position {table}.{column}: current position is zero"
        )));
    }

    // Position mismatches are returned as metadata and classified by the exact
    // contract matcher. This allows the explicitly supported baseline shape to
    // be checked without weakening drift rejection.
    let position_deferred = expected_position.is_none();
    let position_matches = position_deferred
        || (previous_position.is_some()
            && previous_position.and_then(|position| position.checked_add(1))
                == Some(current_position)
            && previous_name.eq_ignore_ascii_case(expected.after));

    if ordinal_position != current_position {
        return Err(MigrationError::Failed(format!(
            "inspect historical column {table}.{column}: ordinal position metadata is inconsistent"
        )));
    }

    Ok(Some(HistoricalColumnMetadata {
        column_type,
        nullable,
        default,
        charset,
        collation,
        after: previous_name,
        position_deferred,
        position_matches,
    }))
}

async fn acquire_migration_lock(connection: &mut MySqlConnection) -> Result<(), MigrationError> {
    let acquired: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 30)")
        .bind(MIGRATION_LOCK_NAME)
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| MigrationError::Failed(format!("acquire migration lock: {e}")))?;
    if acquired != Some(1) {
        return Err(MigrationError::Failed(
            "migration lock was not acquired".into(),
        ));
    }
    Ok(())
}

async fn release_migration_lock(connection: &mut MySqlConnection) -> Result<(), MigrationError> {
    let released: Option<i64> = sqlx::query_scalar("SELECT RELEASE_LOCK(?)")
        .bind(MIGRATION_LOCK_NAME)
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| MigrationError::Failed(format!("release migration lock: {e}")))?;
    if released != Some(1) {
        return Err(MigrationError::Failed(
            "migration lock was not released by owner".into(),
        ));
    }
    Ok(())
}

fn resolve_migration_result(
    migration_result: Result<(), MigrationError>,
    cleanup_result: Result<(), MigrationError>,
) -> Result<(), MigrationError> {
    match (migration_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(original), Ok(())) => Err(original),
        (Ok(()), Err(cleanup)) => Err(MigrationError::RecoveryRequired {
            reason: format!(
                "migrations completed but migration lock cleanup failed; explicit recovery is required: {cleanup}"
            ),
        }),
        (Err(original), Err(cleanup)) => {
            tracing::error!(
                error = %cleanup,
                "migration lock cleanup failed while preserving the original migration error"
            );
            Err(original)
        }
    }
}

async fn normalize_migration_history_schema(pool: &MySqlPool) -> Result<(), MigrationError> {
    if !migration_column_exists(pool, "installed_on").await? {
        sqlx::query(
            "ALTER TABLE _sqlx_migrations \
             ADD COLUMN installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER description",
        )
        .execute(pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("add migration installed_on: {e}")))?;
    }

    // Older Rust startup code created a non-sqlx `type` column.  sqlx 0.8.6
    // does not use it; retaining it means the history table is not the exact
    // contract and can hide future schema drift.
    if migration_column_exists(pool, "type").await? {
        sqlx::query("ALTER TABLE _sqlx_migrations DROP COLUMN `type`")
            .execute(pool)
            .await
            .map_err(|e| MigrationError::Failed(format!("drop obsolete migration type: {e}")))?;
    }
    Ok(())
}

async fn migration_column_exists(pool: &MySqlPool, column: &str) -> Result<bool, MigrationError> {
    let value: Vec<u8> = sqlx::query_scalar(MIGRATION_COLUMN_EXISTS_SQL)
        .bind(column)
        .fetch_one(pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("inspect migration history schema: {e}")))?;
    Ok(metadata_count(value, "inspect migration history schema")? == 1)
}

async fn recorded_successful_versions(pool: &MySqlPool) -> Result<HashSet<i64>, MigrationError> {
    let versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success = 1 ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| MigrationError::Failed(format!("inspect successful migration versions: {e}")))?;
    Ok(versions.into_iter().collect())
}

async fn record_verified_baseline(
    pool: &MySqlPool,
    recorded_versions: &HashSet<i64>,
) -> Result<(), MigrationError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| MigrationError::Failed(format!("begin baseline history adoption: {e}")))?;

    for migration in MIGRATOR.migrations.iter() {
        // 默认拒绝：只有 Java 基线时代的迁移可以记为已应用；Rust-owned 增量
        // 一律保持 pending，由 SQLx 在本次 run 中真实执行。绝不依据人工维护
        // 的清单扩大记录范围（20260831000001 静默吞掉教训）。
        if !is_java_baseline_era(migration.version)
            || recorded_versions.contains(&migration.version)
        {
            continue;
        }

        sqlx::query(
            "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES (?, ?, CURRENT_TIMESTAMP, true, ?, 0)",
        )
        .bind(migration.version)
        .bind(&migration.description)
        .bind(migration.checksum.as_ref())
        .execute(&mut *transaction)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!(
                "record baseline migration {}: {e}",
                migration.version
            ))
        })?;
    }

    transaction
        .commit()
        .await
        .map_err(|e| MigrationError::Failed(format!("commit baseline history adoption: {e}")))
}

async fn verified_baseline(pool: &MySqlPool) -> Result<bool, MigrationError> {
    for contract in VERIFIED_BASELINE_TABLES {
        let table_count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_CONTRACT_SQL)
                .bind(contract.table)
                .bind(contract.charset)
                .bind(contract.collation)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "verify baseline table contract {}: {e}",
                        contract.table
                    ))
                })?,
            "verify baseline table contract",
        )?;
        if table_count != 1 {
            return Ok(false);
        }

        let key_count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_KEY_COLUMN_CONTRACT_SQL)
                .bind(contract.table)
                .bind(contract.key_column)
                .bind(contract.key_type)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "verify baseline key contract {}.{}: {e}",
                        contract.table, contract.key_column
                    ))
                })?,
            "verify baseline key contract",
        )?;
        if key_count != 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn identity_fence_column_contracts() -> Vec<SchemaColumnContract> {
    IDENTITY_CREDENTIAL_FENCE_COLUMNS
        .iter()
        .map(|column| SchemaColumnContract {
            table: column.table,
            name: column.name,
            column_type: column.column_type,
            not_null: column.not_null,
            default: column.default,
            charset: column.charset,
            collation: column.collation,
        })
        .collect()
}

async fn validate_review_table_engine(pool: &MySqlPool, table: &str) -> Result<(), MigrationError> {
    let count = metadata_count(
        sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_ENGINE_CONTRACT_SQL)
            .bind(table)
            .bind("InnoDB")
            .fetch_one(pool)
            .await
            .map_err(|error| MigrationError::Failed(format!("inspect {table} engine: {error}")))?,
        "inspect review table engine",
    )?;
    if count != 1 {
        return Err(MigrationError::Failed(format!(
            "missing or non-InnoDB review table {table}; explicit migration/recovery required"
        )));
    }
    Ok(())
}

async fn validate_review_runtime_schema(pool: &MySqlPool) -> Result<(), MigrationError> {
    for table in [
        "user_local_credential",
        "auth_device_session",
        "user_mfa",
        "mfa_attempt_log",
        "al_message_outbox",
        "al_message_scope_counter",
    ]
    .into_iter()
    .chain(ASYNC_OPERATION_TABLES.iter().copied())
    {
        validate_review_table_engine(pool, table).await?;
    }
    validate_schema_columns(pool, &identity_fence_column_contracts()).await?;
    validate_indexes(pool, IDENTITY_CREDENTIAL_FENCE_INDEXES).await?;
    crate::session_state_repository::validate_identity_credential_fence_schema(pool)
        .await
        .map_err(MigrationError::Failed)?;
    validate_schema_column_exact(pool, &LOCAL_SCOPE_SEQUENCE_COLUMN_CONTRACT).await?;
    validate_schema_columns(pool, LOCAL_SCOPE_COUNTER_COLUMNS).await?;
    validate_indexes(pool, LOCAL_SCOPE_COUNTER_INDEXES).await?;
    validate_indexes(pool, &REVIEW_SCHEMA_REPAIR_INDEXES[..1]).await?;
    validate_schema_columns(pool, ASYNC_OPERATION_COLUMNS).await?;
    validate_indexes(pool, ASYNC_OPERATION_INDEXES).await?;
    let invalid: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM user_local_credential WHERE credential_version <= 0 LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(|error| {
                MigrationError::Failed(format!("inspect credential revision domain: {error}"))
            })?;
    if invalid.is_some() {
        return Err(MigrationError::Failed(
            "invalid credential revision requires explicit recovery".into(),
        ));
    }
    Ok(())
}

fn review_migration_pending(
    applied: &HashSet<i64>,
    migrations: &[Migration],
    version: i64,
) -> bool {
    !applied.contains(&version)
        && migrations.iter().any(|migration| {
            migration.version == version && migration_matches_known_source(migration)
        })
}

fn pending_migration_can_create_table(
    applied: &HashSet<i64>,
    migrations: &[Migration],
    table: &str,
) -> bool {
    migrations.iter().any(|migration| {
        !applied.contains(&migration.version)
            && migration_matches_known_source(migration)
            && migration_defines_table(migration, table)
    })
}

fn pending_migration_can_own_column(
    applied: &HashSet<i64>,
    migrations: &[Migration],
    table: &str,
    column: &str,
    table_absent: bool,
) -> bool {
    migrations.iter().any(|migration| {
        !applied.contains(&migration.version)
            && migration_matches_known_source(migration)
            && (migration_defines_existing_column(migration, table, column)
                || (table_absent && migration_defines_column(migration, table, column)))
    })
}

fn pending_migration_can_own_index(
    applied: &HashSet<i64>,
    migrations: &[Migration],
    table: &str,
    index: &str,
    columns: &[&str],
    unique: bool,
    table_absent: bool,
) -> bool {
    migrations.iter().any(|migration| {
        !applied.contains(&migration.version)
            && migration_matches_known_source(migration)
            && (migration_defines_existing_index(migration, table, index, columns, unique)
                || (table_absent
                    && migration_defines_index(migration, table, index, columns, unique)))
    })
}

#[allow(clippy::too_many_arguments)]
async fn preflight_review_table(
    pool: &MySqlPool,
    applied: &HashSet<i64>,
    migrations: &[Migration],
    table: &str,
    columns: &[SchemaColumnContract],
    indexes: &[(&str, &str, &[&str], bool)],
) -> Result<bool, MigrationError> {
    let table_absent = !schema_table_exists(pool, table).await?;
    if table_absent && !pending_migration_can_create_table(applied, migrations, table) {
        return Err(MigrationError::Failed(format!(
            "recorded or unsupported durable table {table} is missing; restore history before migration"
        )));
    }
    if !table_absent {
        validate_review_table_engine(pool, table).await?;
    }
    let mut complete = !table_absent;
    for column in columns.iter().filter(|column| column.table == table) {
        if !table_absent && schema_column_exists(pool, table, column.name).await? {
            validate_schema_column_exact(pool, column).await?;
        } else if pending_migration_can_own_column(
            applied,
            migrations,
            table,
            column.name,
            table_absent,
        ) {
            complete = false;
        } else {
            return Err(MigrationError::Failed(format!(
                "review column {table}.{} missing without a source-pinned additive owner",
                column.name
            )));
        }
    }
    for (index_table, index, index_columns, unique) in
        indexes.iter().filter(|entry| entry.0 == table)
    {
        if !table_absent && schema_index_exists(pool, table, index).await? {
            validate_indexes(pool, &[(*index_table, *index, *index_columns, *unique)]).await?;
        } else if pending_migration_can_own_index(
            applied,
            migrations,
            index_table,
            index,
            index_columns,
            *unique,
            table_absent,
        ) {
            complete = false;
            if *unique && !table_absent {
                // All identifiers come from closed, source-pinned contracts.
                // MySQL permits repeated NULLs in UNIQUE keys, so only complete
                // non-NULL key tuples conflict with the candidate index.
                let keys = index_columns
                    .iter()
                    .map(|column| format!("`{column}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let nonnull = index_columns
                    .iter()
                    .map(|column| format!("`{column}` IS NOT NULL"))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                let statement = format!(
                    "SELECT 1 FROM `{table}` WHERE {nonnull} GROUP BY {keys} HAVING COUNT(*) > 1 LIMIT 1"
                );
                let duplicate: Option<(i32,)> = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    sqlx::query_as(&statement).fetch_optional(pool),
                )
                .await
                .map_err(|_| {
                    MigrationError::Failed(format!(
                        "duplicate preflight timed out for {table}.{index}"
                    ))
                })?
                .map_err(|error| {
                    MigrationError::Failed(format!(
                        "duplicate preflight for {table}.{index}: {error}"
                    ))
                })?;
                if duplicate.is_some() {
                    return Err(MigrationError::Failed(format!(
                        "duplicate history prevents additive key {table}.{index}; no automatic rewrite"
                    )));
                }
            }
        } else {
            return Err(MigrationError::Failed(format!(
                "review index {table}.{index} missing without a source-pinned additive owner"
            )));
        }
    }
    Ok(complete)
}

async fn preflight_review_schema_contracts(
    pool: &MySqlPool,
    applied: &HashSet<i64>,
    migrations: &[Migration],
) -> Result<bool, MigrationError> {
    let mut complete = true;
    let identity = identity_fence_column_contracts();
    for table in [
        "user_local_credential",
        "auth_device_session",
        "user_mfa",
        "mfa_attempt_log",
    ] {
        complete &= preflight_review_table(
            pool,
            applied,
            migrations,
            table,
            &identity,
            IDENTITY_CREDENTIAL_FENCE_INDEXES,
        )
        .await?;
    }
    for table in ASYNC_OPERATION_TABLES {
        complete &= preflight_review_table(
            pool,
            applied,
            migrations,
            table,
            ASYNC_OPERATION_COLUMNS,
            ASYNC_OPERATION_INDEXES,
        )
        .await?;
    }
    for table in CHAT_DELIVERY_INTENT_TABLES {
        complete &= preflight_review_table(
            pool,
            applied,
            migrations,
            table,
            CHAT_DELIVERY_INTENT_COLUMNS,
            CHAT_DELIVERY_INTENT_INDEXES,
        )
        .await?;
    }
    complete &= preflight_review_table(
        pool,
        applied,
        migrations,
        "learn_assignment",
        LEARN_SYSTEM_ASSIGNMENT_COLUMNS,
        LEARN_SYSTEM_ASSIGNMENT_INDEXES,
    )
    .await?;
    complete &= preflight_review_table(
        pool,
        applied,
        migrations,
        "al_message_outbox",
        &[LOCAL_SCOPE_SEQUENCE_COLUMN_CONTRACT],
        &REVIEW_SCHEMA_REPAIR_INDEXES[..1],
    )
    .await?;
    complete &= preflight_review_table(
        pool,
        applied,
        migrations,
        "al_message_scope_counter",
        LOCAL_SCOPE_COUNTER_COLUMNS,
        LOCAL_SCOPE_COUNTER_INDEXES,
    )
    .await?;
    complete &= preflight_review_table(
        pool,
        applied,
        migrations,
        "org_scope_operation",
        ORG_SCOPE_OPERATION_COLUMNS,
        ORG_SCOPE_OPERATION_INDEXES,
    )
    .await?;
    for table in CROSS_CITY_RUNTIME_PROOF_TABLES {
        complete &= preflight_review_table(
            pool,
            applied,
            migrations,
            table,
            CROSS_CITY_RUNTIME_PROOF_COLUMNS,
            CROSS_CITY_RUNTIME_PROOF_INDEXES,
        )
        .await?;
    }
    let chat_creator_pending =
        review_migration_pending(applied, migrations, CHAT_DELIVERY_INTENT_VERSION);
    let mut chat_tables_present = 0;
    for table in CHAT_DELIVERY_INTENT_TABLES {
        if schema_table_exists(pool, table).await? {
            chat_tables_present += 1;
            validate_chat_delivery_intent_table_contract(pool, table).await?;
        }
    }
    if chat_tables_present != CHAT_DELIVERY_INTENT_TABLES.len() {
        if !chat_creator_pending {
            return Err(MigrationError::Failed(
                "recorded Chat delivery-intent schema is incomplete; restore durable proof instead of recreating it".into(),
            ));
        }
        let chat_migration = migrations
            .iter()
            .find(|migration| migration.version == CHAT_DELIVERY_INTENT_VERSION)
            .ok_or_else(|| {
                MigrationError::Failed("Chat delivery-intent creator is missing".into())
            })?;
        if !migration_matches_known_source(chat_migration) {
            return Err(MigrationError::Failed(
                "Chat delivery-intent creator is not source-pinned".into(),
            ));
        }
        for table in CHAT_DELIVERY_INTENT_TABLES {
            if !schema_table_exists(pool, table).await? {
                if !migration_defines_table(chat_migration, table) {
                    return Err(MigrationError::Failed(format!(
                        "pending Chat migration does not create {table}"
                    )));
                }
                for column in CHAT_DELIVERY_INTENT_COLUMNS
                    .iter()
                    .filter(|column| column.table == *table)
                {
                    if !migration_defines_column(chat_migration, table, column.name) {
                        return Err(MigrationError::Failed(format!(
                            "pending Chat migration does not define {table}.{}",
                            column.name
                        )));
                    }
                }
                for (index_table, index, columns, unique) in CHAT_DELIVERY_INTENT_INDEXES
                    .iter()
                    .filter(|entry| entry.0 == *table)
                {
                    if !migration_defines_index(
                        chat_migration,
                        index_table,
                        index,
                        columns,
                        *unique,
                    ) {
                        return Err(MigrationError::Failed(format!(
                            "pending Chat migration does not define {table}.{index}"
                        )));
                    }
                }
            }
        }
        complete = false;
    }
    Ok(complete)
}

pub async fn validate_schema_contract(pool: &MySqlPool) -> Result<(), MigrationError> {
    match inspect_monitor_schema_state(pool).await? {
        MonitorSchemaState::Missing => {
            return Err(MigrationError::Failed(
                "monitor schema is missing; run the explicit Rust migration job before starting services"
                    .into(),
            ));
        }
        MonitorSchemaState::Partial => {
            return Err(MigrationError::Failed(
                "monitor schema is partially present; refusing to accept an incomplete creator-only schema"
                    .into(),
            ));
        }
        MonitorSchemaState::Complete => validate_monitor_schema_contract(pool).await?,
    }
    validate_contract(pool, REQUIRED_SCHEMA_COLUMNS).await?;
    validate_schema_column_exact(pool, &AUDIT_QUARANTINE_REPLAY_LEASE_GENERATION_CONTRACT).await?;
    for expected in RULE_SET_PROJECTION_EVENT_KEY_COLUMN_CONTRACTS {
        validate_schema_column_exact(pool, expected).await?;
    }
    validate_decommissionable_snapshot_column_contracts(pool).await?;
    // rule_set_snapshot_manifest is decommissionable via 20260827000002: its
    // exact column/index contracts only apply while the table is still present
    // (same conditional pre-drop enforcement as the two legacy snapshot tables).
    if schema_table_exists(pool, "rule_set_snapshot_manifest").await? {
        validate_schema_columns(pool, RULE_SET_SNAPSHOT_MANIFEST_COLUMN_CONTRACTS).await?;
        validate_indexes(pool, RULE_SET_SNAPSHOT_MANIFEST_INDEXES).await?;
    }
    validate_incremental_projection_archive_schema_contract(pool).await?;
    // Cross-city schema is optional and default-off. Its enabled-only runtime
    // admission validates creator and proof tables in
    // `validate_cross_city_runtime_schema`; ordinary service startup never probes it.
    // auth_internal_request_guard 是 Redis-free 网关/Identity 重放与幂等路径的
    // durable 互斥表（迁移 20261001000001）：缺表/缺列/唯一键漂移必须在启动期
    // fail-early，由 session_state_repository 的契约检查统一裁决。
    crate::session_state_repository::validate_auth_internal_request_guard_schema(pool)
        .await
        .map_err(MigrationError::Failed)?;
    validate_review_runtime_schema(pool).await?;
    validate_indexes(pool, REQUIRED_SCHEMA_INDEXES).await?;
    // Archive tables validate over the RESOLVED index contract: post-creator
    // additions (10.D-2 claim-gate support index) are required once recorded
    // and tolerated while their migration is still pending.
    for table in INCREMENTAL_PROJECTION_ARCHIVE_TABLES {
        validate_indexes(
            pool,
            &incremental_projection_resolved_index_contract(pool, table).await?,
        )
        .await?;
    }
    Ok(())
}

/// The legacy snapshot tables and rule_set_snapshot_manifest are
/// decommissionable via 20260827000002. After that migration has dropped them
/// their exact column contracts no longer apply; while a table is still present
/// it keeps its exact historical contract, so a drifted or partially repaired
/// legacy table still fails closed instead of being waved through as "optional".
async fn validate_decommissionable_snapshot_column_contracts(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    if schema_table_exists(pool, RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT.table).await? {
        validate_schema_column_exact(pool, &RULE_SET_SNAPSHOT_PROJECTION_GENERATION_CONTRACT)
            .await?;
    }
    for expected in SNAPSHOT_VALIDITY_COLUMN_CONTRACTS {
        if schema_table_exists(pool, expected.table).await? {
            validate_schema_column_exact(pool, expected).await?;
        }
    }
    Ok(())
}

async fn validate_school_tenant_mapping_table_contract(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    validate_table_contract(
        pool,
        "school_tenant_migration",
        MYSQL_SCHEMA_CHARSET,
        MYSQL_MIGRATION_COLLATION,
        Some("InnoDB"),
    )
    .await?;
    validate_schema_columns(pool, SCHOOL_TENANT_MIGRATION_COLUMN_CONTRACT).await?;
    let mapping_indexes: Vec<(&str, &str, &[&str], bool)> = REQUIRED_SCHOOL_CUTOVER_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table == "school_tenant_migration")
        .copied()
        .collect();
    validate_indexes(pool, &mapping_indexes).await?;
    validate_foreign_keys(pool, REQUIRED_SCHOOL_CUTOVER_FOREIGN_KEYS).await
}

async fn validate_school_tenant_cutover_contract(pool: &MySqlPool) -> Result<(), MigrationError> {
    validate_contract(pool, REQUIRED_SCHOOL_CUTOVER_COLUMNS).await?;
    validate_school_tenant_mapping_table_contract(pool).await?;
    let child_indexes: Vec<(&str, &str, &[&str], bool)> = REQUIRED_SCHOOL_CUTOVER_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table != "school_tenant_migration")
        .copied()
        .collect();
    validate_indexes(pool, &child_indexes).await
}

async fn school_tenant_cutover_table_exists(pool: &MySqlPool) -> Result<bool, MigrationError> {
    let table_count = metadata_count(
        sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_EXISTS_SQL)
            .bind("school_tenant_migration")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!(
                    "inspect school tenant cutover mapping table before data backfill: {e}"
                ))
            })?,
        "inspect school tenant cutover mapping table",
    )?;
    Ok(table_count == 1)
}

async fn schema_index_exists(
    pool: &MySqlPool,
    table: &str,
    index: &str,
) -> Result<bool, MigrationError> {
    for candidate in schema_index_candidates(table, index) {
        let (index_count, _, _): (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) =
            sqlx::query_as(SCHEMA_INDEX_STATS_SQL)
                .bind(table)
                .bind(&candidate)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "inspect schema index {table}.{index} before cutover backfill: {e}"
                    ))
                })?;
        if metadata_count(index_count, "inspect schema index existence")? != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn validate_school_tenant_cutover_pre_data_contract(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    if school_tenant_cutover_table_exists(pool).await? {
        validate_school_tenant_mapping_table_contract(pool).await?;
    }

    for (table, index, columns, unique) in REQUIRED_SCHOOL_CUTOVER_INDEXES
        .iter()
        .filter(|(table, _, _, _)| *table != "school_tenant_migration")
    {
        if schema_index_exists(pool, table, index).await? {
            let existing_index = [(*table, *index, *columns, *unique)];
            validate_indexes(pool, &existing_index).await?;
        }
    }
    Ok(())
}

async fn validate_school_tenant_backfill_source_conflicts(
    pool: &MySqlPool,
) -> Result<(), MigrationError> {
    for (table, statement) in SCHOOL_TENANT_BACKFILL_CONFLICTS
        .iter()
        .filter(|(table, _)| *table != "school_tenant_migration")
    {
        let conflicts = count(pool, statement).await?;
        if conflicts != 0 {
            return Err(MigrationError::Failed(format!(
                "school tenant cutover found {conflicts} conflicting non-null tenant_id assignment(s) in {table}; refusing to overwrite unrelated tenant data"
            )));
        }
    }
    Ok(())
}

async fn validate_school_tenant_backfill_conflicts(pool: &MySqlPool) -> Result<(), MigrationError> {
    validate_school_tenant_backfill_source_conflicts(pool).await?;

    let mapping_conflicts = count(
        pool,
        "SELECT COUNT(*) FROM school_tenant_migration m \
         LEFT JOIN tenant target ON target.tenant_code = CONCAT('SCHOOL-', m.school_id) \
         WHERE m.tenant_id IS NOT NULL \
           AND (target.tenant_id IS NULL OR m.tenant_id <> target.tenant_id)",
    )
    .await?;
    if mapping_conflicts != 0 {
        return Err(MigrationError::Failed(format!(
            "school tenant cutover found {mapping_conflicts} conflicting non-null tenant_id assignment(s) in school_tenant_migration; repair the mapping before rerunning the explicit migration"
        )));
    }
    Ok(())
}

fn classify_school_tenant_cutover_state(
    invalid_statuses: i64,
    incomplete_mapping: i64,
    incomplete_children: bool,
) -> Result<SchoolTenantCutoverState, MigrationError> {
    if invalid_statuses != 0 {
        return Err(MigrationError::Failed(format!(
            "recorded school tenant cutover contains {invalid_statuses} mapping row(s) with an unsupported migration_status; repair the mapping explicitly"
        )));
    }
    if incomplete_mapping != 0 || incomplete_children {
        return Ok(SchoolTenantCutoverState::Recoverable);
    }
    Ok(SchoolTenantCutoverState::Complete)
}

async fn school_tenant_cutover_state(
    pool: &MySqlPool,
) -> Result<SchoolTenantCutoverState, MigrationError> {
    let invalid_statuses = count(
        pool,
        "SELECT COUNT(*) FROM school_tenant_migration \
         WHERE migration_status NOT IN ('MIGRATED', 'VERIFIED', 'ROLLED_BACK')",
    )
    .await?;

    let incomplete = count(
        pool,
        "SELECT COUNT(*) FROM schools s \
         LEFT JOIN school_tenant_migration m ON m.school_id = s.id \
         LEFT JOIN tenant target ON target.tenant_code = CONCAT('SCHOOL-', s.id) \
         WHERE m.school_id IS NULL \
            OR m.migration_status <> 'VERIFIED' \
            OR m.verified_at IS NULL \
            OR m.tenant_code <> CONCAT('SCHOOL-', s.id) \
            OR target.tenant_id IS NULL \
            OR m.tenant_id <> target.tenant_id \
            OR s.tenant_id IS NULL \
            OR s.tenant_id <> m.tenant_id",
    )
    .await?;

    let mut incomplete_children = false;
    for (table, condition) in [
        (
            "school_members",
            "t.school_id IS NOT NULL AND (m.school_id IS NULL OR t.tenant_id IS NULL OR t.tenant_id <> m.tenant_id)",
        ),
        (
            "user_profiles",
            "t.school_id IS NOT NULL AND (m.school_id IS NULL OR t.tenant_id IS NULL OR t.tenant_id <> m.tenant_id)",
        ),
        (
            "leaderboards",
            "t.school_id IS NOT NULL AND (m.school_id IS NULL OR t.tenant_id IS NULL OR t.tenant_id <> m.tenant_id)",
        ),
    ] {
        let rows = count(
            pool,
            &format!(
                "SELECT COUNT(*) FROM {table} t LEFT JOIN school_tenant_migration m ON m.school_id = t.school_id WHERE {condition}"
            ),
        )
        .await?;
        incomplete_children |= rows != 0;
    }

    classify_school_tenant_cutover_state(invalid_statuses, incomplete, incomplete_children)
}

async fn validate_school_tenant_cutover_complete(pool: &MySqlPool) -> Result<(), MigrationError> {
    validate_school_tenant_cutover_contract(pool).await?;

    let mapping_inconsistency = count(
        pool,
        "SELECT COUNT(*) FROM school_tenant_migration m \
         LEFT JOIN schools s ON s.id = m.school_id \
         LEFT JOIN tenant t ON t.tenant_code = CONCAT('SCHOOL-', m.school_id) \
         WHERE s.id IS NULL \
            OR m.tenant_code <> CONCAT('SCHOOL-', m.school_id) \
            OR t.tenant_id IS NULL \
            OR m.tenant_id <> t.tenant_id \
            OR m.migration_status <> 'VERIFIED' \
            OR m.verified_at IS NULL",
    )
    .await?;
    if mapping_inconsistency != 0 {
        return Err(MigrationError::Failed(format!(
            "school tenant cutover has {mapping_inconsistency} mapping row(s) with non-deterministic tenant_code, tenant_id, status, or verified_at"
        )));
    }

    let incomplete = count(
        pool,
        "SELECT COUNT(*) FROM schools s \
         LEFT JOIN school_tenant_migration m ON m.school_id = s.id \
         WHERE s.tenant_id IS NULL OR m.school_id IS NULL OR m.tenant_id <> s.tenant_id",
    )
    .await?;
    if incomplete != 0 {
        return Err(MigrationError::Failed(format!(
            "recorded school tenant cutover has {incomplete} incomplete school mapping(s); refusing to accept migration history"
        )));
    }

    for (table, condition) in [
        (
            "school_members",
            "t.school_id IS NOT NULL AND (t.tenant_id IS NULL OR m.school_id IS NULL OR m.tenant_id <> t.tenant_id)",
        ),
        (
            "user_profiles",
            "t.school_id IS NOT NULL AND (t.tenant_id IS NULL OR m.school_id IS NULL OR m.tenant_id <> t.tenant_id)",
        ),
        (
            "leaderboards",
            "t.school_id IS NOT NULL AND (t.tenant_id IS NULL OR m.school_id IS NULL OR m.tenant_id <> t.tenant_id)",
        ),
    ] {
        let incomplete = count(
            pool,
            &format!(
                "SELECT COUNT(*) FROM {table} t LEFT JOIN school_tenant_migration m ON m.school_id = t.school_id WHERE {condition}"
            ),
        )
        .await?;
        if incomplete != 0 {
            return Err(MigrationError::Failed(format!(
                "recorded school tenant cutover has {incomplete} incomplete {table} backfill row(s); refusing to accept migration history"
            )));
        }
    }
    Ok(())
}

async fn validate_table_contract(
    pool: &MySqlPool,
    table: &str,
    charset: &str,
    collation: &str,
    engine: Option<&str>,
) -> Result<(), MigrationError> {
    let table_count = metadata_count(
        sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_CONTRACT_SQL)
            .bind(table)
            .bind(charset)
            .bind(collation)
            .fetch_one(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!("inspect schema table contract {table}: {e}"))
            })?,
        "inspect schema table contract",
    )?;
    if table_count != 1 {
        return Err(MigrationError::Failed(format!(
            "schema contract has missing or incompatible table {table}; run the explicit Rust migration job"
        )));
    }
    if let Some(engine) = engine {
        let engine_count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_ENGINE_CONTRACT_SQL)
                .bind(table)
                .bind(engine)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!("inspect schema table engine {table}: {e}"))
                })?,
            "inspect schema table engine",
        )?;
        if engine_count != 1 {
            return Err(MigrationError::Failed(format!(
                "schema contract has incompatible engine for {table}; expected {engine}"
            )));
        }
    }
    Ok(())
}

async fn validate_foreign_keys(
    pool: &MySqlPool,
    required: &[(&str, &str, &str, &str, &str)],
) -> Result<(), MigrationError> {
    for (table, constraint, column, referenced_table, referenced_column) in required {
        let (total_columns, matching_columns): (Vec<u8>, Vec<u8>) =
            sqlx::query_as(SCHEMA_FOREIGN_KEY_CONTRACT_SQL)
                .bind(column)
                .bind(referenced_table)
                .bind(referenced_column)
                .bind("RESTRICT")
                .bind(table)
                .bind(constraint)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!(
                        "inspect schema foreign key {table}.{constraint}: {e}"
                    ))
                })?;
        let total_columns = metadata_count(total_columns, "inspect schema foreign key columns")?;
        let matching_columns =
            metadata_count(matching_columns, "inspect schema foreign key definition")?;
        if total_columns != 1 || matching_columns != 1 {
            return Err(MigrationError::Failed(format!(
                "schema contract has missing or incompatible foreign key {table}.{constraint}; expected {column} REFERENCES {referenced_table}({referenced_column}) ON DELETE RESTRICT"
            )));
        }
    }
    Ok(())
}

async fn schema_columns_match(
    pool: &MySqlPool,
    expected: &[SchemaColumnContract],
) -> Result<bool, MigrationError> {
    let mut by_table = HashSet::new();
    for column in expected {
        by_table.insert(column.table);
        let metadata: Option<SchemaColumnMetadataRow> = sqlx::query_as(SCHEMA_COLUMN_METADATA_SQL)
            .bind(column.table)
            .bind(column.name)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!(
                    "inspect TrustGraph column {}.{}: {e}",
                    column.table, column.name
                ))
            })?;
        let Some((name, column_type, nullable, default, charset, collation)) = metadata else {
            return Ok(false);
        };
        let name = metadata_text("COLUMN_NAME", &name, column.table, column.name)?;
        let column_type = metadata_text("COLUMN_TYPE", &column_type, column.table, column.name)?;
        let nullable = metadata_text("IS_NULLABLE", &nullable, column.table, column.name)?;
        let default = default
            .as_deref()
            .map(|value| metadata_text("COLUMN_DEFAULT", value, column.table, column.name))
            .transpose()?;
        let charset = metadata_optional_name(
            "CHARACTER_SET_NAME",
            charset.as_deref(),
            column.table,
            column.name,
        )?;
        let collation = metadata_optional_name(
            "COLLATION_NAME",
            collation.as_deref(),
            column.table,
            column.name,
        )?;
        let matches = name == column.name
            && normalize_column_definition(&column_type)
                == normalize_column_definition(column.column_type)
            && nullable.eq_ignore_ascii_case(if column.not_null { "NO" } else { "YES" })
            && column_default_matches(default.as_deref(), column.default)
            && validate_character_metadata(
                &column_type,
                charset.as_deref(),
                collation.as_deref(),
                &HistoricalColumnSpec {
                    table: column.table,
                    name: column.name,
                    column_type: column.column_type,
                    not_null: column.not_null,
                    default: column.default,
                    charset: column.charset,
                    collation: column.collation,
                    after: "",
                },
            );
        if !matches {
            return Ok(false);
        }
    }

    for table in by_table {
        let rows: Vec<SchemaColumnOrderRow> = sqlx::query_as(SCHEMA_COLUMN_ORDER_SQL)
            .bind(table)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!("inspect TrustGraph column order {table}: {e}"))
            })?;
        let expected_columns: Vec<&str> = expected
            .iter()
            .filter(|column| column.table == table)
            .map(|column| column.name)
            .collect();
        if rows.len() != expected_columns.len() {
            return Ok(false);
        }
        for (position, (name, ordinal)) in rows.into_iter().enumerate() {
            let name = metadata_text("COLUMN_NAME", &name, table, "<order>")?;
            let ordinal = metadata_u64("ORDINAL_POSITION", &ordinal, table, &name)?;
            if expected_columns.get(position).copied() != Some(name.as_str())
                || position as u64 + 1 != ordinal
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

async fn schema_indexes_match(
    pool: &MySqlPool,
    expected: &[(&str, &str, &[&str], bool)],
) -> Result<bool, MigrationError> {
    let mut tables = HashSet::new();
    for (table, _, _, _) in expected {
        tables.insert(*table);
    }
    for table in tables {
        let rows: Vec<SchemaIndexMetadataRow> = sqlx::query_as(SCHEMA_INDEX_METADATA_SQL)
            .bind(table)
            .fetch_all(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!("inspect TrustGraph indexes {table}: {e}"))
            })?;
        let actual: Vec<(String, bool, u64, String)> = rows
            .into_iter()
            .map(|(name, non_unique, position, column, sub_part, expression)| {
                let non_unique = metadata_count(non_unique, "TrustGraph index uniqueness")? != 0;
                if sub_part.is_some() || expression.is_some() {
                    return Err(MigrationError::Failed(format!(
                        "inspect TrustGraph index {table}: prefix or expression key parts are unsupported"
                    )));
                }
                Ok((
                    metadata_text("INDEX_NAME", &name, table, "<index>")?,
                    non_unique,
                    metadata_count(position, "TrustGraph index position")?,
                    column
                        .as_deref()
                        .map(|column| metadata_text("COLUMN_NAME", column, table, "<index>"))
                        .transpose()?
                        .ok_or_else(|| MigrationError::Failed(format!(
                            "inspect TrustGraph index {table}: expression key part has no column"
                        )))?,
                ))
            })
            .collect::<Result<_, MigrationError>>()?;
        if !schema_index_rows_match(table, actual, expected) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn schema_index_rows_match(
    table: &str,
    mut actual: Vec<(String, bool, u64, String)>,
    expected: &[(&str, &str, &[&str], bool)],
) -> bool {
    actual.sort();
    let mut expected_rows = Vec::new();
    for (_, index, columns, unique) in expected.iter().filter(|(owner, _, _, _)| *owner == table) {
        for (position, column) in columns.iter().enumerate() {
            expected_rows.push((
                (*index).to_owned(),
                !*unique,
                position as u64 + 1,
                (*column).to_owned(),
            ));
        }
    }
    expected_rows.sort();
    actual == expected_rows
}

async fn schema_foreign_keys_match(
    pool: &MySqlPool,
    table: &str,
    expected: &[(&str, &str, &str, &str, &str, &str)],
) -> Result<bool, MigrationError> {
    let rows: Vec<SchemaForeignKeyMetadataRow> = sqlx::query_as(SCHEMA_FOREIGN_KEY_LIST_SQL)
        .bind(table)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!("inspect TrustGraph foreign keys {table}: {e}"))
        })?;
    let actual: Vec<(String, String, String, String, String)> = rows
        .into_iter()
        .map(
            |(name, column, referenced_table, referenced_column, delete_rule)| {
                Ok((
                    metadata_text("CONSTRAINT_NAME", &name, table, "<foreign-key>")?,
                    metadata_text("COLUMN_NAME", &column, table, "<foreign-key>")?,
                    metadata_text(
                        "REFERENCED_TABLE_NAME",
                        &referenced_table,
                        table,
                        "<foreign-key>",
                    )?,
                    metadata_text(
                        "REFERENCED_COLUMN_NAME",
                        &referenced_column,
                        table,
                        "<foreign-key>",
                    )?,
                    metadata_text("DELETE_RULE", &delete_rule, table, "<foreign-key>")?,
                ))
            },
        )
        .collect::<Result<_, MigrationError>>()?;
    let expected = expected
        .iter()
        .map(
            |(_, constraint, column, referenced_table, referenced_column, delete_rule)| {
                (
                    (*constraint).to_owned(),
                    (*column).to_owned(),
                    (*referenced_table).to_owned(),
                    (*referenced_column).to_owned(),
                    (*delete_rule).to_owned(),
                )
            },
        )
        .collect::<Vec<_>>();
    Ok(actual == expected)
}

type SchemaColumnMetadataRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
type SchemaColumnOrderRow = (Vec<u8>, Vec<u8>);
type SchemaIndexMetadataRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
type SchemaForeignKeyMetadataRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn normalize_column_default(value: &str) -> String {
    let mut normalized = normalize_column_definition(value);
    loop {
        let wraps_whole_value = normalized.starts_with('(')
            && normalized.ends_with(')')
            && matching_parenthesis(&normalized, 0) == Some(normalized.len() - 1);
        if !wraps_whole_value {
            return normalized;
        }
        normalized = normalized[1..normalized.len() - 1].trim().to_owned();
    }
}

fn column_default_matches(actual: Option<&str>, expected: Option<&str>) -> bool {
    match (actual, expected) {
        (None, None) => true,
        (Some(actual), Some(expected)) => {
            normalize_column_default(actual) == normalize_column_default(expected)
        }
        _ => false,
    }
}

fn schema_column_contract_matches(
    name: &str,
    column_type: &str,
    nullable: &str,
    default: Option<&str>,
    charset: Option<&str>,
    collation: Option<&str>,
    expected: &SchemaColumnContract,
) -> bool {
    name == expected.name
        && normalize_column_definition(column_type)
            == normalize_column_definition(expected.column_type)
        && nullable.eq_ignore_ascii_case(if expected.not_null { "NO" } else { "YES" })
        && column_default_matches(default, expected.default)
        && if is_character_type(column_type) {
            charset == expected.charset && collation == expected.collation
        } else {
            !metadata_name_is_present(charset) && !metadata_name_is_present(collation)
        }
}

async fn validate_schema_column_exact(
    pool: &MySqlPool,
    expected: &SchemaColumnContract,
) -> Result<(), MigrationError> {
    let metadata: Option<SchemaColumnMetadataRow> = sqlx::query_as(SCHEMA_COLUMN_METADATA_SQL)
        .bind(expected.table)
        .bind(expected.name)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            MigrationError::Failed(format!(
                "inspect strict schema column {}.{}: {e}",
                expected.table, expected.name
            ))
        })?;
    let Some((name, column_type, nullable, default, charset, collation)) = metadata else {
        return Err(MigrationError::Failed(format!(
            "strict schema contract is missing {}.{}; expected COLUMN_TYPE={}, IS_NULLABLE=NO, COLUMN_DEFAULT=0, CHARACTER_SET_NAME/COLLATION_NAME NULL or empty; refusing automatic ALTER/DROP",
            expected.table, expected.name, expected.column_type
        )));
    };

    let name = metadata_text("COLUMN_NAME", &name, expected.table, expected.name)?;
    let column_type = metadata_text("COLUMN_TYPE", &column_type, expected.table, expected.name)?;
    let nullable = metadata_text("IS_NULLABLE", &nullable, expected.table, expected.name)?;
    let default = default
        .as_deref()
        .map(|value| metadata_text("COLUMN_DEFAULT", value, expected.table, expected.name))
        .transpose()?;
    let charset = metadata_optional_name(
        "CHARACTER_SET_NAME",
        charset.as_deref(),
        expected.table,
        expected.name,
    )?;
    let collation = metadata_optional_name(
        "COLLATION_NAME",
        collation.as_deref(),
        expected.table,
        expected.name,
    )?;

    if !schema_column_contract_matches(
        &name,
        &column_type,
        &nullable,
        default.as_deref(),
        charset.as_deref(),
        collation.as_deref(),
        expected,
    ) {
        return Err(MigrationError::Failed(format!(
            "strict schema contract drift at {}.{}; expected COLUMN_TYPE={}, IS_NULLABLE=NO, COLUMN_DEFAULT=0, CHARACTER_SET_NAME/COLLATION_NAME NULL or empty, found COLUMN_TYPE={column_type:?}, IS_NULLABLE={nullable:?}, COLUMN_DEFAULT={default:?}, CHARACTER_SET_NAME={charset:?}, COLLATION_NAME={collation:?}; refusing automatic ALTER/DROP",
            expected.table, expected.name, expected.column_type
        )));
    }
    Ok(())
}

async fn validate_schema_columns(
    pool: &MySqlPool,
    required: &[SchemaColumnContract],
) -> Result<(), MigrationError> {
    for expected in required {
        let metadata: Option<SchemaColumnMetadataRow> = sqlx::query_as(SCHEMA_COLUMN_METADATA_SQL)
            .bind(expected.table)
            .bind(expected.name)
            .fetch_optional(pool)
            .await
            .map_err(|e| {
                MigrationError::Failed(format!(
                    "inspect schema column {}.{}: {e}",
                    expected.table, expected.name
                ))
            })?;
        let Some((name, column_type, nullable, default, charset, collation)) = metadata else {
            return Err(MigrationError::Failed(format!(
                "schema contract is missing required column {}.{}; run the explicit Rust migration job",
                expected.table, expected.name
            )));
        };
        let name = metadata_text("COLUMN_NAME", &name, expected.table, expected.name)?;
        let column_type =
            metadata_text("COLUMN_TYPE", &column_type, expected.table, expected.name)?;
        let nullable = metadata_text("IS_NULLABLE", &nullable, expected.table, expected.name)?;
        let default = default
            .as_deref()
            .map(|value| metadata_text("COLUMN_DEFAULT", value, expected.table, expected.name))
            .transpose()?;
        let charset = metadata_optional_name(
            "CHARACTER_SET_NAME",
            charset.as_deref(),
            expected.table,
            expected.name,
        )?;
        let collation = metadata_optional_name(
            "COLLATION_NAME",
            collation.as_deref(),
            expected.table,
            expected.name,
        )?;
        let metadata_matches = name == expected.name
            && normalize_column_definition(&column_type)
                == normalize_column_definition(expected.column_type)
            && nullable.eq_ignore_ascii_case(if expected.not_null { "NO" } else { "YES" })
            && column_default_matches(default.as_deref(), expected.default)
            && if is_character_type(&column_type) {
                charset.as_deref() == expected.charset && collation.as_deref() == expected.collation
            } else {
                !metadata_name_is_present(charset.as_deref())
                    && !metadata_name_is_present(collation.as_deref())
            };
        if !metadata_matches {
            return Err(MigrationError::Failed(format!(
                "schema contract has incompatible column {}.{}; run the explicit Rust migration job",
                expected.table, expected.name
            )));
        }
    }
    Ok(())
}

async fn validate_contract(
    pool: &MySqlPool,
    required: &[(&str, &[&str])],
) -> Result<(), MigrationError> {
    for (table, columns) in required {
        let table_count = metadata_count(
            sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_TABLE_EXISTS_SQL)
                .bind(table)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!("inspect schema table {table}: {e}"))
                })?,
            "inspect schema table",
        )?;
        if table_count != 1 {
            return Err(MigrationError::Failed(format!(
                "schema contract is missing required table {table}; run the explicit Rust migration job"
            )));
        }

        for column in *columns {
            let column_count = metadata_count(
                sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_COLUMN_EXISTS_SQL)
                    .bind(table)
                    .bind(column)
                    .fetch_one(pool)
                    .await
                    .map_err(|e| {
                        MigrationError::Failed(format!(
                            "inspect schema column {table}.{column}: {e}"
                        ))
                    })?,
                "inspect schema column",
            )?;
            if column_count != 1 {
                return Err(MigrationError::Failed(format!(
                    "schema contract is missing required column {table}.{column}; run the explicit Rust migration job"
                )));
            }
        }
    }
    Ok(())
}

async fn validate_indexes(
    pool: &MySqlPool,
    required: &[(&str, &str, &[&str], bool)],
) -> Result<(), MigrationError> {
    for (table, index, columns, unique) in required {
        // Match the index by bound identifiers and inspect only numeric
        // metadata. This is the same VARBINARY-safe approach as table/column
        // validation, while the per-position checks retain exact index shape.
        let mut matched_candidate = None;
        for candidate in schema_index_candidates(table, index) {
            let (index_count, min_non_unique, max_non_unique): (
                Vec<u8>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            ) = sqlx::query_as(SCHEMA_INDEX_STATS_SQL)
                .bind(table)
                .bind(&candidate)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    MigrationError::Failed(format!("inspect schema index {table}.{index}: {e}"))
                })?;
            let index_count = metadata_count(index_count, "inspect schema index count")?;
            let min_non_unique =
                metadata_optional_u64(min_non_unique, "inspect schema index minimum NON_UNIQUE")?;
            let max_non_unique =
                metadata_optional_u64(max_non_unique, "inspect schema index maximum NON_UNIQUE")?;
            let expected_non_unique = u64::from(!*unique);
            let shape_matches = index_count == columns.len() as u64
                && min_non_unique == Some(expected_non_unique)
                && max_non_unique == Some(expected_non_unique);
            // A recognized canonical name takes precedence over compatibility
            // aliases. If it exists with the wrong shape, accepting a valid
            // alias would hide schema drift and leave the conflicting index in
            // place. Fail closed instead of silently selecting the alias.
            if candidate == *index && index_count != 0 && !shape_matches {
                return Err(MigrationError::Failed(format!(
                    "schema contract has missing or incompatible index {table}.{index}; run the explicit Rust migration job"
                )));
            }
            if !shape_matches {
                continue;
            }
            let mut columns_match = true;
            for (position, column) in columns.iter().enumerate() {
                let column_count = metadata_count(
                    sqlx::query_scalar::<_, Vec<u8>>(SCHEMA_INDEX_COLUMN_EXISTS_SQL)
                        .bind(table)
                        .bind(&candidate)
                        .bind((position as u64) + 1)
                        .bind(column)
                        .fetch_one(pool)
                        .await
                        .map_err(|e| {
                            MigrationError::Failed(format!(
                                "inspect schema index {table}.{index} column {column}: {e}"
                            ))
                        })?,
                    "inspect schema index column",
                )?;
                if column_count != 1 {
                    columns_match = false;
                    break;
                }
            }
            if !columns_match && candidate == *index {
                return Err(MigrationError::Failed(format!(
                    "schema contract has missing or incompatible index {table}.{index}; run the explicit Rust migration job"
                )));
            }
            if columns_match {
                matched_candidate = Some(candidate);
                break;
            }
        }
        if matched_candidate.is_none() {
            return Err(MigrationError::Failed(format!(
                "schema contract has missing or incompatible index {table}.{index}; run the explicit Rust migration job"
            )));
        }
    }
    Ok(())
}

pub async fn school_tenant_cutover_report(
    pool: &MySqlPool,
) -> Result<SchoolTenantCutoverReport, MigrationError> {
    validate_school_tenant_cutover_contract(pool).await?;
    Ok(SchoolTenantCutoverReport {
        mapped_schools: count(pool, "SELECT COUNT(*) FROM school_tenant_migration").await?,
        active_schools_without_mapping: count(
            pool,
            "SELECT COUNT(*) FROM schools s \
             LEFT JOIN school_tenant_migration m ON m.school_id = s.id \
             WHERE s.status = 'ACTIVE' AND m.school_id IS NULL",
        )
        .await?,
        school_members_without_tenant: count(
            pool,
            "SELECT COUNT(*) FROM school_members WHERE school_id IS NOT NULL AND tenant_id IS NULL",
        )
        .await?,
        user_profiles_without_tenant: count(
            pool,
            "SELECT COUNT(*) FROM user_profiles WHERE school_id IS NOT NULL AND tenant_id IS NULL",
        )
        .await?,
        leaderboards_without_tenant: count(
            pool,
            "SELECT COUNT(*) FROM leaderboards WHERE school_id IS NOT NULL AND tenant_id IS NULL",
        )
        .await?,
    })
}

async fn count(pool: &MySqlPool, statement: &str) -> Result<i64, MigrationError> {
    sqlx::query_scalar(statement)
        .fetch_one(pool)
        .await
        .map_err(|e| MigrationError::Failed(format!("school tenant cutover report: {e}")))
}

#[cfg(test)]
mod tests;
