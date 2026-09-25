//! AstralLight 数据库访问层
//!
//! 提供 `policy-engine` 的 `RuleRepository` 的 sqlx 实现。
//! 查询 MySQL 中的 `rule_set_snapshot`、`permission_rule`、`card_rule_set_ref` 表。
//!
//! # 数据库迁移
//!
//! ```
//! use astral_db::connect_and_validate_schema;
//! use std::error::Error;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn Error>> {
//!     if let Ok(database_url) = std::env::var("DATABASE_URL") {
//!         let pool = connect_and_validate_schema(&database_url).await?;
//!         drop(pool);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # 服务连接池扩容
//!
//! 高并发服务（trustgraph）使用
//! [`connect_and_validate_schema_with_pool_options`] 以可配置的
//! `max_connections` / `acquire_timeout` 构建服务池；启动校验契约与
//! [`connect_and_validate_schema`] 完全一致。

use std::str::FromStr;
use std::time::Duration;

#[cfg(feature = "e4-observability")]
use sha2::{Digest, Sha256};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};

mod authorization_projection_repository;
mod cache_epoch;
mod cross_city_repository;
mod cross_city_transport_repository;
mod eligibility;
pub mod evidence_cache;
pub mod grant_ledger;
mod grant_repository;
mod migration;
pub mod org_scope_repository;
mod permission_query;
mod projection;
mod quarantine;
mod repository;
mod resource_ownership;
mod sod_check;

pub use authorization_projection_repository::*;
pub use cache_epoch::*;
pub use cross_city_repository::*;
pub use cross_city_transport_repository::*;
pub use eligibility::*;
pub use evidence_cache::*;
pub use grant_repository::*;
pub use migration::*;
pub use org_scope_repository::*;
pub use permission_query::*;
pub use projection::*;
pub use quarantine::*;
pub use repository::*;
pub use resource_ownership::*;
pub use sod_check::*;

// ─────────────────────────────────────────────────────────────────────────────
// 服务连接池扩容（读链规模化：默认 5 连接 / 30s acquire 在并发下排队成瓶颈）
// ─────────────────────────────────────────────────────────────────────────────

/// 服务池会话契约字面量（必须与 `migration.rs` 的同名常量逐字一致——
/// `migration.rs` 禁改，故以源码文本比对锚定防止两份契约漂移，见测试
/// `service_pool_session_contract_mirrors_migration_contract`）。
const SERVICE_POOL_CHARSET: &str = "utf8mb4";
const SERVICE_POOL_COLLATION: &str = "utf8mb4_unicode_ci";
const SERVICE_POOL_UTC_TIME_ZONE_SQL: &str = "SET time_zone = '+00:00'";

#[cfg(feature = "e4-observability")]
const SERVICE_POOL_PRECONDITION_SQL: &str = "SELECT CONNECTION_ID(), @@server_uuid, @@global.read_only, @@global.super_read_only, @@session.transaction_isolation, @@session.time_zone, CAST(UNIX_TIMESTAMP(UTC_TIMESTAMP(6)) * 1000000000 AS UNSIGNED)";

#[cfg(feature = "e4-observability")]
fn wall_unix_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(feature = "e4-observability")]
async fn observe_service_pool_connection(
    connection: &mut sqlx::MySqlConnection,
) -> Result<(), sqlx::Error> {
    let wall_start_ns = wall_unix_ns();
    let (
        connection_id,
        server_uuid,
        read_only,
        super_read_only,
        isolation,
        time_zone,
        db_utc_unix_ns,
    ): (u64, String, i64, i64, String, String, u64) = sqlx::query_as(SERVICE_POOL_PRECONDITION_SQL)
        .fetch_one(&mut *connection)
        .await?;
    let wall_end_ns = wall_unix_ns();
    let db_utc_unix_ns = u128::from(db_utc_unix_ns);
    let offset_lower_ns = db_utc_unix_ns as i128 - wall_end_ns as i128;
    let offset_upper_ns = db_utc_unix_ns as i128 - wall_start_ns as i128;
    let server_identity_sha256 = format!("{:x}", Sha256::digest(server_uuid.as_bytes()));
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e4",
        event = "pool_connection_precondition",
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        connection_id,
        server_identity_sha256,
        global_read_only = read_only != 0,
        global_super_read_only = super_read_only != 0,
        primary_route = read_only == 0 && super_read_only == 0,
        session_isolation = %isolation,
        session_time_zone = %time_zone,
        db_utc_unix_ns = %db_utc_unix_ns,
        wall_start_ns = %wall_start_ns,
        wall_end_ns = %wall_end_ns,
        offset_lower_ns = %offset_lower_ns,
        offset_upper_ns = %offset_upper_ns,
        db_clock_inside_call_interval = wall_start_ns <= db_utc_unix_ns
            && db_utc_unix_ns <= wall_end_ns,
        "e4 deployment precondition observation"
    );
    Ok(())
}

/// 以可配置的池参数（`max_connections` / `acquire_timeout`）构建服务连接池，
/// 启动校验契约与 [`connect_and_validate_schema`] 完全一致。
///
/// 背景（读链规模化）：压测显示默认池（5 连接 / 30s acquire）在 50 并发下
/// 连接排队成为吞吐瓶颈（Threads_connected 排队主因）。trustgraph 以更大
/// 池（默认 80，处于 MySQL 服务端 max_connections=151 预算内）与更快的
/// acquire 失败反馈（默认 5s）运行。
///
/// 校验契约保持逐字一致的原因：历史迁移栅栏 preflight 的实现细节在 `migration`
/// 模块内部（不导出），此处不复制第二份会漂移的校验实现，而是复用
/// [`connect_and_validate_schema`] 在其专用小池（5 连接）上完成全部启动校验
/// （历史迁移 preflight + schema 契约），校验池用后即弃；服务池以扩容参数
/// 惰性建立（`min_connections` 保持 sqlx 默认 0，物理连接按需打开），并对其
/// 本体复跑 [`validate_schema_contract`]，证明扩容池的会话契约下 schema 契约
/// 依然成立。两段校验都只在启动期执行，不构成运行期成本。
///
/// 参数守卫：`max_connections`/`acquire_timeout` 为 0 在任何 DB 连接发生之前
/// 即拒绝（fail-fast，绝不以病态池参数静默启动）。
pub async fn connect_and_validate_schema_with_pool_options(
    database_url: &str,
    max_connections: u32,
    acquire_timeout: Duration,
) -> Result<MySqlPool, MigrationError> {
    if max_connections == 0 {
        return Err(MigrationError::Failed(
            "service pool max_connections must be >= 1".into(),
        ));
    }
    if acquire_timeout.is_zero() {
        return Err(MigrationError::Failed(
            "service pool acquire_timeout must be positive".into(),
        ));
    }

    // 服务池会话契约与 mysql_pool_options 一致：schema charset/collation 的
    // 物理连接级契约 + UTC 会话时区（字面量经测试锚定与 migration.rs 同源）。
    let connect_options = MySqlConnectOptions::from_str(database_url)
        .map(|options| {
            options
                .charset(SERVICE_POOL_CHARSET)
                .collation(SERVICE_POOL_COLLATION)
        })
        .map_err(|e| MigrationError::Failed(format!("parse database URL: {e}")))?;
    let pool = MySqlPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(acquire_timeout)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query(SERVICE_POOL_UTC_TIME_ZONE_SQL)
                    .execute(&mut *connection)
                    .await?;
                #[cfg(feature = "e4-observability")]
                observe_service_pool_connection(connection).await?;
                Ok(())
            })
        })
        .connect_with(connect_options)
        .await
        .map_err(|e| MigrationError::Failed(format!("connect: {e}")))?;

    match connect_and_validate_schema(database_url).await {
        Ok(validation_pool) => {
            // 校验池使命完成即弃（5 连接上限，启动期瞬时占用）。
            drop(validation_pool);
        }
        Err(error) => {
            drop(pool);
            return Err(error);
        }
    }
    // 服务池本体复跑 schema 契约校验（启动期；证明扩容池会话契约下契约
    // 成立，同时是对新池的连通性冒烟）。校验失败即弃服务池并上抛。
    match validate_schema_contract(&pool).await {
        Ok(()) => Ok(pool),
        Err(error) => {
            drop(pool);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 服务池会话契约字面量与 migration.rs 的常量逐字锚定（migration.rs 禁改，
    /// 以源码文本比对防漂移：任一侧改动而另一侧未同步即失败）。
    #[test]
    fn service_pool_session_contract_mirrors_migration_contract() {
        let source = include_str!("migration.rs");
        for (constant, ours) in [
            ("const MYSQL_SCHEMA_CHARSET: &str = ", SERVICE_POOL_CHARSET),
            (
                "const MYSQL_SCHEMA_COLLATION: &str = ",
                SERVICE_POOL_COLLATION,
            ),
            (
                "const SET_UTC_TIME_ZONE_SQL: &str = ",
                SERVICE_POOL_UTC_TIME_ZONE_SQL,
            ),
        ] {
            let line = source
                .lines()
                .find(|line| line.trim_start().starts_with(constant))
                .unwrap_or_else(|| panic!("migration contract constant missing: {constant}"));
            assert!(
                line.contains(ours),
                "service pool session contract {ours:?} must mirror the migration.rs contract: {line}"
            );
        }
    }

    /// 扩容池参数守卫：0 连接 / 0 超时在任何 DB 连接发生之前即拒绝
    /// （fail-fast；本测试不接触真实数据库）。
    #[tokio::test]
    async fn pool_options_guard_rejects_zero_bounds_before_connecting() {
        let error = connect_and_validate_schema_with_pool_options(
            "mysql://user:pass@127.0.0.1:1/none",
            0,
            Duration::from_secs(5),
        )
        .await
        .expect_err("zero max_connections must be rejected");
        assert!(error.to_string().contains("max_connections"));

        let error = connect_and_validate_schema_with_pool_options(
            "mysql://user:pass@127.0.0.1:1/none",
            80,
            Duration::ZERO,
        )
        .await
        .expect_err("zero acquire_timeout must be rejected");
        assert!(error.to_string().contains("acquire_timeout"));
    }
}
