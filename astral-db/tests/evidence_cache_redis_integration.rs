//! published card evidence 三级缓存链路（L1 moka 进程内 → L2 Redis 分发层 →
//! L3 DB 严格 reader 回源）的**真实 Redis** 集成测试。
//!
//! # 被测对象
//!
//! `astral_db::evidence_cache`：命中协议（读前对牌 + epoch + 读后复读对牌 +
//! 时钟重验）、miss 协议（L2 Redis 优先 → L3 DB 兜底 + 回填两级）、污染清除
//! （content_hash 重验 / schema / 合同校验）、epoch 内嵌键轮换、发布后推送
//! （`push_published_card_evidence_to_l2`）。与 `src/evidence_cache.rs` 内的
//! 批次 C/D 单元测试（内存注入 L2）互补：本文件所有 L2 读写都落**真实
//! Redis**（`REDIS_URL`），DB 依赖场景再经 `DATABASE_URL`（SSH 隧道）走真实
//! 严格 reader / 指针栅栏 / 发布管线。
//!
//! # 环境门禁（对齐既有 integration 门禁风格）
//!
//! - `REDIS_URL`（本套件全部用例必需）：未设置或 PING 失败时默认显式
//!   `[SKIP]`；设置 `RUST_INTEGRATION_REQUIRED=1` 时这些前置失败转换为
//!   panic（`[SKIP]` 不算 PASS）。
//! - `DATABASE_URL`（仅 DB 依赖用例必需）：同上门禁；且要求 Rust 自有投影
//!   迁移已应用（六张 `authorization_projection_*`/`authorization_archive_*`
//!   表存在，只读预检，绝不执行临时 DDL）。
//!
//! # 运行方式
//!
//! ```text
//! # 全量（Redis + DB 隧道）：
//! REDIS_URL="redis://192.0.2.10:6381" \
//! DATABASE_URL="mysql://…@127.0.0.1:3308/astral_rehearsal" \
//!   cargo test -p astral-db --test evidence_cache_redis_integration -- --ignored --test-threads=1
//! # 仅纯 Redis 场景（不设 DATABASE_URL，DB 用例显式 [SKIP]）：
//! REDIS_URL="redis://192.0.2.10:6381" \
//!   cargo test -p astral-db --test evidence_cache_redis_integration -- --ignored --test-threads=1
//! ```
//!
//! # 隔离与清理
//!
//! - 每个用例独立 uuid 派生的 `(tenant_id, card_id)` 大整数命名空间与独立
//!   `it-<uuid>` 缓存时代；L2 键 = `astral:auth:l2ev:{epoch}:{tenant}:{card}`
//!   时代内嵌，天然互不冲突，也不触碰生产键族（epoch 分量随机）。
//! - 用例结束删除自身 L2 键与自身 DB 命名空间行；断言 panic 时清理不执行，
//!   但所有 L2 键都带 ≤300s TTL（Redis 侧自愈过期），DB 行由随机 tenant
//!   隔离（与 `authorization_projection_integration.rs` 同一残余面）。
//! - 唯一例外：`db_push_after_publish_then_fresh_instance_hits_l2` 走生产
//!   `current_cache_epoch()`（全局 `astral:auth:cache_epoch` 键）。该键缺失
//!   时由用例创建、结束时删除还原；已存在则只读不删。
//! - 注入时钟仅在用例内推进（不真实等待 TTL）；栅栏推进使用真实 DB 发布
//!   管线（或 D3 的指针行直改）。
//!
//! # 场景矩阵与 Java 基线对应
//!
//! | 用例 | Java 基线 | 依赖 |
//! |------|-----------|------|
//! | `redis_ci1_cold_miss_strict_once_then_l1_hit_and_l2_entry_shape` | CI_1 + CI_7 | Redis |
//! | `redis_ci6_fresh_instance_hits_l2_then_l1_only` | CI_6 | Redis |
//! | `redis_content_hash_pollution_purges_and_self_heals` | CI_9（加深） | Redis |
//! | `redis_schema_version_mismatch_purges_and_refills` | 新链加深 | Redis |
//! | `redis_epoch_rotation_old_epoch_key_mismatches_then_revives` | CI_10（加深） | Redis |
//! | `redis_ttl_semantics_l2_300s_and_l1_entry_presence` | CI_11 | Redis |
//! | `redis_clock_revalidation_purges_expired_l2_entry` | CI_11（加深） | Redis |
//! | `redis_cross_instance_sharing_second_instance_reads_l2` | 新链（多节点分发） | Redis |
//! | `redis_contract_violating_payload_with_valid_hash_purges` | 新链加深 | Redis |
//! | `redis_unreachable_degrades_to_l1_plus_strict` | CI_8 | Redis |
//! | `redis_v3_two_cards_share_one_rule_set_unit_with_separate_envelopes` | 新链（v3 跨卡存储去重） | Redis |
//! | `redis_v3_shared_unit_missing_purges_and_strict_reads` | 新链加深（v3 部分写） | Redis |
//! | `redis_v3_shared_unit_hash_mismatch_purges` | 新链加深（v3 单元投毒） | Redis |
//! | `redis_v3_mac_missing_entry_purges` | 新链加深（v3 HMAC 缺失） | Redis |
//! | `redis_v3_mac_wrong_secret_purges` | 新链加深（v3 HMAC 错误密钥） | Redis |
//! | `redis_v3_key_bound_replay_purges` | 新链加深（v3 键绑定重放） | Redis |
//! | `redis_v3_record_level_scope_poison_purges` | 新链加深（v3 记录级作用域） | Redis |
//! | `redis_v2_entry_purges_and_self_heals` | 新链加深（v2 退役自愈） | Redis |
//! | `redis_v3_secret_unavailable_bypasses_l2_read_and_write` | 新链加深（HMAC 密钥不可用 fail-closed） | Redis |
//! | `db_ci1_strict_reader_called_once_then_l1_hit` | CI_1（真实 reader） | Redis+DB |
//! | `db_ci7_double_miss_full_chain_backfills_l1_and_l2` | CI_7（真实回源） | Redis+DB |
//! | `db_pointer_only_generation_update_fails_closed_without_stale_serving` | CI_2/CS_1（直改指针行） | Redis+DB |
//! | `db_generation_advance_via_publish_busts_l1_l2_and_refills_new_version` | CI_2/CI_3 | Redis+DB |
//! | `db_revoke_fence_advance_via_publish_busts_and_refills` | CS_1 | Redis+DB |
//! | `db_push_after_publish_then_fresh_instance_hits_l2` | 新链（发布推送） | Redis+DB |

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use astral_db::{
    claim_authorization_manifest_in_tx, connect_and_validate_schema, current_cache_epoch,
    finalize_authorization_manifest_in_tx, l2_evidence_key, l2_shared_unit_key,
    load_card_scope_fence_snapshot, load_evidence_through_cache,
    load_evidence_through_cache_with_mac, load_published_card_grant_evidence,
    publish_current_pointer_in_tx, push_published_card_evidence_to_l2,
    stage_authorization_manifest_in_tx, AuthorizationEvidenceError, AuthorizationFinalizeRequest,
    AuthorizationPublishOutcome, AuthorizationPublishRequest, AuthorizationStageRequest,
    CardScopeFenceSnapshot, CurrentPointerView, DbError, EvidenceCacheStore, EvidenceReadDeps,
    L2EvidenceStore, PermissionCacheManifestVersion, PublishRevokeFenceEvidence,
    RedisL2EvidenceStore, StagedSegmentContent, CACHE_EPOCH_KEY, L2_EVIDENCE_HMAC_SECRET_ENV,
    L2_EVIDENCE_TTL_SECONDS,
};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, GrantEffect, GrantId, GrantProvenance,
    GrantRevision, GrantSourceKind, GrantState, PublishedAggregateManifestSummary,
    PublishedCardAuthorization, PublishedCardAuthorizationGate, PublishedCardEvidenceScope,
    PublishedEvidenceGateStatus, TenantScope, UnacceptedGrantReason, ValidityWindow,
    VerifiedPublishedGrantRecord,
};
use moka::future::Cache;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// 集成测试进程的 L2 HMAC 密钥（专用集成测试值；生产密钥由部署环境提供）。
/// 必须在任何 L2 读/写发生前写入环境变量——进程级密钥解析是单次的
/// （单密钥语义），本套件 runbook 为 `--test-threads=1`，即使并行运行全部
/// 用例也写入同一值（幂等，无语义竞争）。
const INTEGRATION_HMAC_SECRET: &str = "integration-only-l2-evidence-hmac-secret-0123456789abcdef";

/// 在首次 L2 使用前确保 HMAC 密钥环境变量就位（fail-closed 语义下缺失密钥
/// 会让全部 L2 用例退化为纯严格读——那是另一条用例显式验证的行为）。
fn ensure_l2_hmac_secret_env() {
    if std::env::var(L2_EVIDENCE_HMAC_SECRET_ENV).as_deref() != Ok(INTEGRATION_HMAC_SECRET) {
        std::env::set_var(L2_EVIDENCE_HMAC_SECRET_ENV, INTEGRATION_HMAC_SECRET);
    }
}

/// Rust 自有投影/归档表；DB 依赖用例要求六张表全部存在（迁移已应用）。
const REQUIRED_PROJECTION_TABLES: &[&str] = &[
    "authorization_projection_manifest",
    "authorization_projection_segment",
    "authorization_projection_manifest_segment",
    "authorization_projection_current",
    "authorization_archive_outbox",
    "authorization_archive_manifest",
];

/// DB 发布夹具使用的聚合类型：合法标识符且属于卡级证据读取器接受的类型集。
const AGGREGATE_TYPE: &str = "USER_CARD";

const MANIFEST_LEASE_SECONDS: i64 = 600;

/// 断言 Redis TTL 时允许的网络/时钟损耗（秒）：写后立即读 TTL 应仍接近满值。
const TTL_SLACK_SECONDS: i64 = 10;

// ─────────────────────────────────────────────────────────────────────────────
// 环境门禁（缺省显式 [SKIP]；RUST_INTEGRATION_REQUIRED=1 转 panic）
// ─────────────────────────────────────────────────────────────────────────────

/// 真实 Redis 夹具：全部用例共享的门禁入口（连接 + PING 只读探测）。
struct RedisFixture {
    client: redis::Client,
}

fn integration_required() -> bool {
    std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1")
}

async fn redis_gate() -> Option<RedisFixture> {
    ensure_l2_hmac_secret_env();
    let required = integration_required();
    let url = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        Ok(_) | Err(_) => {
            let message = "REDIS_URL must be set to run the real-Redis evidence cache tests";
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };
    let client = match redis::Client::open(url.as_str()) {
        Ok(client) => client,
        Err(error) => {
            let message = format!("REDIS_URL is not a valid Redis URL: {error}");
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };
    match client.get_connection_manager().await {
        Ok(mut conn) => match redis::cmd("PING").query_async::<String>(&mut conn).await {
            Ok(pong) if pong == "PONG" => Some(RedisFixture { client }),
            Ok(other) => {
                let message = format!("REDIS_URL did not answer PING with PONG: {other}");
                if required {
                    panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
                }
                eprintln!("[SKIP] {message}");
                None
            }
            Err(error) => {
                let message = format!("Redis PING failed: {error}");
                if required {
                    panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
                }
                eprintln!("[SKIP] {message}");
                None
            }
        },
        Err(error) => {
            let message = format!("cannot connect to REDIS_URL: {error}");
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            None
        }
    }
}

impl RedisFixture {
    async fn conn(&self) -> redis::aio::ConnectionManager {
        self.client
            .get_connection_manager()
            .await
            .expect("redis connection must succeed after the gate")
    }

    async fn get(&self, key: &str) -> Option<String> {
        let mut conn = self.conn().await;
        conn.get::<_, Option<String>>(key.to_owned())
            .await
            .expect("redis GET must succeed after the gate")
    }

    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) {
        let mut conn = self.conn().await;
        conn.set_ex::<_, _, ()>(key.to_owned(), value.to_owned(), ttl_seconds)
            .await
            .expect("redis SETEX must succeed after the gate");
    }

    async fn ttl(&self, key: &str) -> i64 {
        let mut conn = self.conn().await;
        redis::cmd("TTL")
            .arg(key)
            .query_async::<i64>(&mut conn)
            .await
            .expect("redis TTL must succeed after the gate")
    }

    async fn del(&self, keys: &[String]) {
        if keys.is_empty() {
            return;
        }
        let mut conn = self.conn().await;
        redis::cmd("DEL")
            .arg(keys)
            .query_async::<i64>(&mut conn)
            .await
            .expect("redis DEL must succeed after the gate");
    }

    /// 本用例命名空间的 L2 键（epoch 内嵌，单 (tenant, card) 单键）。
    fn l2_key(&self, epoch: &str, tenant_id: i64, card_id: i64) -> String {
        l2_evidence_key(epoch, tenant_id, card_id)
    }
}

/// 连接数据库并完成只读 schema 预检（DB 依赖用例专用）。
async fn db_gate() -> Option<MySqlPool> {
    let required = integration_required();
    let url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        Ok(_) | Err(_) => {
            let message = "DATABASE_URL must be set to run the DB-backed evidence cache tests";
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };
    let pool = match connect_and_validate_schema(&url).await {
        Ok(pool) => pool,
        Err(error) => {
            let message = format!("MySQL connection/schema validation failed: {error}");
            if required {
                panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
            }
            eprintln!("[SKIP] {message}");
            return None;
        }
    };
    let mut missing = Vec::new();
    for table in REQUIRED_PROJECTION_TABLES {
        let present: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.TABLES \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("information_schema query must succeed after schema validation");
        if present.0 == 0 {
            missing.push((*table).to_owned());
        }
    }
    if !missing.is_empty() {
        let message = format!(
            "Rust-owned authorization projection tables are missing (migrations \
             20260825000002/20260827000001 not applied): {missing:?}"
        );
        if required {
            panic!("RUST_INTEGRATION_REQUIRED=1: {message}");
        }
        eprintln!("[SKIP] {message}");
        return None;
    }
    Some(pool)
}

// ─────────────────────────────────────────────────────────────────────────────
// 随机命名空间与清理（对齐 authorization_projection_integration 的 uuid 风格）
// ─────────────────────────────────────────────────────────────────────────────

/// 独立随机测试命名空间：uuid 派生的大整数，保证跨运行/跨用例互不冲突。
struct TestNamespace {
    label: &'static str,
    salt: u128,
    tenant_id: i64,
    card_id: i64,
    aggregate_id: i64,
    user_id: i64,
    domain_id: i64,
}

impl TestNamespace {
    fn new(label: &'static str) -> Self {
        let salt = Uuid::new_v4().as_u128();
        // 8e12 起步、步长 1e5 的稀疏大整数区间，远离真实业务 id。
        let base = 8_000_000_000_000_i64 + ((salt % 1_000_000_000) as i64) * 100_000;
        Self {
            label,
            salt,
            tenant_id: base,
            card_id: base + 1,
            aggregate_id: base + 2,
            user_id: base + 3,
            domain_id: base + 4,
        }
    }

    fn identity(&self) -> astral_db::ProjectionAggregateIdentity {
        astral_db::ProjectionAggregateIdentity::new(
            self.tenant_id,
            AGGREGATE_TYPE,
            self.aggregate_id,
        )
        .expect("test namespace identity must be valid")
    }

    /// 缓存协议只服务卡级 lens（user_filter None + Unconstrained）。
    fn card_level_scope(&self) -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        }
    }

    fn event_id(&self, tag: &str) -> String {
        format!("ev-{}-{salt:032x}-{tag}", self.label, salt = self.salt)
    }

    fn operation_id(&self, tag: &str) -> String {
        format!("op-{}-{salt:032x}-{tag}", self.label, salt = self.salt)
    }
}

/// 只删除本命名空间 `tenant_id` 下的行（先子后父，无外键纯防御顺序）。
async fn cleanup_namespace(pool: &MySqlPool, namespace: &TestNamespace) {
    for statement in [
        "DELETE FROM authorization_archive_manifest WHERE tenant_id = ?",
        "DELETE FROM authorization_archive_outbox WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_current WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_manifest_segment WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_segment WHERE tenant_id = ?",
        "DELETE FROM authorization_projection_manifest WHERE tenant_id = ?",
    ] {
        sqlx::query(statement)
            .bind(namespace.tenant_id)
            .execute(pool)
            .await
            .expect("namespace cleanup must succeed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试侧 SPI 实现：计数装饰的真实 Redis L2 / 不可达 Redis / 读取依赖
// ─────────────────────────────────────────────────────────────────────────────

/// 生产 `RedisL2EvidenceStore` 的计数装饰：L2 全部落真实 Redis（走生产
/// `REDIS_URL` 连接路径），同时暴露 get/set/del 调用计数供协议断言。
struct CountingL2Store {
    inner: RedisL2EvidenceStore,
    get_calls: AtomicUsize,
    set_calls: AtomicUsize,
    del_calls: AtomicUsize,
}

impl CountingL2Store {
    fn new() -> Self {
        Self {
            inner: RedisL2EvidenceStore,
            get_calls: AtomicUsize::new(0),
            set_calls: AtomicUsize::new(0),
            del_calls: AtomicUsize::new(0),
        }
    }

    fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }

    fn set_calls(&self) -> usize {
        self.set_calls.load(Ordering::SeqCst)
    }

    fn del_calls(&self) -> usize {
        self.del_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl L2EvidenceStore for CountingL2Store {
    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key).await
    }

    async fn set_ex(&self, key: &str, value: String, ttl_seconds: u64) -> Result<(), String> {
        self.set_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.set_ex(key, value, ttl_seconds).await
    }

    async fn del(&self, key: &str) -> Result<(), String> {
        self.del_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.del(key).await
    }
}

/// 真实不可达 Redis（127.0.0.1:1 每次操作真实 TCP 连接拒绝）：降级语义
/// （`Err` → 静默旁路 L1+DB 照常）的端到端验证，不注入伪造错误。
struct UnreachableL2Store;

async fn unreachable_connection() -> Result<redis::aio::ConnectionManager, String> {
    let client = redis::Client::open("redis://127.0.0.1:1/")
        .map_err(|error| format!("code=it.unreachable_client_open;{error}"))?;
    client
        .get_connection_manager()
        .await
        .map_err(|error| format!("code=it.unreachable_connect;{error}"))
}

#[async_trait::async_trait]
impl L2EvidenceStore for UnreachableL2Store {
    async fn get(&self, _key: &str) -> Result<Option<String>, String> {
        let mut conn = unreachable_connection().await?;
        conn.get::<_, Option<String>>(_key.to_owned())
            .await
            .map_err(|error| format!("code=it.unreachable_get;{error}"))
    }

    async fn set_ex(&self, _key: &str, _value: String, _ttl_seconds: u64) -> Result<(), String> {
        let mut conn = unreachable_connection().await?;
        conn.set_ex::<_, _, ()>(_key.to_owned(), _value, _ttl_seconds)
            .await
            .map_err(|error| format!("code=it.unreachable_set_ex;{error}"))
    }

    async fn del(&self, _key: &str) -> Result<(), String> {
        let mut conn = unreachable_connection().await?;
        redis::cmd("DEL")
            .arg(_key)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|error| format!("code=it.unreachable_del;{error}"))
    }
}

/// 纯 Redis 用例（无 DB）的读取依赖：栅栏版本组持久可变（模拟指针状态）、
/// 严格读来自预置队列、时代/时钟用例内可控。
struct FixtureDeps {
    epoch: Mutex<String>,
    fence: Mutex<CardScopeFenceSnapshot>,
    strict: Mutex<VecDeque<PublishedCardAuthorization>>,
    strict_calls: AtomicUsize,
    fence_calls: AtomicUsize,
    now: AtomicI64,
}

impl FixtureDeps {
    fn new(epoch: &str, fence: CardScopeFenceSnapshot, now: i64) -> Self {
        Self {
            epoch: Mutex::new(epoch.to_owned()),
            fence: Mutex::new(fence),
            strict: Mutex::new(VecDeque::new()),
            strict_calls: AtomicUsize::new(0),
            fence_calls: AtomicUsize::new(0),
            now: AtomicI64::new(now),
        }
    }

    fn push_strict(&self, evidence: PublishedCardAuthorization) {
        self.strict.lock().unwrap().push_back(evidence);
    }

    fn set_epoch(&self, epoch: &str) {
        *self.epoch.lock().unwrap() = epoch.to_owned();
    }

    fn strict_calls(&self) -> usize {
        self.strict_calls.load(Ordering::SeqCst)
    }

    fn fence_calls(&self) -> usize {
        self.fence_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl EvidenceReadDeps for FixtureDeps {
    async fn card_scope_fence_snapshot(
        &self,
        _tenant_id: i64,
        _card_id: i64,
    ) -> Result<CardScopeFenceSnapshot, DbError> {
        self.fence_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.fence.lock().unwrap().clone())
    }

    async fn strict_read(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
        self.strict_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .strict
            .lock()
            .unwrap()
            .pop_front()
            .expect("fixture strict queue must not be exhausted (test bug)"))
    }

    async fn current_epoch(&self) -> Option<String> {
        Some(self.epoch.lock().unwrap().clone())
    }

    fn now_unix_seconds(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// DB 依赖用例的读取依赖：栅栏轻读与严格回源都走真实 MySQL（隧道），时代
/// 注入（uuid 命名空间，不触碰全局 epoch 键），时钟注入（默认真实 UTC）。
struct DbBackedDeps {
    pool: MySqlPool,
    epoch: String,
    now: AtomicI64,
    strict_calls: AtomicUsize,
    fence_calls: AtomicUsize,
}

impl DbBackedDeps {
    fn new(pool: MySqlPool, epoch: &str) -> Self {
        Self {
            pool,
            epoch: epoch.to_owned(),
            now: AtomicI64::new(OffsetDateTime::now_utc().unix_timestamp()),
            strict_calls: AtomicUsize::new(0),
            fence_calls: AtomicUsize::new(0),
        }
    }

    fn strict_calls(&self) -> usize {
        self.strict_calls.load(Ordering::SeqCst)
    }

    fn fence_calls(&self) -> usize {
        self.fence_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl EvidenceReadDeps for DbBackedDeps {
    async fn card_scope_fence_snapshot(
        &self,
        tenant_id: i64,
        card_id: i64,
    ) -> Result<CardScopeFenceSnapshot, DbError> {
        self.fence_calls.fetch_add(1, Ordering::SeqCst);
        load_card_scope_fence_snapshot(&self.pool, tenant_id, card_id).await
    }

    async fn strict_read(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
        self.strict_calls.fetch_add(1, Ordering::SeqCst);
        load_published_card_grant_evidence(&self.pool, scope).await
    }

    async fn current_epoch(&self) -> Option<String> {
        Some(self.epoch.clone())
    }

    fn now_unix_seconds(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 通用夹具：fresh moka L1 / load 包装 / L2 条目镜像 / 证据 fixture
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_cache() -> EvidenceCacheStore {
    Cache::builder()
        .max_capacity(1_000)
        .time_to_live(Duration::from_secs(30))
        .build()
}

async fn load_through<D: EvidenceReadDeps>(
    deps: &D,
    cache: &EvidenceCacheStore,
    l2: Option<&dyn L2EvidenceStore>,
    namespace: &TestNamespace,
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    load_evidence_through_cache(deps, cache, l2, &namespace.card_level_scope()).await
}

/// L2 条目的测试侧镜像（与写侧 serde 契约同形同序；仅断言/播种用）。
/// schema 3 起 `payload` 为**因子化存储形态**（非 RULE_SET 记录内联、
/// RULE_SET 记录拆 envelope + 共享单元引用）；完整 payload 由
/// [`mirror_reconstruct_full`] 依 envelope + 已验证单元唯一重建。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2EntryMirror {
    schema_version: i64,
    manifest_versions: Vec<PermissionCacheManifestVersion>,
    card_source_pending: bool,
    content_hash: String,
    mac: String,
    payload: L2FactoredPayloadMirror,
}

/// 因子化存储形态镜像（镜像写侧 `L2FactoredCardPayload`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2FactoredPayloadMirror {
    tenant_id: i64,
    card_id: i64,
    read_unix_seconds: i64,
    gate: PublishedCardAuthorizationGate,
    manifests: Vec<PublishedAggregateManifestSummary>,
    records: Vec<L2RecordSlotMirror>,
}

/// 记录槽位镜像（镜像写侧 `L2RecordSlot`：保持原始 records 顺序）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum L2RecordSlotMirror {
    Inline(VerifiedPublishedGrantRecord),
    Shared(L2SharedEnvelopeMirror),
}

/// RULE_SET envelope 镜像（镜像写侧 `L2SharedRecordEnvelope`：身份/绑定/
/// provenance 逐卡私有）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2SharedEnvelopeMirror {
    aggregate_id: i64,
    publication_generation: u64,
    revoke_fence: u64,
    manifest_id: i64,
    event_id: String,
    operation_id: String,
    segment_ordinal: u64,
    position_in_segment: u64,
    grant: L2GrantEnvelopeMirror,
    shared_unit_digest: String,
    accepted_into_effective_set: bool,
    unaccepted_reason: Option<UnacceptedGrantReason>,
}

/// grant envelope 镜像（镜像写侧 `L2GrantEnvelope`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2GrantEnvelopeMirror {
    grant_id: GrantId,
    revision: GrantRevision,
    state: GrantState,
    source_kind: GrantSourceKind,
    binding_layer: BindingLayer,
    tenant: TenantScope,
    card_id: i64,
    user_id: i64,
    provenance: GrantProvenance,
}

/// 共享单元镜像（镜像写侧 `L2SharedUnit`：内容摘要自校验）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2SharedUnitMirror {
    unit_schema_version: i64,
    digest: String,
    content: L2SharedUnitContentMirror,
}

/// 共享内容镜像（镜像写侧 `L2SharedUnitContent`：card-less 规则内容）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2SharedUnitContentMirror {
    resource: String,
    action: String,
    effect: GrantEffect,
    validity: ValidityWindow,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
    compiler_version: String,
}

/// 完整 payload 序列化 JSON 的 sha256（镜像写侧 `l2_content_hash` 的口径：
/// 绑定量是因子化前的完整证据，读侧对重建结果重验）。
fn mirror_content_hash(payload: &PublishedCardAuthorization) -> String {
    let payload_json = serde_json::to_string(payload).expect("payload serialization must succeed");
    hex::encode(Sha256::digest(payload_json.as_bytes()))
}

/// 共享单元内容摘要（镜像写侧 `l2_shared_unit_digest`：内容寻址基础）。
fn mirror_unit_digest(content: &L2SharedUnitContentMirror) -> String {
    let json = serde_json::to_string(content).expect("unit content serialization must succeed");
    hex::encode(Sha256::digest(json.as_bytes()))
}

/// L2 条目 MAC（镜像写侧 `l2_entry_mac_hex`：HMAC-SHA256 over 域分隔 + 精确
/// 键 + schema + 版本组 + content_hash + 完整 payload 的规范 JSON）。
fn mirror_entry_mac(
    redis_key: &str,
    manifest_versions: &[PermissionCacheManifestVersion],
    content_hash: &str,
    payload: &PublishedCardAuthorization,
) -> String {
    mirror_entry_mac_with_secret(
        INTEGRATION_HMAC_SECRET.as_bytes(),
        redis_key,
        manifest_versions,
        content_hash,
        payload,
    )
}

/// [`mirror_entry_mac`] 的密钥参数化变体（错误密钥攻击模拟用）。
fn mirror_entry_mac_with_secret(
    secret: &[u8],
    redis_key: &str,
    manifest_versions: &[PermissionCacheManifestVersion],
    content_hash: &str,
    payload: &PublishedCardAuthorization,
) -> String {
    use hmac::Mac;
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Cover<'a> {
        domain: &'static str,
        redis_key: &'a str,
        schema_version: i64,
        manifest_versions: &'a [PermissionCacheManifestVersion],
        card_source_pending: bool,
        content_hash: &'a str,
        payload: &'a PublishedCardAuthorization,
    }
    let cover = Cover {
        domain: "astral:l2-evidence:v4:hmac-sha256",
        redis_key,
        schema_version: 4,
        manifest_versions,
        card_source_pending: false,
        content_hash,
        payload,
    };
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(&serde_json::to_vec(&cover).expect("cover serialization must succeed"));
    hex::encode(mac.finalize().into_bytes())
}

/// v3 因子化镜像（镜像写侧 `l2_factored_storage_form`）：返回条目 payload 与
/// 去重后的共享单元集合（digest → 内容）。
fn mirror_factored_storage_form(
    evidence: &PublishedCardAuthorization,
) -> (
    L2FactoredPayloadMirror,
    std::collections::BTreeMap<String, L2SharedUnitContentMirror>,
) {
    let mut records = Vec::with_capacity(evidence.records.len());
    let mut units = std::collections::BTreeMap::new();
    for record in &evidence.records {
        if record.aggregate_type == "RULE_SET" {
            let content = L2SharedUnitContentMirror {
                resource: record.grant.resource.clone(),
                action: record.grant.action.clone(),
                effect: record.grant.effect,
                validity: record.grant.validity,
                semantic_hash_hex: record.semantic_hash_hex.clone(),
                dependency_hash_hex: record.dependency_hash_hex.clone(),
                compiler_version: record.compiler_version.clone(),
            };
            let digest = mirror_unit_digest(&content);
            units.entry(digest.clone()).or_insert(content);
            records.push(L2RecordSlotMirror::Shared(L2SharedEnvelopeMirror {
                aggregate_id: record.aggregate_id,
                publication_generation: record.publication_generation,
                revoke_fence: record.revoke_fence,
                manifest_id: record.manifest_id,
                event_id: record.event_id.clone(),
                operation_id: record.operation_id.clone(),
                segment_ordinal: record.segment_ordinal,
                position_in_segment: record.position_in_segment,
                grant: L2GrantEnvelopeMirror {
                    grant_id: record.grant.grant_id,
                    revision: record.grant.revision,
                    state: record.grant.state,
                    source_kind: record.grant.source_kind,
                    binding_layer: record.grant.binding_layer,
                    tenant: record.grant.tenant.clone(),
                    card_id: record.grant.card_id,
                    user_id: record.grant.user_id,
                    provenance: record.grant.provenance.clone(),
                },
                shared_unit_digest: digest,
                accepted_into_effective_set: record.accepted_into_effective_set,
                unaccepted_reason: record.unaccepted_reason,
            }));
        } else {
            records.push(L2RecordSlotMirror::Inline(record.clone()));
        }
    }
    (
        L2FactoredPayloadMirror {
            tenant_id: evidence.tenant_id,
            card_id: evidence.card_id,
            read_unix_seconds: evidence.read_unix_seconds,
            gate: evidence.gate.clone(),
            manifests: evidence.manifests.clone(),
            records,
        },
        units,
    )
}

/// 由镜像条目 + 已验证单元重建完整 payload（镜像写侧合同定理 join：
/// 身份字段全部来自 envelope，内容来自单元；单元缺失 → None）。
fn mirror_reconstruct_full(
    stored: &L2FactoredPayloadMirror,
    units: &std::collections::HashMap<String, L2SharedUnitContentMirror>,
) -> Option<PublishedCardAuthorization> {
    let mut records = Vec::with_capacity(stored.records.len());
    for slot in &stored.records {
        match slot {
            L2RecordSlotMirror::Inline(record) => records.push(record.clone()),
            L2RecordSlotMirror::Shared(envelope) => {
                let content = units.get(&envelope.shared_unit_digest)?;
                records.push(VerifiedPublishedGrantRecord {
                    aggregate_type: "RULE_SET".to_string(),
                    aggregate_id: envelope.aggregate_id,
                    publication_generation: envelope.publication_generation,
                    revoke_fence: envelope.revoke_fence,
                    manifest_id: envelope.manifest_id,
                    event_id: envelope.event_id.clone(),
                    operation_id: envelope.operation_id.clone(),
                    semantic_hash_hex: content.semantic_hash_hex.clone(),
                    dependency_hash_hex: content.dependency_hash_hex.clone(),
                    compiler_version: content.compiler_version.clone(),
                    segment_ordinal: envelope.segment_ordinal,
                    position_in_segment: envelope.position_in_segment,
                    grant: CanonicalGrant {
                        grant_id: envelope.grant.grant_id,
                        revision: envelope.grant.revision,
                        state: envelope.grant.state,
                        source_kind: envelope.grant.source_kind,
                        binding_layer: envelope.grant.binding_layer,
                        tenant: envelope.grant.tenant.clone(),
                        card_id: envelope.grant.card_id,
                        user_id: envelope.grant.user_id,
                        resource: content.resource.clone(),
                        action: content.action.clone(),
                        effect: content.effect,
                        validity: content.validity,
                        provenance: envelope.grant.provenance.clone(),
                    },
                    accepted_into_effective_set: envelope.accepted_into_effective_set,
                    unaccepted_reason: envelope.unaccepted_reason,
                });
            }
        }
    }
    let effective_grants = records
        .iter()
        .filter(|record| record.accepted_into_effective_set)
        .map(|record| record.grant.clone())
        .collect();
    Some(PublishedCardAuthorization {
        tenant_id: stored.tenant_id,
        card_id: stored.card_id,
        read_unix_seconds: stored.read_unix_seconds,
        gate: stored.gate.clone(),
        manifests: stored.manifests.clone(),
        records,
        effective_grants,
    })
}

fn parse_l2_entry(raw: &str) -> L2EntryMirror {
    serde_json::from_str(raw).expect("L2 entry JSON must match the write-side contract")
}

/// 从真实 Redis 取回条目引用的全部共享单元（自校验：unit schema + 摘要一致）
/// 并 join 重建完整 payload——镜像读侧协议"单元缺失/失配绝不放行部分数据"。
async fn reconstruct_entry_from_redis(
    redis: &RedisFixture,
    epoch: &str,
    tenant_id: i64,
    entry: &L2EntryMirror,
) -> PublishedCardAuthorization {
    let mut digests: Vec<String> = entry
        .payload
        .records
        .iter()
        .filter_map(|slot| match slot {
            L2RecordSlotMirror::Shared(envelope) => Some(envelope.shared_unit_digest.clone()),
            L2RecordSlotMirror::Inline(_) => None,
        })
        .collect();
    digests.sort();
    digests.dedup();
    let mut units = std::collections::HashMap::new();
    for digest in &digests {
        let unit_key = l2_shared_unit_key(epoch, tenant_id, digest);
        let raw = redis
            .get(&unit_key)
            .await
            .expect("referenced shared unit must exist in Redis");
        let unit: L2SharedUnitMirror = serde_json::from_str(&raw).expect("unit json");
        assert_eq!(unit.unit_schema_version, 1, "unit schema must match");
        assert_eq!(unit.digest, *digest, "unit digest must match the reference");
        units.insert(digest.clone(), unit.content);
    }
    mirror_reconstruct_full(&entry.payload, &units).expect("full reconstruction")
}

/// 从 Ready 证据提取版本组（镜像 `permission_query::evidence_manifest_versions`
/// 的推导：按 `(aggregate_type, aggregate_id)` 升序）。
fn versions_of(evidence: &PublishedCardAuthorization) -> Vec<PermissionCacheManifestVersion> {
    let mut versions: Vec<PermissionCacheManifestVersion> = evidence
        .manifests
        .iter()
        .map(|manifest| PermissionCacheManifestVersion {
            aggregate_type: manifest.aggregate_type.clone(),
            aggregate_id: manifest.aggregate_id,
            manifest_id: manifest.manifest_id,
            generation: manifest.generation,
            revoke_fence: manifest.revoke_fence,
        })
        .collect();
    versions.sort_by(|left, right| {
        left.aggregate_type
            .cmp(&right.aggregate_type)
            .then(left.aggregate_id.cmp(&right.aggregate_id))
    });
    versions
}

/// 从 Ready 证据提取完整栅栏快照（镜像 `permission_query::evidence_fence_baseline`：
/// 填充侧 pending 位恒为 false——证据只能来自通过 source-freshness 门禁的严格 reader）。
fn fence_of(evidence: &PublishedCardAuthorization) -> CardScopeFenceSnapshot {
    CardScopeFenceSnapshot {
        manifest_versions: versions_of(evidence),
        card_source_pending: false,
    }
}

fn fixture_grant_id(seed: u32) -> String {
    format!("00000000-0000-4000-8000-{seed:012}")
}

/// 构造一条规范形 ALLOW/ACTIVE 授权（纯 Redis 用例的内存 fixture，不落 DB）。
fn fixture_grant(namespace: &TestNamespace, seed: u32, validity: ValidityWindow) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: GrantId::parse(&fixture_grant_id(seed)).expect("valid grant id"),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::Direct,
        binding_layer: BindingLayer::None,
        tenant: TenantScope::new(namespace.tenant_id, Some(namespace.domain_id))
            .expect("valid tenant scope"),
        card_id: namespace.card_id,
        user_id: namespace.user_id,
        resource: format!("learn_subject:{}", namespace.aggregate_id),
        action: "read".to_string(),
        effect: GrantEffect::Allow,
        validity,
        provenance: GrantProvenance {
            source_id: "source-1".to_string(),
            source_entry: Some("entry-1".to_string()),
            binding_id: None,
            delegation_id: None,
            operation_id: "op-1".to_string(),
            event_id: Some("event-1".to_string()),
            actor_user_id: None,
        },
    }
}

fn fixture_record(
    aggregate_type: &str,
    aggregate_id: i64,
    manifest_id: i64,
    grant: CanonicalGrant,
    accepted: bool,
    unaccepted_reason: Option<UnacceptedGrantReason>,
) -> VerifiedPublishedGrantRecord {
    VerifiedPublishedGrantRecord {
        aggregate_type: aggregate_type.to_string(),
        aggregate_id,
        publication_generation: 1,
        revoke_fence: 0,
        manifest_id,
        event_id: "event-1".to_string(),
        operation_id: "op-1".to_string(),
        semantic_hash_hex: "a".repeat(64),
        dependency_hash_hex: "b".repeat(64),
        compiler_version: "test".to_string(),
        segment_ordinal: 0,
        position_in_segment: 0,
        grant,
        accepted_into_effective_set: accepted,
        unaccepted_reason,
    }
}

/// 手工 Ready 证据 fixture（每个 distinct 来源聚合补一个 manifest，始终满足
/// 合同校验；manifest 按 (type,id) 升序与 reader 一致）。
fn fixture_evidence(
    namespace: &TestNamespace,
    read_unix_seconds: i64,
    records: Vec<VerifiedPublishedGrantRecord>,
) -> PublishedCardAuthorization {
    let mut manifests: Vec<PublishedAggregateManifestSummary> = Vec::new();
    for record in &records {
        let present = manifests.iter().any(|manifest| {
            manifest.aggregate_type == record.aggregate_type
                && manifest.aggregate_id == record.aggregate_id
        });
        if !present {
            manifests.push(PublishedAggregateManifestSummary {
                tenant_id: namespace.tenant_id,
                card_id: namespace.card_id,
                aggregate_type: record.aggregate_type.clone(),
                aggregate_id: record.aggregate_id,
                manifest_id: record.manifest_id,
                generation: 1,
                source_generation: 1,
                projected_generation: 1,
                revoke_fence: 0,
                cas_version: 1,
                semantic_hash_hex: "a".repeat(64),
                dependency_hash_hex: "b".repeat(64),
                manifest_digest_hex: "c".repeat(64),
                compiler_version: "test".to_string(),
                event_id: "event-1".to_string(),
                operation_id: "op-1".to_string(),
                parent_manifest_id: None,
                segment_count: 1,
                declared_grant_row_count: records.len() as u64,
            });
        }
    }
    manifests.sort_by(|left, right| {
        (left.aggregate_type.as_str(), left.aggregate_id)
            .cmp(&(right.aggregate_type.as_str(), right.aggregate_id))
    });
    let effective_grants: Vec<CanonicalGrant> = records
        .iter()
        .filter(|record| record.accepted_into_effective_set)
        .map(|record| record.grant.clone())
        .collect();
    let gate = PublishedCardAuthorizationGate {
        status: PublishedEvidenceGateStatus::Ready,
        aggregate_manifest_count: manifests.len(),
        verified_record_count: records.len(),
        effective_grant_count: effective_grants.len(),
        not_in_effective_count: records.len() - effective_grants.len(),
        equivalent_duplicate_collapsed_count: 0,
    };
    let evidence = PublishedCardAuthorization {
        tenant_id: namespace.tenant_id,
        card_id: namespace.card_id,
        read_unix_seconds,
        gate,
        manifests,
        records,
        effective_grants,
    };
    assert!(
        evidence.validate().is_ok(),
        "fixture must satisfy the evidence contract"
    );
    evidence
}

/// 单记录永久授权证据（纯 Redis 用例的默认形态）。
fn perpetual_single_record_evidence(
    namespace: &TestNamespace,
    read_at: i64,
) -> PublishedCardAuthorization {
    fixture_evidence(
        namespace,
        read_at,
        vec![fixture_record(
            "USER_CARD",
            namespace.aggregate_id,
            9,
            fixture_grant(namespace, 1, ValidityWindow::perpetual()),
            true,
            None,
        )],
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// DB 发布夹具（与 authorization_projection_integration 同构；fence 可参数化）
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_hex(label: &str) -> String {
    hex::encode(Sha256::digest(label.as_bytes()))
}

/// DB 夹具授权：规范形 ALLOW/ACTIVE 永久授权，GrantId 由命名空间 salt 派生。
fn db_fixture_grant(namespace: &TestNamespace, unique_tail: u16) -> CanonicalGrant {
    assert!(
        unique_tail <= 0x0FFF,
        "tail must fit the 12 hex digit field"
    );
    let entropy = (namespace.salt & 0xFFFF_FFFF_F000) | u128::from(unique_tail);
    CanonicalGrant {
        grant_id: GrantId::parse(&format!("550e8400-e29b-41d4-a716-{entropy:012x}"))
            .expect("test grant id must be a valid UUID"),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(namespace.tenant_id, Some(namespace.domain_id))
            .expect("test tenant scope must be valid"),
        card_id: namespace.card_id,
        user_id: namespace.user_id,
        resource: format!("itest_resource:{}", namespace.aggregate_id),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("itest-rule-set-entry-{unique_tail}"),
            source_entry: None,
            binding_id: Some(format!("itest-binding-{}", namespace.card_id)),
            delegation_id: None,
            operation_id: "itest-op-placeholder".to_owned(),
            event_id: None,
            actor_user_id: Some(namespace.user_id),
        },
    }
}

/// 一个已完成 stage（BUILDING）→ claim lease → finalize（READY）的 manifest。
struct ReadyManifest {
    manifest_id: i64,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
    compiler_version: String,
}

/// stage + claim + finalize，各自独立短事务并提交（`revoke_fence` 可参数化，
/// 供撤销发布夹具把目标 manifest 直接钉到新 fence 层级）。
async fn stage_and_finalize_manifest(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    generation: u64,
    grants: &[CanonicalGrant],
    tag: &str,
    revoke_fence: u64,
) -> ReadyManifest {
    let identity = namespace.identity();
    let event_id = namespace.event_id(tag);
    let operation_id = namespace.operation_id(tag);
    let semantic_hash_hex = sha256_hex(&format!("itest/{}/semantic/{tag}", namespace.tenant_id));
    let dependency_hash_hex =
        sha256_hex(&format!("itest/{}/dependency/{tag}", namespace.tenant_id));
    let compiler_version = "itest-compiler-v1".to_owned();

    // 与载荷 provenance 保持一致：grant 的 operation/event 与 manifest 对齐。
    let mut payload_grants = grants.to_vec();
    for grant in &mut payload_grants {
        grant.provenance.operation_id = operation_id.clone();
        grant.provenance.event_id = Some(event_id.clone());
    }

    let stage_request = AuthorizationStageRequest {
        identity: identity.clone(),
        card_id: Some(namespace.card_id),
        target_generation: generation,
        source_generation: generation,
        projected_generation: generation,
        event_id,
        operation_id,
        semantic_hash_hex: semantic_hash_hex.clone(),
        dependency_hash_hex: dependency_hash_hex.clone(),
        compiler_version: compiler_version.clone(),
        revoke_fence,
        segments: vec![StagedSegmentContent::New(payload_grants)],
    };

    let mut tx = pool.begin().await.expect("stage tx must begin");
    let stage_outcome = stage_authorization_manifest_in_tx(&mut tx, &stage_request)
        .await
        .expect("staging must succeed");
    tx.commit().await.expect("stage tx must commit");

    assert!(
        !stage_outcome.resumed_existing_manifest,
        "a fresh test namespace must never resume an existing manifest"
    );
    assert_eq!(stage_outcome.new_segment_count, 1);
    assert_eq!(stage_outcome.reused_segment_count, 0);

    let lease_owner = format!("itest-manifest-owner-{tag}");
    let mut tx = pool.begin().await.expect("claim tx must begin");
    let lease = claim_authorization_manifest_in_tx(
        &mut tx,
        &identity,
        generation,
        &lease_owner,
        MANIFEST_LEASE_SECONDS,
    )
    .await
    .expect("claim query must succeed")
    .expect("the staged BUILDING manifest must be claimable right after staging");
    assert_eq!(lease.manifest_id, stage_outcome.manifest_id);

    let finalize_request = AuthorizationFinalizeRequest {
        identity,
        target_generation: generation,
        manifest_id: stage_outcome.manifest_id,
        lease_owner: lease.lease_owner.clone(),
        lease_token: lease.lease_token,
        expected_cas_version: lease.cas_version_after_claim,
        expected_reference_count: Some(1),
    };
    finalize_authorization_manifest_in_tx(&mut tx, &finalize_request)
        .await
        .expect("finalize must succeed");
    tx.commit().await.expect("finalize tx must commit");

    ReadyManifest {
        manifest_id: stage_outcome.manifest_id,
        semantic_hash_hex,
        dependency_hash_hex,
        compiler_version,
    }
}

/// 组装一次发布请求（fence 证据可参数化；不执行）。
#[allow(clippy::too_many_arguments)]
fn publish_request_for(
    namespace: &TestNamespace,
    manifest: &ReadyManifest,
    generation: u64,
    current_pointer: Option<CurrentPointerView>,
    previous_revoke_fence: u64,
    new_revoke_fence: u64,
) -> AuthorizationPublishRequest {
    AuthorizationPublishRequest {
        identity: namespace.identity(),
        card_id: Some(namespace.card_id),
        target_manifest_id: manifest.manifest_id,
        target_generation: generation,
        current_pointer,
        expected_target_semantic_hash_hex: manifest.semantic_hash_hex.clone(),
        expected_target_dependency_hash_hex: manifest.dependency_hash_hex.clone(),
        expected_target_compiler_version: manifest.compiler_version.clone(),
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence,
            new_revoke_fence,
        },
    }
}

/// 在独立短事务中执行发布并提交（成功提交、失败回滚）。
async fn publish_ready_manifest(
    pool: &MySqlPool,
    namespace: &TestNamespace,
    manifest: &ReadyManifest,
    generation: u64,
    current_pointer: Option<CurrentPointerView>,
    previous_revoke_fence: u64,
    new_revoke_fence: u64,
) -> AuthorizationPublishOutcome {
    let request = publish_request_for(
        namespace,
        manifest,
        generation,
        current_pointer,
        previous_revoke_fence,
        new_revoke_fence,
    );
    let mut tx = pool.begin().await.expect("publish tx must begin");
    let outcome = publish_current_pointer_in_tx(&mut tx, &request)
        .await
        .expect("publish must succeed");
    tx.commit().await.expect("publish tx must commit");
    outcome
}

/// DB 用例的 gen1 夹具：发布第一代（fence 0→0，单条永久授权）。
async fn publish_first_generation(
    pool: &MySqlPool,
    namespace: &TestNamespace,
) -> AuthorizationPublishOutcome {
    let manifest = stage_and_finalize_manifest(
        pool,
        namespace,
        1,
        &[db_fixture_grant(namespace, 1)],
        "gen1",
        0,
    )
    .await;
    publish_ready_manifest(pool, namespace, &manifest, 1, None, 0, 0).await
}

// ─────────────────────────────────────────────────────────────────────────────
// 纯 Redis 场景（无 DB：fixture deps + 真实 Redis L2）
// ─────────────────────────────────────────────────────────────────────────────

/// CI_1 + CI_7：L1 miss → 读前对牌 → L2 miss → 严格读恰 1 次（计数 SPI）→
/// 回填 L1 + L2（真实 Redis 条目形状/schema/hash/TTL 逐项验证）→ 二次请求
/// L1 命中（零额外严格读、零额外 L2 读取），结果与直读逐字段 parity。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_ci1_cold_miss_strict_once_then_l1_hit_and_l2_entry_shape() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-ci1");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);
    let fence = fence_of(&evidence);

    let deps = FixtureDeps::new(&epoch, fence.clone(), now);
    deps.push_strict(evidence.clone());
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();

    // 冷 miss：读前对牌（L2 分支）1 次 + L2 GET miss + 严格读恰 1 次。
    let first = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("cold miss must refill from the strict reader");
    assert_eq!(deps.strict_calls(), 1, "CI_1: exactly one strict read");
    assert_eq!(deps.fence_calls(), 1, "cold miss reads the pre-fence once");
    assert_eq!(l2.get_calls(), 1);
    assert_eq!(l2.set_calls(), 1, "refill must backfill L2");
    assert_eq!(first, evidence);

    // L2 条目形状：schema 4、版本组与栅栏组一致（pending 位恒 false）、
    // content_hash 绑定完整载荷、因子化存储（USER_CARD 内联、零共享单元）+
    // 重建 parity、TTL 满额 300s。
    let raw = redis.get(&key).await.expect("L2 entry must exist in Redis");
    let entry = parse_l2_entry(&raw);
    assert_eq!(entry.schema_version, 4);
    assert_eq!(entry.manifest_versions, fence.manifest_versions);
    assert!(!entry.card_source_pending);
    assert!(
        entry
            .payload
            .records
            .iter()
            .all(|slot| matches!(slot, L2RecordSlotMirror::Inline(_))),
        "v3 storage: USER_CARD records stay inline"
    );
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &entry).await,
        evidence,
        "reconstruction parity with the strict read"
    );
    assert_eq!(entry.content_hash, mirror_content_hash(&evidence));
    let ttl = redis.ttl(&key).await;
    assert!(
        (L2_EVIDENCE_TTL_SECONDS as i64 - TTL_SLACK_SECONDS..=L2_EVIDENCE_TTL_SECONDS as i64)
            .contains(&ttl),
        "L2 TTL must be the full {L2_EVIDENCE_TTL_SECONDS}s budget, got {ttl}"
    );

    // 二次请求：L1 命中（读前 + 读后复读对牌，零严格读、零 L2 读取）。
    let second = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("second load must hit L1");
    assert_eq!(deps.strict_calls(), 1, "L1 hit must not reread strictly");
    assert_eq!(deps.fence_calls(), 3, "hit adds pre-fence + recheck reads");
    assert_eq!(l2.get_calls(), 1, "L1 hit must not consult L2");
    assert_eq!(second, evidence, "cached evidence must be identical");

    redis.del(&[key]).await;
}

/// CI_6：实例 A 冷 miss 填充 L1+L2 后，全新实例（fresh moka，模拟重启/另一
/// 节点）L1 miss → 真实 Redis L2 命中 → 零严格读 → 回填 L1；第二次请求只走
/// L1（L2 不再被读取）。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_ci6_fresh_instance_hits_l2_then_l1_only() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-ci6");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 实例 A：冷 miss 回源并回填两级（真实写路径产出 Redis 条目）。
    let deps_a = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_a.push_strict(evidence.clone());
    let cache_a = fresh_cache();
    let l2_a = CountingL2Store::new();
    load_through(&deps_a, &cache_a, Some(&l2_a), &ns)
        .await
        .expect("instance A must refill");
    assert!(redis.get(&key).await.is_some(), "L2 must be populated");

    // 实例 B：fresh moka + 零严格读预算 → L2 命中回填 L1。
    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    let cache_b = fresh_cache();
    let l2_b = CountingL2Store::new();
    let from_l2 = load_through(&deps_b, &cache_b, Some(&l2_b), &ns)
        .await
        .expect("instance B must hit L2");
    assert_eq!(
        deps_b.strict_calls(),
        0,
        "CI_6: L2 hit must skip the strict read entirely"
    );
    assert_eq!(l2_b.get_calls(), 1);
    assert_eq!(l2_b.set_calls(), 0, "L2 hit must not rewrite L2");
    assert_eq!(from_l2, evidence, "serde roundtrip parity");

    // L1 已回填：第二次请求走 L1 命中，L2 不再被读取。
    let second = load_through(&deps_b, &cache_b, Some(&l2_b), &ns)
        .await
        .expect("instance B second load must hit L1");
    assert_eq!(deps_b.strict_calls(), 0);
    assert_eq!(l2_b.get_calls(), 1, "L1 hit must not consult L2");
    assert_eq!(second, evidence);

    redis.del(&[key]).await;
}

/// CI_9 加深：真实 Redis 条目被手工篡改（payload 变化而 content_hash 未随
/// 之重算）→ 读侧重验哈希不匹配 → 删键 → 回源自愈（新条目恢复正确哈希与
/// 未篡改 payload）。检测方是全新实例（污染场景 = 另一节点/重启后拉取）。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_content_hash_pollution_purges_and_self_heals() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-pollution");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    let deps_a = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_a.push_strict(evidence.clone());
    load_through(&deps_a, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill");

    // 手工污染：payload 字段变化、content_hash 保持旧值。
    let raw = redis.get(&key).await.expect("entry must exist");
    let mut polluted: serde_json::Value = serde_json::from_str(&raw).expect("entry json");
    let original_read_at = polluted["payload"]["readUnixSeconds"]
        .as_i64()
        .expect("readUnixSeconds");
    polluted["payload"]["readUnixSeconds"] = serde_json::json!(original_read_at + 1);
    redis
        .set_ex(&key, &polluted.to_string(), L2_EVIDENCE_TTL_SECONDS)
        .await;
    assert_ne!(
        redis.get(&key).await.as_deref(),
        Some(raw.as_str()),
        "pollution must actually change the stored bytes"
    );

    // 全新实例读取：哈希重验失败 → 删键 → 回源自愈。
    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let cache_b = fresh_cache();
    let l2_b = CountingL2Store::new();
    let healed = load_through(&deps_b, &cache_b, Some(&l2_b), &ns)
        .await
        .expect("pollution must fall back to the strict reader");
    assert_eq!(deps_b.strict_calls(), 1, "polluted entry must reread");
    assert_eq!(l2_b.del_calls(), 1, "polluted key must be purged");
    assert_eq!(healed, evidence);

    // 自愈：键被回源路径以正确内容重写（因子化存储 + 重建 parity）。
    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &refilled).await,
        evidence
    );
    assert_eq!(refilled.content_hash, mirror_content_hash(&evidence));
    assert_eq!(l2_b.set_calls(), 1, "healing must backfill L2");

    redis.del(&[key]).await;
}

/// 新链加深：真实 Redis 条目的 schema_version 被篡改（payload/hash 均合法）
/// → schema 栅栏拒绝 → 删键回源重写为 schema 3。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_schema_version_mismatch_purges_and_refills() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-schema");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    let deps_a = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_a.push_strict(evidence.clone());
    load_through(&deps_a, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill");

    let raw = redis.get(&key).await.expect("entry must exist");
    let mut mutated: serde_json::Value = serde_json::from_str(&raw).expect("entry json");
    mutated["schemaVersion"] = serde_json::json!(999);
    redis
        .set_ex(&key, &mutated.to_string(), L2_EVIDENCE_TTL_SECONDS)
        .await;

    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let l2_b = CountingL2Store::new();
    let reloaded = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("schema mismatch must fall back to the strict reader");
    assert_eq!(deps_b.strict_calls(), 1);
    assert_eq!(l2_b.del_calls(), 1, "schema-mismatched key must be purged");
    assert_eq!(reloaded, evidence);
    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(
        refilled.schema_version,
        astral_db::L2_EVIDENCE_SCHEMA_VERSION,
        "refill must restore the current L2 schema version"
    );

    redis.del(&[key]).await;
}

/// CI_10 加深：epoch 内嵌键轮换——填充于旧时代的条目在新时代下自然失配
/// （读取侧只查新时代键，旧键不被误删）；回源在新键下回填；轮换回旧时代时
/// 旧条目仍然有效（对牌/时钟通过即复活，零额外严格读）。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_epoch_rotation_old_epoch_key_mismatches_then_revives() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-epoch");
    let epoch_a = format!("it-{}", Uuid::new_v4().simple());
    let epoch_b = format!("it-{}", Uuid::new_v4().simple());
    let key_a = redis.l2_key(&epoch_a, ns.tenant_id, ns.card_id);
    let key_b = redis.l2_key(&epoch_b, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);
    let fence = fence_of(&evidence);

    // 时代 A 填充。
    let deps = FixtureDeps::new(&epoch_a, fence.clone(), now);
    deps.push_strict(evidence.clone());
    deps.push_strict(evidence.clone());
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("fill under epoch A");
    assert!(redis.get(&key_a).await.is_some());
    assert_eq!(deps.strict_calls(), 1);

    // 时代轮换到 B：L1 条目携带旧时代 → miss；L2 只查 B 键 → miss → 回源。
    deps.set_epoch(&epoch_b);
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("reload after rotation");
    assert_eq!(deps.strict_calls(), 2, "rotated epoch must miss");
    assert!(
        redis.get(&key_a).await.is_some(),
        "old-epoch key must not be deleted (natural mismatch, no scan-delete)"
    );
    assert!(redis.get(&key_b).await.is_some(), "refill lands under B");

    // 轮换回 A：L2 旧条目对牌/时钟全部通过 → 复活命中，零额外严格读。
    deps.set_epoch(&epoch_a);
    let revived = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("old-epoch entry must revive");
    assert_eq!(
        deps.strict_calls(),
        2,
        "revived old-epoch entry must not reread strictly"
    );
    assert_eq!(revived, evidence);
    assert_eq!(l2.get_calls(), 3, "A-fill miss + B miss + A revive GETs");

    redis.del(&[key_a, key_b]).await;
}

/// CI_11：TTL 语义——L2 条目以 300s 满额 TTL 落 Redis（真实 `TTL` 命令，
/// 不真实等待）；L1 条目在填充后存在且二次请求命中（30s 封顶驻留的常量与
/// 过期判定已由单元测试钉死，这里验证装配后条目存在性与命中路径）。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_ttl_semantics_l2_300s_and_l1_entry_presence() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-ttl");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();

    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("fill");
    assert!(
        cache.contains_key(&(ns.tenant_id, ns.card_id)),
        "L1 entry must be present right after the fill"
    );
    let ttl = redis.ttl(&key).await;
    assert!(
        (L2_EVIDENCE_TTL_SECONDS as i64 - TTL_SLACK_SECONDS..=L2_EVIDENCE_TTL_SECONDS as i64)
            .contains(&ttl),
        "L2 TTL must be the full {L2_EVIDENCE_TTL_SECONDS}s budget, got {ttl}"
    );
    assert_eq!(L2_EVIDENCE_TTL_SECONDS, 300, "L2 TTL budget is pinned");

    // L1 命中（零额外严格读）；时钟方向的 TTL 语义由
    // redis_clock_revalidation_purges_expired_l2_entry 以注入时钟验证。
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("L1 hit");
    assert_eq!(deps.strict_calls(), 1);

    redis.del(&[key]).await;
}

/// CI_11 加深：注入时钟推进到 accepted 记录窗口之外（不真实等待）→ L1 命中
/// 协议与时钟重验同时判陈旧 → miss；L2 条目被时钟重验清除（删键）→ 回源重填。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_clock_revalidation_purges_expired_l2_entry() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-clock");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    // 窗口 [now-60, now+30)：填充时钟在窗口内，注入时钟推进 31s 即过期。
    let evidence = fixture_evidence(
        &ns,
        now,
        vec![fixture_record(
            "USER_CARD",
            ns.aggregate_id,
            9,
            fixture_grant(&ns, 1, ValidityWindow::between(now - 60, now + 30)),
            true,
            None,
        )],
    );

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    deps.push_strict(evidence.clone());
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();

    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("fill");
    assert!(redis.get(&key).await.is_some());

    // 注入时钟推进 31s：L1 对牌通过但时钟重验失败 → miss；L2 条目同样被
    // 时钟重验判陈旧 → 删键 → 回源（第二个预置严格读）重填。
    deps.now.store(now + 31, Ordering::SeqCst);
    let reloaded = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("clock-stale entry must fall back to the strict reader");
    assert_eq!(deps.strict_calls(), 2, "clock staleness must bust caches");
    assert_eq!(l2.del_calls(), 1, "clock-stale L2 entry must be purged");
    assert_eq!(reloaded, evidence);
    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &refilled).await,
        evidence,
        "refill must overwrite the purge"
    );

    redis.del(&[key]).await;
}

/// 新链（多节点分发）：两个独立 moka 实例（独立 deps 计数）共享同一真实
/// Redis L2——实例 A 填充后，实例 B 在零严格读预算下从 L2 拉取并回填自身 L1。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_cross_instance_sharing_second_instance_reads_l2() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-share");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);
    let fence = fence_of(&evidence);

    // 实例 A：回源一次并填充 L1A + L2。
    let deps_a = FixtureDeps::new(&epoch, fence.clone(), now);
    deps_a.push_strict(evidence.clone());
    let cache_a = fresh_cache();
    let l2_a = CountingL2Store::new();
    load_through(&deps_a, &cache_a, Some(&l2_a), &ns)
        .await
        .expect("instance A fill");
    assert_eq!(deps_a.strict_calls(), 1);

    // 实例 B：独立 L1/依赖，零严格读预算——多节点分发必须由 L2 承担。
    let deps_b = FixtureDeps::new(&epoch, fence, now);
    let cache_b = fresh_cache();
    let l2_b = CountingL2Store::new();
    let from_l2 = load_through(&deps_b, &cache_b, Some(&l2_b), &ns)
        .await
        .expect("instance B must read through L2");
    assert_eq!(
        deps_b.strict_calls(),
        0,
        "cross-instance distribution must not hit the strict reader"
    );
    assert_eq!(
        deps_b.fence_calls(),
        2,
        "B still runs the double-read fence"
    );
    assert!(cache_b.contains_key(&(ns.tenant_id, ns.card_id)));
    assert_eq!(from_l2, evidence);
    assert!(
        redis.get(&key).await.is_some(),
        "L2 entry must remain shared after B's read"
    );

    redis.del(&[key]).await;
}

/// 新链加深：哈希正确但 payload 违反证据合同（gate 计数与集合矛盾）的条目
/// ——content_hash 重验通过、合同校验必须拦下（哈希不替代授权有效性）→
/// 删键回源，污染不残留。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_contract_violating_payload_with_valid_hash_purges() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-contract");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 篡改 gate 计数后以写侧同构协议播种（schema 3 + 合法 MAC）：content_hash
    // 与篡改 payload 精确绑定（重建后哈希重验必然通过），MAC 对篡改载荷合法
    // ——只有 payload.validate() 合同校验能拦下。
    let mut tampered = evidence.clone();
    tampered.gate.effective_grant_count += 1;
    assert!(
        tampered.validate().is_err(),
        "tampered payload must violate the contract"
    );
    let (tampered_payload, _) = mirror_factored_storage_form(&tampered);
    let entry = L2EntryMirror {
        schema_version: 4,
        card_source_pending: false,
        manifest_versions: versions_of(&evidence),
        content_hash: mirror_content_hash(&tampered),
        mac: mirror_entry_mac(
            &key,
            &versions_of(&evidence),
            &mirror_content_hash(&tampered),
            &tampered,
        ),
        payload: tampered_payload,
    };
    redis
        .set_ex(
            &key,
            &serde_json::to_string(&entry).expect("entry json"),
            L2_EVIDENCE_TTL_SECONDS,
        )
        .await;

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let l2 = CountingL2Store::new();
    let reloaded = load_through(&deps, &fresh_cache(), Some(&l2), &ns)
        .await
        .expect("contract violation must fall back to the strict reader");
    assert_eq!(
        deps.strict_calls(),
        1,
        "a hash-valid but contract-violating payload must not be served"
    );
    assert_eq!(l2.del_calls(), 1, "contract-violating entry must be purged");
    assert_eq!(reloaded, evidence, "the legal evidence must be served");
    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &refilled).await,
        evidence,
        "pollution must not persist"
    );

    redis.del(&[key]).await;
}

/// CI_8：Redis 不可用（真实连接拒绝）→ L2 静默旁路，L1+严格回源照常；L1
/// 仍被回填且写入失败不阻塞（第二次请求 L1 命中，Redis 侧确无残留写入）。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_unreachable_degrades_to_l1_plus_strict() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-degrade");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let cache = fresh_cache();

    let first = load_through(&deps, &cache, Some(&UnreachableL2Store), &ns)
        .await
        .expect("Redis failure must degrade, not error");
    assert_eq!(deps.strict_calls(), 1, "degraded miss must reread strictly");
    assert_eq!(first, evidence);
    assert!(
        cache.contains_key(&(ns.tenant_id, ns.card_id)),
        "L1 must still be backfilled while L2 is down"
    );
    assert!(
        redis.get(&key).await.is_none(),
        "a failing L2 write must leave no partial entry in Redis"
    );

    let second = load_through(&deps, &cache, Some(&UnreachableL2Store), &ns)
        .await
        .expect("second load must hit L1 while L2 is down");
    assert_eq!(deps.strict_calls(), 1, "L1 hit must not reread strictly");
    assert_eq!(second, evidence);

    redis.del(&[key]).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// DB 依赖场景（Redis + DATABASE_URL 隧道：真实严格 reader / 指针栅栏 / 发布）
// ─────────────────────────────────────────────────────────────────────────────

/// CI_1（真实 reader 深化）：真实严格 reader 回源恰 1 次（计数 SPI）→ L1
/// 命中（真实指针栅栏双读走 MySQL），零额外严格读。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_ci1_strict_reader_called_once_then_l1_hit() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let Some(pool) = db_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-db-ci1");
    cleanup_namespace(&pool, &ns).await;
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);

    publish_first_generation(&pool, &ns).await;

    let deps = DbBackedDeps::new(pool.clone(), &epoch);
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();

    let first = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("cold miss must refill via the real strict reader");
    assert_eq!(
        deps.strict_calls(),
        1,
        "CI_1: the real strict reader must run exactly once"
    );
    assert_eq!(deps.fence_calls(), 1, "cold miss reads the pre-fence once");
    assert_eq!(first.gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(first.gate.verified_record_count, 1);
    assert_eq!(first.gate.effective_grant_count, 1);
    assert!(redis.get(&key).await.is_some(), "L2 must be backfilled");

    let second = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("second load must hit L1");
    assert_eq!(deps.strict_calls(), 1, "L1 hit must not reread strictly");
    assert_eq!(
        deps.fence_calls(),
        3,
        "hit adds the real pre/recheck fence reads"
    );
    assert_eq!(l2.get_calls(), 1, "L1 hit must not consult L2");
    assert_eq!(second, first, "cached evidence must be identical");

    cleanup_namespace(&pool, &ns).await;
    redis.del(&[key]).await;
}

/// CI_7（真实回源深化）：L1/L2 双 miss → 真实严格 reader 回源 → L1 + L2 回填；
/// 真实 Redis 条目的版本组与 `load_pointer_fence_versions` 现场重查逐项一致，
/// content_hash 与 payload 精确绑定，TTL 为 300s 满额。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_ci7_double_miss_full_chain_backfills_l1_and_l2() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let Some(pool) = db_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-db-ci7");
    cleanup_namespace(&pool, &ns).await;
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);

    publish_first_generation(&pool, &ns).await;

    let deps = DbBackedDeps::new(pool.clone(), &epoch);
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();

    let evidence = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("double miss must fall back to the DB strict reader");
    assert_eq!(deps.strict_calls(), 1);
    assert_eq!(deps.fence_calls(), 1, "miss reads the pre-fence once");

    // L2 条目与真实 DB 栅栏快照逐项一致（写侧版本组 = 现场栅栏重查；pending
    // 位恒为 false——证据只能来自通过 source-freshness 门的严格 reader）。
    let raw = redis.get(&key).await.expect("L2 entry must exist");
    let entry = parse_l2_entry(&raw);
    let live_fence = load_card_scope_fence_snapshot(&pool, ns.tenant_id, ns.card_id)
        .await
        .expect("fence requery must succeed");
    assert_eq!(entry.manifest_versions, live_fence.manifest_versions);
    assert!(!entry.card_source_pending);
    assert!(!live_fence.card_source_pending);
    assert_eq!(entry.schema_version, 4);
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &entry).await,
        evidence,
        "reconstruction parity with the strict read"
    );
    assert_eq!(entry.content_hash, mirror_content_hash(&evidence));
    assert_eq!(
        entry.payload.gate.status,
        PublishedEvidenceGateStatus::Ready
    );
    let ttl = redis.ttl(&key).await;
    assert!(
        (L2_EVIDENCE_TTL_SECONDS as i64 - TTL_SLACK_SECONDS..=L2_EVIDENCE_TTL_SECONDS as i64)
            .contains(&ttl)
    );

    // 二次请求 L1 命中（零严格读、零 L2 读取）。
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("L1 hit");
    assert_eq!(deps.strict_calls(), 1);
    assert_eq!(l2.get_calls(), 1);

    cleanup_namespace(&pool, &ns).await;
    redis.del(&[key]).await;
}

/// CI_2/CS_1（直改指针行形态）：仅前移 `authorization_projection_current` 行
/// 的 generation（不伴随 manifest 行）→ 命中对牌失败 → L2 条目弃用删键 →
/// 回源严格 reader 以 `pointer_manifest_generation_split` fail-closed（Corrupt
/// 族）——绝不放行旧条目、绝不污染任何缓存；重复请求保持同一 fail-closed。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_pointer_only_generation_update_fails_closed_without_stale_serving() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let Some(pool) = db_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-db-split");
    cleanup_namespace(&pool, &ns).await;
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);

    publish_first_generation(&pool, &ns).await;

    let deps = DbBackedDeps::new(pool.clone(), &epoch);
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("fill");
    assert_eq!(deps.strict_calls(), 1);

    // 直接 UPDATE 指针行（generation 前移一步，manifest 行不动）。
    sqlx::query(
        "UPDATE authorization_projection_current \
         SET current_generation = current_generation + 1 \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ?",
    )
    .bind(ns.tenant_id)
    .bind(AGGREGATE_TYPE)
    .bind(ns.aggregate_id)
    .execute(&pool)
    .await
    .expect("pointer row update must succeed");

    // 对牌失败 → L2 弃用删键 → 严格 reader 拒绝指针/manifest 分裂状态。
    let outcome = load_through(&deps, &cache, Some(&l2), &ns).await;
    match &outcome {
        Err(AuthorizationEvidenceError::Corrupt(message)) => assert!(
            message.contains("pointer_manifest_generation_split"),
            "the split pointer state must fail closed with the split code, got: {message}"
        ),
        other => panic!("expected a fail-closed Corrupt error, got: {other:?}"),
    }
    assert_eq!(
        deps.strict_calls(),
        2,
        "the drifted state must reread strictly"
    );
    assert_eq!(l2.del_calls(), 1, "the stale L2 entry must be purged");
    assert!(
        redis.get(&key).await.is_none(),
        "the purged key must be gone from Redis"
    );
    assert!(
        cache.contains_key(&(ns.tenant_id, ns.card_id)),
        "the old L1 entry must remain (never rewritten, never served again)"
    );

    // 重复请求保持 fail-closed（L2 已无条目，严格 reader 再次拒绝）。
    let outcome = load_through(&deps, &cache, Some(&l2), &ns).await;
    assert!(matches!(
        outcome,
        Err(AuthorizationEvidenceError::Corrupt(_))
    ));
    assert_eq!(deps.strict_calls(), 3);

    cleanup_namespace(&pool, &ns).await;
    redis.del(&[key]).await;
}

/// CI_2/CI_3：真实发布推进（gen2 发布 = 指针行 generation 前移 + 新 manifest）
/// → L1 对牌失败 + L2 版本组失配弃用删键 → 回源取到新版本（两条记录、
/// generation 2）→ L1/L2 以新版本组重填，随后请求 L1 命中。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_generation_advance_via_publish_busts_l1_l2_and_refills_new_version() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let Some(pool) = db_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-db-gen");
    cleanup_namespace(&pool, &ns).await;
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);

    let first_outcome = publish_first_generation(&pool, &ns).await;

    let deps = DbBackedDeps::new(pool.clone(), &epoch);
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("fill with generation 1");
    assert_eq!(deps.strict_calls(), 1);

    // 真实 gen2 发布（指针行 CAS 前移 + 新 READY manifest 晋升）。
    let gen2 = stage_and_finalize_manifest(
        &pool,
        &ns,
        2,
        &[db_fixture_grant(&ns, 1), db_fixture_grant(&ns, 2)],
        "gen2",
        0,
    )
    .await;
    publish_ready_manifest(
        &pool,
        &ns,
        &gen2,
        2,
        Some(first_outcome.pointer.as_view()),
        0,
        0,
    )
    .await;

    let advanced = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("advance must fall back to the strict reader");
    assert_eq!(deps.strict_calls(), 2, "version drift must reread strictly");
    assert_eq!(l2.del_calls(), 1, "the stale L2 entry must be purged");
    assert_eq!(advanced.gate.verified_record_count, 2, "gen2 adds a record");
    assert_eq!(advanced.manifests[0].generation, 2);
    assert_eq!(advanced.manifests[0].manifest_id, gen2.manifest_id);

    // L1/L2 以新版本组重填；随后请求 L1 命中（零额外严格读）。
    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(refilled.manifest_versions[0].generation, 2);
    assert_eq!(refilled.manifest_versions[0].manifest_id, gen2.manifest_id);
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &refilled).await,
        advanced
    );
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("L1 hit");
    assert_eq!(deps.strict_calls(), 2);
    assert_eq!(l2.get_calls(), 2, "gen2 refill GET + no further L2 reads");

    cleanup_namespace(&pool, &ns).await;
    redis.del(&[key]).await;
}

/// CS_1（REVOKE 撤销失效）：真实撤销发布（gen2 manifest 钉到 revoke_fence 1，
/// 发布 fence 0→1 = 指针行 revoke_fence 前移）→ 对牌失败 → L2 弃用删键 →
/// 回源取到撤销后的新版本（fence 1）→ 两级重填。撤销延迟 ≈ 0。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_revoke_fence_advance_via_publish_busts_and_refills() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let Some(pool) = db_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-db-revoke");
    cleanup_namespace(&pool, &ns).await;
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);

    let first_outcome = publish_first_generation(&pool, &ns).await;

    let deps = DbBackedDeps::new(pool.clone(), &epoch);
    let cache = fresh_cache();
    let l2 = CountingL2Store::new();
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("fill with fence 0");
    assert_eq!(deps.strict_calls(), 1);
    let before = parse_l2_entry(&redis.get(&key).await.expect("L2 entry after fill"));
    assert_eq!(before.manifest_versions[0].revoke_fence, 0);

    // 真实撤销发布：gen2 manifest 直接以 revoke_fence 1 stage，发布 fence 0→1。
    let gen2 =
        stage_and_finalize_manifest(&pool, &ns, 2, &[db_fixture_grant(&ns, 1)], "revoke-gen2", 1)
            .await;
    publish_ready_manifest(
        &pool,
        &ns,
        &gen2,
        2,
        Some(first_outcome.pointer.as_view()),
        0,
        1,
    )
    .await;

    let revoked = load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("revoke must fall back to the strict reader");
    assert_eq!(deps.strict_calls(), 2, "fence advance must reread strictly");
    assert_eq!(l2.del_calls(), 1, "the pre-revoke L2 entry must be purged");
    assert_eq!(
        revoked.manifests[0].revoke_fence, 1,
        "the refilled evidence must carry the revoked fence level"
    );
    assert_eq!(revoked.manifests[0].generation, 2);

    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(refilled.manifest_versions[0].revoke_fence, 1);
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &refilled).await,
        revoked
    );
    load_through(&deps, &cache, Some(&l2), &ns)
        .await
        .expect("L1 hit");
    assert_eq!(deps.strict_calls(), 2);

    cleanup_namespace(&pool, &ns).await;
    redis.del(&[key]).await;
}

/// 新链（发布推送）：发布事务提交后的生产推送路径
/// （`push_published_card_evidence_to_l2`：真实严格 reader 自读 + 真实 Redis
/// 写入 + 生产 `current_cache_epoch()` 时代）→ 全新实例从 L2 命中，零严格读。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn db_push_after_publish_then_fresh_instance_hits_l2() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let Some(pool) = db_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-db-push");
    cleanup_namespace(&pool, &ns).await;

    // 生产时代键：缺失则由本用例创建（结束时删除还原）；已存在则只读不删。
    let epoch_pre_existed = redis.get(CACHE_EPOCH_KEY).await.is_some();
    publish_first_generation(&pool, &ns).await;
    let epoch = current_cache_epoch()
        .await
        .expect("the production epoch must be readable from the gated Redis");
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);

    // 生产推送路径（发布后自读 + 写 L2）。
    push_published_card_evidence_to_l2(&pool, ns.tenant_id, ns.card_id).await;
    let raw = redis
        .get(&key)
        .await
        .expect("the post-publish push must populate L2");
    let pushed = parse_l2_entry(&raw);
    assert_eq!(pushed.schema_version, astral_db::L2_EVIDENCE_SCHEMA_VERSION);
    assert_eq!(
        pushed.payload.gate.status,
        PublishedEvidenceGateStatus::Ready
    );
    let ttl = redis.ttl(&key).await;
    assert!(
        (L2_EVIDENCE_TTL_SECONDS as i64 - TTL_SLACK_SECONDS..=L2_EVIDENCE_TTL_SECONDS as i64)
            .contains(&ttl)
    );

    // 全新实例（fresh moka + 真实 DB deps + 生产时代）从 L2 命中，零严格读。
    let deps_b = DbBackedDeps::new(pool.clone(), &epoch);
    let l2_b = CountingL2Store::new();
    let from_l2 = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("the pushed entry must serve a fresh instance");
    assert_eq!(
        deps_b.strict_calls(),
        0,
        "the post-publish push must spare the fresh instance the strict read"
    );
    assert_eq!(
        from_l2,
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &pushed).await,
        "L2 payload parity"
    );

    cleanup_namespace(&pool, &ns).await;
    let mut cleanup_keys = vec![key];
    if !epoch_pre_existed {
        cleanup_keys.push(CACHE_EPOCH_KEY.to_owned());
    }
    redis.del(&cleanup_keys).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// v3 因子化存储矩阵（纯 Redis 场景：内存 fixture + 真实 Redis 读写）
// ─────────────────────────────────────────────────────────────────────────────

/// 同租户兄弟卡命名空间（共享 tenant、独立 card；跨卡去重测试用）。
fn sibling_card(ns: &TestNamespace, card_offset: i64) -> TestNamespace {
    TestNamespace {
        label: ns.label,
        salt: ns.salt,
        tenant_id: ns.tenant_id,
        card_id: ns.card_id + card_offset,
        aggregate_id: ns.aggregate_id,
        user_id: ns.user_id,
        domain_id: ns.domain_id,
    }
}

/// RULE_SET 单记录证据（v3 共享单元场景的内存 fixture；同 seed 同租户下两张
/// 卡的单元内容字节级相同）。
fn rule_set_single_record_evidence(
    namespace: &TestNamespace,
    read_at: i64,
) -> PublishedCardAuthorization {
    fixture_evidence(
        namespace,
        read_at,
        vec![fixture_record(
            "RULE_SET",
            namespace.aggregate_id,
            9,
            fixture_grant(namespace, 1, ValidityWindow::perpetual()),
            true,
            None,
        )],
    )
}

/// 条目引用的全部共享单元键（清理与缺失模拟用）。
fn entry_unit_keys(entry: &L2EntryMirror, epoch: &str, tenant_id: i64) -> Vec<String> {
    entry
        .payload
        .records
        .iter()
        .filter_map(|slot| match slot {
            L2RecordSlotMirror::Shared(envelope) => Some(l2_shared_unit_key(
                epoch,
                tenant_id,
                &envelope.shared_unit_digest,
            )),
            L2RecordSlotMirror::Inline(_) => None,
        })
        .collect()
}

/// 新链（跨卡存储去重）：同租户两张卡字节级相同的 RULE_SET 内容 → 真实
/// Redis 中恰好共享一个 `astral:auth:l2sh:*` 单元键；两张卡各自保留独立卡
/// 条目与逐卡 envelope（卡戳/grant 身份不同、单元摘要相同），且各自命中并
/// 逐字节还原自己的证据。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_two_cards_share_one_rule_set_unit_with_separate_envelopes() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-share");
    let ns_b = sibling_card(&ns, 100);
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key_a = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let key_b = redis.l2_key(&epoch, ns_b.tenant_id, ns_b.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence_a = rule_set_single_record_evidence(&ns, now);
    let evidence_b = rule_set_single_record_evidence(&ns_b, now);

    // 各自经读链回源填充（写路径：单元先写、卡条目后写）。
    let deps_a = FixtureDeps::new(&epoch, fence_of(&evidence_a), now);
    deps_a.push_strict(evidence_a.clone());
    load_through(&deps_a, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill card A");
    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence_b), now);
    deps_b.push_strict(evidence_b.clone());
    load_through(
        &deps_b,
        &fresh_cache(),
        Some(&CountingL2Store::new()),
        &ns_b,
    )
    .await
    .expect("fill card B");

    // 两张卡的卡键各自存在；共享单元恰好一个（内容寻址、卡无关）。
    let entry_a = parse_l2_entry(&redis.get(&key_a).await.expect("entry A"));
    let entry_b = parse_l2_entry(&redis.get(&key_b).await.expect("entry B"));
    let unit_keys_a = entry_unit_keys(&entry_a, &epoch, ns.tenant_id);
    let unit_keys_b = entry_unit_keys(&entry_b, &epoch, ns_b.tenant_id);
    assert_eq!(
        unit_keys_a, unit_keys_b,
        "identical content must share one unit key"
    );
    let mut shared_keys = unit_keys_a.clone();
    shared_keys.sort();
    shared_keys.dedup();
    assert_eq!(shared_keys.len(), 1, "exactly one shared unit must exist");
    assert!(
        shared_keys[0].starts_with("astral:auth:l2sh:"),
        "shared unit must live in the l2sh key family: {}",
        shared_keys[0]
    );

    // 两张卡的 envelope 引用同一摘要、卡戳/grant 身份逐卡不同；重建逐字节
    // 还原各自证据（共享单元绝不改写身份）。
    for (card_ns, entry, evidence) in [(&ns, &entry_a, &evidence_a), (&ns_b, &entry_b, &evidence_b)]
    {
        let L2RecordSlotMirror::Shared(envelope) = &entry.payload.records[0] else {
            panic!("RULE_SET record must be factored");
        };
        assert_eq!(envelope.grant.card_id, card_ns.card_id);
        assert_eq!(envelope.grant.tenant.tenant_id, card_ns.tenant_id);
        assert_eq!(
            reconstruct_entry_from_redis(&redis, &epoch, card_ns.tenant_id, entry).await,
            *evidence,
            "per-card byte-identical reconstruction"
        );
    }

    // 各自命中：读前对牌 + L2 命中 + 读后复读，零严格读，身份绝不串卡。
    let deps_a2 = FixtureDeps::new(&epoch, fence_of(&evidence_a), now);
    let hit_a = load_through(&deps_a2, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("card A hits");
    assert_eq!(deps_a2.strict_calls(), 0);
    assert_eq!(hit_a, evidence_a);
    let deps_b2 = FixtureDeps::new(&epoch, fence_of(&evidence_b), now);
    let hit_b = load_through(
        &deps_b2,
        &fresh_cache(),
        Some(&CountingL2Store::new()),
        &ns_b,
    )
    .await
    .expect("card B hits");
    assert_eq!(deps_b2.strict_calls(), 0);
    assert_eq!(hit_b, evidence_b);

    let mut cleanup = vec![key_a, key_b];
    cleanup.extend(shared_keys);
    redis.del(&cleanup).await;
}

/// 新链加深：共享单元缺失（部分写/驱逐）→ purge 卡条目 + 回源严格 reader；
/// 绝不放行部分数据；回源自愈后单元与卡条目都被重写。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_shared_unit_missing_purges_and_strict_reads() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-missing");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = rule_set_single_record_evidence(&ns, now);

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    load_through(&deps, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill");
    let entry = parse_l2_entry(&redis.get(&key).await.expect("entry"));
    let unit_keys = entry_unit_keys(&entry, &epoch, ns.tenant_id);
    assert_eq!(unit_keys.len(), 1);
    redis.del(&[unit_keys[0].clone()]).await;

    // 共享单元缺失 → purge 卡条目 → 回源（预置严格读）。
    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let l2_b = CountingL2Store::new();
    let reloaded = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("missing unit must fall back to the strict reader");
    assert_eq!(
        deps_b.strict_calls(),
        1,
        "missing unit must never serve partial data"
    );
    assert_eq!(l2_b.del_calls(), 1, "card entry must be purged");
    assert_eq!(reloaded, evidence);
    // 回源自愈：单元先写、卡条目重写。
    assert!(
        redis.get(&unit_keys[0]).await.is_some(),
        "refill must restore the shared unit"
    );
    assert!(
        redis.get(&key).await.is_some(),
        "refill must restore the card entry"
    );

    let healed = parse_l2_entry(&redis.get(&key).await.expect("healed entry"));
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &healed).await,
        evidence
    );

    let mut cleanup = vec![key];
    cleanup.extend(unit_keys);
    redis.del(&cleanup).await;
}

/// 新链加深：共享单元内容被篡改（同键不同内容、摘要字段保持原值）→ 自校验
/// 失配 → purge 卡条目回源；被投毒的共享字节绝不参与重建。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_shared_unit_hash_mismatch_purges() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-poison");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = rule_set_single_record_evidence(&ns, now);

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    load_through(&deps, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill");
    let entry = parse_l2_entry(&redis.get(&key).await.expect("entry"));
    let unit_keys = entry_unit_keys(&entry, &epoch, ns.tenant_id);
    assert_eq!(unit_keys.len(), 1);

    // 同键覆写：内容改、摘要字段保持原值 → 单元自校验（重算摘要）失配。
    let mut unit: L2SharedUnitMirror =
        serde_json::from_str(&redis.get(&unit_keys[0]).await.expect("unit")).expect("unit json");
    unit.content.resource = "tampered:*".to_owned();
    redis
        .set_ex(
            &unit_keys[0],
            &serde_json::to_string(&unit).expect("tampered unit json"),
            L2_EVIDENCE_TTL_SECONDS,
        )
        .await;

    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let l2_b = CountingL2Store::new();
    let reloaded = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("hash-mismatched unit must fall back to the strict reader");
    assert_eq!(deps_b.strict_calls(), 1, "poisoned unit must never serve");
    assert_eq!(l2_b.del_calls(), 1, "card entry must be purged");
    assert_eq!(reloaded, evidence);

    let mut cleanup = vec![key];
    cleanup.extend(unit_keys);
    redis.del(&cleanup).await;
}

/// 新链加深（MAC 缺失）：条目 JSON 移除 `mac` 字段 → 解码失败 → 删键回源；
/// 未认证条目绝不可能被接受。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_mac_missing_entry_purges() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-macless");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    load_through(&deps, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill");
    let raw = redis.get(&key).await.expect("entry");
    let mut value: serde_json::Value = serde_json::from_str(&raw).expect("entry value");
    assert!(
        value
            .as_object_mut()
            .expect("object")
            .remove("mac")
            .is_some(),
        "fixture must carry a mac field to remove"
    );
    redis
        .set_ex(&key, &value.to_string(), L2_EVIDENCE_TTL_SECONDS)
        .await;

    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let l2_b = CountingL2Store::new();
    let reloaded = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("MAC-less entry must fall back to the strict reader");
    assert_eq!(deps_b.strict_calls(), 1, "MAC-less entry must never serve");
    assert_eq!(l2_b.del_calls(), 1, "MAC-less entry must be purged");
    assert_eq!(reloaded, evidence);

    redis.del(&[key]).await;
}

/// 新链加深（MAC 错误密钥）：cover 全部一致（键/栅栏/哈希/载荷）但 MAC 以
/// 攻击者自己的密钥计算 → 校验失败 → 删键回源；无密钥者无法伪造可接受条目。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_mac_wrong_secret_purges() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-macwrong");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 攻击者用自己的密钥对（真实键 + 真实栅栏 + 真实哈希 + 真实载荷）签名。
    let attacker_secret = b"attacker-held-l2-secret-value-0123456789abcdef";
    let (payload, _) = mirror_factored_storage_form(&evidence);
    let forged = L2EntryMirror {
        schema_version: 4,
        card_source_pending: false,
        manifest_versions: versions_of(&evidence),
        content_hash: mirror_content_hash(&evidence),
        mac: mirror_entry_mac_with_secret(
            attacker_secret,
            &key,
            &versions_of(&evidence),
            &mirror_content_hash(&evidence),
            &evidence,
        ),
        payload,
    };
    redis
        .set_ex(
            &key,
            &serde_json::to_string(&forged).expect("forged entry json"),
            L2_EVIDENCE_TTL_SECONDS,
        )
        .await;

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let l2 = CountingL2Store::new();
    let reloaded = load_through(&deps, &fresh_cache(), Some(&l2), &ns)
        .await
        .expect("wrong-secret MAC must fall back to the strict reader");
    assert_eq!(deps.strict_calls(), 1, "wrong-secret MAC must never serve");
    assert_eq!(l2.del_calls(), 1, "wrong-MAC entry must be purged");
    assert_eq!(reloaded, evidence);

    redis.del(&[key]).await;
}

/// 新链加深（键绑定重放）：卡 A 在时代 A 键下被签发的合法条目字节，复制到
/// 同卡时代 B 键下 → MAC cover 的精确键失配 → purge 回源；复制到他卡键下 →
/// envelope 顶层 scope 预检拦截。键名不是身份，条目与键的绑定由 MAC 承担。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_key_bound_replay_purges() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-replay");
    let epoch_a = format!("it-{}", Uuid::new_v4().simple());
    let epoch_b = format!("it-{}", Uuid::new_v4().simple());
    let key_a = redis.l2_key(&epoch_a, ns.tenant_id, ns.card_id);
    let key_b = redis.l2_key(&epoch_b, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 时代 A 填充（合法条目，MAC 绑定 key_a）。
    let deps = FixtureDeps::new(&epoch_a, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    load_through(&deps, &fresh_cache(), Some(&CountingL2Store::new()), &ns)
        .await
        .expect("fill");
    let raw_a = redis.get(&key_a).await.expect("entry A");

    // 1) 同卡跨时代键重放。
    redis.set_ex(&key_b, &raw_a, L2_EVIDENCE_TTL_SECONDS).await;
    let deps_b = FixtureDeps::new(&epoch_b, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let l2_b = CountingL2Store::new();
    let reloaded_b = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("key-bound replay must fall back to the strict reader");
    assert_eq!(
        deps_b.strict_calls(),
        1,
        "key-bound replay must never serve"
    );
    assert_eq!(l2_b.del_calls(), 1, "replayed entry must be purged");
    assert_eq!(reloaded_b, evidence);

    // 2) 跨卡重放：A 的条目字节复制到 B 键 → envelope 顶层 scope 预检拦截。
    let ns_card_b = sibling_card(&ns, 100);
    let evidence_b = perpetual_single_record_evidence(&ns_card_b, now);
    let key_cb = redis.l2_key(&epoch_a, ns_card_b.tenant_id, ns_card_b.card_id);
    redis.set_ex(&key_cb, &raw_a, L2_EVIDENCE_TTL_SECONDS).await;
    let deps_cb = FixtureDeps::new(&epoch_a, fence_of(&evidence_b), now);
    deps_cb.push_strict(evidence_b.clone());
    let l2_cb = CountingL2Store::new();
    let reloaded_cb = load_through(&deps_cb, &fresh_cache(), Some(&l2_cb), &ns_card_b)
        .await
        .expect("cross-card replay must fall back to the strict reader");
    assert_eq!(
        deps_cb.strict_calls(),
        1,
        "cross-card replay must never serve"
    );
    assert_eq!(
        l2_cb.del_calls(),
        1,
        "cross-card replayed entry must be purged"
    );
    assert_eq!(
        reloaded_cb, evidence_b,
        "card B must only receive its own evidence"
    );

    redis.del(&[key_a, key_b, key_cb]).await;
}

/// 新链加深（记录级作用域投毒，持有密钥的攻击者模型）：条目顶层/栅栏/哈希/
/// MAC 全部合法，但 record 的 grant 携带他卡（或他租户）戳 → 记录级作用域
/// 绑定失败 → 删键回源；他卡/他租户的 grant 绝不借同卡条目放行。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_record_level_scope_poison_purges() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-scope");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 1) 同卡条目 + 他卡 grant（顶层与 manifest 戳保持卡 A）。
    let mut cross_card = evidence.clone();
    cross_card.records[0].grant.card_id = ns.card_id + 1;
    cross_card.effective_grants[0].card_id = ns.card_id + 1;
    assert!(
        cross_card.validate().is_ok(),
        "contract does not gate identity stamps"
    );
    let (poison_payload, _) = mirror_factored_storage_form(&cross_card);
    let poisoned = L2EntryMirror {
        schema_version: 4,
        card_source_pending: false,
        manifest_versions: versions_of(&evidence),
        content_hash: mirror_content_hash(&cross_card),
        mac: mirror_entry_mac(
            &key,
            &versions_of(&evidence),
            &mirror_content_hash(&cross_card),
            &cross_card,
        ),
        payload: poison_payload,
    };
    redis
        .set_ex(
            &key,
            &serde_json::to_string(&poisoned).expect("poisoned entry json"),
            L2_EVIDENCE_TTL_SECONDS,
        )
        .await;

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let l2 = CountingL2Store::new();
    let reloaded = load_through(&deps, &fresh_cache(), Some(&l2), &ns)
        .await
        .expect("record-level poison must fall back to the strict reader");
    assert_eq!(
        deps.strict_calls(),
        1,
        "foreign-card grant must never serve"
    );
    assert_eq!(l2.del_calls(), 1, "record-poisoned entry must be purged");
    assert_eq!(reloaded, evidence);

    // 2) 同卡条目 + 他租户 grant。
    let mut cross_tenant = evidence.clone();
    cross_tenant.records[0].grant.tenant.tenant_id = ns.tenant_id + 1;
    cross_tenant.effective_grants[0].tenant.tenant_id = ns.tenant_id + 1;
    let (tenant_poison_payload, _) = mirror_factored_storage_form(&cross_tenant);
    let tenant_poisoned = L2EntryMirror {
        schema_version: 4,
        card_source_pending: false,
        manifest_versions: versions_of(&evidence),
        content_hash: mirror_content_hash(&cross_tenant),
        mac: mirror_entry_mac(
            &key,
            &versions_of(&evidence),
            &mirror_content_hash(&cross_tenant),
            &cross_tenant,
        ),
        payload: tenant_poison_payload,
    };
    redis
        .set_ex(
            &key,
            &serde_json::to_string(&tenant_poisoned).expect("poisoned entry json"),
            L2_EVIDENCE_TTL_SECONDS,
        )
        .await;

    let deps_b = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps_b.push_strict(evidence.clone());
    let l2_b = CountingL2Store::new();
    let reloaded_b = load_through(&deps_b, &fresh_cache(), Some(&l2_b), &ns)
        .await
        .expect("foreign-tenant grant must fall back to the strict reader");
    assert_eq!(
        deps_b.strict_calls(),
        1,
        "foreign-tenant grant must never serve"
    );
    assert_eq!(l2_b.del_calls(), 1, "record-poisoned entry must be purged");
    assert_eq!(reloaded_b, evidence);

    redis.del(&[key]).await;
}

/// v2 退役条目（真实 Redis）：schema 2 完整载荷形状 → schema 栅栏拒绝 →
/// 删键回源重写为 schema 3（自愈），无需人工清理。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v2_entry_purges_and_self_heals() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v2-retired");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 手工构造 v2 形状条目：payload = 完整 v2 载荷（含 effectiveGrants、
    // records 无槽位标签），content_hash 对完整载荷一致。
    let v2_entry = serde_json::json!({
        "schemaVersion": 2,
        "manifestVersions": versions_of(&evidence),
        "contentHash": mirror_content_hash(&evidence),
        "payload": serde_json::to_value(&evidence).expect("full v2 payload value"),
    });
    redis
        .set_ex(&key, &v2_entry.to_string(), L2_EVIDENCE_TTL_SECONDS)
        .await;

    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let l2 = CountingL2Store::new();
    let reloaded = load_through(&deps, &fresh_cache(), Some(&l2), &ns)
        .await
        .expect("v2 entry must fall back to the strict reader");
    assert_eq!(deps.strict_calls(), 1, "retired v2 entry must never serve");
    assert_eq!(l2.del_calls(), 1, "v2 entry must be purged");
    assert_eq!(reloaded, evidence);
    let refilled = parse_l2_entry(&redis.get(&key).await.expect("refilled entry"));
    assert_eq!(
        refilled.schema_version,
        astral_db::L2_EVIDENCE_SCHEMA_VERSION,
        "refill must restore the current L2 schema version"
    );
    assert_eq!(
        reconstruct_entry_from_redis(&redis, &epoch, ns.tenant_id, &refilled).await,
        evidence
    );

    redis.del(&[key]).await;
}

/// 新链加深（密钥不可用 fail-closed）：显式 mac=None 注入（等价于进程密钥
/// 未设置/无效的旁路语义）→ L2 在场但零访问、严格 reader 兜底、零写入残留
/// ——绝不在未认证字节上授权，也绝不落未认证条目。
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_v3_secret_unavailable_bypasses_l2_read_and_write() {
    let Some(redis) = redis_gate().await else {
        return;
    };
    let ns = TestNamespace::new("l2ev-v3-nosecret");
    let epoch = format!("it-{}", Uuid::new_v4().simple());
    let key = redis.l2_key(&epoch, ns.tenant_id, ns.card_id);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let evidence = perpetual_single_record_evidence(&ns, now);

    // 读旁路：L2 存储在场但 mac=None → 零 L2 GET，严格读一次并只回填 L1。
    let deps = FixtureDeps::new(&epoch, fence_of(&evidence), now);
    deps.push_strict(evidence.clone());
    let l2 = CountingL2Store::new();
    let next = load_evidence_through_cache_with_mac(
        &deps,
        &fresh_cache(),
        Some(&l2),
        None,
        &ns.card_level_scope(),
    )
    .await
    .expect("strict read");
    assert_eq!(
        deps.strict_calls(),
        1,
        "no-secret must fall back to the strict reader"
    );
    assert_eq!(l2.get_calls(), 0, "no-secret reads must not touch L2");
    assert_eq!(l2.set_calls(), 0, "no-secret refills must not write L2");
    assert_eq!(next, evidence);
    assert!(
        redis.get(&key).await.is_none(),
        "no-secret flow must leave no card entry in Redis"
    );

    redis.del(&[key]).await;
}
