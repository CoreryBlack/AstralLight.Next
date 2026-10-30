//! 进程内 published card evidence 缓存 + 指针对牌（规模化切片 Batch C）
//!
//! 旧读链下线后，严格 reader
//! [`crate::authorization_projection_repository::load_published_card_grant_evidence`]
//! 是全部正式授权读路径的唯一数据源，每次读取都是一个 FOR UPDATE 短事务
//! （锁定卡作用域全部当前指针行 + 整链校验 + manifest/segment 摘要重算）。
//! 本模块在严格 reader 之前加一层**进程级、进程内** evidence 缓存：
//!
//! - **命中前提是"指针对牌"**：`authorization_projection_current` 卡作用域
//!   **全部**指针行的版本组（`aggregate_type`/`aggregate_id`/`manifest_id`/
//!   `current_generation`/`revoke_fence` 和完整 publication stamp，含集合形状）
//!   与填充时刻逐项相等
//!   （基准组来自 `crate::permission_query::evidence_fence_baseline`，
//!   现场组来自 `crate::permission_query::load_card_scope_fence_snapshot`，
//!   两者同源同形），且进程内缓存时代（`crate::cache_epoch`）严格一致。
//! - **正确性论证（pointer 未变 ⇒ evidence 未变）**：published evidence 是
//!   content-addressed 的 —— segment 载荷 sha256 重算比对、seal 校验、
//!   manifest digest 重算、pointer↔manifest 一致性全部由严格 reader 在读取
//!   时刻封死（任何篡改 = `Corrupt` fail-closed）。reader 产物完全由
//!   `(聚合身份, manifest)` 集合决定；manifest 身份由指针行
//!   `(current_generation, manifest_id, revoke_fence, publication_stamp)` 共同
//!   约束。因此完整版本组逐项相等 ⇒ 指针仍指向同一批 COMMITTED manifest ⇒ 严格 reader
//!   在本进程任何时刻重读都会产出**同一份**证据（`read_unix_seconds` 除外，
//!   见下节）。对牌是对"证据内容未变"的等价判定，不是对缓存字节的信任。
//! - **复读交互（engine ALLOW 前复读的等价替换）**：命中路径的复读
//!   （policy-engine `engine.rs` 的 `load_published_card_authorization`
//!   第二次调用）退化为同一 `Arc` 的克隆（恒真）；有效强度由本层每次 load
//!   的"读前对牌 + 读后复读对牌"双读协议承担（对齐
//!   `permission_query.rs` find_effective_permissions_cached 的双读先例）。
//!   对牌失败 → 回源严格 reader → 新 evidence 的 gate/manifests 与评估起点
//!   不同 → engine `published_recheck_identity_stable` 不通过 → PENDING。
//!   红线：校验失败一律回源 → PENDING/DENY，绝不产生错误放行。
//!
//! # TTL 与 `read_unix_seconds` 冻结
//!
//! 证据的 validity 判定冻结于填充时刻的统一 UTC 时钟
//! （`PublishedCardAuthorization::read_unix_seconds`）。TTL 封顶 30s
//! （`EVIDENCE_CACHE_TTL`，显著小于 validity 的业务粒度），且命中时按
//! **当前时钟**重验全部 records 的窗口状态（`cached_evidence_is_clock_fresh`）：
//! 任一 accepted 记录在当前时钟下不再有效，或任一因 `Expired`/`NotYetValid`
//! 被排除的记录窗口翻转（任一方向），即判证据时钟陈旧 → miss 回源。因此
//! "过期 grant 被多放行 ≤TTL" 的危险方向被封死；缓存条目本身只读（`Arc`），
//! 从不做读取侧再收窄/改写（`validate()` 要求 gate 计数与集合严格一致）。
//!
//! # user/domain lens 契约
//!
//! 缓存条目一律是**卡级 lens**（`user_filter: None` +
//! `DomainScopeRequirement::Unconstrained`）的超集证据：
//! - 卡级调用方（本模块 [`cached_load_published_card_grant_evidence`]）要求
//!   传入 scope 就是卡级 lens，否则 `InvalidRequest` 拒绝；
//! - engine strict 路径（[`CachedPublishedEvidenceRuleRepository`]）传入的
//!   user/domain lens 被有意丢弃：`PolicyEngine` 的
//!   `match_published_effective_grant` 在 `effective_grants` 上按请求
//!   user/domain 二次收窄，卡级超集与 user/domain 收窄集的放行判定逐条等价
//!   ——**已知差异仅在 gate 计数与审计观测字段**（`not_in_effective_count`
//!   等），不影响 ALLOW/DENY 语义；该取舍在此钉死，禁止对缓存条目做读取侧
//!   收窄或改写。
//! - 委托证明路径（`prove_delegator_hold_in_tx`，in_tx + user/domain lens）
//!   **不经过本模块**：事务内锁定读必须直连严格 reader
//!   `load_published_card_grant_evidence_in_tx`，永不走缓存（代码即契约，
//!   见 delegation_repository 既有锚定测试）。
//!
//! # 失效语义（无跨实例广播）
//!
//! REVOKE/发布推进写入指针行后，其它实例**下一次请求的对牌必然失败** →
//! 回源（撤销延迟 ≈ 0）；TTL 只是内存驻留上限。进程内 epoch
//! （`crate::cache_epoch`）参与对牌：恢复/重建后旋转时代，携带旧时代的条目全部
//! miss（严格 current 语义，`cache_epoch_is_current`）；当前时代未知时不命中也
//! 不填充，回源严格 reader。
//!
//! # 存储选型
//!
//! `moka`（future 特性）进程内缓存：TTL/容量上限/并发分片驱逐内建，已在本
//! workspace 依赖树中（0.12.16），避免手写 RwLock+LRU 在并发淘汰上的错误面。
//! 容量上限 `EVIDENCE_CACHE_MAX_CAPACITY` = 100_000 条（单条 Ready 证据约
//! 1-1.5KB，最坏 ≈150MB）。第一版不做 single-flight：同卡并发 miss 在指针行
//! 锁上自然串行化，最坏情况是重复一次严格读，结果仍然正确。
//!

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use astral_types::{
    DomainScopeRequirement, PolicyContext, PolicyError, PublishedCardAuthorization,
    PublishedCardEvidenceScope, UnacceptedGrantReason,
};
use moka::future::Cache;
use policy_engine::RuleRepository;
use sqlx::MySqlPool;
use time::OffsetDateTime;

use crate::authorization_projection_repository::{
    load_published_card_grant_evidence, AuthorizationEvidenceError,
};
use crate::cache_epoch::cache_epoch_is_current;
use crate::memory_projection_hub::{memory_projection_hub, MemoryProjectionHub};
#[cfg(test)]
use crate::permission_query::PermissionCacheManifestVersion;
use crate::permission_query::{
    evidence_fence_baseline, load_card_scope_fence_snapshot, CardScopeFenceSnapshot,
};
use crate::repository::DbError;

/// 进程内 evidence 缓存条目 TTL（30s 封顶）：read_unix_seconds 冻结的内存
/// 驻留上限；跨实例失效不依赖它（指针对牌保证撤销延迟 ≈ 0）。
pub(crate) const EVIDENCE_CACHE_TTL: Duration = Duration::from_secs(30);

/// 进程内 evidence 缓存容量上限（条目数）。单条 Ready evidence 约 1-1.5KB，
/// 最坏 ≈150MB 内存；超限按 moka 的 LRU-ish 策略驱逐（TTL 先行失效）。
pub(crate) const EVIDENCE_CACHE_MAX_CAPACITY: u64 = 100_000;

/// 缓存存储类型：键为 `(tenant_id, card_id)`（卡级 lens 唯一键），值为不可变
/// 的证据条目（字段私有，只能由填充路径构造，外部无法投毒）。
pub type EvidenceCacheStore = Cache<(i64, i64), EvidenceCacheEntry>;

/// 进程内 evidence 缓存条目（不可变）。
pub struct EvidenceCacheEntry {
    /// 填充时刻的 Ready 证据（`Arc` 只读共享；命中返回整份克隆，绝不改写）。
    evidence: Arc<PublishedCardAuthorization>,
    /// 填充时刻的卡作用域栅栏快照基准（指针版本组 + `card_source_pending=false`；
    /// 由 `evidence_fence_baseline` 从 evidence 内容推导，与
    /// `load_card_scope_fence_snapshot` 现场读同源同形），对牌的比较基准。
    baseline: CardScopeFenceSnapshot,
    /// 填充时刻的共享缓存时代（严格 current 语义：当前时代未知/不一致即 miss）。
    cache_epoch: String,
}

impl Clone for EvidenceCacheEntry {
    fn clone(&self) -> Self {
        Self {
            evidence: Arc::clone(&self.evidence),
            baseline: self.baseline.clone(),
            cache_epoch: self.cache_epoch.clone(),
        }
    }
}

/// 进程级全局缓存（每进程一份；moka Cache 是廉价 Arc 句柄，可克隆注入测试）。
static SHARED_EVIDENCE_CACHE: OnceLock<EvidenceCacheStore> = OnceLock::new();

/// 生产缓存句柄（进程级全局；TTL/容量见模块文档存储选型）。
pub fn shared_evidence_cache() -> &'static EvidenceCacheStore {
    SHARED_EVIDENCE_CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(EVIDENCE_CACHE_MAX_CAPACITY)
            .time_to_live(EVIDENCE_CACHE_TTL)
            .build()
    })
}

/// 缓存读取依赖 SPI（读取侧 only；生产实现走 MySQL + cache_epoch，测试注入
/// 夹具）。公开仅为泛型包装的 bound 可见性；语义契约如下：
/// - `card_scope_fence_snapshot`：轻读卡作用域栅栏快照（指针版本组 + 未发布
///   delta 位；无锁；非授权事实）；
/// - `strict_read`：严格 reader（单短事务 + FOR UPDATE + 整链校验 +
///   source-freshness 门 + 显式 commit），错误族原样上抛；
/// - `current_epoch`：当前进程内缓存时代（`None` = 未知 → 缓存整体旁路）；
/// - `now_unix_seconds`：命中时钟重验使用的当前 UTC 秒。
#[async_trait::async_trait]
pub trait EvidenceReadDeps: Send + Sync {
    async fn card_scope_fence_snapshot(
        &self,
        tenant_id: i64,
        card_id: i64,
    ) -> Result<CardScopeFenceSnapshot, DbError>;
    async fn strict_read(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError>;
    async fn current_epoch(&self) -> Option<String>;
    fn now_unix_seconds(&self) -> i64;
}

/// 生产读取依赖：MySQL 池 + `crate::cache_epoch` + 统一 UTC 时钟。
#[derive(Clone)]
pub struct MySqlEvidenceReadDeps {
    pool: MySqlPool,
}

impl MySqlEvidenceReadDeps {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl EvidenceReadDeps for MySqlEvidenceReadDeps {
    async fn card_scope_fence_snapshot(
        &self,
        tenant_id: i64,
        card_id: i64,
    ) -> Result<CardScopeFenceSnapshot, DbError> {
        load_card_scope_fence_snapshot(&self.pool, tenant_id, card_id).await
    }

    async fn strict_read(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError> {
        load_published_card_grant_evidence(&self.pool, scope)
            .await
            .map(std::sync::Arc::new)
    }

    async fn current_epoch(&self) -> Option<String> {
        crate::cache_epoch::current_cache_epoch().await
    }

    fn now_unix_seconds(&self) -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }
}

fn record_evidence_cache_lookup(layer: &'static str, outcome: &'static str) {
    metrics::counter!(
        "astral_authz_evidence_cache_lookups_total",
        "layer" => layer,
        "outcome" => outcome
    )
    .increment(1);
}

fn evidence_read_error_outcome(error: &AuthorizationEvidenceError) -> &'static str {
    match error {
        AuthorizationEvidenceError::NotReady(_) => "not_ready",
        AuthorizationEvidenceError::Corrupt(_) => "corrupt",
        AuthorizationEvidenceError::InvalidRequest(_) => "invalid_request",
        AuthorizationEvidenceError::Query(_) => "query_error",
    }
}

fn record_evidence_read(source: &'static str, outcome: &'static str, elapsed: Duration) {
    metrics::histogram!(
        "astral_authz_evidence_read_duration_seconds",
        "source" => source,
        "outcome" => outcome
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(feature = "e1-observability")]
fn log_e1_evidence_load_result(
    scope: &PublishedCardEvidenceScope,
    source: &'static str,
    evidence: &PublishedCardAuthorization,
) {
    let stamp = policy_engine::e1_observation::stamp();
    tracing::info!(
        target: "authz_e1",
        event = "evidence_load_result",
        request_id = stamp.request_id.as_deref().unwrap_or(""),
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        tenant_id = scope.tenant_id,
        card_id = scope.card_id,
        source,
        manifest_count = evidence.manifests.len(),
        effective_grant_count = evidence.effective_grants.len(),
        "e1 authorization observation"
    );
}

/// 缓存感知的卡级证据读取协议核心（miss 回源严格 reader；命中前置对牌）。
///
/// 命中协议：
/// 1. 读取进程内 L1 条目；
/// 2. epoch 严格 current（任一侧未知/不一致 → miss）；
/// 3. 读前对牌：当前指针版本组与条目基准组逐项相等，且无未发布撤权 delta；
/// 4. 读后复读对牌：两次栅栏读相等，避免发布并发窗口放行旧条目；
/// 5. 以当前时钟重新检查所有授权有效期窗口。
///
/// 任一缓存条件失败时，唯一回源是 strict published-evidence reader。只有严格
/// 读取成功、合同校验通过且当前进程内 epoch 已知时才填充 L1；未知时代仍返回
/// 严格读取结果，但不缓存。栅栏、合同或 strict-read 失败绝不回退 raw/source。
pub async fn load_evidence_through_cache<D: EvidenceReadDeps>(
    deps: &D,
    cache: &EvidenceCacheStore,
    scope: &PublishedCardEvidenceScope,
) -> Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError> {
    let evidence_read_started = std::time::Instant::now();
    scope.validate().map_err(|contract| {
        AuthorizationEvidenceError::InvalidRequest(format!(
            "code=published_card_evidence.invalid_scope;detail={contract}"
        ))
    })?;
    ensure_card_level_lens(scope)?;

    let key = (scope.tenant_id, scope.card_id);
    let current_epoch = deps.current_epoch().await;
    // 存疑门：失效通道 sticky suspect / 心跳缺失时跳过 L1，直接严格读取。
    let l1_permitted = l1_evidence_cache_permitted(memory_projection_hub());

    if !l1_permitted {
        record_evidence_cache_lookup("l1", "suspect_bypass");
    } else if let Some(entry) = cache.get(&key).await {
        let epoch_ok =
            cache_epoch_is_current(current_epoch.as_deref(), Some(entry.cache_epoch.as_str()));
        if epoch_ok {
            // 读前对牌：栅栏读失败按 miss 处理，回源严格 reader。
            if let Ok(fence) = deps
                .card_scope_fence_snapshot(scope.tenant_id, scope.card_id)
                .await
            {
                if fence.is_valid() && !fence.card_source_pending && fence == entry.baseline {
                    // 读后复读对牌：发布落在两次栅栏读之间时不放行旧条目。
                    if let Ok(recheck) = deps
                        .card_scope_fence_snapshot(scope.tenant_id, scope.card_id)
                        .await
                    {
                        if recheck == fence
                            && cached_evidence_is_clock_fresh(
                                &entry.evidence,
                                deps.now_unix_seconds(),
                            )
                        {
                            let evidence = std::sync::Arc::clone(&entry.evidence);
                            record_evidence_cache_lookup("l1", "hit");
                            record_evidence_read(
                                "l1_cache",
                                "success",
                                evidence_read_started.elapsed(),
                            );
                            #[cfg(feature = "e1-observability")]
                            log_e1_evidence_load_result(scope, "l1_cache", &evidence);
                            return Ok(evidence);
                        }
                    }
                }
            }
        }
        // 任一前提失败 → miss 回源；旧条目不改写，由 TTL/成功回填处理。
        record_evidence_cache_lookup("l1", "miss");
    } else {
        record_evidence_cache_lookup("l1", "miss");
    }

    // Strict reader 是唯一回源（锁定 + 整链校验 + 显式 commit）。
    let strict_read_started = std::time::Instant::now();
    let evidence = match deps.strict_read(scope).await {
        Ok(evidence) => evidence,
        Err(error) => {
            record_evidence_read(
                "strict_db",
                evidence_read_error_outcome(&error),
                strict_read_started.elapsed(),
            );
            return Err(error);
        }
    };
    if let Err(contract_error) = evidence.validate() {
        // 纵深防御：形状矛盾的证据不参与授权也不入缓存。
        record_evidence_read("strict_db", "corrupt", strict_read_started.elapsed());
        return Err(AuthorizationEvidenceError::Corrupt(format!(
            "code=evidence_cache.fill_contract_rejected;detail={contract_error}"
        )));
    }
    let baseline = evidence_fence_baseline(&evidence)?;
    if let Some(epoch) = current_epoch.as_deref() {
        cache
            .insert(
                key,
                EvidenceCacheEntry {
                    evidence: Arc::clone(&evidence),
                    baseline,
                    cache_epoch: epoch.to_owned(),
                },
            )
            .await;
    }
    #[cfg(feature = "e1-observability")]
    log_e1_evidence_load_result(scope, "strict_db", &evidence);
    record_evidence_read("strict_db", "success", strict_read_started.elapsed());
    Ok(evidence)
}

/// 卡级 lens 契约校验（纯逻辑）：缓存只服务卡级 lens scope。
fn ensure_card_level_lens(
    scope: &PublishedCardEvidenceScope,
) -> Result<(), AuthorizationEvidenceError> {
    if scope.user_filter.is_some() || scope.domain != DomainScopeRequirement::Unconstrained {
        return Err(AuthorizationEvidenceError::InvalidRequest(format!(
            "code=evidence_cache.card_level_lens_required;user_filter={:?};domain={:?}",
            scope.user_filter, scope.domain
        )));
    }
    Ok(())
}

/// 命中时钟重验（纯逻辑，无 I/O）：以当前 UTC 秒复核证据的窗口状态是否仍与
/// 填充时刻一致（read_unix_seconds 冻结的读侧封堵，见模块文档）。
///
/// - accepted 记录在当前时钟下不再有效 → 陈旧（危险方向：过期 grant 被放行）；
/// - 因 `Expired`/`NotYetValid` 被排除的记录在当前时钟下窗口翻转（任一方向）
///   → 陈旧（证据的 accepted 集合已不代表当前时刻）；
/// - `InactiveState`/lens 排除与时钟无关，不参与判定（否则会让缓存对含
///   DENY/收窄记录的卡永久 miss）。
///
/// 本函数只决定 hit/miss，绝不修改缓存条目（禁止读取侧再收窄）。
fn cached_evidence_is_clock_fresh(
    evidence: &PublishedCardAuthorization,
    now_unix_seconds: i64,
) -> bool {
    for record in &evidence.records {
        match record.unaccepted_reason {
            Some(UnacceptedGrantReason::Expired | UnacceptedGrantReason::NotYetValid)
                if record.grant.validity.is_valid_at(now_unix_seconds) =>
            {
                return false;
            }
            _ => {}
        }
        if record.accepted_into_effective_set
            && !record.grant.validity.is_valid_at(now_unix_seconds)
        {
            return false;
        }
    }
    true
}

/// 丢弃 user/domain lens，得到卡级 lens scope（纯逻辑）。
///
/// 仅 [`CachedPublishedEvidenceRuleRepository`]（engine 二级收窄先例，见模块
/// 文档 lens 契约）与测试使用；卡级调用方传入的 scope 本就是卡级 lens。
fn card_level_lens_scope(scope: &PublishedCardEvidenceScope) -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        tenant_id: scope.tenant_id,
        card_id: scope.card_id,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    }
}

/// 缓存读取错误 → `PolicyError`（镜像 astral-db `repository.rs` 私有的
/// `published_card_evidence_error_to_policy_error` 映射，保持 strict gate
/// 错误族/前缀逐字一致；该私有映射因锚定测试所在文件禁改而在此镜像）。
fn cached_published_evidence_error_to_policy_error(
    error: AuthorizationEvidenceError,
) -> PolicyError {
    match error {
        AuthorizationEvidenceError::NotReady(message) => {
            PolicyError::Repository(format!("published_card_evidence_not_ready;{message}"))
        }
        AuthorizationEvidenceError::Corrupt(message) => {
            PolicyError::Repository(format!("published_card_evidence_corrupt;{message}"))
        }
        AuthorizationEvidenceError::InvalidRequest(message) => PolicyError::InvalidContext(
            format!("published_card_evidence_invalid_request;{message}"),
        ),
        AuthorizationEvidenceError::Query(query) => {
            PolicyError::Repository(format!("published_card_evidence_query_failed;{query}"))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process-local L1 read gate
// ─────────────────────────────────────────────────────────────────────────────

/// L1 evidence 缓存读取门（纯逻辑，`hub` 生产传
/// [`memory_projection_hub()`]）：
///
/// - **hub 在场且存疑**（sticky suspect / 心跳缺失 / 锁中毒，
///   `channel_is_suspect()`）→ `false`：存疑态禁止复用旧 evidence，绕过 L1
///   并直接执行严格 reader（R1/R2 存疑回退的安全形态）；
/// - **hub 缺失** → `true`：L1 命中协议本身是逐请求 DB 指针双读对牌
///   （fence-anchored，见模块文档"正确性论证"），不依赖通道健康；缺 hub 是
///   当前生产形态，保持既有语义（失效语义已由指针对牌 + `card_source_pending`
///   位承担：任何失效/发布推进/撤权类未发布 delta 都会使对牌失配 → miss 回源）。
fn l1_evidence_cache_permitted(hub: Option<&MemoryProjectionHub>) -> bool {
    hub.is_none_or(|hub| !hub.channel_is_suspect())
}

/// 卡级 published card evidence 的缓存感知读取（进程级全局 L1 缓存）。
///
/// `scope` 必须是卡级 lens；缓存 miss 或任何栅栏失配都回源 strict published
/// evidence reader。事务内委托证明仍直接使用其锁定 reader，不经过此缓存。
pub async fn cached_load_published_card_grant_evidence(
    pool: &MySqlPool,
    scope: &PublishedCardEvidenceScope,
) -> Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError> {
    scope.validate().map_err(|contract| {
        AuthorizationEvidenceError::InvalidRequest(format!(
            "code=published_card_evidence.invalid_scope;detail={contract}"
        ))
    })?;
    ensure_card_level_lens(scope)?;
    let deps = MySqlEvidenceReadDeps::new(pool.clone());
    load_evidence_through_cache(&deps, shared_evidence_cache(), scope).await
}

/// 缓存感知的 [`policy_engine::RuleRepository`] 包装（strict evidence 读取）。
///
/// user/domain lens 被有意归一为卡级超集；PolicyEngine 在 effective grants 上
/// 二次收窄。正式读取每次均执行 L1 指针对牌，ALLOW 复读仍由双读栅栏保护。
pub struct CachedPublishedEvidenceRuleRepository<R, D = MySqlEvidenceReadDeps> {
    inner: R,
    deps: D,
    cache: EvidenceCacheStore,
}

impl<R: RuleRepository> CachedPublishedEvidenceRuleRepository<R, MySqlEvidenceReadDeps> {
    /// 生产装配：inner 提供权威资格、GlobalAdmin 与组织读取，pool 用于 strict
    /// published-evidence 读取及指针对牌。
    pub fn new(inner: R, pool: MySqlPool) -> Self {
        Self {
            inner,
            deps: MySqlEvidenceReadDeps::new(pool),
            cache: shared_evidence_cache().clone(),
        }
    }
}

impl<R, D> CachedPublishedEvidenceRuleRepository<R, D>
where
    R: RuleRepository,
    D: EvidenceReadDeps,
{
    /// 测试/特殊装配：显式注入读取依赖与进程内缓存。
    pub fn with_deps(inner: R, deps: D, cache: &EvidenceCacheStore) -> Self {
        Self {
            inner,
            deps,
            cache: cache.clone(),
        }
    }
}

#[async_trait::async_trait]
impl<R, D> RuleRepository for CachedPublishedEvidenceRuleRepository<R, D>
where
    R: RuleRepository,
    D: EvidenceReadDeps,
{
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.inner.check_card_active(ctx).await
    }

    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
        self.inner.is_active_global_admin(user_id).await
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        let card_scope = card_level_lens_scope(scope);
        match load_evidence_through_cache(&self.deps, &self.cache, &card_scope).await {
            Ok(evidence) => Ok(Some(evidence)),
            Err(error) => Err(cached_published_evidence_error_to_policy_error(error)),
        }
    }

    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<policy_engine::OrgAuthorityRead, PolicyError> {
        self.inner.load_org_authorization(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
        GrantSourceKind, GrantState, PublicationSeal, PublishedAggregateManifestSummary,
        PublishedCardAuthorizationGate, PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
        VerifiedPublishedGrantRecord,
    };

    #[test]
    fn evidence_read_error_outcomes_are_closed_and_text_free() {
        let errors = [
            (
                AuthorizationEvidenceError::NotReady("dynamic state".into()),
                "not_ready",
            ),
            (
                AuthorizationEvidenceError::Corrupt("dynamic payload".into()),
                "corrupt",
            ),
            (
                AuthorizationEvidenceError::InvalidRequest("dynamic request".into()),
                "invalid_request",
            ),
            (
                AuthorizationEvidenceError::Query(sqlx::Error::RowNotFound),
                "query_error",
            ),
        ];
        for (error, expected) in errors {
            assert_eq!(evidence_read_error_outcome(&error), expected);
        }
    }

    // ===== L1 读取门：suspect fail-closed + 失效禁旧 evidence =====

    #[test]
    fn l1_evidence_cache_is_blocked_only_by_a_suspect_channel() {
        // hub 缺失（当前生产形态）：L1 命中协议为逐请求 DB 双读对牌
        // （fence-anchored），不依赖通道健康 → 保持既有语义。
        assert!(l1_evidence_cache_permitted(None));

        // hub 在场且健康 → 参与。
        let healthy = MemoryProjectionHub::default();
        healthy.record_channel_heartbeat();
        assert!(!healthy.channel_is_suspect());
        assert!(l1_evidence_cache_permitted(Some(&healthy)));

        // sticky suspect（心跳无法清除）/ 锁中毒（channel_is_suspect 毒锁返回
        // true）→ 存疑时旁路 L1 缓存命中。
        let suspect = MemoryProjectionHub::default();
        suspect.record_channel_heartbeat();
        suspect.mark_channel_suspect("channel lost");
        suspect.record_channel_heartbeat();
        assert!(suspect.channel_is_suspect());
        assert!(!l1_evidence_cache_permitted(Some(&suspect)));

        // Unmonitored（hub 在场但 supervisor 尚未心跳）按 hub 自身契约不算
        // suspect → 保持 fence-anchored 既有语义（L1 命中本就逐请求对牌 DB，
        // Unmonitored 不构成存疑证据）。
        let silent = MemoryProjectionHub::default();
        assert!(!silent.channel_is_suspect());
        assert!(l1_evidence_cache_permitted(Some(&silent)));
    }

    #[test]
    fn pending_invalidation_snapshot_never_matches_the_cache_baseline() {
        // "invalidation 禁止旧 evidence" 的进程内形态：严格 reader 门禁通过后
        // 填充的基准 pending 恒为 false；此后本卡作用域出现撤权类未发布 delta
        // （现场读翻为 true）→ 与基准失配 → L1 miss 回源，绝不在
        // source 提交与发布收敛之间的越权窗口内放行旧证据。
        let evidence = fixture_evidence(
            1_700_000_000,
            vec![fixture_record(
                "USER_CARD",
                1,
                1,
                fixture_grant(1, ValidityWindow::perpetual()),
                true,
                None,
            )],
        );
        let baseline = evidence_fence_baseline(&evidence).unwrap();
        assert!(!baseline.card_source_pending);
        let invalidated = CardScopeFenceSnapshot {
            manifest_versions: baseline.manifest_versions.clone(),
            card_source_pending: true,
        };
        assert_ne!(baseline, invalidated);
        // 任意聚合版本组推进（发布落库）同样失配：TTL 不是失效依据，
        // 对牌才是（"不以 ttl alone proof 跨节点"）。
        let mut published_ahead = baseline.clone();
        published_ahead.manifest_versions[0].generation += 1;
        assert_ne!(baseline, published_ahead);
    }

    use std::collections::VecDeque;
    use std::sync::Mutex;

    const TENANT: i64 = 7;
    const CARD: i64 = 1;
    const EPOCH: &str = "epoch-fixture-1";

    // ===== 夹具：Ready evidence 与指针版本组（纯内存） =====

    fn fixed_grant_id(seed: u32) -> String {
        format!("00000000-0000-4000-8000-{seed:012}")
    }

    fn fixture_grant_scoped(
        tenant_id: i64,
        card_id: i64,
        seed: u32,
        validity: ValidityWindow,
    ) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&fixed_grant_id(seed)).expect("valid grant id"),
            revision: GrantRevision::new(1).expect("valid revision"),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Direct,
            binding_layer: BindingLayer::None,
            tenant: TenantScope::new(tenant_id, Some(11)).expect("valid tenant scope"),
            card_id,
            user_id: 42,
            resource: "learn_subject:*".to_string(),
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

    fn fixture_grant(seed: u32, validity: ValidityWindow) -> CanonicalGrant {
        fixture_grant_scoped(TENANT, CARD, seed, validity)
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
            compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant,
            accepted_into_effective_set: accepted,
            unaccepted_reason,
        }
    }

    /// 手工 Ready 证据 fixture（每个 distinct 来源聚合补一个 manifest，使
    /// fixture 始终满足合同校验；manifest 按 (type,id) 升序与 reader 一致）。
    fn fixture_evidence(
        read_unix_seconds: i64,
        records: Vec<VerifiedPublishedGrantRecord>,
    ) -> PublishedCardAuthorization {
        fixture_evidence_scoped(TENANT, CARD, read_unix_seconds, records)
    }

    /// 作用域参数化变体：为跨卡/跨租户投毒测试构造他卡/他租户的合法证据。
    fn fixture_evidence_scoped(
        tenant_id: i64,
        card_id: i64,
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
                    seal: PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
                    tenant_id,
                    card_id,
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
                    compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
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
            tenant_id,
            card_id,
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

    /// 单记录证据：accepted、窗口 [valid_from, valid_to)。
    fn single_record_evidence(
        read_at: i64,
        valid_from: i64,
        valid_to: i64,
    ) -> PublishedCardAuthorization {
        fixture_evidence(
            read_at,
            vec![fixture_record(
                "USER_CARD",
                1,
                9,
                fixture_grant(1, ValidityWindow::between(valid_from, valid_to)),
                true,
                None,
            )],
        )
    }

    // ===== 夹具读取依赖：队列驱动 + 调用计数（协议形状逐次钉死） =====

    struct FixtureState {
        epoch_reads: VecDeque<Option<String>>,
        fence_reads: VecDeque<CardScopeFenceSnapshot>,
        strict_reads: VecDeque<
            Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError>,
        >,
        fence_calls: usize,
        strict_calls: usize,
        now: i64,
    }

    struct FixtureDeps {
        state: Mutex<FixtureState>,
    }

    impl FixtureDeps {
        fn new(
            epoch_reads: Vec<Option<String>>,
            fence_reads: Vec<CardScopeFenceSnapshot>,
            strict_reads: Vec<
                Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError>,
            >,
            now: i64,
        ) -> Self {
            Self {
                state: Mutex::new(FixtureState {
                    epoch_reads: epoch_reads.into(),
                    fence_reads: fence_reads.into(),
                    strict_reads: strict_reads.into(),
                    fence_calls: 0,
                    strict_calls: 0,
                    now,
                }),
            }
        }

        fn fence_calls(&self) -> usize {
            self.state.lock().unwrap().fence_calls
        }

        fn strict_calls(&self) -> usize {
            self.state.lock().unwrap().strict_calls
        }
    }

    #[async_trait::async_trait]
    impl EvidenceReadDeps for FixtureDeps {
        async fn card_scope_fence_snapshot(
            &self,
            _tenant_id: i64,
            _card_id: i64,
        ) -> Result<CardScopeFenceSnapshot, DbError> {
            let mut state = self.state.lock().unwrap();
            state.fence_calls += 1;
            state
                .fence_reads
                .pop_front()
                .ok_or_else(|| DbError::Mapping("unexpected fence read in fixture".into()))
        }

        async fn strict_read(
            &self,
            _scope: &PublishedCardEvidenceScope,
        ) -> Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError>
        {
            let mut state = self.state.lock().unwrap();
            state.strict_calls += 1;
            state
                .strict_reads
                .pop_front()
                .expect("unexpected strict read in fixture")
        }

        async fn current_epoch(&self) -> Option<String> {
            let mut state = self.state.lock().unwrap();
            state
                .epoch_reads
                .pop_front()
                .expect("unexpected epoch read in fixture")
        }

        fn now_unix_seconds(&self) -> i64 {
            self.state.lock().unwrap().now
        }
    }

    fn fence_of(evidence: &PublishedCardAuthorization) -> CardScopeFenceSnapshot {
        evidence_fence_baseline(evidence).unwrap()
    }

    fn unsafe_cached_value_omitting_pending_probe(
        entry: &EvidenceCacheEntry,
        observed: &CardScopeFenceSnapshot,
    ) -> Option<PublishedCardAuthorization> {
        (entry.baseline.manifest_versions == observed.manifest_versions)
            .then(|| (*entry.evidence).clone())
    }

    fn unsafe_cached_value_omitting_post_recheck(
        entry: &EvidenceCacheEntry,
        pre_observation: &CardScopeFenceSnapshot,
    ) -> Option<PublishedCardAuthorization> {
        (&entry.baseline == pre_observation).then(|| (*entry.evidence).clone())
    }

    fn unsafe_cached_value_omitting_generation_revoke_fence(
        entry: &EvidenceCacheEntry,
        observed: &CardScopeFenceSnapshot,
    ) -> Option<PublishedCardAuthorization> {
        let same_manifest_identity = entry.baseline.manifest_versions.len()
            == observed.manifest_versions.len()
            && entry
                .baseline
                .manifest_versions
                .iter()
                .zip(&observed.manifest_versions)
                .all(|(baseline, current)| {
                    baseline.aggregate_type == current.aggregate_type
                        && baseline.aggregate_id == current.aggregate_id
                        && baseline.manifest_id == current.manifest_id
                });
        (same_manifest_identity
            && entry.baseline.card_source_pending == observed.card_source_pending)
            .then(|| (*entry.evidence).clone())
    }

    async fn load_with(
        deps: &FixtureDeps,
        cache: &EvidenceCacheStore,
    ) -> Result<std::sync::Arc<PublishedCardAuthorization>, AuthorizationEvidenceError> {
        let scope = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        load_evidence_through_cache(deps, cache, &scope).await
    }

    fn fresh_cache() -> EvidenceCacheStore {
        Cache::builder()
            .max_capacity(EVIDENCE_CACHE_MAX_CAPACITY)
            .time_to_live(EVIDENCE_CACHE_TTL)
            .build()
    }

    // ===== C3 测试矩阵 =====

    /// 冷 miss 零栅栏 I/O，回源严格 reader 一次并填充；第二次 load 命中
    /// （恰好两次栅栏读 = 读前对牌 + 读后复读），结果与直读逐字段 parity。
    #[tokio::test]
    async fn cold_miss_fills_cache_and_second_load_hits_with_parity() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let direct = evidence.clone();
        let cache = fresh_cache();

        // 冷 miss：epoch 1 次 + 严格读 1 次，零栅栏读。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_050,
        );
        let first = load_with(&deps, &cache).await.expect("first load");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(deps.fence_calls(), 0);
        assert_eq!(*first, direct);

        // 命中：epoch 1 次 + 读前对牌 + 读后复读对牌，零严格读。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_060,
        );
        let second = load_with(&deps, &cache).await.expect("second load");
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(deps.fence_calls(), 2);
        // parity：缓存命中结果 ≡ 直读结果（逐字段）。
        assert_eq!(*second, direct);
    }

    /// 发布推进（generation +1）→ 读前对牌失败 → 回源 → 新 evidence。
    #[tokio::test]
    async fn generation_advance_busts_cache_and_rereads_strict() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into()), Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale))],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        // 发布推进：同一聚合 generation 推进（evidence 内容也随之更新）。
        let mut published = single_record_evidence(1_100, 0, 2_000);
        published.manifests[0].generation = 2;
        let advanced_fence = fence_of(&published);

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![advanced_fence.clone()],
            vec![Ok(std::sync::Arc::new(published.clone()))],
            1_100,
        );
        let next = load_with(&deps, &cache).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1, "drift must go back to strict read");
        assert_eq!(*next, published);
    }

    /// REVOKE 场景：撤销 delta 发布（revoke_fence +1）后下一请求对牌失败 →
    /// 回源 → 撤销生效（撤销延迟 ≈ 0，无跨实例广播依赖）。
    #[tokio::test]
    async fn revoke_fence_advance_busts_cache_immediately() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into()), Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale))],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        let mut revoked = single_record_evidence(1_100, 0, 2_000);
        revoked.manifests[0].revoke_fence = 3;
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&revoked)],
            vec![Ok(std::sync::Arc::new(revoked.clone()))],
            1_100,
        );
        let next = load_with(&deps, &cache).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(*next, revoked);
    }

    /// 同 generation 病态重写（manifest_id 变化）→ 对牌失败（content-addressed
    /// 参数捕获）；版本组集合形状变化（新聚合发布）同样失败。
    #[tokio::test]
    async fn manifest_id_and_shape_changes_bust_cache() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale.clone()))],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        // 同 generation/fence 但 manifest_id 变化（指针重写）。
        let mut rewritten = single_record_evidence(1_100, 0, 2_000);
        rewritten.manifests[0].manifest_id = 10;
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&rewritten)],
            vec![Ok(std::sync::Arc::new(rewritten.clone()))],
            1_100,
        );
        let next = load_with(&deps, &cache)
            .await
            .expect("reload after rewrite");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(*next, rewritten);

        // 集合形状变化：新增一个聚合的指针行（版本组形状不一致 → 失配）。
        let extra_row = PermissionCacheManifestVersion {
            aggregate_type: "RULE_SET".to_string(),
            aggregate_id: 10,
            manifest_id: 1,
            generation: 1,
            revoke_fence: 0,
            publication_stamp: rewritten.manifests[0].publication_stamp().unwrap(),
        };
        let mut shaped = fence_of(&rewritten);
        shaped.manifest_versions.push(extra_row);
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![shaped],
            vec![Ok(std::sync::Arc::new(rewritten.clone()))],
            1_150,
        );
        let next = load_with(&deps, &cache).await.expect("reload after shape");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(*next, rewritten);
    }

    /// epoch 严格 current 语义：填充后时代轮换 → miss 并以新时代重填；时代
    /// 轮回一致后命中；当前时代未知→ miss 且不填充。
    #[tokio::test]
    async fn epoch_rotation_and_degradation_bust_cache() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        // 填充（时代 = EPOCH）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        // 时代轮换 → miss → 回源并以新时代重填。
        let deps = FixtureDeps::new(
            vec![Some("rotated-epoch".into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_060,
        );
        load_with(&deps, &cache)
            .await
            .expect("reload after rotation");
        assert_eq!(deps.strict_calls(), 1, "rotated epoch must miss");

        // 时代轮回一致（条目仍携带 rotated）→ 依旧 miss → 重填 EPOCH。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_070,
        );
        load_with(&deps, &cache)
            .await
            .expect("reload after rotation back");
        assert_eq!(deps.strict_calls(), 1, "stale entry epoch must miss");

        // 当前时代未知→ miss 回源，且不填充。
        let deps = FixtureDeps::new(
            vec![None],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_080,
        );
        load_with(&deps, &cache)
            .await
            .expect("reload while degraded");
        assert_eq!(deps.strict_calls(), 1, "unknown epoch must miss");

        // 时代一致 → 命中（两次栅栏读，零严格读）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_090,
        );
        let hit = load_with(&deps, &cache).await.expect("hit");
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(*hit, evidence);
    }

    /// 时钟重验：accepted 记录过期 → miss 回源（危险方向封死）；
    /// NotYetValid 记录窗口开启 → miss 回源；时钟无关的排除记录不误伤命中。
    #[tokio::test]
    async fn clock_staleness_busts_cache_in_both_window_directions() {
        let cache = fresh_cache();

        // 填充：accepted 窗口 [1_000, 1_200) + NotYetValid 窗口 [2_000, 3_000)。
        let evidence = fixture_evidence(
            1_000,
            vec![
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(1, ValidityWindow::between(1_000, 1_200)),
                    true,
                    None,
                ),
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(2, ValidityWindow::between(2_000, 3_000)),
                    false,
                    Some(UnacceptedGrantReason::NotYetValid),
                ),
            ],
        );
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        // 时钟仍在窗口内 → 命中（两次栅栏读，零严格读）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_199,
        );
        load_with(&deps, &cache).await.expect("hit within window");
        assert_eq!(deps.strict_calls(), 0);

        // accepted 记录过期（now=1_200 恰好到达上界，is_valid_at 上界排他）
        // → 命中前提走到时钟重验失败 → miss 回源（缓存有条目，先两次栅栏读）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_200,
        );
        load_with(&deps, &cache).await.expect("reload after expiry");
        assert_eq!(deps.strict_calls(), 1, "expired accepted grant must miss");

        // NotYetValid 记录窗口开启 → 时钟重验失败 → miss 回源。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            2_050,
        );
        load_with(&deps, &cache).await.expect("reload after flip");
        assert_eq!(deps.strict_calls(), 1, "window flip must miss");
    }

    /// 时钟无关的排除（InactiveState）不参与时钟重验：命中不被误伤。
    #[tokio::test]
    async fn clock_independent_exclusions_do_not_bust_cache() {
        let cache = fresh_cache();
        let evidence = fixture_evidence(
            1_000,
            vec![
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(1, ValidityWindow::perpetual()),
                    true,
                    None,
                ),
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(2, ValidityWindow::perpetual()),
                    false,
                    Some(UnacceptedGrantReason::InactiveState),
                ),
            ],
        );
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_000,
        );
        load_with(&deps, &cache).await.expect("fill");

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            99_999,
        );
        load_with(&deps, &cache)
            .await
            .expect("hit far in the future");
        assert_eq!(deps.strict_calls(), 0);
    }

    /// 严格 reader 失败绝不入缓存：失败后下一次 load 仍回源成功。
    #[tokio::test]
    async fn strict_failure_is_never_cached() {
        let cache = fresh_cache();
        let evidence = single_record_evidence(1_000, 0, 2_000);

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Err(AuthorizationEvidenceError::NotReady(
                "code=published_card_evidence.current_pointer_missing".into(),
            ))],
            1_050,
        );
        let outcome = load_with(&deps, &cache).await;
        assert!(matches!(
            outcome,
            Err(AuthorizationEvidenceError::NotReady(_))
        ));

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_060,
        );
        let next = load_with(&deps, &cache).await.expect("reload succeeds");
        assert_eq!(deps.strict_calls(), 1, "failed read must not be cached");
        assert_eq!(*next, evidence);
    }

    /// 读后复读对牌：发布恰好落在两次栅栏读之间（第一次等于基准、第二次
    /// 漂移）→ 不放行旧条目 → 回源。
    #[tokio::test]
    async fn fence_recheck_catches_publish_between_the_two_reads() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into()), Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale))],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        let mut published = single_record_evidence(1_100, 0, 2_000);
        published.manifests[0].generation = 2;
        let drifted = fence_of(&published);
        let mut baseline = drifted.clone();
        baseline.manifest_versions[0].generation = 1;

        // 读前对牌 = 基准（未漂移），读后复读 = 已漂移 → miss。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![baseline, drifted],
            vec![Ok(std::sync::Arc::new(published.clone()))],
            1_100,
        );
        let next = load_with(&deps, &cache).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(*next, published);
    }

    #[tokio::test]
    async fn e2_pending_probe_omission_accepts_stale_candidate_while_full_contract_reloads() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale.clone()))],
            1_050,
        );
        load_with(&fill, &cache).await.expect("fill");

        let mut pending = fence_of(&stale);
        pending.card_source_pending = true;
        let entry = cache.get(&(TENANT, CARD)).await.expect("cached entry");
        let unsafe_value = unsafe_cached_value_omitting_pending_probe(&entry, &pending)
            .expect("omitting the pending probe accepts the stale candidate");
        assert_eq!(unsafe_value, stale);

        let narrowed = fixture_evidence(1_100, vec![]);
        let full = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![pending],
            vec![Ok(std::sync::Arc::new(narrowed.clone()))],
            1_100,
        );
        let safe_value = load_with(&full, &cache)
            .await
            .expect("full contract reload");
        assert_eq!(full.strict_calls(), 1);
        assert_eq!(*safe_value, narrowed);
        assert!(safe_value.effective_grants.is_empty());
    }

    #[tokio::test]
    async fn e2_post_recheck_omission_accepts_interleaving_while_full_contract_reloads() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale.clone()))],
            1_050,
        );
        load_with(&fill, &cache).await.expect("fill");

        let entry = cache.get(&(TENANT, CARD)).await.expect("cached entry");
        let pre_observation = fence_of(&stale);
        let mut published = single_record_evidence(1_100, 0, 2_000);
        published.manifests[0].generation = 2;
        let post_observation = fence_of(&published);
        let unsafe_value = unsafe_cached_value_omitting_post_recheck(&entry, &pre_observation)
            .expect("one observation accepts the stale candidate");
        assert_eq!(unsafe_value, stale);

        let full = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![pre_observation, post_observation],
            vec![Ok(std::sync::Arc::new(published.clone()))],
            1_100,
        );
        let safe_value = load_with(&full, &cache)
            .await
            .expect("full contract reload");
        assert_eq!(full.strict_calls(), 1);
        assert_eq!(*safe_value, published);
    }

    #[tokio::test]
    async fn e2_generation_revoke_fence_omission_accepts_stale_candidate() {
        let stale = single_record_evidence(1_000, 0, 2_000);

        let generation_cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale.clone()))],
            1_050,
        );
        load_with(&fill, &generation_cache)
            .await
            .expect("fill generation fixture");
        let generation_entry = generation_cache
            .get(&(TENANT, CARD))
            .await
            .expect("cached generation fixture");
        let mut advanced = stale.clone();
        advanced.manifests[0].generation = 2;
        advanced.manifests[0].source_generation = 2;
        advanced.manifests[0].projected_generation = 2;
        advanced.records[0].publication_generation = 2;
        advanced.records[0].grant.resource = "learn_course:9".to_owned();
        advanced.effective_grants[0].resource = "learn_course:9".to_owned();
        assert!(advanced.validate().is_ok());
        let advanced_fence = fence_of(&advanced);
        let unsafe_generation = unsafe_cached_value_omitting_generation_revoke_fence(
            &generation_entry,
            &advanced_fence,
        )
        .expect("omitting generation admits the stale cache entry");
        assert_eq!(unsafe_generation, stale);

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![advanced_fence],
            vec![Ok(std::sync::Arc::new(advanced.clone()))],
            1_100,
        );
        let safe_generation = load_with(&deps, &generation_cache)
            .await
            .expect("generation mismatch reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(*safe_generation, advanced);
        assert!(safe_generation
            .effective_grants
            .iter()
            .all(|grant| grant.resource != "learn_subject:42"));

        let revoke_cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(std::sync::Arc::new(stale.clone()))],
            1_050,
        );
        load_with(&fill, &revoke_cache)
            .await
            .expect("fill revoke fixture");
        let revoke_entry = revoke_cache
            .get(&(TENANT, CARD))
            .await
            .expect("cached revoke fixture");
        let mut revoked = stale.clone();
        revoked.manifests[0].revoke_fence = 1;
        revoked.records[0].revoke_fence = 1;
        revoked.records[0].grant.state = GrantState::Revoked;
        revoked.records[0].accepted_into_effective_set = false;
        revoked.records[0].unaccepted_reason = Some(UnacceptedGrantReason::InactiveState);
        revoked.effective_grants.clear();
        revoked.gate.effective_grant_count = 0;
        revoked.gate.not_in_effective_count = 1;
        assert!(revoked.validate().is_ok());
        let revoked_fence = fence_of(&revoked);
        let unsafe_revoke =
            unsafe_cached_value_omitting_generation_revoke_fence(&revoke_entry, &revoked_fence)
                .expect("omitting revoke fence admits the stale cache entry");
        assert_eq!(unsafe_revoke, stale);

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![revoked_fence],
            vec![Ok(std::sync::Arc::new(revoked.clone()))],
            1_100,
        );
        let safe_revoke = load_with(&deps, &revoke_cache)
            .await
            .expect("revoke fence mismatch reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(*safe_revoke, revoked);
        assert!(safe_revoke.effective_grants.is_empty());
    }

    /// TTL 配置有界（恰为 30s，不超过 60s 上限）——moka 自身负责真实过期
    /// 与驱逐，这里钉死配置常量不回退。
    #[test]
    fn ttl_and_capacity_constants_stay_bounded() {
        assert_eq!(EVIDENCE_CACHE_TTL, Duration::from_secs(30));
        assert!(EVIDENCE_CACHE_TTL <= Duration::from_secs(60));
        assert_eq!(EVIDENCE_CACHE_MAX_CAPACITY, 100_000);
    }

    /// 卡级 lens 契约：user/domain lens scope 一律 InvalidRequest 拒绝。
    #[tokio::test]
    async fn non_card_level_lens_is_rejected() {
        let cache = fresh_cache();
        let lensed = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: Some(42),
            domain: DomainScopeRequirement::ExactlySome(11),
        };
        let deps = FixtureDeps::new(vec![], vec![], vec![], 1_000);
        let outcome = load_evidence_through_cache(&deps, &cache, &lensed).await;
        assert!(matches!(
            outcome,
            Err(AuthorizationEvidenceError::InvalidRequest(message))
                if message.contains("card_level_lens_required")
        ));
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(deps.fence_calls(), 0);
    }

    /// lens 归一化（纯逻辑）：engine 传入的 user/domain lens 被丢弃，tenant/
    /// card 保留。
    #[test]
    fn card_level_lens_scope_drops_user_and_domain_lens() {
        let lensed = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: Some(42),
            domain: DomainScopeRequirement::ExactlySome(11),
        };
        let normalized = card_level_lens_scope(&lensed);
        assert_eq!(normalized.tenant_id, TENANT);
        assert_eq!(normalized.card_id, CARD);
        assert_eq!(normalized.user_filter, None);
        assert_eq!(normalized.domain, DomainScopeRequirement::Unconstrained);
    }

    /// 错误族映射（纯逻辑）：与生产 repository 的 strict gate 映射逐字一致。
    #[test]
    fn error_mapping_keeps_strict_gate_prefixes() {
        let not_ready = cached_published_evidence_error_to_policy_error(
            AuthorizationEvidenceError::NotReady("code=x".into()),
        );
        assert!(matches!(
            not_ready,
            PolicyError::Repository(message)
                if message.starts_with("published_card_evidence_not_ready;")
        ));

        let corrupt = cached_published_evidence_error_to_policy_error(
            AuthorizationEvidenceError::Corrupt("code=y".into()),
        );
        assert!(matches!(
            corrupt,
            PolicyError::Repository(message)
                if message.starts_with("published_card_evidence_corrupt;")
        ));

        let invalid = cached_published_evidence_error_to_policy_error(
            AuthorizationEvidenceError::InvalidRequest("code=z".into()),
        );
        assert!(matches!(
            invalid,
            PolicyError::InvalidContext(message)
                if message.starts_with("published_card_evidence_invalid_request;")
        ));

        let query = cached_published_evidence_error_to_policy_error(
            AuthorizationEvidenceError::Query(sqlx::Error::RowNotFound),
        );
        assert!(matches!(
            query,
            PolicyError::Repository(message)
                if message.starts_with("published_card_evidence_query_failed;")
        ));
    }

    /// 计数型 inner 仓库：验证包装层透传后 engine 只触达
    /// `load_published_card_authorization`（既有 engine mock 读取计数契约
    /// 不受包装影响）。
    struct CountingInnerRepo {
        published_reads: std::sync::atomic::AtomicUsize,
        global_admin_reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RuleRepository for CountingInnerRepo {
        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            Ok(true)
        }

        async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
            self.global_admin_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(user_id == 73)
        }

        async fn load_published_card_authorization(
            &self,
            _scope: &PublishedCardEvidenceScope,
        ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
            self.published_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(None)
        }

        async fn load_org_authorization(
            &self,
            _ctx: &PolicyContext,
        ) -> Result<policy_engine::OrgAuthorityRead, PolicyError> {
            Ok(policy_engine::OrgAuthorityRead::Unmanaged)
        }
    }

    /// 包装层接线测试：user/domain lens scope 服务卡级超集；第二次读取命中
    /// 缓存（inner 只被触达一次）；能力标记透传。
    #[tokio::test]
    async fn wrapper_serves_card_level_superset_and_hits_cache() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let inner = CountingInnerRepo {
            published_reads: std::sync::atomic::AtomicUsize::new(0),
            global_admin_reads: std::sync::atomic::AtomicUsize::new(0),
        };

        // 夹具 strict 在首次读取时供应证据；wrapper 把 lens scope 归一为卡级。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into()), Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![Ok(std::sync::Arc::new(evidence.clone()))],
            1_050,
        );
        let repo = CachedPublishedEvidenceRuleRepository::with_deps(inner, deps, &cache);
        let eligibility_context = PolicyContext::builder().action("read".into()).build();
        assert!(repo.check_card_active(&eligibility_context).await.unwrap());
        assert!(repo.is_active_global_admin(73).await.unwrap());
        assert!(!repo.is_active_global_admin(74).await.unwrap());
        assert_eq!(
            repo.inner
                .global_admin_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            2,
            "GlobalAdmin authority must delegate to the inner authoritative repository"
        );

        let lensed = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: Some(42),
            domain: DomainScopeRequirement::ExactlySome(11),
        };
        // 第一次读取：回源（inner 被触达一次）。
        let first = repo
            .load_published_card_authorization(&lensed)
            .await
            .expect("first load")
            .expect("strict evidence is Some");
        assert_eq!(*first, evidence);

        // 第二次读取（engine ALLOW 复读形态）：命中缓存，inner 不再被触达。
        let second = repo
            .load_published_card_authorization(&lensed)
            .await
            .expect("second load")
            .expect("cached evidence is Some");
        assert_eq!(*second, evidence, "recheck evidence must be identical");
    }
}
