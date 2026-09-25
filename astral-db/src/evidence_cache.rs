//! 进程内 published card evidence 缓存 + 指针对牌（规模化切片 Batch C）
//!
//! 旧读链下线后，严格 reader
//! [`crate::authorization_projection_repository::load_published_card_grant_evidence`]
//! 是全部正式授权读路径的唯一数据源，每次读取都是一个 FOR UPDATE 短事务
//! （锁定卡作用域全部当前指针行 + 整链校验 + manifest/segment 摘要重算）。
//! 本模块在严格 reader 之前加一层**进程级、进程内**（非 Redis）evidence 缓存：
//!
//! - **命中前提是"指针对牌"**：`authorization_projection_current` 卡作用域
//!   **全部**指针行的版本组（`aggregate_type`/`aggregate_id`/`manifest_id`/
//!   `current_generation`/`revoke_fence`，含集合形状）与填充时刻逐项相等
//!   （基准组来自 [`crate::permission_query::evidence_manifest_versions`]，
//!   现场组来自 [`crate::permission_query::load_pointer_fence_versions`]，
//!   两者同源同形），且共享缓存时代（`crate::cache_epoch`）严格一致。
//! - **正确性论证（pointer 未变 ⇒ evidence 未变）**：published evidence 是
//!   content-addressed 的 —— segment 载荷 sha256 重算比对、seal 校验、
//!   manifest digest 重算、pointer↔manifest 一致性全部由严格 reader 在读取
//!   时刻封死（任何篡改 = `Corrupt` fail-closed）。reader 产物完全由
//!   `(聚合身份, manifest)` 集合决定；manifest 身份由指针行
//!   `(current_generation, manifest_id, revoke_fence)` 唯一确定。因此指针
//!   版本组逐项相等 ⇒ 指针仍指向同一批 COMMITTED manifest ⇒ 严格 reader
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
//! （[`EVIDENCE_CACHE_TTL`]，显著小于 validity 的业务粒度），且命中时按
//! **当前时钟**重验全部 records 的窗口状态（[`cached_evidence_is_clock_fresh`]）：
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
//! 回源（撤销延迟 ≈ 0）；TTL 只是内存驻留上限。epoch（`crate::cache_epoch`）
//! 参与对牌：整库恢复/重建换时代后，携带旧时代的条目全部 miss（严格 current
//! 语义，`cache_epoch_is_current`）；当前时代未知（Redis 降级）→ 不命中也
//! 不填充，缓存整体旁路，回源严格 reader。
//!
//! # 存储选型
//!
//! `moka`（future 特性）进程内缓存：TTL/容量上限/并发分片驱逐内建，已在本
//! workspace 依赖树中（0.12.16），避免手写 RwLock+LRU 在并发淘汰上的错误面。
//! 容量上限 [`EVIDENCE_CACHE_MAX_CAPACITY`] = 100_000 条（单条 Ready 证据约
//! 1-1.5KB，最坏 ≈150MB）。第一版不做 single-flight：同卡并发 miss 在指针行
//! 锁上自然串行化，最坏情况是重复一次严格读，结果仍然正确。
//!
//! # L2 Redis 分发层（读链规模化 Batch D）
//!
//! L1 是进程内的：重启冷启动、实例间不共享。本层把 miss 回源路径增强为
//! "**L2 Redis 优先 → L3 DB 兜底**"，并把发布产物在发布事务提交后推入 L2
//! （跨实例共享、进程重启不冷）：
//!
//! - **键族**（全部时代**内嵌**，换时代（`crate::cache_epoch`
//!   `DEL astral:auth:cache_epoch`）后旧键自然失配，无需扫描删除）：
//!   - 卡证据键 [`L2_EVIDENCE_KEY_PREFIX`] `astral:auth:l2ev:{cache_epoch}:
//!     {tenant_id}:{card_id}` —— 逐卡私有（条目/栅栏/envelope 绝不跨卡共享）；
//!   - 共享内容单元键 [`L2_EVIDENCE_SHARED_KEY_PREFIX`]
//!     `astral:auth:l2sh:{cache_epoch}:{tenant_id}:{digest}` —— **tenant+时代
//!     限定**的内容寻址 RULE_SET 存储单元（见"去重边界"）。
//! - **值 JSON（schema 3 因子化存储形态）**：[`L2EvidenceEntry`] `{
//!   schema_version, manifest_versions（与 L1 基准组同结构
//!   [`PermissionCacheManifestVersion`]，逐卡 envelope）, content_hash, mac,
//!   payload }`。`payload` 是**因子化存储形态**
//!   （[`L2FactoredCardPayload`]）：非 RULE_SET 记录完整内联；RULE_SET 记录
//!   拆为"逐卡 envelope（身份/绑定/来源字段 + 单元摘要引用）"+"tenant+时代
//!   限定的共享内容单元"（[`L2SharedUnit`]，只含规则内容 resource/action/
//!   effect/validity 与编译器元数据，**绝不含 tenant/card/user/grant 身份**，
//!   自带内容摘要自校验）。读侧以纯函数 join 重建（[`l2_reconstruct_full_payload`]），
//!   `effective_grants` 由合同定理（必须恰好等于 records 中 accepted 子集、
//!   同序同内容）展开，**身份字段全部来自逐卡 envelope，读侧绝不改写、补盖
//!   或重定戳任何身份**。`content_hash` = **重建后完整 payload** 序列化 JSON
//!   的 sha256（独立于 MAC 的全载荷完整性校验：不匹配即污染/部分写/重建偏差，
//!   删除该卡键并回源）。schema 1/2 旧条目在升级后按 schema 失配自然 purge
//!   自愈（与 permission_query v4 envelope 的既有先例同一模式）。
//! - **HMAC 认证（强制，fail-closed）**：每张卡证据条目携带
//!   `mac = HMAC-SHA256(ASTRAL_L2_EVIDENCE_HMAC_SECRET, 规范序列化 cover)`，
//!   cover 绑定：域分隔符（[`L2_MAC_DOMAIN`]）+ **精确 Redis 键**（防键间
//!   重放）+ schema 版本 + 版本组 + content_hash + **重建后完整 payload**。
//!   密钥来自专用环境变量 [`L2_EVIDENCE_HMAC_SECRET_ENV`]（绝不复用网关/
//!   内部签名密钥，绝不硬编码）：仅接受非占位符且 ≥32 字节/字符的值；未设置
//!   或无效 → **L2 读与写整体旁路，直接严格 reader（fail-closed）**，进程内
//!   warn 一次，绝不在未认证字节上授权。每进程只解析一次密钥（单密钥语义，
//!   不接受双密钥）；轮换 = 更换环境变量并轮换共享时代（Exec-L3 运维动作），
//!   旧密钥条目在新密钥下 MAC 失配 → purge → 严格读 → 新密钥重填（即使忘记
//!   换时代也自愈，只是旧键多驻留一个 TTL）。
//! - **命中前提**（[`try_l2_evidence_hit`]）：HMAC 密钥可用 + schema 匹配 +
//!   L2 版本组与**读前对牌**的 DB 指针组逐项一致（并发两次发布的推送竞态由
//!   该对牌兜底：版本不符即弃）+ envelope 顶层 scope 一致 + 共享单元逐个
//!   GET 且自校验（缺失/摘要失配 → purge 卡键回源，绝不放行部分数据）+
//!   join 重建完整 payload + content_hash 重验 + MAC 重验（常数时间比较）+
//!   payload 合同校验 + **作用域绑定（记录级）**：payload 顶层、每个 manifest
//!   摘要、**每条 record 的 grant（tenant/card）与每条 effective_grant** 的
//!   身份戳必须与请求 scope 逐项一致——对齐严格 reader 的 scope 代数，封死
//!   "同卡/顶层合法 + 他卡/他租户 grant"的伪造与栅栏碰撞下的跨卡/跨租户投毒；
//!   之后是 payload 与版本组的绑定一致、时钟重验（与 L1 同一函数，危险方向
//!   封死），以及**读后复读对牌**（与 L1 命中协议同强度：发布落在两次栅栏
//!   读之间时不放行旧条目）。
//! - **正确性边界**：L2 条目与 L1 条目同源——都由严格 reader（锁定 + 整链
//!   校验）产出；L2 只是"换一个存储位置的同源条目"，命中判定复用 L1 的全部
//!   栅栏语义。对牌失败/污染/部分写/单元缺失/Redis 错误一律回源严格 reader，
//!   绝不把 L2 字节当授权事实，也绝不在读取侧修补/改写条目身份。
//! - **去重边界与存储-only 红线（诚实声明）**：跨卡共享**仅限存储字节**——
//!   只有 RULE_SET 记录中与卡无关的规则内容（resource/action/effect/validity/
//!   编译器哈希）被因子化为内容寻址单元；tenant/card/user/grant 身份、绑定
//!   与 provenance 全部留在逐卡 envelope，重建 join 不合成任何身份。共享单元
//!   **只是存储**，永远不是授权来源：授权语义完全由"逐卡 envelope + 指针对
//!   牌 + 合同校验 + MAC/content_hash + 记录级 scope 绑定"承载，与共享单元
//!   的存在与否无关（单元缺失 = miss 回源，绝不降级放行）。
//! - **TTL 取舍**：L2 TTL 300s（[`L2_EVIDENCE_TTL_SECONDS`]）比 L1 的 30s
//!   长：L2 条目不是直接放行依据，被拉入 L1 后受 L1 的 30s TTL + 每次命中
//!   的时钟重验约束；L2 直接命中的路径在本层同样执行时钟重验与双读对牌，
//!   因此内容时效与 L1 同强度，300s 只是"冷实例少一次 DB 读"的驻留上限，
//!   撤销正确性仍由指针对牌承担（撤销延迟 ≈ 0，见"失效语义"）。共享单元与
//!   卡条目同 TTL；卡条目 purge 不删共享单元（内容寻址、可能被他卡引用，
//!   靠 TTL/换时代自然回收）。
//! - **写序与部分写安全**：先写全部共享单元、再写卡条目；任一单元写失败 →
//!   卡条目不写（纯 miss/refill 语义）。读侧对缺失/失配单元一律 purge 回源
//!   ——**绝无"部分条目被接受"的路径**。
//! - **降级**：Redis 不可用/错误 → 静默跳过 L2（日志 warn），L1+DB 照常；
//!   当前时代未知（Redis 降级）→ 不查也不填 L2（与 L1 填充门槛一致）；HMAC
//!   密钥不可用 → L2 读/写整体旁路（fail-closed，见上）。
//! - **推送**（[`push_published_card_evidence_to_l2`]）：发布事务提交后，
//!   对本次发布涉及的卡（CARD 聚合且携带卡作用域；ELIGIBILITY/RULE_SET 等
//!   其它聚合不推——L2 只承载 CARD 聚合的评估 evidence）以严格 reader 自读
//!   一次并推入 L2（方案 a：与 miss 回源同源同实现，天然 parity，无需另建
//!   candidate→evidence 构造函数）。推送失败静默：L2 miss 的自然回源保证
//!   正确性，推送只是跨实例共享优化，不构成 durable 义务。
//! - **范围边界（本切片外）**：Java 侧缓存家族（`perm:card:status` 等）、
//!   permission_query v4 envelope 与其它无关键族不在本变更内；本模块只触碰
//!   `astral:auth:l2ev:*` 与 `astral:auth:l2sh:*` 两个 Rust 专属键族。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, GrantEffect, GrantId, GrantProvenance,
    GrantRevision, GrantSourceKind, GrantState, PolicyContext, PolicyError,
    PublishedAggregateManifestSummary, PublishedCardAuthorization, PublishedCardAuthorizationGate,
    PublishedCardEvidenceScope, TenantScope, UnacceptedGrantReason, ValidityWindow,
    VerifiedPublishedGrantRecord,
};
use moka::future::Cache;
use policy_engine::{
    PermissionRule, ProjectionGate, RuleRepository, RuleSetDependencyStatus, RuleSetSnapshot,
    SnapshotWinner,
};
use redis::AsyncCommands;
use sqlx::MySqlPool;
use time::OffsetDateTime;

use crate::authorization_projection_repository::{
    load_published_card_grant_evidence, AuthorizationEvidenceError,
};
use crate::cache_epoch::cache_epoch_is_current;
use crate::permission_query::{
    evidence_fence_baseline, evidence_manifest_versions, load_card_scope_fence_snapshot,
    CardScopeFenceSnapshot, PermissionCacheManifestVersion,
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
/// - `current_epoch`：当前共享缓存时代（`None` = 未知 → 缓存整体旁路）；
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
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError>;
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
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
        load_published_card_grant_evidence(&self.pool, scope).await
    }

    async fn current_epoch(&self) -> Option<String> {
        crate::cache_epoch::current_cache_epoch().await
    }

    fn now_unix_seconds(&self) -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 Redis evidence 分发层（读链规模化 Batch D）
// ─────────────────────────────────────────────────────────────────────────────

/// L2 条目 schema 版本：条目形状/serde 兼容性栅栏；不匹配即弃（purge 回源）。
///
/// - v1（已退役）：完整 `PublishedCardAuthorization` 直存（含 `effective_grants`
///   冗余副本）；
/// - v2（已退役）：存储形态折叠 `effective_grants`（读侧由合同定理唯一重建）
///   + 卡作用域绑定校验；
/// - v3（已退役）：因子化存储形态 + HMAC-SHA256 条目认证 + 记录级作用域绑定；
/// - v4（现行）：在 v3 基础上新增**卡作用域未发布 delta 位**
///   `card_source_pending`（source 提交未发布的越权窗口内条目整体失配 →
///   purge 回源撞 source-freshness 门）。旧 v1/v2/v3 条目按 schema 失配自然
///   purge 自愈，无需人工清理。
pub const L2_EVIDENCE_SCHEMA_VERSION: i64 = 4;

/// L2 条目 TTL（300s）：L1 的 30s 封顶内存驻留之上，"冷实例少一次 DB 读"的
/// 共享驻留上限；内容时效由 L1 的时钟重验 + 本层 L2 命中时的时钟重验与双读
/// 对牌约束（取舍见模块文档 L2 节）。`pub` 仅为真实 Redis 集成测试的断言
/// 可见性（`tests/evidence_cache_redis_integration.rs`），不构成新调用面。
pub const L2_EVIDENCE_TTL_SECONDS: u64 = 300;

/// L2 evidence 键前缀（Rust 专属命名空间，不与 Java 契约键重叠）：完整键为
/// `{前缀}{cache_epoch}:{tenant_id}:{card_id}`，时代内嵌键——换时代后旧键
/// 自然失配。
pub(crate) const L2_EVIDENCE_KEY_PREFIX: &str = "astral:auth:l2ev:";

/// L2 推送唯一承载的聚合类型：CARD 聚合发布推进卡作用域评估 evidence。
/// ELIGIBILITY/RULE_SET 等其它聚合不推（L2 只承载 CARD 聚合的评估 evidence；
/// RULE_SET 的依赖状态门禁已退役）。
pub(crate) const L2_EVIDENCE_CARD_AGGREGATE_TYPE: &str = "CARD";

/// L2 卡证据条目的 HMAC 密钥环境变量（专用；绝不复用网关/内部签名密钥，
/// 绝不硬编码）。仅接受非占位符且 ≥32 字节/字符的值；未设置/无效 → L2 读/写
/// 整体旁路（fail-closed，严格 reader 兜底）。`pub` 仅为真实 Redis 集成测试
/// 设置同名环境变量可见。
pub const L2_EVIDENCE_HMAC_SECRET_ENV: &str = "ASTRAL_L2_EVIDENCE_HMAC_SECRET";

/// HMAC 密钥最小长度（字节与字符数同时要求；`"at least 32 bytes/chars"`）。
pub(crate) const L2_HMAC_SECRET_MIN_LENGTH: usize = 32;

/// MAC 域分隔符：把密钥用途钉死在"L2 evidence 条目认证"，杜绝同一密钥被
/// （有意或无意）复用到其它协议时的跨协议重放。域分隔进入 MAC cover 的
/// 规范序列化首字段。
pub(crate) const L2_MAC_DOMAIN: &str = "astral:l2-evidence:v4:hmac-sha256";

/// 共享内容单元键前缀（Rust 专属命名空间）：完整键为
/// `{前缀}{cache_epoch}:{tenant_id}:{digest}` —— tenant+时代限定、内容寻址。
pub(crate) const L2_EVIDENCE_SHARED_KEY_PREFIX: &str = "astral:auth:l2sh:";

/// 参与跨卡存储去重（共享内容单元）的聚合类型：只有 RULE_SET 聚合的记录被
/// 因子化；其它聚合（USER_CARD/CARD/APPROVAL/DELEGATION）完整内联。
pub(crate) const L2_SHARED_UNIT_AGGREGATE_TYPE: &str = "RULE_SET";

/// 共享内容单元自身 schema 版本（独立于卡条目 schema；自校验字段之一）。
pub(crate) const L2_SHARED_UNIT_SCHEMA_VERSION: i64 = 1;

/// 已知的占位符/示例密钥标记（大小写不敏感子串匹配）：环境变量携带这些
/// 标记视为占位符配置 → fail-closed 旁路，绝不以占位符密钥认证授权证据。
const L2_HMAC_PLACEHOLDER_MARKERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "placeholder",
    "dummy",
    "example",
    "sample-secret",
    "fixme",
    "todo",
    "tobefilled",
    "tbd",
    "xxxx",
];

/// L2 HMAC 密钥的进程级解析缓存（单次解析、单密钥语义：不接受双密钥；
/// 轮换 = 更换环境变量并轮换共享时代 + 重启进程）。
static L2_HMAC_SECRET: OnceLock<Option<Vec<u8>>> = OnceLock::new();

/// fail-closed warn 的一次性闸门（密钥缺失/无效时进程内只告警一次）。
static L2_HMAC_SECRET_WARNED: AtomicBool = AtomicBool::new(false);

/// F5 修复 1c：commit 后 L2 推送的整体硬预算。推送是 best-effort 优化路径，
/// 任何挂起（Redis 黑洞、strict read 卡死等）必须在预算内变成"放弃"——
/// L2 miss 的自然回源保证正确性，超时只损失一次预热。
pub const L2_PUSH_BUDGET: Duration = Duration::from_secs(1);

/// 推送超时丢弃计数（观测面：stats 端点聚合暴露；无租户/卡语义）。
static L2_PUSH_DROPPED: AtomicU64 = AtomicU64::new(0);

/// 已丢弃（超时放弃）的 L2 推送总数，只增计数器。
pub fn l2_push_dropped_count() -> u64 {
    L2_PUSH_DROPPED.load(AtomicOrdering::Relaxed)
}

/// 预算化执行体：`push` 在 `budget` 内完成 → true；超时 → 计数并返回 false。
/// 独立成函数使预算机制可无 I/O 单测。
pub(crate) async fn push_with_l2_budget<F: std::future::Future<Output = ()>>(
    budget: Duration,
    push: F,
) -> bool {
    match tokio::time::timeout(budget, push).await {
        Ok(()) => true,
        Err(_) => {
            L2_PUSH_DROPPED.fetch_add(1, AtomicOrdering::Relaxed);
            false
        }
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

/// L2 HMAC 密钥校验（纯函数）：`None`（未设置）或占位符/过短的值一律拒绝；
/// 通过的值按字节返回。拒绝即 fail-closed（L2 整体旁路），绝不以弱密钥认证
/// 授权证据。
fn validate_l2_hmac_secret(raw: Option<&str>) -> Option<Vec<u8>> {
    let raw = raw?;
    let trimmed = raw.trim();
    if trimmed.len() < L2_HMAC_SECRET_MIN_LENGTH
        || trimmed.chars().count() < L2_HMAC_SECRET_MIN_LENGTH
    {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if L2_HMAC_PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return None;
    }
    // 退化密钥（全部字符相同）视为占位符拒绝。
    let first = trimmed.as_bytes()[0];
    if trimmed.as_bytes().iter().all(|byte| *byte == first) {
        return None;
    }
    Some(trimmed.as_bytes().to_vec())
}

/// 解析进程级 L2 HMAC 密钥（首次调用读环境变量并缓存；缺失/无效 → `None`
/// 并 warn 一次 —— 调用方对 L2 读/写整体旁路，fail-closed）。
fn l2_hmac_secret() -> Option<&'static [u8]> {
    L2_HMAC_SECRET
        .get_or_init(|| {
            let resolved =
                validate_l2_hmac_secret(std::env::var(L2_EVIDENCE_HMAC_SECRET_ENV).ok().as_deref());
            if resolved.is_none() && !L2_HMAC_SECRET_WARNED.swap(true, AtomicOrdering::Relaxed) {
                tracing::warn!(
                    "code=l2_evidence.hmac_secret_unavailable;env={L2_EVIDENCE_HMAC_SECRET_ENV};\
                     L2 evidence layer disabled (fail-closed): reads bypass to the strict reader \
                     and writes are skipped; set a dedicated secret of at least 32 chars"
                );
            }
            resolved
        })
        .as_deref()
}

/// L2 Redis 存取 SPI（读取/写入/删除三个最小原语）：生产实现走
/// `crate::eligibility::redis_conn`，测试注入内存实现——Redis 协议细节被
/// 隔离在本 trait 之后，命中协议/对牌/污染清除逻辑全部可离线测试。
///
/// 错误语义：`Err` = Redis 不可用/命令失败（调用方静默降级，绝不阻塞主
/// 路径）；`Ok(None)` = 键不存在（自然 miss）。错误统一以 `String` 承载
/// （仅用于日志，不参与分支语义），避免把 redis 类型泄漏进 SPI。
#[async_trait::async_trait]
pub trait L2EvidenceStore: Send + Sync {
    /// 读取原始条目 JSON。
    async fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// 写入原始条目 JSON（带 TTL）。
    async fn set_ex(&self, key: &str, value: String, ttl_seconds: u64) -> Result<(), String>;
    /// 删除条目（污染清除；best-effort）。
    async fn del(&self, key: &str) -> Result<(), String>;
}

/// 生产 L2 存取：经 `crate::eligibility::redis_conn` 的进程级连接池获取
/// `ConnectionManager`（池化复用 + runtime 边界语义见该函数文档；连接管理器
/// 自带自动重连）。Redis 不可用 → `Err` → 调用方降级为 L1+DB。
pub struct RedisL2EvidenceStore;

#[async_trait::async_trait]
impl L2EvidenceStore for RedisL2EvidenceStore {
    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let mut conn = crate::eligibility::redis_conn()
            .await
            .ok_or_else(|| "code=l2_evidence.redis_unavailable".to_owned())?;
        conn.get::<_, Option<String>>(key)
            .await
            .map_err(|error: redis::RedisError| error.to_string())
    }

    async fn set_ex(&self, key: &str, value: String, ttl_seconds: u64) -> Result<(), String> {
        let mut conn = crate::eligibility::redis_conn()
            .await
            .ok_or_else(|| "code=l2_evidence.redis_unavailable".to_owned())?;
        conn.set_ex::<_, _, ()>(key, value, ttl_seconds)
            .await
            .map_err(|error: redis::RedisError| error.to_string())
    }

    async fn del(&self, key: &str) -> Result<(), String> {
        let mut conn = crate::eligibility::redis_conn()
            .await
            .ok_or_else(|| "code=l2_evidence.redis_unavailable".to_owned())?;
        redis::cmd("DEL")
            .arg(key)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|error| error.to_string())
    }
}

/// 进程级全局 L2 存取句柄（生产装配默认值；测试可整体旁路或注入内存实现）。
static SHARED_L2_EVIDENCE_STORE: OnceLock<Arc<dyn L2EvidenceStore>> = OnceLock::new();

/// 生产 L2 存取句柄（`RedisL2EvidenceStore`）。
pub fn shared_l2_evidence_store() -> &'static Arc<dyn L2EvidenceStore> {
    SHARED_L2_EVIDENCE_STORE.get_or_init(|| Arc::new(RedisL2EvidenceStore))
}

/// L2 evidence 完整键（epoch 内嵌：换时代后旧键自然失配）。`pub` 仅为真实
/// Redis 集成测试的键计算/清理可见性（`tests/evidence_cache_redis_integration.rs`）。
pub fn l2_evidence_key(cache_epoch: &str, tenant_id: i64, card_id: i64) -> String {
    format!("{L2_EVIDENCE_KEY_PREFIX}{cache_epoch}:{tenant_id}:{card_id}")
}

/// L2 条目（JSON 载荷，schema 3 因子化存储形态）：`manifest_versions` 与 L1
/// 基准组同结构同源（[`PermissionCacheManifestVersion`]）且**逐卡私有**；
/// `content_hash` 绑定**重建后完整 payload** 的序列化字节（写侧对完整证据
/// 计算、读侧对重建结果重验，独立于 MAC 的全载荷完整性校验）；`mac` 为强制
/// HMAC-SHA256 条目认证（见 [`L2MacCover`]）；`payload` 是因子化存储形态
/// （[`L2FactoredCardPayload`]，读侧 [`l2_reconstruct_full_payload`] 唯一重建）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2EvidenceEntry {
    schema_version: i64,
    manifest_versions: Vec<PermissionCacheManifestVersion>,
    /// 卡作用域存在未发布授权 delta（v4 新增必填；写侧恒为 false——证据只能
    /// 来自通过 source-freshness 门禁的严格 reader）。
    card_source_pending: bool,
    content_hash: String,
    mac: String,
    payload: L2FactoredCardPayload,
}

/// 条目 schema 探针（解码前先行读取 schema 版本：旧 v1/v2 条目按精确原因
/// purge 自愈，而不是混入"undecodable"）。
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2EntrySchemaProbe {
    schema_version: i64,
}

/// 因子化卡存储形态（v3）：顶层/manifest/gate 逐卡保留；记录按原始顺序存于
/// [`L2RecordSlot`]（内联完整记录或 RULE_SET envelope + 单元引用）。
/// `effective_grants` 不存储——由合同定理（accepted 子集、同序同内容）在
/// 重建时展开，身份字段绝不读侧合成。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2FactoredCardPayload {
    tenant_id: i64,
    card_id: i64,
    read_unix_seconds: i64,
    gate: PublishedCardAuthorizationGate,
    manifests: Vec<PublishedAggregateManifestSummary>,
    records: Vec<L2RecordSlot>,
}

/// 单条记录的存储槽位：保持原始 `records` 顺序（字节级重建的前提）。
/// `Inline` = 非 RULE_SET 记录完整内联；`Shared` = RULE_SET 记录的逐卡
/// envelope + 共享单元摘要引用（内容在 [`L2SharedUnit`]）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum L2RecordSlot {
    Inline(VerifiedPublishedGrantRecord),
    Shared(L2SharedRecordEnvelope),
}

/// RULE_SET 记录的逐卡 envelope：身份/绑定/provenance 全部留卡（tenant/
/// card/user/grant 身份绝不进入共享单元），内容字段由共享单元按摘要引用。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2SharedRecordEnvelope {
    aggregate_id: i64,
    publication_generation: u64,
    revoke_fence: u64,
    manifest_id: i64,
    event_id: String,
    operation_id: String,
    segment_ordinal: u64,
    position_in_segment: u64,
    grant: L2GrantEnvelope,
    shared_unit_digest: String,
    accepted_into_effective_set: bool,
    unaccepted_reason: Option<UnacceptedGrantReason>,
}

/// grant 的逐卡身份/绑定/provenance envelope（内容字段 resource/action/
/// effect/validity 由共享单元提供）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2GrantEnvelope {
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

/// 共享内容单元（tenant+时代限定键下的自校验 JSON）：`digest` 是
/// `content` 规范序列化字节的 sha256（读侧重算比对 + 与键内摘要比对）。
/// `content` **绝不含 tenant/card/user/grant 身份**——只有与卡无关的规则
/// 内容与编译器元数据；共享字节是存储，不是授权来源。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2SharedUnit {
    unit_schema_version: i64,
    digest: String,
    content: L2SharedUnitContent,
}

/// 共享 RULE_SET 内容（card-less）：规则语义内容 + 编译器元数据。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2SharedUnitContent {
    resource: String,
    action: String,
    effect: GrantEffect,
    validity: ValidityWindow,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
    compiler_version: String,
}

/// MAC cover（规范序列化后经 HMAC-SHA256）：域分隔符 + 精确 Redis 键（防
/// 键间重放）+ schema 版本 + 版本组 + pending 位 + content_hash + **重建后
/// 完整 payload**。任一字段被篡改 → MAC 失配 → purge 回源。
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct L2MacCover<'a> {
    domain: &'static str,
    redis_key: &'a str,
    schema_version: i64,
    manifest_versions: &'a [PermissionCacheManifestVersion],
    card_source_pending: bool,
    content_hash: &'a str,
    payload: &'a PublishedCardAuthorization,
}

type L2HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// 计算 L2 条目 MAC（小写十六进制；写侧存入）。
fn l2_entry_mac_hex(secret: &[u8], cover: &L2MacCover<'_>) -> String {
    use hmac::Mac;
    let mut mac = L2HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(&serde_json::to_vec(cover).expect("MAC cover serialization cannot fail"));
    hex::encode(mac.finalize().into_bytes())
}

/// 常数时间校验 L2 条目 MAC（读侧；`hmac::Mac::verify_slice` 防时序侧信道）。
fn l2_entry_mac_valid(secret: &[u8], cover: &L2MacCover<'_>, provided_hex: &str) -> bool {
    use hmac::Mac;
    let Ok(provided) = hex::decode(provided_hex) else {
        return false;
    };
    let mut mac = L2HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(&serde_json::to_vec(cover).expect("MAC cover serialization cannot fail"));
    mac.verify_slice(&provided).is_ok()
}

/// 共享内容单元完整键（tenant+时代内嵌：换时代/跨租户后旧键自然失配）。
/// `pub` 仅为真实 Redis 集成测试的键计算/清理可见性。
pub fn l2_shared_unit_key(cache_epoch: &str, tenant_id: i64, digest: &str) -> String {
    format!("{L2_EVIDENCE_SHARED_KEY_PREFIX}{cache_epoch}:{tenant_id}:{digest}")
}

/// payload 序列化 JSON 的 sha256（小写十六进制；写侧存入、读侧重验）。
fn l2_content_hash(payload_json: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(payload_json.as_bytes()))
}

/// 共享单元内容的摘要（内容寻址的规范基础：两侧同一 struct 同一 serde 派生，
/// 字段序确定，字节级可比）。
fn l2_shared_unit_digest(content: &L2SharedUnitContent) -> String {
    let json =
        serde_json::to_string(content).expect("shared unit content serialization cannot fail");
    l2_content_hash(&json)
}

/// 从 RULE_SET 记录提取 card-less 内容单元（纯函数）。
fn l2_shared_unit_content(record: &VerifiedPublishedGrantRecord) -> L2SharedUnitContent {
    L2SharedUnitContent {
        resource: record.grant.resource.clone(),
        action: record.grant.action.clone(),
        effect: record.grant.effect,
        validity: record.grant.validity,
        semantic_hash_hex: record.semantic_hash_hex.clone(),
        dependency_hash_hex: record.dependency_hash_hex.clone(),
        compiler_version: record.compiler_version.clone(),
    }
}

/// 因子化存储形态（纯函数，写侧）：RULE_SET 记录拆 envelope + 内容寻址单元，
/// 其余记录完整内联；记录顺序经 [`L2RecordSlot`] 逐位保留。返回条目 payload
/// 与去重后的单元集合（键 = 内容摘要）。
fn l2_factored_storage_form(
    evidence: &PublishedCardAuthorization,
) -> (L2FactoredCardPayload, BTreeMap<String, L2SharedUnitContent>) {
    let mut records = Vec::with_capacity(evidence.records.len());
    let mut units: BTreeMap<String, L2SharedUnitContent> = BTreeMap::new();
    for record in &evidence.records {
        if record.aggregate_type == L2_SHARED_UNIT_AGGREGATE_TYPE {
            let content = l2_shared_unit_content(record);
            let digest = l2_shared_unit_digest(&content);
            units.entry(digest.clone()).or_insert(content);
            records.push(L2RecordSlot::Shared(L2SharedRecordEnvelope {
                aggregate_id: record.aggregate_id,
                publication_generation: record.publication_generation,
                revoke_fence: record.revoke_fence,
                manifest_id: record.manifest_id,
                event_id: record.event_id.clone(),
                operation_id: record.operation_id.clone(),
                segment_ordinal: record.segment_ordinal,
                position_in_segment: record.position_in_segment,
                grant: L2GrantEnvelope {
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
            records.push(L2RecordSlot::Inline(record.clone()));
        }
    }
    let factored = L2FactoredCardPayload {
        tenant_id: evidence.tenant_id,
        card_id: evidence.card_id,
        read_unix_seconds: evidence.read_unix_seconds,
        gate: evidence.gate.clone(),
        manifests: evidence.manifests.clone(),
        records,
    };
    (factored, units)
}

/// 条目引用的全部共享单元摘要（读侧按需 GET 的去重集合）。
fn l2_referenced_unit_digests(stored: &L2FactoredCardPayload) -> BTreeSet<String> {
    stored
        .records
        .iter()
        .filter_map(|slot| match slot {
            L2RecordSlot::Shared(envelope) => Some(envelope.shared_unit_digest.clone()),
            L2RecordSlot::Inline(_) => None,
        })
        .collect()
}

/// 由 envelope + 已验证共享单元 join 重建单条 RULE_SET 记录（纯函数）：
/// 身份/绑定/provenance 全部来自 envelope，内容字段全部来自单元——读侧绝不
/// 改写、补盖或重定戳任何身份字段。
fn l2_reconstruct_shared_record(
    envelope: &L2SharedRecordEnvelope,
    content: &L2SharedUnitContent,
) -> VerifiedPublishedGrantRecord {
    VerifiedPublishedGrantRecord {
        aggregate_type: L2_SHARED_UNIT_AGGREGATE_TYPE.to_owned(),
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
    }
}

/// 由因子化存储形态重建完整 payload（纯函数，读侧专用）。
///
/// 身份安全边界：内联记录原样保留；RULE_SET 记录由 envelope + 摘要已验证的
/// 单元 join；`effective_grants` 从 records 的 accepted 子集展开（合同定理
/// 保证唯一）。任何被引用单元缺失 → `None`（调用方 purge 回源，绝不放行
/// 部分数据）。
fn l2_reconstruct_full_payload(
    stored: &L2FactoredCardPayload,
    units: &HashMap<String, L2SharedUnitContent>,
) -> Option<PublishedCardAuthorization> {
    let mut records = Vec::with_capacity(stored.records.len());
    for slot in &stored.records {
        match slot {
            L2RecordSlot::Inline(record) => records.push(record.clone()),
            L2RecordSlot::Shared(envelope) => {
                let content = units.get(&envelope.shared_unit_digest)?;
                records.push(l2_reconstruct_shared_record(envelope, content));
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

/// 作用域绑定（纯函数）：payload 顶层、每个 manifest 摘要、**每条 record 的
/// grant 与每条 effective_grant** 的 tenant/card 戳必须与请求 scope 逐项一致。
/// 对齐严格 reader 的 scope 代数（`pointer_tenant_scope_split`/
/// `pointer_card_scope_split`）——栅栏版本组不含 tenant/card 字段，fence 碰撞
/// 下"同卡/顶层合法 + 他卡/他租户 grant"的内容级身份防线在此（记录级校验
/// 覆盖内联记录与 join 重建后的共享记录）。
fn l2_scope_binding_matches(
    payload: &PublishedCardAuthorization,
    tenant_id: i64,
    card_id: i64,
) -> bool {
    if payload.tenant_id != tenant_id || payload.card_id != card_id {
        return false;
    }
    if !payload
        .manifests
        .iter()
        .all(|manifest| manifest.tenant_id == tenant_id && manifest.card_id == card_id)
    {
        return false;
    }
    if !payload
        .records
        .iter()
        .all(|record| record.grant.card_id == card_id && record.grant.tenant.tenant_id == tenant_id)
    {
        return false;
    }
    payload
        .effective_grants
        .iter()
        .all(|grant| grant.card_id == card_id && grant.tenant.tenant_id == tenant_id)
}

/// L2 查询结果（miss 分支内部词汇）。
enum L2Lookup {
    /// 命中：payload 已通过 schema/对牌/哈希/合同/时钟全部校验。
    Hit(Box<PublishedCardAuthorization>),
    /// 键存在但未通过任一校验 → 删除该键后回源（污染/失配清除）。
    Purge(&'static str),
    /// 无条目或 Redis 错误（错误已在函数内记日志）→ 静默旁路，直接回源。
    Bypass,
}

/// L2 命中判定协议（miss 分支专用；调用前已取得"读前对牌"的 DB 指针组，且
/// 调用方已确认 HMAC 密钥可用）。
///
/// 顺序：GET（错误/缺失 → Bypass）→ schema 探针（v1/v2 失配 → Purge）→ 解码
/// （失败 = 部分写/截断/异形 payload → Purge）→ 对牌（L2 版本组与读前对牌的
/// DB 指针组逐项相等；并发两次发布的推送竞态由此兜底）→ envelope 顶层 scope
/// 预检 → 共享单元逐个 GET + 自校验（缺失/失配 → Purge；Redis 错误 → Bypass）
/// → join 重建完整 payload（单元缺失 → Purge，绝不放行部分数据）→
/// content_hash 重验（对重建结果重序列化比对）→ MAC 重验（常数时间；绑定
/// 域分隔、精确键、schema、版本组、content_hash 与 payload，任一被篡改即
/// 失配）→ payload 合同校验 → **记录级作用域绑定**（顶层 + manifest 戳 +
/// 每条 record.grant 与 effective_grant 与 scope 一致，跨卡/跨租户投毒在此
/// 封死，绝不改写身份后放行）→ payload 与版本组绑定一致 → 时钟重验（与 L1
/// 同一函数）。任一失败 → Purge 删卡键回源，绝不放行。
async fn try_l2_evidence_hit(
    l2: &dyn L2EvidenceStore,
    mac_secret: &[u8],
    cache_epoch: &str,
    pre_fence: &CardScopeFenceSnapshot,
    tenant_id: i64,
    card_id: i64,
    now_unix_seconds: i64,
) -> L2Lookup {
    let key = l2_evidence_key(cache_epoch, tenant_id, card_id);
    let raw = match l2.get(&key).await {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(key = %key, %error, "l2 evidence read failed; degrading to L1+DB");
            return L2Lookup::Bypass;
        }
    };
    let Some(raw) = raw else {
        return L2Lookup::Bypass;
    };
    // schema 探针先行：旧 v1/v2 条目按精确原因 purge 自愈。
    let probe: L2EntrySchemaProbe = match serde_json::from_str(&raw) {
        Ok(probe) => probe,
        Err(error) => {
            tracing::warn!(key = %key, %error, "l2 evidence entry undecodable; purging");
            return L2Lookup::Purge("undecodable");
        }
    };
    if probe.schema_version != L2_EVIDENCE_SCHEMA_VERSION {
        return L2Lookup::Purge("schema_version");
    }
    let entry: L2EvidenceEntry = match serde_json::from_str(&raw) {
        Ok(entry) => entry,
        Err(error) => {
            tracing::warn!(key = %key, %error, "l2 evidence entry undecodable; purging");
            return L2Lookup::Purge("undecodable");
        }
    };
    if entry.manifest_versions != pre_fence.manifest_versions
        || entry.card_source_pending != pre_fence.card_source_pending
    {
        return L2Lookup::Purge("fence_mismatch");
    }
    // envelope 顶层 scope 预检：与键身份不符的条目在单元读取前即弃（避免为
    // 跨卡/跨租户投毒条目浪费 Redis 往返；完整记录级校验在重建后执行）。
    if entry.payload.tenant_id != tenant_id || entry.payload.card_id != card_id {
        return L2Lookup::Purge("scope_binding");
    }
    // 共享单元逐个 GET + 自校验：缺失/失配 → purge 卡键回源；Redis 错误 →
    // 静默旁路（降级不 purge，避免可用性抖动放大为缓存清洗）。
    let digests = l2_referenced_unit_digests(&entry.payload);
    let units = match fetch_verified_shared_units(l2, cache_epoch, tenant_id, &digests).await {
        L2UnitFetch::Verified(units) => units,
        L2UnitFetch::Redis(error) => {
            tracing::warn!(key = %key, %error, "l2 shared unit read failed; degrading to L1+DB");
            return L2Lookup::Bypass;
        }
        L2UnitFetch::Missing(digest) => {
            tracing::warn!(key = %key, %digest, "l2 shared unit missing; purging card entry");
            return L2Lookup::Purge("shared_unit_missing");
        }
        L2UnitFetch::Invalid(digest) => {
            tracing::warn!(key = %key, %digest, "l2 shared unit failed self-hash; purging card entry");
            return L2Lookup::Purge("shared_unit_invalid");
        }
    };
    // 由 envelope + 已验证单元 join 重建完整 payload：身份字段全部来自逐卡
    // envelope，读侧绝不重写；单元缺失 = 不可能到达此处（上方已拦）。
    let payload = match l2_reconstruct_full_payload(&entry.payload, &units) {
        Some(payload) => payload,
        None => return L2Lookup::Purge("shared_unit_missing"),
    };
    // content_hash 重验：对重建后的完整 payload 重序列化并重算哈希。写侧
    // 哈希的对象是同一份完整证据的序列化字节（两侧同一 struct 同一 serde
    // 派生，字段序确定，字节级可比）；不等即污染/部分写/重建偏差。
    let Ok(payload_json) = serde_json::to_string(&payload) else {
        return L2Lookup::Purge("payload_reserialize");
    };
    if l2_content_hash(&payload_json) != entry.content_hash {
        return L2Lookup::Purge("content_hash");
    }
    // MAC 重验（常数时间）：域分隔 + 精确 Redis 键 + schema + 版本组 +
    // content_hash + 重建后 payload 任一被篡改即失配 → purge 回源。
    let cover = L2MacCover {
        domain: L2_MAC_DOMAIN,
        redis_key: &key,
        schema_version: entry.schema_version,
        manifest_versions: &entry.manifest_versions,
        card_source_pending: entry.card_source_pending,
        content_hash: &entry.content_hash,
        payload: &payload,
    };
    if !l2_entry_mac_valid(mac_secret, &cover, &entry.mac) {
        return L2Lookup::Purge("mac");
    }
    if let Err(contract_error) = payload.validate() {
        tracing::warn!(key = %key, %contract_error, "l2 evidence payload failed contract; purging");
        return L2Lookup::Purge("contract");
    }
    // 记录级作用域绑定：顶层 + manifest 戳 + 每条 record.grant 与
    // effective_grant 的 tenant/card 戳必须与请求 scope 逐项一致。不一致 =
    // 同卡/顶层伪造 + 他卡/他租户 grant，或跨卡/跨租户投毒 → 删键回源，
    // 绝不改写身份后放行。
    if !l2_scope_binding_matches(&payload, tenant_id, card_id) {
        return L2Lookup::Purge("scope_binding");
    }
    // 载荷与版本组的绑定一致性：payload 自身推导的版本组必须与随条目携带
    // （且已通过对牌）的版本组一致，防止条目内部"版本组与内容"被拼接。
    // （pending 位是作用域级标志，不派生自 payload，绑定校验只针对版本组。）
    if evidence_manifest_versions(&payload) != pre_fence.manifest_versions {
        return L2Lookup::Purge("payload_fence_binding");
    }
    if !cached_evidence_is_clock_fresh(&payload, now_unix_seconds) {
        return L2Lookup::Purge("clock_stale");
    }
    L2Lookup::Hit(Box::new(payload))
}

/// 共享单元读取结果（读侧内部词汇）：Redis 错误与数据级失配严格区分——
/// 前者 Bypass（降级不清洗），后者 Purge（污染清除）。
enum L2UnitFetch {
    Verified(HashMap<String, L2SharedUnitContent>),
    Missing(String),
    Invalid(String),
    Redis(String),
}

/// 逐个 GET 并自校验共享单元：unit_schema 匹配 + 单元内摘要 == 引用摘要 +
/// 内容重算摘要 == 引用摘要（三重一致才可信；键内摘要由键构造隐式比对）。
async fn fetch_verified_shared_units(
    l2: &dyn L2EvidenceStore,
    cache_epoch: &str,
    tenant_id: i64,
    digests: &BTreeSet<String>,
) -> L2UnitFetch {
    let mut units: HashMap<String, L2SharedUnitContent> = HashMap::with_capacity(digests.len());
    for digest in digests {
        let key = l2_shared_unit_key(cache_epoch, tenant_id, digest);
        let raw = match l2.get(&key).await {
            Ok(raw) => raw,
            Err(error) => return L2UnitFetch::Redis(error),
        };
        let Some(raw) = raw else {
            return L2UnitFetch::Missing(digest.clone());
        };
        let unit: L2SharedUnit = match serde_json::from_str(&raw) {
            Ok(unit) => unit,
            Err(_) => return L2UnitFetch::Invalid(digest.clone()),
        };
        if unit.unit_schema_version != L2_SHARED_UNIT_SCHEMA_VERSION
            || unit.digest != *digest
            || l2_shared_unit_digest(&unit.content) != *digest
        {
            return L2UnitFetch::Invalid(digest.clone());
        }
        units.insert(digest.clone(), unit.content);
    }
    L2UnitFetch::Verified(units)
}

/// 写入/刷新一条 L2 条目（schema 3 因子化存储形态 + content_hash + 强制
/// MAC；失败静默 warn —— L2 miss 的自然回源保证正确性，写侧不构成 durable
/// 义务）。`mac_secret` 为 `None`（HMAC 密钥不可用）→ 整体跳过（fail-closed：
/// 绝不写入未认证条目）。
///
/// 写序（部分写安全）：先写全部共享单元，任一失败即返回（卡条目不写）；
/// 全部单元落定后才写卡条目。任何部分写在读侧表现为"单元缺失/卡键缺失"，
/// 一律 miss/refill，绝无被接受的部分条目。
///
/// `content_hash` 绑定**完整证据**（因子化前）的序列化字节；MAC 绑定域分隔、
/// 精确键、schema、版本组、content_hash 与完整 payload。写侧先自证
/// "因子化 → 重建"逐字节无损（不等即写侧 bug → 拒写），调用方必须已通过
/// `evidence.validate()`。
async fn write_l2_evidence(
    l2: &dyn L2EvidenceStore,
    mac_secret: Option<&[u8]>,
    cache_epoch: &str,
    evidence: &PublishedCardAuthorization,
) {
    let Some(mac_secret) = mac_secret else {
        tracing::debug!(
            tenant_id = evidence.tenant_id,
            card_id = evidence.card_id,
            "l2 hmac secret unavailable; skipping L2 write (fail-closed)"
        );
        return;
    };
    let Ok(full_json) = serde_json::to_string(evidence) else {
        tracing::warn!(
            tenant_id = evidence.tenant_id,
            card_id = evidence.card_id,
            "l2 evidence payload serialization failed; skipping L2 write"
        );
        return;
    };
    let (factored, units) = l2_factored_storage_form(evidence);
    // 写侧自证：因子化 → 重建必须逐字节还原完整证据（无损证明；不等即写侧
    // bug → 拒写，绝不落一条读侧无法复原的条目）。
    let unit_refs: HashMap<String, L2SharedUnitContent> = units
        .iter()
        .map(|(digest, content)| (digest.clone(), content.clone()))
        .collect();
    let lossless = matches!(
        l2_reconstruct_full_payload(&factored, &unit_refs)
            .map(|rebuilt| serde_json::to_string(&rebuilt)),
        Some(Ok(json)) if json == full_json,
    );
    if !lossless {
        tracing::warn!(
            tenant_id = evidence.tenant_id,
            card_id = evidence.card_id,
            "l2 factorization is not lossless; refusing to write"
        );
        return;
    }
    let manifest_versions = evidence_manifest_versions(evidence);
    let content_hash = l2_content_hash(&full_json);
    let key = l2_evidence_key(cache_epoch, evidence.tenant_id, evidence.card_id);
    let mac = l2_entry_mac_hex(
        mac_secret,
        &L2MacCover {
            domain: L2_MAC_DOMAIN,
            redis_key: &key,
            schema_version: L2_EVIDENCE_SCHEMA_VERSION,
            manifest_versions: &manifest_versions,
            // 写侧恒为 false：本证据只能来自通过 source-freshness 门禁的严格
            // reader（存在未发布 delta 时根本没有证据可写）。
            card_source_pending: false,
            content_hash: &content_hash,
            payload: evidence,
        },
    );
    let entry = L2EvidenceEntry {
        schema_version: L2_EVIDENCE_SCHEMA_VERSION,
        manifest_versions,
        card_source_pending: false,
        content_hash,
        mac,
        payload: factored,
    };
    let Ok(json) = serde_json::to_string(&entry) else {
        tracing::warn!(
            tenant_id = evidence.tenant_id,
            card_id = evidence.card_id,
            "l2 evidence entry serialization failed; skipping L2 write"
        );
        return;
    };
    // 1) 共享单元先落定（同 TTL；epoch+tenant 内嵌键）。
    for (digest, content) in &units {
        let unit = L2SharedUnit {
            unit_schema_version: L2_SHARED_UNIT_SCHEMA_VERSION,
            digest: digest.clone(),
            content: content.clone(),
        };
        let Ok(unit_json) = serde_json::to_string(&unit) else {
            tracing::warn!(
                tenant_id = evidence.tenant_id,
                card_id = evidence.card_id,
                "l2 shared unit serialization failed; skipping L2 write"
            );
            return;
        };
        let unit_key = l2_shared_unit_key(cache_epoch, evidence.tenant_id, digest);
        if let Err(error) = l2
            .set_ex(&unit_key, unit_json, L2_EVIDENCE_TTL_SECONDS)
            .await
        {
            tracing::warn!(key = %unit_key, %error, "l2 shared unit write failed; card entry not written");
            return;
        }
    }
    // 2) 全部单元落定后才写卡条目。
    if let Err(error) = l2.set_ex(&key, json, L2_EVIDENCE_TTL_SECONDS).await {
        tracing::warn!(key = %key, %error, "l2 evidence write failed; L2 miss will refill from DB");
    }
}

/// 发布影响卡作用域（纯逻辑）：CARD 聚合且事件携带卡作用域 → `(tenant, card)`；
/// 其它聚合（ELIGIBILITY/RULE_SET 等不承载评估 evidence）或卡作用域缺失
/// （无法定位卡级 evidence 键）→ `None`（不推，L2 miss 自然回源）。
pub fn publish_affected_card_scope(
    identity: &crate::authorization_projection_repository::ProjectionAggregateIdentity,
    card_id: Option<i64>,
) -> Option<(i64, i64)> {
    if identity.aggregate_type != L2_EVIDENCE_CARD_AGGREGATE_TYPE {
        return None;
    }
    card_id.map(|card_id| (identity.tenant_id, card_id))
}

/// 发布事务提交后的 L2 evidence 推送（方案 a：发布后自读）。
///
/// 对受影响卡以严格 reader（pool 版，与 miss 回源同源同实现，天然 parity）
/// 重读一次并推入 L2；发布低频，每卡一次 DB 完整读可接受。任何失败（时代
/// 未知、严格读失败、Redis 失败）一律静默 warn，绝不阻塞/回报失败——发布
/// 本身已 durable commit，推送只是跨实例共享优化。
pub async fn push_published_card_evidence_to_l2(pool: &MySqlPool, tenant_id: i64, card_id: i64) {
    let deps = MySqlEvidenceReadDeps::new(pool.clone());
    // HMAC 密钥不可用 → L2 整体旁路（fail-closed）：连严格读都不做，因为
    // 读出的证据也无法以认证形态推入 L2（自然回源保证正确性）。
    let Some(mac_secret) = l2_hmac_secret() else {
        return;
    };
    // F5 修复 1c：整体 1s 硬超时（含 epoch 读、strict read 与写回）。推送
    // 挂起必须变成"放弃"而不是无限等待；超时只损失一次预热，读路径 miss
    // 自然回源，正确性不受影响。
    let push = async {
        push_evidence_to_l2_with(
            shared_l2_evidence_store().as_ref(),
            mac_secret,
            &deps,
            tenant_id,
            card_id,
        )
        .await;
    };
    if !push_with_l2_budget(L2_PUSH_BUDGET, push).await {
        tracing::debug!(
            tenant_id,
            card_id,
            budget_ms = L2_PUSH_BUDGET.as_millis() as u64,
            "l2 evidence push exceeded budget; dropped (natural refill covers correctness)"
        );
    }
}

/// 推送核心（SPI 注入形态，供测试与生产包装共用）。
pub(crate) async fn push_evidence_to_l2_with<D: EvidenceReadDeps>(
    l2: &dyn L2EvidenceStore,
    mac_secret: &[u8],
    deps: &D,
    tenant_id: i64,
    card_id: i64,
) {
    // 时代未知（Redis 降级）→ 无法构造内嵌时代的键，也不该在降级窗口写入。
    let Some(cache_epoch) = deps.current_epoch().await else {
        return;
    };
    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    };
    let evidence = match deps.strict_read(&scope).await {
        Ok(evidence) => evidence,
        Err(error) => {
            tracing::warn!(tenant_id, card_id, %error, "l2 evidence post-publish strict read failed; L2 left to natural refill");
            return;
        }
    };
    if let Err(contract_error) = evidence.validate() {
        // 纵深防御：形状矛盾的证据不推入 L2（对齐 miss 填充路径的合同门槛）。
        tracing::warn!(tenant_id, card_id, %contract_error, "l2 evidence post-publish read failed contract; refusing to push");
        return;
    }
    write_l2_evidence(l2, Some(mac_secret), &cache_epoch, &evidence).await;
}

/// 缓存感知的卡级证据读取协议核心（miss 回源严格 reader；命中前置对牌）。
///
/// 命中协议（对齐 `permission_query::find_effective_permissions_cached` 的
/// 双读先例，见模块文档"复读交互"）：
/// 1. 读缓存条目（存在才继续，冷 miss 零栅栏 I/O）；
/// 2. epoch 严格 current（任一侧未知/不一致 → miss）；
/// 3. **读前对牌**：当前指针版本组 == 条目基准组（逐项相等，含集合形状；
///    栅栏读失败按 miss 处理，回源严格 reader 保持错误语义）；
/// 4. **读后复读对牌**：复读栅栏与第一次逐项相等（发布恰好落在两次读之间
///    时不放行旧条目）；
/// 5. 时钟新鲜度：当前时钟下窗口状态与填充时刻一致（任一翻转 → miss）。
///
/// miss 协议（L2 Redis 优先 → L3 DB 兜底，见模块文档 L2 节）：
/// 1. **HMAC 密钥门槛**：`mac_secret` 为 `None`（密钥未设置/无效）→ L2 读/写
///    整体旁路（fail-closed），直接回源严格 reader；
/// 2. **读前对牌**取得 DB 指针组（栅栏读失败 → L2 整体旁路，直接回源）；
/// 3. 查 L2：命中前提全部通过（含共享单元自校验、MAC、记录级 scope 绑定）→
///    反序列化 evidence → 回填 L1 → 返回；键存在但任一前提失败 → 删除该 L2
///    卡键（污染/失配清除；共享单元不动）→ 回源；无条目/Redis 错误 → 静默
///    旁路 → 回源；
/// 4. L2 命中后仍有**读后复读对牌**（与 L1 同强度：复读漂移 → 不删除 L2 键
///    ——可能误删发布者刚推送的新鲜条目——直接回源，成功后回填覆盖）；
/// 5. 严格 reader 是唯一回源（错误族原样上抛，fail-closed 语义与直读完全
///    一致）；成功且通过合同校验才回填：当前时代已知 → 写 L1 + 写 L2（含
///    content_hash + MAC + 共享单元先写），时代未知（Redis 降级）→ 均不填充。
///    校验失败一律以错误返回（`Corrupt` 族），绝不写入任何缓存，更绝不降级
///    为空授权。
///
/// `pub` 仅为真实 Redis 集成测试的注入入口（`EvidenceReadDeps`/
/// `L2EvidenceStore` 测试实现 + 独立 moka 实例 + 显式 HMAC 密钥；
/// `tests/evidence_cache_redis_integration.rs`），生产调用方仍走
/// [`cached_load_published_card_grant_evidence`] 与
/// [`CachedPublishedEvidenceRuleRepository`]。
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

pub async fn load_evidence_through_cache_with_mac<D: EvidenceReadDeps>(
    deps: &D,
    cache: &EvidenceCacheStore,
    l2: Option<&dyn L2EvidenceStore>,
    mac_secret: Option<&[u8]>,
    scope: &PublishedCardEvidenceScope,
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    let evidence_read_started = std::time::Instant::now();
    scope.validate().map_err(|contract| {
        AuthorizationEvidenceError::InvalidRequest(format!(
            "code=published_card_evidence.invalid_scope;detail={contract}"
        ))
    })?;
    ensure_card_level_lens(scope)?;

    let key = (scope.tenant_id, scope.card_id);
    let current_epoch = deps.current_epoch().await;

    if let Some(entry) = cache.get(&key).await {
        let epoch_ok =
            cache_epoch_is_current(current_epoch.as_deref(), Some(entry.cache_epoch.as_str()));
        if epoch_ok {
            // 读前对牌：栅栏读失败按 miss 处理（回源严格 reader）。
            if let Ok(fence) = deps
                .card_scope_fence_snapshot(scope.tenant_id, scope.card_id)
                .await
            {
                if fence == entry.baseline {
                    // 读后复读对牌：发布落在两次栅栏读之间 → 不放行旧条目。
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
                            let evidence = (*entry.evidence).clone();
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
        // 任一前提失败 → miss 回源；旧条目绝不改写，由 TTL/下次成功填充覆盖。
        record_evidence_cache_lookup("l1", "miss");
    } else {
        record_evidence_cache_lookup("l1", "miss");
    }

    // miss：L2 优先。仅当 L2 可用、HMAC 密钥可用（密钥缺失/无效 → L2 读/写
    // 整体旁路，fail-closed）且当前时代已知（epoch 内嵌键，换时代后旧键自然
    // 失配；时代未知 = Redis 降级 → L2 整体旁路）才读"读前对牌"栅栏，L2 旁路
    // （未注入/降级）保持冷 miss 零栅栏 I/O 的原协议。栅栏读失败 → L2 旁路，
    // 直接回源严格 reader 保持错误语义。
    if let (Some(l2), Some(cache_epoch), Some(mac_secret)) =
        (l2, current_epoch.as_deref(), mac_secret)
    {
        if let Ok(pre_fence) = deps
            .card_scope_fence_snapshot(scope.tenant_id, scope.card_id)
            .await
        {
            match try_l2_evidence_hit(
                l2,
                mac_secret,
                cache_epoch,
                &pre_fence,
                scope.tenant_id,
                scope.card_id,
                deps.now_unix_seconds(),
            )
            .await
            {
                L2Lookup::Hit(evidence) => {
                    // 读后复读对牌：发布落在读前对牌与 L2 接受之间 → 不放行
                    // 旧条目。
                    if let Ok(recheck) = deps
                        .card_scope_fence_snapshot(scope.tenant_id, scope.card_id)
                        .await
                    {
                        if recheck == pre_fence {
                            // 回填 L1（与回源填充同一构造：基准组由 evidence
                            // 内容推导；L2 命中协议已证明它与 DB 栅栏快照逐项
                            // 一致）。
                            cache
                                .insert(
                                    key,
                                    EvidenceCacheEntry {
                                        evidence: Arc::new((*evidence).clone()),
                                        baseline: evidence_fence_baseline(&evidence),
                                        cache_epoch: cache_epoch.to_owned(),
                                    },
                                )
                                .await;
                            #[cfg(feature = "e1-observability")]
                            log_e1_evidence_load_result(scope, "l2_cache", &evidence);
                            record_evidence_cache_lookup("l2", "hit");
                            record_evidence_read(
                                "l2_cache",
                                "success",
                                evidence_read_started.elapsed(),
                            );
                            return Ok(*evidence);
                        }
                    }
                    record_evidence_cache_lookup("l2", "miss");
                }
                L2Lookup::Purge(reason) => {
                    record_evidence_cache_lookup("l2", "purged");
                    // 污染/失配清除（best-effort；删除失败静默，对牌仍兜底）。
                    if let Err(error) = l2
                        .del(&l2_evidence_key(
                            cache_epoch,
                            scope.tenant_id,
                            scope.card_id,
                        ))
                        .await
                    {
                        tracing::warn!(reason, %error, "l2 evidence purge failed");
                    }
                }
                L2Lookup::Bypass => {
                    record_evidence_cache_lookup("l2", "bypass");
                }
            }
        } else {
            record_evidence_cache_lookup("l2", "bypass");
        }
    } else {
        record_evidence_cache_lookup("l2", "bypass");
    }

    // miss：严格 reader 是唯一回源（锁定 + 整链校验 + 显式 commit）。
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
        // 纵深防御：形状矛盾的证据不参与授权也不入缓存（Corrupt 族，对齐
        // sod_check / 卡摘要读路径的合同校验语义）。
        record_evidence_read("strict_db", "corrupt", strict_read_started.elapsed());
        return Err(AuthorizationEvidenceError::Corrupt(format!(
            "code=evidence_cache.fill_contract_rejected;detail={contract_error}"
        )));
    }
    if let Some(epoch) = current_epoch.as_deref() {
        // 当前时代未知（Redis 降级）→ 不填充：严格 current 语义下该条目永远
        // 无法命中，写入即死代码，还会掩盖降级窗口。
        cache
            .insert(
                key,
                EvidenceCacheEntry {
                    evidence: Arc::new(evidence.clone()),
                    baseline: evidence_fence_baseline(&evidence),
                    cache_epoch: epoch.to_owned(),
                },
            )
            .await;
        // 回填 L2（含 content_hash + MAC + 共享单元先写；失败静默 —— L2 miss
        // 自然回源；密钥不可用时写侧自行跳过）。
        if let Some(l2) = l2 {
            write_l2_evidence(l2, mac_secret, epoch, &evidence).await;
        }
    }
    #[cfg(feature = "e1-observability")]
    log_e1_evidence_load_result(scope, "strict_db", &evidence);
    record_evidence_read("strict_db", "success", strict_read_started.elapsed());
    Ok(evidence)
}

/// 缓存感知的卡级证据读取（生产入口：进程级 HMAC 密钥在此解析）。
///
/// `l2` 为 `Some` 时解析进程级 L2 HMAC 密钥并委托
/// [`load_evidence_through_cache_with_mac`]：密钥可用 → 完整 L2 协议；密钥
/// 未设置/无效 → L2 读/写整体旁路（fail-closed，严格 reader 兜底，warn 一次）。
pub async fn load_evidence_through_cache<D: EvidenceReadDeps>(
    deps: &D,
    cache: &EvidenceCacheStore,
    l2: Option<&dyn L2EvidenceStore>,
    scope: &PublishedCardEvidenceScope,
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    let mac_secret = l2.and_then(|_| l2_hmac_secret());
    load_evidence_through_cache_with_mac(deps, cache, l2, mac_secret, scope).await
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

/// 卡级 published card evidence 的缓存感知读取（进程级全局缓存 + L2 Redis
/// 分发层）。
///
/// - scope 必须是卡级 lens（`user_filter: None` + `Unconstrained`），否则
///   `InvalidRequest` 拒绝（见模块文档 lens 契约）；
/// - 命中：指针对牌 + epoch + 时钟重验全部通过 → 返回证据整份克隆；
/// - miss：L2 Redis 优先（键内嵌时代、对牌 + content_hash + 时钟全部通过
///   才接受并回填 L1），未命中/被弃用/降级回源严格 reader（错误族与直读
///   完全一致），成功后回填 L1 + L2；
/// - **委托证明路径（`load_published_card_grant_evidence_in_tx`）不经过本
///   函数**——事务内锁定读必须直连严格 reader，永不走缓存。
pub async fn cached_load_published_card_grant_evidence(
    pool: &MySqlPool,
    scope: &PublishedCardEvidenceScope,
) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
    scope.validate().map_err(|contract| {
        AuthorizationEvidenceError::InvalidRequest(format!(
            "code=published_card_evidence.invalid_scope;detail={contract}"
        ))
    })?;
    ensure_card_level_lens(scope)?;
    let deps = MySqlEvidenceReadDeps::new(pool.clone());
    load_evidence_through_cache(
        &deps,
        shared_evidence_cache(),
        Some(shared_l2_evidence_store().as_ref()),
        scope,
    )
    .await
}

/// 缓存感知的 [`policy_engine::RuleRepository`] 包装（engine strict 路径装配
/// 侧接线，policy-engine 与 astral-db 严格 reader 零改动）。
///
/// # lens 契约（重要，代码即契约）
///
/// [`RuleRepository::load_published_card_authorization`] 收到的 user/domain
/// lens 被有意丢弃，服务/填充的始终是**卡级 lens 超集**证据：`PolicyEngine`
/// 的 `match_published_effective_grant` 在 `effective_grants` 上按请求
/// user/domain 二次收窄，放行语义等价；**已知差异仅在 gate 计数与审计观测
/// 字段**（如 `not_in_effective_count`），不影响 ALLOW/DENY。禁止对本层返回
/// 的证据做读取侧收窄或改写。
///
/// # 复读交互
///
/// engine 在 ALLOW 返回前的第二次
/// `load_published_card_authorization` 调用经本包装再次走命中协议：同一缓存
/// 条目使证据逐字段一致（engine 的 identity-stable 判定因此退化为恒真），
/// 有效强度由本层每次 load 的"读前 + 读后"双读指针对牌承担；对牌失败回源
/// 重读 → 新证据与评估起点不同 → engine PENDING（fail-closed）。
///
/// 其余 trait 方法全部透传 inner（穷举转发，inner 的 override 永远生效，
/// 包装层不引入任何额外读取器调用——engine mock 的读取计数契约不受影响）。
pub struct CachedPublishedEvidenceRuleRepository<R, D = MySqlEvidenceReadDeps> {
    inner: R,
    deps: D,
    cache: EvidenceCacheStore,
    /// L2 Redis 分发层（生产 = [`shared_l2_evidence_store`]；测试可注入
    /// 内存实现或 `None` 整体旁路）。
    l2: Option<Arc<dyn L2EvidenceStore>>,
}

impl<R: RuleRepository> CachedPublishedEvidenceRuleRepository<R, MySqlEvidenceReadDeps> {
    /// 生产装配：inner 通常是 `astral_db::SqlxRuleRepository`（严格 reader
    /// 生产实现）；`pool` 为指针对牌与回源读取使用的同一 MySQL 池。
    pub fn new(inner: R, pool: MySqlPool) -> Self {
        Self {
            inner,
            deps: MySqlEvidenceReadDeps::new(pool),
            cache: shared_evidence_cache().clone(),
            l2: Some(shared_l2_evidence_store().clone()),
        }
    }
}

impl<R, D> CachedPublishedEvidenceRuleRepository<R, D>
where
    R: RuleRepository,
    D: EvidenceReadDeps,
{
    /// 测试/特殊装配：显式注入读取依赖、缓存实例与 L2 存取（生产走
    /// [`Self::new`]）。
    pub fn with_deps(
        inner: R,
        deps: D,
        cache: &EvidenceCacheStore,
        l2: Option<Arc<dyn L2EvidenceStore>>,
    ) -> Self {
        Self {
            inner,
            deps,
            cache: cache.clone(),
            l2,
        }
    }
}

#[async_trait::async_trait]
impl<R, D> RuleRepository for CachedPublishedEvidenceRuleRepository<R, D>
where
    R: RuleRepository,
    D: EvidenceReadDeps,
{
    fn requires_published_card_evidence(&self) -> bool {
        self.inner.requires_published_card_evidence()
    }

    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<policy_engine::OrgAuthorityRead, PolicyError> {
        self.inner.load_org_authorization(ctx).await
    }

    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.inner.check_card_active(ctx).await
    }

    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
        self.inner.is_active_global_admin(user_id).await
    }

    async fn load_rule_set_snapshots(
        &self,
        card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.inner.load_rule_set_snapshots(card_id).await
    }

    async fn load_permission_rules(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner.load_permission_rules(card_id).await
    }

    async fn load_rule_set_dependency_statuses(
        &self,
        card_id: i64,
    ) -> Result<Option<Vec<RuleSetDependencyStatus>>, PolicyError> {
        self.inner.load_rule_set_dependency_statuses(card_id).await
    }

    async fn load_snapshot_winners(
        &self,
        card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        self.inner.load_snapshot_winners(card_id).await
    }

    async fn load_rule_set_entries_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.inner.load_rule_set_entries_raw(card_id).await
    }

    async fn load_permission_rules_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner.load_permission_rules_raw(card_id).await
    }

    async fn load_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner
            .load_delegated_rules(delegate_id, resource, action)
            .await
    }

    async fn load_projected_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner
            .load_projected_delegated_rules(delegate_id, resource, action)
            .await
    }

    async fn get_projection_gate(
        &self,
        card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        self.inner.get_projection_gate(card_id).await
    }

    /// 缓存感知的 published evidence 读取：lens 归一化（见类型文档）→
    /// 指针对牌命中协议 → miss 回源严格 reader → 错误族映射与生产实现一致。
    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        let card_scope = card_level_lens_scope(scope);
        match load_evidence_through_cache(&self.deps, &self.cache, self.l2.as_deref(), &card_scope)
            .await
        {
            Ok(evidence) => Ok(Some(evidence)),
            Err(error) => Err(cached_published_evidence_error_to_policy_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
        GrantSourceKind, GrantState, PublishedAggregateManifestSummary,
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

    #[tokio::test]
    async fn l2_push_budget_drops_hanging_push_and_counts() {
        let before = super::l2_push_dropped_count();
        // 永久挂起的推送体（F5 形态）：必须在预算内被放弃并计数。
        let completed =
            super::push_with_l2_budget(Duration::from_millis(30), std::future::pending()).await;
        assert!(!completed, "hanging push must be dropped at the budget");
        assert_eq!(super::l2_push_dropped_count(), before + 1);
        // 预算内完成的推送：不丢弃、不计数。
        let completed = super::push_with_l2_budget(Duration::from_millis(30), async {}).await;
        assert!(completed);
        assert_eq!(super::l2_push_dropped_count(), before + 1);
    }
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const TENANT: i64 = 7;
    const CARD: i64 = 1;
    const EPOCH: &str = "epoch-fixture-1";

    // ===== 夹具：Ready evidence 与指针版本组（纯内存，无 DB/Redis） =====

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
            compiler_version: "test".to_string(),
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
        strict_reads: VecDeque<Result<PublishedCardAuthorization, AuthorizationEvidenceError>>,
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
            strict_reads: Vec<Result<PublishedCardAuthorization, AuthorizationEvidenceError>>,
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
        ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
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
        evidence_fence_baseline(evidence)
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
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
        let scope = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        load_evidence_through_cache(deps, cache, None, &scope).await
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
            vec![Ok(evidence.clone())],
            1_050,
        );
        let first = load_with(&deps, &cache).await.expect("first load");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(deps.fence_calls(), 0);
        assert_eq!(first, direct);

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
        assert_eq!(second, direct);
    }

    /// 发布推进（generation +1）→ 读前对牌失败 → 回源 → 新 evidence。
    #[tokio::test]
    async fn generation_advance_busts_cache_and_rereads_strict() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into()), Some(EPOCH.into())],
            vec![],
            vec![Ok(stale)],
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
            vec![Ok(published.clone())],
            1_100,
        );
        let next = load_with(&deps, &cache).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1, "drift must go back to strict read");
        assert_eq!(next, published);
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
            vec![Ok(stale)],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        let mut revoked = single_record_evidence(1_100, 0, 2_000);
        revoked.manifests[0].revoke_fence = 3;
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&revoked)],
            vec![Ok(revoked.clone())],
            1_100,
        );
        let next = load_with(&deps, &cache).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(next, revoked);
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
            vec![Ok(stale.clone())],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        // 同 generation/fence 但 manifest_id 变化（指针重写）。
        let mut rewritten = single_record_evidence(1_100, 0, 2_000);
        rewritten.manifests[0].manifest_id = 10;
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&rewritten)],
            vec![Ok(rewritten.clone())],
            1_100,
        );
        let next = load_with(&deps, &cache)
            .await
            .expect("reload after rewrite");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(next, rewritten);

        // 集合形状变化：新增一个聚合的指针行（版本组形状不一致 → 失配）。
        let extra_row = PermissionCacheManifestVersion {
            aggregate_type: "RULE_SET".to_string(),
            aggregate_id: 10,
            manifest_id: 1,
            generation: 1,
            revoke_fence: 0,
        };
        let mut shaped = fence_of(&rewritten);
        shaped.manifest_versions.push(extra_row);
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![shaped],
            vec![Ok(rewritten.clone())],
            1_150,
        );
        let next = load_with(&deps, &cache).await.expect("reload after shape");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(next, rewritten);
    }

    /// epoch 严格 current 语义：填充后时代轮换 → miss 并以新时代重填；时代
    /// 轮回一致后命中；当前时代未知（Redis 降级）→ miss 且不填充。
    #[tokio::test]
    async fn epoch_rotation_and_degradation_bust_cache() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();

        // 填充（时代 = EPOCH）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(evidence.clone())],
            1_050,
        );
        load_with(&deps, &cache).await.expect("fill");

        // 时代轮换 → miss → 回源并以新时代重填。
        let deps = FixtureDeps::new(
            vec![Some("rotated-epoch".into())],
            vec![],
            vec![Ok(evidence.clone())],
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
            vec![Ok(evidence.clone())],
            1_070,
        );
        load_with(&deps, &cache)
            .await
            .expect("reload after rotation back");
        assert_eq!(deps.strict_calls(), 1, "stale entry epoch must miss");

        // 当前时代未知（Redis 降级）→ miss 回源，且不填充。
        let deps = FixtureDeps::new(vec![None], vec![], vec![Ok(evidence.clone())], 1_080);
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
        assert_eq!(hit, evidence);
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
            vec![Ok(evidence.clone())],
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
            vec![Ok(evidence.clone())],
            1_200,
        );
        load_with(&deps, &cache).await.expect("reload after expiry");
        assert_eq!(deps.strict_calls(), 1, "expired accepted grant must miss");

        // NotYetValid 记录窗口开启 → 时钟重验失败 → miss 回源。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![Ok(evidence.clone())],
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
            vec![Ok(evidence.clone())],
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
            vec![Ok(evidence.clone())],
            1_060,
        );
        let next = load_with(&deps, &cache).await.expect("reload succeeds");
        assert_eq!(deps.strict_calls(), 1, "failed read must not be cached");
        assert_eq!(next, evidence);
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
            vec![Ok(stale)],
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
            vec![Ok(published.clone())],
            1_100,
        );
        let next = load_with(&deps, &cache).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(next, published);
    }

    #[tokio::test]
    async fn e2_pending_probe_omission_accepts_stale_candidate_while_full_contract_reloads() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(stale.clone())],
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
            vec![Ok(narrowed.clone())],
            1_100,
        );
        let safe_value = load_with(&full, &cache)
            .await
            .expect("full contract reload");
        assert_eq!(full.strict_calls(), 1);
        assert_eq!(safe_value, narrowed);
        assert!(safe_value.effective_grants.is_empty());
    }

    #[tokio::test]
    async fn e2_post_recheck_omission_accepts_interleaving_while_full_contract_reloads() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(stale.clone())],
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
            vec![Ok(published.clone())],
            1_100,
        );
        let safe_value = load_with(&full, &cache)
            .await
            .expect("full contract reload");
        assert_eq!(full.strict_calls(), 1);
        assert_eq!(safe_value, published);
    }

    #[tokio::test]
    async fn e2_generation_revoke_fence_omission_accepts_stale_candidate() {
        let stale = single_record_evidence(1_000, 0, 2_000);

        let generation_cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(stale.clone())],
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
            vec![Ok(advanced.clone())],
            1_100,
        );
        let safe_generation = load_with(&deps, &generation_cache)
            .await
            .expect("generation mismatch reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(safe_generation, advanced);
        assert!(safe_generation
            .effective_grants
            .iter()
            .all(|grant| grant.resource != "learn_subject:42"));

        let revoke_cache = fresh_cache();
        let fill = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(stale.clone())],
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
            vec![Ok(revoked.clone())],
            1_100,
        );
        let safe_revoke = load_with(&deps, &revoke_cache)
            .await
            .expect("revoke fence mismatch reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(safe_revoke, revoked);
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
        let outcome = load_evidence_through_cache(&deps, &cache, None, &lensed).await;
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
        fn requires_published_card_evidence(&self) -> bool {
            true
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }

        async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
            self.global_admin_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(user_id == 73)
        }

        async fn load_published_card_authorization(
            &self,
            _scope: &PublishedCardEvidenceScope,
        ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
            self.published_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(None)
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
            vec![Ok(evidence.clone())],
            1_050,
        );
        let repo = CachedPublishedEvidenceRuleRepository::with_deps(inner, deps, &cache, None);
        assert!(repo.requires_published_card_evidence());
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
        assert_eq!(first, evidence);

        // 第二次读取（engine ALLOW 复读形态）：命中缓存，inner 不再被触达。
        let second = repo
            .load_published_card_authorization(&lensed)
            .await
            .expect("second load")
            .expect("cached evidence is Some");
        assert_eq!(second, evidence, "recheck evidence must be identical");
    }

    // =====================================================================
    // D 批次测试矩阵：L2 Redis evidence 分发层（内存注入实现，无真实 Redis）
    // =====================================================================

    /// 内存 L2 存取：记录调用计数与写入 TTL，支持按原语注入失败（降级测试）。
    struct MemoryL2Store {
        entries: Mutex<std::collections::HashMap<String, (String, u64)>>,
        get_calls: std::sync::atomic::AtomicUsize,
        set_calls: std::sync::atomic::AtomicUsize,
        del_calls: std::sync::atomic::AtomicUsize,
        fail_get: bool,
        fail_set: bool,
        fail_del: bool,
    }

    impl MemoryL2Store {
        fn new() -> Self {
            Self {
                entries: Mutex::new(std::collections::HashMap::new()),
                get_calls: std::sync::atomic::AtomicUsize::new(0),
                set_calls: std::sync::atomic::AtomicUsize::new(0),
                del_calls: std::sync::atomic::AtomicUsize::new(0),
                fail_get: false,
                fail_set: false,
                fail_del: false,
            }
        }

        fn failing(kind: &str) -> Self {
            let mut store = Self::new();
            store.fail_get = kind.contains("get");
            store.fail_set = kind.contains("set");
            store.fail_del = kind.contains("del");
            store
        }

        /// 测试侧直接播种（绕过被测写入路径）。
        fn seed(&self, key: &str, value: &str, ttl_seconds: u64) {
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_owned(), (value.to_owned(), ttl_seconds));
        }

        fn contains(&self, key: &str) -> bool {
            self.entries.lock().unwrap().contains_key(key)
        }

        fn is_empty(&self) -> bool {
            self.entries.lock().unwrap().is_empty()
        }

        /// 当前全部键（共享单元键族枚举/清理断言用）。
        fn keys(&self) -> Vec<String> {
            self.entries.lock().unwrap().keys().cloned().collect()
        }

        fn get_calls(&self) -> usize {
            self.get_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn set_calls(&self) -> usize {
            self.set_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn del_calls(&self) -> usize {
            self.del_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl L2EvidenceStore for MemoryL2Store {
        async fn get(&self, key: &str) -> Result<Option<String>, String> {
            self.get_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_get {
                return Err("code=test.l2_get_failed".to_owned());
            }
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(key)
                .map(|(value, _ttl)| value.clone()))
        }

        async fn set_ex(&self, key: &str, value: String, ttl_seconds: u64) -> Result<(), String> {
            self.set_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_set {
                return Err("code=test.l2_set_failed".to_owned());
            }
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_owned(), (value, ttl_seconds));
            Ok(())
        }

        async fn del(&self, key: &str) -> Result<(), String> {
            self.del_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_del {
                return Err("code=test.l2_del_failed".to_owned());
            }
            self.entries.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// 以指定 deps/cache/L2 执行一次卡级 load（scope = 卡级 lens）。单测统一
    /// 使用 [`TEST_MAC_SECRET`]（生产入口的进程级密钥解析由
    /// `load_evidence_through_cache` 承担，不经过本 helper）。
    async fn load_with_l2(
        deps: &FixtureDeps,
        cache: &EvidenceCacheStore,
        l2: &dyn L2EvidenceStore,
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
        load_card_with_l2(deps, cache, l2, TENANT, CARD).await
    }

    /// 作用域参数化 load（跨卡/跨租户投毒与栅栏隔离测试使用）。
    async fn load_card_with_l2(
        deps: &FixtureDeps,
        cache: &EvidenceCacheStore,
        l2: &dyn L2EvidenceStore,
        tenant_id: i64,
        card_id: i64,
    ) -> Result<PublishedCardAuthorization, AuthorizationEvidenceError> {
        let scope = PublishedCardEvidenceScope {
            tenant_id,
            card_id,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        load_evidence_through_cache_with_mac(deps, cache, Some(l2), Some(TEST_MAC_SECRET), &scope)
            .await
    }

    fn l2_key_of(epoch: &str) -> String {
        l2_evidence_key(epoch, TENANT, CARD)
    }

    /// 经被测写入路径播种：把 evidence 以写侧协议（schema 3/版本组/content_hash/
    /// MAC/共享单元先写/TTL）写入内存 L2。
    async fn seed_valid_entry(
        store: &MemoryL2Store,
        epoch: &str,
        evidence: &PublishedCardAuthorization,
    ) {
        write_l2_evidence(store, Some(TEST_MAC_SECRET), epoch, evidence).await;
        assert!(store.contains(&l2_key_of(epoch)), "seed must land in store");
    }

    /// 单元测试专用 HMAC 密钥（仅测试构建可见；生产密钥一律走
    /// `L2_EVIDENCE_HMAC_SECRET_ENV` 环境变量解析，绝不复用本常量）。
    const TEST_MAC_SECRET: &[u8] = b"astral-l2-evidence-unit-test-hmac-secret-0123456789abcdef";

    /// 手工构造条目 JSON（用于污染/合同破坏等写侧协议之外的夹具）。模拟
    /// **持有密钥的**写侧/攻击者：MAC 对给定 `payload` 与给定（可能伪造的）
    /// `content_hash` 合法——只有更深的内容级校验（content_hash/scope/合同）
    /// 能拦下伪造。`payload` 参数是**完整证据**，条目内存其 v3 因子化存储
    /// 形态（MAC 绑定 `l2_key_of(EPOCH)`）。仅用于内联记录（USER_CARD 等）
    /// 的载荷；含 RULE_SET 记录的载荷必须走 `seed_valid_entry`（单元先写）。
    fn raw_entry_json(
        snapshot: CardScopeFenceSnapshot,
        content_hash: String,
        payload: &PublishedCardAuthorization,
    ) -> String {
        raw_entry_json_for_key(
            &l2_key_of(EPOCH),
            snapshot,
            content_hash,
            payload,
            TEST_MAC_SECRET,
        )
    }

    /// [`raw_entry_json`] 的键/密钥参数化变体（键绑定重放与错误密钥测试用）。
    fn raw_entry_json_for_key(
        redis_key: &str,
        snapshot: CardScopeFenceSnapshot,
        content_hash: String,
        payload: &PublishedCardAuthorization,
        mac_secret: &[u8],
    ) -> String {
        let (factored, _units) = l2_factored_storage_form(payload);
        let mac = l2_entry_mac_hex(
            mac_secret,
            &L2MacCover {
                domain: L2_MAC_DOMAIN,
                redis_key,
                schema_version: L2_EVIDENCE_SCHEMA_VERSION,
                manifest_versions: &snapshot.manifest_versions,
                card_source_pending: snapshot.card_source_pending,
                content_hash: &content_hash,
                payload,
            },
        );
        let entry = L2EvidenceEntry {
            schema_version: L2_EVIDENCE_SCHEMA_VERSION,
            manifest_versions: snapshot.manifest_versions,
            card_source_pending: snapshot.card_source_pending,
            content_hash,
            mac,
            payload: factored,
        };
        serde_json::to_string(&entry).expect("entry json")
    }

    /// 完整证据序列化字节的 sha256（镜像写侧 content_hash 口径）。
    fn full_payload_hash(evidence: &PublishedCardAuthorization) -> String {
        let json = serde_json::to_string(evidence).expect("full payload json");
        l2_content_hash(&json)
    }

    /// 由条目重建完整 payload（单测便捷：按 EPOCH/TENANT 显式取回被引用的
    /// 共享单元再 join；任何单元缺失即 panic —— 部分重建绝不被容忍）。
    fn reconstruct_entry_payload(
        entry: &L2EvidenceEntry,
        store: &MemoryL2Store,
    ) -> PublishedCardAuthorization {
        let mut units = HashMap::new();
        for digest in l2_referenced_unit_digests(&entry.payload) {
            let raw = store
                .entries
                .lock()
                .unwrap()
                .get(&l2_shared_unit_key(EPOCH, TENANT, &digest))
                .expect("referenced shared unit must exist")
                .0
                .clone();
            let unit: L2SharedUnit = serde_json::from_str(&raw).expect("unit json");
            units.insert(digest, unit.content);
        }
        l2_reconstruct_full_payload(&entry.payload, &units).expect("full reconstruction")
    }

    /// L2 命中：零严格读 + 零 L2 写；回填 L1 后第二次 load 完全走 L1 命中
    /// （L2 不再被读取）；命中结果与直读逐字段 parity（serde 往返保真）。
    #[tokio::test]
    async fn l2_hit_backfills_l1_and_second_load_hits_l1_only() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;

        // 冷 miss（L1 空）→ 读前对牌 + L2 命中 + 读后复读：零严格读。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_050,
        );
        let first = load_with_l2(&deps, &cache, &l2).await.expect("l2 hit");
        assert_eq!(deps.strict_calls(), 0, "L2 hit must skip the strict read");
        assert_eq!(l2.get_calls(), 1);
        assert_eq!(first, evidence, "serde roundtrip parity with direct read");

        // 回填 L1 后：第二次 load 走 L1 命中（L2 不再被读取）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_060,
        );
        let second = load_with_l2(&deps, &cache, &l2).await.expect("l1 hit");
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(l2.get_calls(), 1, "L1 hit must not consult L2");
        assert_eq!(second, evidence);
    }

    /// L2 版本组与读前对牌失配（发布推进）→ 弃用 + 删键 → 回源严格 reader。
    #[tokio::test]
    async fn l2_fence_mismatch_purges_and_falls_back_to_strict() {
        let stale = single_record_evidence(1_000, 0, 2_000);
        let mut published = single_record_evidence(1_100, 0, 2_000);
        published.manifests[0].generation = 2;
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &stale).await;

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&published)],
            vec![Ok(published.clone())],
            1_100,
        );
        let next = load_with_l2(&deps, &cache, &l2).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1, "version mismatch must reread");
        assert_eq!(l2.del_calls(), 1, "mismatched entry must be purged");
        // 回源成功 → 键被新版本组的正确内容重写（自愈）。
        let refilled: L2EvidenceEntry = serde_json::from_str(
            &l2.entries
                .lock()
                .unwrap()
                .get(&l2_key_of(EPOCH))
                .expect("refilled entry")
                .0,
        )
        .expect("refilled json");
        assert_eq!(
            refilled.manifest_versions,
            fence_of(&published).manifest_versions
        );
        assert!(!refilled.card_source_pending);
        assert_eq!(next, published);
    }

    /// content_hash 重验失败（污染）→ 删键 → 回源；随后回源成功会以正确
    /// content_hash 重写 L2。
    #[tokio::test]
    async fn l2_content_hash_pollution_purges_then_refills() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(fence_of(&evidence), l2_content_hash("tampered"), &evidence),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(next, evidence);
        // 回源成功 → L2 被正确内容重写（自愈）。
        assert_eq!(l2.set_calls(), 1, "strict refill must backfill L2");
        let refilled = l2
            .entries
            .lock()
            .unwrap()
            .get(&l2_key_of(EPOCH))
            .expect("refilled entry")
            .0
            .clone();
        let entry: L2EvidenceEntry = serde_json::from_str(&refilled).expect("refilled json");
        assert!(
            entry
                .payload
                .records
                .iter()
                .all(|slot| matches!(slot, L2RecordSlot::Inline(_))),
            "v3 storage: USER_CARD records stay inline"
        );
        // 回源成功 → content_hash 重新绑定完整证据（因子化前）的序列化字节。
        assert_eq!(entry.content_hash, full_payload_hash(&evidence));
    }

    /// epoch 轮换：条目留在旧时代键下，读取侧只查新时代键 → 自然失配
    /// （不误删旧键；回源后在新键下回填）。
    #[tokio::test]
    async fn l2_epoch_rotation_key_mismatch_bypasses() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, "old-epoch", &evidence).await;

        let deps = FixtureDeps::new(
            vec![Some("new-epoch".into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1, "rotated epoch must miss");
        assert!(
            l2.contains(&l2_key_of("old-epoch")),
            "old-epoch key must not be touched"
        );
        assert!(
            l2.contains(&l2_key_of("new-epoch")),
            "refill must land under the current epoch key"
        );
        assert_eq!(next, evidence);
    }

    /// Redis 错误全面降级：GET 失败 → 静默旁路回源；SET 失败 → 静默；L1+DB
    /// 照常（L1 仍回填，第二次 load 命中 L1）。
    #[tokio::test]
    async fn l2_redis_errors_degrade_silently_to_l1_plus_db() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::failing("get+set");

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let first = load_with_l2(&deps, &cache, &l2).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1, "Redis failure must fall back to DB");
        assert_eq!(first, evidence);

        // L1 仍被回填：第二次 load 命中 L1（零严格读、零 L2 读取成功语义）。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_060,
        );
        let second = load_with_l2(&deps, &cache, &l2).await.expect("l1 hit");
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(second, evidence);
    }

    /// L2 命中后读后复读漂移（发布落在读前对牌与 L2 接受之间）→ 不放行旧
    /// 条目回源；且不删 L2 键（可能误删发布者刚推送的新鲜条目）。
    #[tokio::test]
    async fn l2_hit_recheck_drift_falls_back_without_purge() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let mut published = single_record_evidence(1_100, 0, 2_000);
        published.manifests[0].generation = 2;
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;

        let drifted = fence_of(&published);
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), drifted],
            vec![Ok(published.clone())],
            1_100,
        );
        let next = load_with_l2(&deps, &cache, &l2).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(next, published);
        assert!(
            l2.contains(&l2_key_of(EPOCH)),
            "recheck drift must not purge the entry"
        );
    }

    /// 哈希正确但 payload 违反合同的条目（哈希不能替代授权有效性）→ 合同
    /// 校验失败 → 删键回源。
    #[tokio::test]
    async fn l2_contract_violating_payload_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();

        // 篡改 gate 计数后重算哈希：content_hash 重验通过，但合同校验必须拦下。
        let mut tampered = evidence.clone();
        tampered.gate.effective_grant_count += 1;
        let payload_json = serde_json::to_string(&tampered).expect("payload json");
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(
                fence_of(&evidence),
                l2_content_hash(&payload_json),
                &tampered,
            ),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2).await.expect("reload");
        assert_eq!(deps.strict_calls(), 1, "contract violation must not serve");
        assert_eq!(l2.del_calls(), 1, "contract-violating entry must be purged");
        // 回源成功 → 键被合法内容重写（污染不残留）；存储形折叠 + 重建 parity。
        let refilled: L2EvidenceEntry = serde_json::from_str(
            &l2.entries
                .lock()
                .unwrap()
                .get(&l2_key_of(EPOCH))
                .expect("refilled entry")
                .0,
        )
        .expect("refilled json");
        assert_eq!(reconstruct_entry_payload(&refilled, &l2), evidence);
        assert_eq!(next, evidence);
    }

    /// L2 命中路径的时钟重验（与 L1 同一函数）：accepted 记录在当前时钟下
    /// 过期 → 判陈旧 → 删键回源。
    #[tokio::test]
    async fn l2_clock_stale_payload_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            2_000,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("reload after expiry");
        assert_eq!(deps.strict_calls(), 1, "clock-stale L2 entry must miss");
        assert_eq!(l2.del_calls(), 1, "clock-stale entry must be purged");
        // 回源成功 → 键被回填覆盖（fixture 的严格读仍供应同一份合法证据）。
        let refilled: L2EvidenceEntry = serde_json::from_str(
            &l2.entries
                .lock()
                .unwrap()
                .get(&l2_key_of(EPOCH))
                .expect("refilled entry")
                .0,
        )
        .expect("refilled json");
        assert_eq!(reconstruct_entry_payload(&refilled, &l2), evidence);
        assert_eq!(next, evidence);
    }

    /// 推送形状：严格读一次 → 以内嵌当前时代的键、schema 3、TTL 300s、
    /// content_hash + MAC 与版本组写入（与读侧协议逐字段对齐）。
    #[tokio::test]
    async fn push_writes_epoch_embedded_key_with_hash_and_ttl() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let l2 = MemoryL2Store::new();
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(evidence.clone())],
            1_000,
        );
        push_evidence_to_l2_with(&l2, TEST_MAC_SECRET, &deps, TENANT, CARD).await;

        assert_eq!(deps.strict_calls(), 1, "option-a post-publish self-read");
        assert_eq!(l2.set_calls(), 1);
        let (raw, ttl) = l2
            .entries
            .lock()
            .unwrap()
            .get(&l2_key_of(EPOCH))
            .expect("pushed entry")
            .clone();
        assert_eq!(ttl, L2_EVIDENCE_TTL_SECONDS);
        assert!(raw.starts_with('{'), "value must be the entry JSON");
        let entry: L2EvidenceEntry = serde_json::from_str(&raw).expect("entry json");
        assert_eq!(entry.schema_version, L2_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(
            entry.manifest_versions,
            fence_of(&evidence).manifest_versions
        );
        assert!(!entry.card_source_pending);
        // v3 存储形态：USER_CARD 记录内联；重建后与完整证据逐字段 parity；
        // content_hash 绑定完整证据的序列化字节。
        assert!(
            entry
                .payload
                .records
                .iter()
                .all(|slot| matches!(slot, L2RecordSlot::Inline(_))),
            "v3 storage: records stay inline for non-RULE_SET aggregates"
        );
        assert_eq!(reconstruct_entry_payload(&entry, &l2), evidence);
        assert_eq!(entry.content_hash, full_payload_hash(&evidence));
    }

    /// 推送跳过：时代未知（Redis 降级）不推；严格读失败不推（静默，L2 留给
    /// 自然回源）。
    #[tokio::test]
    async fn push_skipped_for_unknown_epoch_or_strict_failure() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let l2 = MemoryL2Store::new();

        // 时代未知 → 不推。
        let deps = FixtureDeps::new(vec![None], vec![], vec![], 1_000);
        push_evidence_to_l2_with(&l2, TEST_MAC_SECRET, &deps, TENANT, CARD).await;
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(l2.set_calls(), 0);

        // 严格读失败 → 不推。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Err(AuthorizationEvidenceError::NotReady(
                "code=published_card_evidence.current_pointer_missing".into(),
            ))],
            1_000,
        );
        push_evidence_to_l2_with(&l2, TEST_MAC_SECRET, &deps, TENANT, CARD).await;
        assert_eq!(deps.strict_calls(), 1);
        assert_eq!(l2.set_calls(), 0);
        assert!(l2.is_empty());

        // 证据本身仍会被产出（deps 供应成功）→ 推送一次，对照形状。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(evidence.clone())],
            1_000,
        );
        push_evidence_to_l2_with(&l2, TEST_MAC_SECRET, &deps, TENANT, CARD).await;
        assert_eq!(l2.set_calls(), 1);
    }

    /// 发布影响卡作用域（纯逻辑）：仅 CARD 聚合且携带卡作用域才推送；
    /// ELIGIBILITY/RULE_SET 不推（L2 只承载 CARD 聚合的评估 evidence）；
    /// 卡作用域缺失不推。
    #[test]
    fn publish_affected_card_scope_only_for_card_aggregate() {
        let card = crate::authorization_projection_repository::ProjectionAggregateIdentity::new(
            TENANT, "CARD", 17,
        )
        .expect("valid identity");
        assert_eq!(
            publish_affected_card_scope(&card, Some(CARD)),
            Some((TENANT, CARD))
        );
        // 卡作用域缺失（aggregate-wide delta）→ 无法定位卡级 evidence 键。
        assert_eq!(publish_affected_card_scope(&card, None), None);

        for aggregate in ["ELIGIBILITY", "RULE_SET", "USER_CARD", "UNKNOWN"] {
            let other =
                crate::authorization_projection_repository::ProjectionAggregateIdentity::new(
                    TENANT, aggregate, 17,
                )
                .expect("valid identity");
            assert_eq!(
                publish_affected_card_scope(&other, Some(CARD)),
                None,
                "{aggregate} aggregates must not push L2 evidence"
            );
        }
    }

    /// 键族与 TTL/(schema) 常量钉死：epoch 内嵌键形状、L2 TTL 300s 严格大于
    /// L1 的 30s（取舍见模块文档）、schema 版本 4（v3 因子化存储 + HMAC +
    /// 记录级作用域绑定的基础上新增卡作用域未发布 delta 位 `card_source_pending`；
    /// v1 完整直存 / v2 折叠存储 / v3 无 pending 位均已退役，旧条目自然 purge
    /// 自愈）、共享单元键族形状与专用 HMAC 环境变量名。
    #[test]
    fn l2_key_shape_ttl_and_schema_constants_stay_bounded() {
        assert_eq!(
            l2_evidence_key("epoch-x", 7, 1),
            "astral:auth:l2ev:epoch-x:7:1"
        );
        assert_eq!(
            l2_shared_unit_key("epoch-x", 7, "digest"),
            "astral:auth:l2sh:epoch-x:7:digest"
        );
        assert_eq!(L2_EVIDENCE_SCHEMA_VERSION, 4);
        assert_eq!(L2_SHARED_UNIT_SCHEMA_VERSION, 1);
        assert_eq!(L2_EVIDENCE_TTL_SECONDS, 300);
        assert!(L2_EVIDENCE_TTL_SECONDS > EVIDENCE_CACHE_TTL.as_secs());
        assert_eq!(L2_EVIDENCE_CARD_AGGREGATE_TYPE, "CARD");
        assert_eq!(L2_SHARED_UNIT_AGGREGATE_TYPE, "RULE_SET");
        assert_eq!(
            L2_EVIDENCE_HMAC_SECRET_ENV,
            "ASTRAL_L2_EVIDENCE_HMAC_SECRET"
        );
        // 最小密钥长度的行为语义由 l2_hmac_secret_validation_is_fail_closed
        // 钉死（31 字符拒绝 / 32 字符接受），此处不重复常量断言。
        // 两个键族不相交；共享键族同样时代内嵌。
        assert_ne!(L2_EVIDENCE_SHARED_KEY_PREFIX, L2_EVIDENCE_KEY_PREFIX);
        assert_ne!(
            l2_shared_unit_key("e1", 7, "d"),
            l2_shared_unit_key("e2", 7, "d"),
            "shared unit keys must be epoch-scoped"
        );
        assert_ne!(
            l2_shared_unit_key("e1", 7, "d"),
            l2_shared_unit_key("e1", 8, "d"),
            "shared unit keys must be tenant-scoped"
        );
    }

    /// HMAC 密钥校验（纯逻辑，fail-closed）：未设置/过短/占位符/退化重复字符
    /// 一律拒绝；合法密钥按字节返回并做空白修剪。
    #[test]
    fn l2_hmac_secret_validation_is_fail_closed() {
        assert!(validate_l2_hmac_secret(None).is_none(), "unset must reject");
        assert!(validate_l2_hmac_secret(Some("")).is_none());
        assert!(validate_l2_hmac_secret(Some("short")).is_none());
        // ≥32 但命中占位符标记。
        let placeholder = format!("changeme-{}", "a".repeat(40));
        assert!(validate_l2_hmac_secret(Some(&placeholder)).is_none());
        let marker = format!("{}-secret", "x".repeat(40));
        assert!(validate_l2_hmac_secret(Some(&marker)).is_none());
        // 退化：全部字符相同。
        let repeated = "a".repeat(40);
        assert!(validate_l2_hmac_secret(Some(&repeated)).is_none());
        // 合法：≥32 字节/字符、无占位符标记。
        let good = "unit-l2-hmac-secret-value-0123456789abcdef";
        assert_eq!(
            validate_l2_hmac_secret(Some(good)).as_deref(),
            Some(good.as_bytes())
        );
        // 空白修剪后仍合法（修剪恰好达到下界时接受）。
        assert_eq!(
            validate_l2_hmac_secret(Some(&format!("  {good} "))).as_deref(),
            Some(good.as_bytes())
        );
    }

    // =====================================================================
    // L2 条目合同 v3 回归矩阵：因子化存储 + 共享单元 + HMAC + 记录级作用域
    // =====================================================================

    /// v3 因子化往返（真实写路径）：混合 USER_CARD/RULE_SET、accepted/排除
    /// 证据写入后，条目按原始顺序持有 Inline/Shared 槽位，RULE_SET 内容落
    /// tenant+时代限定共享单元（恰好一个），重建逐字节还原完整载荷，
    /// content_hash/MAC 绑定完整载荷，命中与直读逐字段相等（含排除记录）。
    #[tokio::test]
    async fn l2_v3_factored_roundtrip_reconstructs_byte_identical_payload() {
        let evidence = fixture_evidence(
            1_000,
            vec![
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(1, ValidityWindow::between(0, 2_000)),
                    true,
                    None,
                ),
                fixture_record(
                    "RULE_SET",
                    5,
                    10,
                    fixture_grant(2, ValidityWindow::between(0, 2_000)),
                    true,
                    None,
                ),
                fixture_record(
                    "RULE_SET",
                    5,
                    10,
                    fixture_grant(3, ValidityWindow::between(0, 2_000)),
                    false,
                    Some(UnacceptedGrantReason::InactiveState),
                ),
            ],
        );
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;

        let raw = l2
            .entries
            .lock()
            .unwrap()
            .get(&l2_key_of(EPOCH))
            .expect("entry")
            .0
            .clone();
        let entry: L2EvidenceEntry = serde_json::from_str(&raw).expect("entry json");
        // 槽位顺序 = 原始 records 顺序（字节级重建的前提）。
        assert!(matches!(entry.payload.records[0], L2RecordSlot::Inline(_)));
        assert!(matches!(entry.payload.records[1], L2RecordSlot::Shared(_)));
        assert!(matches!(entry.payload.records[2], L2RecordSlot::Shared(_)));
        assert!(
            !raw.contains(r#""effectiveGrants":"#),
            "effective_grants are never stored"
        );
        // RULE_SET 内容恰好落一个 tenant+时代限定共享单元；同卡同内容引用同一摘要。
        let digests = l2_referenced_unit_digests(&entry.payload);
        assert_eq!(
            digests.len(),
            1,
            "identical RULE_SET content dedupes to one unit"
        );
        let digest = digests.iter().next().expect("digest").clone();
        let unit_key = l2_shared_unit_key(EPOCH, TENANT, &digest);
        assert!(
            l2.contains(&unit_key),
            "unit must be written before the card entry"
        );
        assert!(
            !l2.contains(&l2_shared_unit_key("other-epoch", TENANT, &digest)),
            "units are epoch-scoped"
        );
        assert!(
            !l2.contains(&l2_shared_unit_key(EPOCH, TENANT + 1, &digest)),
            "units are tenant-scoped"
        );
        let unit_raw = l2
            .entries
            .lock()
            .unwrap()
            .get(&unit_key)
            .expect("unit")
            .0
            .clone();
        let unit: L2SharedUnit = serde_json::from_str(&unit_raw).expect("unit json");
        assert_eq!(unit.unit_schema_version, L2_SHARED_UNIT_SCHEMA_VERSION);
        assert_eq!(unit.digest, digest);
        assert_eq!(
            l2_shared_unit_digest(&unit.content),
            digest,
            "unit self-hash"
        );
        // 重建逐字节还原；content_hash 绑定完整证据。
        let mut units = HashMap::new();
        units.insert(digest, unit.content);
        let rebuilt = l2_reconstruct_full_payload(&entry.payload, &units).expect("reconstruction");
        assert_eq!(rebuilt, evidence);
        assert_eq!(
            serde_json::to_string(&rebuilt).expect("rebuilt json"),
            serde_json::to_string(&evidence).expect("evidence json"),
            "reconstruction must be byte-identical to the original evidence"
        );
        assert_eq!(entry.content_hash, full_payload_hash(&evidence));

        // 命中 parity：重建结果与直读逐字段相等，零严格读。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_050,
        );
        let hit = load_with_l2(&deps, &cache, &l2).await.expect("hit");
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(hit, evidence);
    }

    /// 跨卡存储去重：卡 A/卡 B 的 RULE_SET 内容单元字节级相同 → 恰好共享一个
    /// 共享单元键；两张卡各自保留独立卡条目与逐卡 envelope（grant 身份/卡戳
    /// 不同、单元摘要相同），且各自命中并逐字节还原自己的证据。
    #[tokio::test]
    async fn l2_v3_two_cards_share_one_rule_set_unit_with_separate_envelopes() {
        let evidence_a = fixture_evidence(
            1_000,
            vec![fixture_record(
                "RULE_SET",
                5,
                10,
                fixture_grant(2, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let evidence_b = fixture_evidence_scoped(
            TENANT,
            CARD + 1,
            1_000,
            vec![fixture_record(
                "RULE_SET",
                5,
                10,
                fixture_grant_scoped(TENANT, CARD + 1, 2, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence_a).await;
        seed_valid_entry(&l2, EPOCH, &evidence_b).await;

        // 卡键各自存在；共享单元恰好一个（内容寻址、卡无关）。
        assert!(l2.contains(&l2_evidence_key(EPOCH, TENANT, CARD)));
        assert!(l2.contains(&l2_evidence_key(EPOCH, TENANT, CARD + 1)));
        let shared: Vec<String> = l2
            .keys()
            .into_iter()
            .filter(|key| key.starts_with(L2_EVIDENCE_SHARED_KEY_PREFIX))
            .collect();
        assert_eq!(
            shared.len(),
            1,
            "two cards with identical content share one unit"
        );
        let digest = l2_referenced_unit_digests(
            &serde_json::from_str::<L2EvidenceEntry>(
                &l2.entries
                    .lock()
                    .unwrap()
                    .get(&l2_evidence_key(EPOCH, TENANT, CARD))
                    .expect("entry a")
                    .0,
            )
            .expect("entry a json")
            .payload,
        )
        .into_iter()
        .next()
        .expect("digest");
        // 两张卡的 envelope 引用同一单元摘要，但 grant 身份逐卡不同。
        for (card_id, evidence) in [(CARD, &evidence_a), (CARD + 1, &evidence_b)] {
            let entry: L2EvidenceEntry = serde_json::from_str(
                &l2.entries
                    .lock()
                    .unwrap()
                    .get(&l2_evidence_key(EPOCH, TENANT, card_id))
                    .expect("entry")
                    .0,
            )
            .expect("entry json");
            let L2RecordSlot::Shared(envelope) = &entry.payload.records[0] else {
                panic!("RULE_SET record must be factored");
            };
            assert_eq!(envelope.shared_unit_digest, digest);
            assert_eq!(envelope.grant.card_id, card_id, "envelope stays per-card");
            assert_eq!(envelope.grant.grant_id, evidence.records[0].grant.grant_id);
            let rebuilt = reconstruct_entry_payload(&entry, &l2);
            assert_eq!(rebuilt, *evidence, "per-card byte-identical reconstruction");
        }
        // 各自命中：零严格读，身份绝不串卡。
        let cache_a = fresh_cache();
        let deps_a = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_a), fence_of(&evidence_a)],
            vec![],
            1_050,
        );
        let hit_a = load_card_with_l2(&deps_a, &cache_a, &l2, TENANT, CARD)
            .await
            .expect("a hit");
        assert_eq!(deps_a.strict_calls(), 0);
        assert_eq!(hit_a, evidence_a);

        let cache_b = fresh_cache();
        let deps_b = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_b), fence_of(&evidence_b)],
            vec![],
            1_050,
        );
        let hit_b = load_card_with_l2(&deps_b, &cache_b, &l2, TENANT, CARD + 1)
            .await
            .expect("b hit");
        assert_eq!(deps_b.strict_calls(), 0);
        assert_eq!(hit_b, evidence_b);
    }

    /// 共享单元缺失（部分写/驱逐）→ purge 卡条目 + 回源；绝不放行部分数据。
    /// 回源自愈后单元与卡条目都被重写。
    #[tokio::test]
    async fn l2_v3_shared_unit_missing_purges_and_strict_reads() {
        let evidence = fixture_evidence(
            1_000,
            vec![fixture_record(
                "RULE_SET",
                5,
                10,
                fixture_grant(2, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;
        let digest = {
            let entry: L2EvidenceEntry = serde_json::from_str(
                &l2.entries
                    .lock()
                    .unwrap()
                    .get(&l2_key_of(EPOCH))
                    .expect("entry")
                    .0,
            )
            .expect("entry json");
            l2_referenced_unit_digests(&entry.payload)
                .into_iter()
                .next()
                .expect("digest")
        };
        let unit_key = l2_shared_unit_key(EPOCH, TENANT, &digest);
        l2.entries.lock().unwrap().remove(&unit_key);

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "missing unit must never serve partial data"
        );
        assert_eq!(l2.del_calls(), 1, "card entry must be purged");
        assert_eq!(next, evidence);
        // 回源自愈：单元先写、卡条目重写。
        assert!(
            l2.contains(&unit_key),
            "refill must restore the shared unit"
        );
        assert!(
            l2.contains(&l2_key_of(EPOCH)),
            "refill must restore the card entry"
        );
    }

    /// 共享单元内容被篡改（同键不同内容，摘要字段保持原值）→ 自校验失配 →
    /// purge 卡条目回源；被投毒的共享字节绝不参与重建。
    #[tokio::test]
    async fn l2_v3_shared_unit_hash_mismatch_purges() {
        let evidence = fixture_evidence(
            1_000,
            vec![fixture_record(
                "RULE_SET",
                5,
                10,
                fixture_grant(2, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;
        let digest = {
            let entry: L2EvidenceEntry = serde_json::from_str(
                &l2.entries
                    .lock()
                    .unwrap()
                    .get(&l2_key_of(EPOCH))
                    .expect("entry")
                    .0,
            )
            .expect("entry json");
            l2_referenced_unit_digests(&entry.payload)
                .into_iter()
                .next()
                .expect("digest")
        };
        let unit_key = l2_shared_unit_key(EPOCH, TENANT, &digest);
        let mut unit: L2SharedUnit =
            serde_json::from_str(&l2.entries.lock().unwrap().get(&unit_key).expect("unit").0)
                .expect("unit json");
        unit.content.resource = "tampered:*".to_owned();
        l2.seed(
            &unit_key,
            &serde_json::to_string(&unit).expect("tampered unit json"),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "hash-mismatched unit must never serve"
        );
        assert_eq!(l2.del_calls(), 1, "card entry must be purged");
        assert_eq!(next, evidence);
    }

    /// 跨卡投毒：卡 B 的完整证据（哈希对 B 一致、条目栅栏伪造为卡 A 的当前
    /// 栅栏）挂在卡 A 的键下 → 卡作用域绑定失败 → 删键回源；A 只能收到 A 的
    /// 严格证据，绝不放行 B 的授权，也绝不把 B 的身份改写成 A。
    #[tokio::test]
    async fn l2_cross_card_poisoned_payload_purges_scope_binding() {
        let evidence_a = single_record_evidence(1_000, 0, 2_000);
        let evidence_b = fixture_evidence_scoped(
            TENANT,
            CARD + 1,
            1_000,
            vec![fixture_record(
                "USER_CARD",
                1,
                9,
                fixture_grant_scoped(TENANT, CARD + 1, 1, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        // 攻击者手工播种：A 的键 + A 的栅栏 + B 的载荷 + 对 B 一致的哈希。
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(
                fence_of(&evidence_a),
                full_payload_hash(&evidence_b),
                &evidence_b,
            ),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_a)],
            vec![Ok(evidence_a.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "poisoned entry must fall back to strict read"
        );
        assert_eq!(l2.del_calls(), 1, "poisoned entry must be purged");
        assert_eq!(
            next, evidence_a,
            "card A must only ever receive its own evidence"
        );
        // 回源自愈：A 的键被 A 的合法存储形覆盖。
        let refilled: L2EvidenceEntry = serde_json::from_str(
            &l2.entries
                .lock()
                .unwrap()
                .get(&l2_key_of(EPOCH))
                .expect("refilled entry")
                .0,
        )
        .expect("refilled json");
        assert_eq!(reconstruct_entry_payload(&refilled, &l2), evidence_a);
    }

    /// 跨租户投毒：他租户证据挂在目标卡键下（栅栏伪造一致）→ 作用域绑定
    /// 失败 → 删键回源；租户边界在 L2 命中路径同样封死。
    #[tokio::test]
    async fn l2_cross_tenant_poisoned_payload_purges_scope_binding() {
        let evidence_a = single_record_evidence(1_000, 0, 2_000);
        let other_tenant = TENANT + 1;
        let evidence_x = fixture_evidence_scoped(
            other_tenant,
            CARD,
            1_000,
            vec![fixture_record(
                "USER_CARD",
                1,
                9,
                fixture_grant_scoped(other_tenant, CARD, 1, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(
                fence_of(&evidence_a),
                full_payload_hash(&evidence_x),
                &evidence_x,
            ),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_a)],
            vec![Ok(evidence_a.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "cross-tenant payload must never serve"
        );
        assert_eq!(l2.del_calls(), 1, "cross-tenant entry must be purged");
        assert_eq!(next, evidence_a);
    }

    /// manifest 戳投毒：顶层身份与 scope 一致、但 manifest 摘要携带他卡戳
    /// （哈希一致、合同校验不拦戳）→ 唯一防线是卡作用域绑定 → 删键回源。
    #[tokio::test]
    async fn l2_manifest_stamp_mismatch_purges_scope_binding() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let mut forged = evidence.clone();
        forged.manifests[0].card_id = CARD + 1;
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(fence_of(&evidence), full_payload_hash(&forged), &forged),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "forged manifest stamp must never serve"
        );
        assert_eq!(l2.del_calls(), 1, "forged entry must be purged");
        assert_eq!(next, evidence);
    }

    /// 部分写（截断/垃圾字节）→ 解码失败 → 删键回源；半截条目绝不放行。
    #[tokio::test]
    async fn l2_partial_write_undecodable_entry_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        l2.seed(
            &l2_key_of(EPOCH),
            "{\"schemaVersion\":2,\"manifestVersions\":[{\"aggregateType\":\"USER",
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "partial write must fall back to strict read"
        );
        assert_eq!(l2.del_calls(), 1, "undecodable entry must be purged");
        assert_eq!(next, evidence);
    }

    /// v3 形状违约：payload 携带旧 v2 完整载荷形状（records 无槽位标签、
    /// 含 effectiveGrants）→ 解码失败 → 删键回源；非因子化载荷绝不被信任。
    #[tokio::test]
    async fn l2_non_factored_payload_undecodable_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        // 手工把 v2 完整 payload 塞进 schema 3 条目（哈希对完整形式一致、
        // MAC 合法）—— 只有因子化形状门槛能拦下。
        let stuffed = serde_json::json!({
            "schemaVersion": L2_EVIDENCE_SCHEMA_VERSION,
            "manifestVersions": fence_of(&evidence),
            "contentHash": full_payload_hash(&evidence),
            "mac": "0".repeat(64),
            "payload": serde_json::to_value(&evidence).expect("full payload value"),
        });
        l2.seed(
            &l2_key_of(EPOCH),
            &stuffed.to_string(),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "non-factored payload must never serve"
        );
        assert_eq!(l2.del_calls(), 1, "stuffed entry must be purged");
        assert_eq!(next, evidence);
    }

    /// 不变式钉死：读侧绝不重写 payload/grant 身份，共享单元绝不含身份。
    /// 因子化→重建的往返逐字节还原完整证据（含 accepted 展开）；测试逐字段
    /// 显式断言 tenant/card/grant_id/provenance 戳在 envelope 与重建前后不变，
    /// 且单元内容序列化字节不含任何身份字段。
    #[test]
    fn l2_factored_reconstruction_preserves_identity_and_units_are_identity_free() {
        let evidence = fixture_evidence(
            1_000,
            vec![
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(1, ValidityWindow::between(0, 2_000)),
                    true,
                    None,
                ),
                fixture_record(
                    "RULE_SET",
                    5,
                    10,
                    fixture_grant(2, ValidityWindow::between(0, 2_000)),
                    true,
                    None,
                ),
                fixture_record(
                    "RULE_SET",
                    5,
                    10,
                    fixture_grant(3, ValidityWindow::between(0, 2_000)),
                    false,
                    Some(UnacceptedGrantReason::InactiveState),
                ),
            ],
        );
        let (factored, units) = l2_factored_storage_form(&evidence);
        // 因子化不改身份：顶层、manifest 摘要逐项相等；槽位顺序与原 records
        // 一致；共享槽位的 envelope 身份（grant_id/tenant/card/user/provenance/
        // 生命周期字段）与原记录逐项相等。
        assert_eq!(factored.tenant_id, evidence.tenant_id);
        assert_eq!(factored.card_id, evidence.card_id);
        assert_eq!(factored.manifests, evidence.manifests);
        assert_eq!(factored.records.len(), evidence.records.len());
        assert!(matches!(factored.records[0], L2RecordSlot::Inline(_)));
        assert!(matches!(factored.records[1], L2RecordSlot::Shared(_)));
        assert!(matches!(factored.records[2], L2RecordSlot::Shared(_)));
        for (slot, original) in factored.records.iter().zip(&evidence.records) {
            if let L2RecordSlot::Shared(envelope) = slot {
                assert_eq!(envelope.grant.grant_id, original.grant.grant_id);
                assert_eq!(envelope.grant.tenant, original.grant.tenant);
                assert_eq!(envelope.grant.card_id, original.grant.card_id);
                assert_eq!(envelope.grant.user_id, original.grant.user_id);
                assert_eq!(envelope.grant.state, original.grant.state);
                assert_eq!(envelope.grant.revision, original.grant.revision);
                assert_eq!(envelope.grant.source_kind, original.grant.source_kind);
                assert_eq!(envelope.grant.binding_layer, original.grant.binding_layer);
                assert_eq!(envelope.grant.provenance, original.grant.provenance);
                assert_eq!(envelope.aggregate_id, original.aggregate_id);
                assert_eq!(envelope.manifest_id, original.manifest_id);
                assert_eq!(
                    envelope.publication_generation,
                    original.publication_generation
                );
                assert_eq!(envelope.revoke_fence, original.revoke_fence);
                assert_eq!(envelope.event_id, original.event_id);
                assert_eq!(envelope.operation_id, original.operation_id);
                assert_eq!(envelope.segment_ordinal, original.segment_ordinal);
                assert_eq!(envelope.position_in_segment, original.position_in_segment);
                assert_eq!(
                    envelope.accepted_into_effective_set,
                    original.accepted_into_effective_set
                );
                assert_eq!(envelope.unaccepted_reason, original.unaccepted_reason);
            }
        }
        // 共享单元身份自由：内容序列化字节不含 tenant/card/user/grant 身份。
        assert!(!units.is_empty());
        for content in units.values() {
            let json = serde_json::to_string(content).expect("unit content json");
            for marker in ["tenantId", "cardId", "userId", "grantId", "provenance"] {
                assert!(
                    !json.contains(marker),
                    "shared unit content must not carry identity field {marker}: {json}"
                );
            }
        }
        // 重建 = 完整还原（含 accepted 展开的 effective_grants），逐字节 parity。
        let unit_refs: HashMap<String, L2SharedUnitContent> = units
            .iter()
            .map(|(digest, content)| (digest.clone(), content.clone()))
            .collect();
        let rebuilt = l2_reconstruct_full_payload(&factored, &unit_refs).expect("all units known");
        assert_eq!(rebuilt, evidence);
        assert_eq!(
            serde_json::to_string(&rebuilt).expect("rebuilt json"),
            serde_json::to_string(&evidence).expect("evidence json"),
            "reconstruction must be byte-identical to the original evidence"
        );
        for (record, original) in rebuilt.records.iter().zip(&evidence.records) {
            assert_eq!(record.grant.card_id, original.grant.card_id);
            assert_eq!(record.grant.tenant, original.grant.tenant);
            assert_eq!(record.grant.user_id, original.grant.user_id);
            assert_eq!(record.grant.grant_id, original.grant.grant_id);
            assert_eq!(record.grant.provenance, original.grant.provenance);
        }
        for (manifest, original) in rebuilt.manifests.iter().zip(&evidence.manifests) {
            assert_eq!(manifest.tenant_id, original.tenant_id);
            assert_eq!(manifest.card_id, original.card_id);
        }
    }

    /// 不变式钉死：栅栏/条目逐卡私有，绝不跨卡共享。A/B 各自命中自己的条目
    /// 后，A 的栅栏推进只 purge/重填 A，B 仍按自己的栅栏命中自己的条目
    /// （A 的失配清除不波及 B 的键与栅栏基准）。
    #[tokio::test]
    async fn l2_fence_envelope_is_per_card_and_never_shared() {
        let evidence_a = single_record_evidence(1_000, 0, 2_000);
        let evidence_b = fixture_evidence_scoped(
            TENANT,
            CARD + 1,
            1_000,
            vec![fixture_record(
                "USER_CARD",
                1,
                9,
                fixture_grant_scoped(TENANT, CARD + 1, 1, ValidityWindow::perpetual()),
                true,
                None,
            )],
        );
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence_a).await;
        seed_valid_entry(&l2, EPOCH, &evidence_b).await;

        // 各自命中：读前+读后栅栏 = 各自证据的版本组（逐卡 envelope）。
        let cache_a = fresh_cache();
        let deps_a = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_a), fence_of(&evidence_a)],
            vec![],
            1_050,
        );
        let hit_a = load_card_with_l2(&deps_a, &cache_a, &l2, TENANT, CARD)
            .await
            .expect("a hit");
        assert_eq!(deps_a.strict_calls(), 0);
        assert_eq!(hit_a, evidence_a);

        let cache_b = fresh_cache();
        let deps_b = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_b), fence_of(&evidence_b)],
            vec![],
            1_050,
        );
        let hit_b = load_card_with_l2(&deps_b, &cache_b, &l2, TENANT, CARD + 1)
            .await
            .expect("b hit");
        assert_eq!(deps_b.strict_calls(), 0);
        assert_eq!(hit_b, evidence_b);

        // A 的栅栏推进：A 对牌失败 → purge + 回源；B 的条目与栅栏不受波及。
        let mut advanced = evidence_a.clone();
        advanced.manifests[0].generation = 2;
        let cache_a2 = fresh_cache();
        let deps_a2 = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&advanced)],
            vec![Ok(advanced.clone())],
            1_060,
        );
        let next_a = load_card_with_l2(&deps_a2, &cache_a2, &l2, TENANT, CARD)
            .await
            .expect("a reload");
        assert_eq!(deps_a2.strict_calls(), 1);
        assert_eq!(l2.del_calls(), 1, "A's mismatched entry must be purged");
        assert_eq!(next_a, advanced);

        let cache_b2 = fresh_cache();
        let deps_b2 = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_b), fence_of(&evidence_b)],
            vec![],
            1_070,
        );
        let hit_b2 = load_card_with_l2(&deps_b2, &cache_b2, &l2, TENANT, CARD + 1)
            .await
            .expect("b still hits");
        assert_eq!(deps_b2.strict_calls(), 0, "B must still hit its own entry");
        assert_eq!(hit_b2, evidence_b);
    }

    /// MAC 缺失：条目 JSON 移除 `mac` 字段 → 解码失败（mac 必填）→ 删键回源；
    /// 未认证条目绝不可能被接受。
    #[tokio::test]
    async fn l2_v3_mac_missing_entry_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        let raw = raw_entry_json(fence_of(&evidence), full_payload_hash(&evidence), &evidence);
        let mut value: serde_json::Value = serde_json::from_str(&raw).expect("entry value");
        assert!(
            value
                .as_object_mut()
                .expect("object")
                .remove("mac")
                .is_some(),
            "fixture must carry a mac field to remove"
        );
        l2.seed(
            &l2_key_of(EPOCH),
            &value.to_string(),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(deps.strict_calls(), 1, "MAC-less entry must never serve");
        assert_eq!(l2.del_calls(), 1, "MAC-less entry must be purged");
        assert_eq!(next, evidence);
    }

    /// MAC 错误密钥：cover 全部一致（键/栅栏/哈希/载荷）但 MAC 以攻击者自己的
    /// 密钥计算 → 常数时间校验失败 → 删键回源。
    #[tokio::test]
    async fn l2_v3_mac_wrong_secret_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        let attacker_secret = b"attacker-held-l2-secret-value-0123456789abcdef";
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json_for_key(
                &l2_key_of(EPOCH),
                fence_of(&evidence),
                full_payload_hash(&evidence),
                &evidence,
                attacker_secret,
            ),
            L2_EVIDENCE_TTL_SECONDS,
        );

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(deps.strict_calls(), 1, "wrong-secret MAC must never serve");
        assert_eq!(l2.del_calls(), 1, "wrong-MAC entry must be purged");
        assert_eq!(next, evidence);
    }

    /// 键绑定重放：条目为 epoch-1 键签发（MAC cover 绑定该键），复制到同卡
    /// epoch-2 键下 → 顶层/栅栏一致，但精确键失配 → MAC 校验失败 → purge；
    /// 跨卡复制 A 的合法条目到 B 键 → envelope 顶层 scope 预检拦截。键名绝不
    /// 是身份，条目与键的绑定由 MAC 承担。
    #[tokio::test]
    async fn l2_v3_key_bound_replay_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        // 1) 同卡跨时代键重放：MAC 绑定 epoch-1 键，重放到 epoch-2 键。
        let entry_epoch1 = raw_entry_json_for_key(
            &l2_evidence_key("epoch-1", TENANT, CARD),
            fence_of(&evidence),
            full_payload_hash(&evidence),
            &evidence,
            TEST_MAC_SECRET,
        );
        l2.seed(
            &l2_evidence_key("epoch-2", TENANT, CARD),
            &entry_epoch1,
            L2_EVIDENCE_TTL_SECONDS,
        );
        let deps = FixtureDeps::new(
            vec![Some("epoch-2".into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let scope = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        let next = load_evidence_through_cache_with_mac(
            &deps,
            &cache,
            Some(&l2),
            Some(TEST_MAC_SECRET),
            &scope,
        )
        .await
        .expect("strict fallback");
        assert_eq!(deps.strict_calls(), 1, "key-bound replay must never serve");
        assert_eq!(l2.del_calls(), 1, "replayed entry must be purged");
        assert_eq!(next, evidence);

        // 2) 跨卡重放：写路径签发的 A 条目字节复制到 B 键 → 顶层 scope 预检拦截。
        seed_valid_entry(&l2, EPOCH, &evidence).await;
        let card_a_bytes = l2
            .entries
            .lock()
            .unwrap()
            .get(&l2_key_of(EPOCH))
            .expect("card a entry")
            .0
            .clone();
        let cache_b = fresh_cache();
        let l2_b = MemoryL2Store::new();
        l2_b.seed(
            &l2_evidence_key(EPOCH, TENANT, CARD + 1),
            &card_a_bytes,
            L2_EVIDENCE_TTL_SECONDS,
        );
        let evidence_b = fixture_evidence_scoped(
            TENANT,
            CARD + 1,
            1_000,
            vec![fixture_record(
                "USER_CARD",
                1,
                9,
                fixture_grant_scoped(TENANT, CARD + 1, 1, ValidityWindow::between(0, 2_000)),
                true,
                None,
            )],
        );
        let deps_b = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence_b)],
            vec![Ok(evidence_b.clone())],
            1_050,
        );
        let scope_b = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD + 1,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        let next_b = load_evidence_through_cache_with_mac(
            &deps_b,
            &cache_b,
            Some(&l2_b),
            Some(TEST_MAC_SECRET),
            &scope_b,
        )
        .await
        .expect("strict fallback");
        assert_eq!(
            deps_b.strict_calls(),
            1,
            "cross-card replay must never serve"
        );
        assert_eq!(
            l2_b.del_calls(),
            1,
            "cross-card replayed entry must be purged"
        );
        assert_eq!(
            next_b, evidence_b,
            "card B must only receive its own evidence"
        );
    }

    /// 记录级作用域投毒（持有密钥的攻击者模型）：顶层/栅栏/哈希/MAC 全部合法，
    /// 但某条 record 的 grant 携带他卡（或他租户）戳 → 记录级作用域绑定失败 →
    /// 删键回源；他卡/他租户的 grant 绝不借同卡条目放行。
    #[tokio::test]
    async fn l2_v3_record_level_scope_poison_purges() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();

        // 1) 同卡条目 + 他卡 grant（顶层与 manifest 戳保持一致）。
        let mut cross_card = evidence.clone();
        cross_card.records[0].grant.card_id = CARD + 1;
        cross_card.effective_grants[0].card_id = CARD + 1;
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(
                fence_of(&evidence),
                full_payload_hash(&cross_card),
                &cross_card,
            ),
            L2_EVIDENCE_TTL_SECONDS,
        );
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_with_l2(&deps, &cache, &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "foreign-card grant must never serve"
        );
        assert_eq!(l2.del_calls(), 1, "record-poisoned entry must be purged");
        assert_eq!(next, evidence);

        // 2) 同卡条目 + 他租户 grant。
        let mut cross_tenant = evidence.clone();
        cross_tenant.records[0].grant.tenant.tenant_id = TENANT + 1;
        cross_tenant.effective_grants[0].tenant.tenant_id = TENANT + 1;
        l2.seed(
            &l2_key_of(EPOCH),
            &raw_entry_json(
                fence_of(&evidence),
                full_payload_hash(&cross_tenant),
                &cross_tenant,
            ),
            L2_EVIDENCE_TTL_SECONDS,
        );
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence)],
            vec![Ok(evidence.clone())],
            1_060,
        );
        let next = load_with_l2(&deps, &fresh_cache(), &l2)
            .await
            .expect("strict fallback");
        assert_eq!(
            deps.strict_calls(),
            1,
            "foreign-tenant grant must never serve"
        );
        assert_eq!(
            l2.del_calls(),
            2,
            "record-poisoned entry must be purged again"
        );
        assert_eq!(next, evidence);
    }

    /// 非 RULE_SET 记录保持内联：USER_CARD 证据写入后零共享单元键、条目全部
    /// Inline 槽位，命中与直读逐字段相等。
    #[tokio::test]
    async fn l2_v3_non_rule_set_records_stay_inline_without_shared_units() {
        let evidence = fixture_evidence(
            1_000,
            vec![
                fixture_record(
                    "USER_CARD",
                    1,
                    9,
                    fixture_grant(1, ValidityWindow::between(0, 2_000)),
                    true,
                    None,
                ),
                fixture_record(
                    "CARD",
                    2,
                    11,
                    fixture_grant(4, ValidityWindow::between(0, 2_000)),
                    false,
                    Some(UnacceptedGrantReason::InactiveState),
                ),
            ],
        );
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        seed_valid_entry(&l2, EPOCH, &evidence).await;
        assert!(
            l2.keys()
                .into_iter()
                .all(|key| !key.starts_with(L2_EVIDENCE_SHARED_KEY_PREFIX)),
            "non-RULE_SET evidence must not create shared units"
        );
        let entry: L2EvidenceEntry = serde_json::from_str(
            &l2.entries
                .lock()
                .unwrap()
                .get(&l2_key_of(EPOCH))
                .expect("entry")
                .0,
        )
        .expect("entry json");
        assert!(entry
            .payload
            .records
            .iter()
            .all(|slot| matches!(slot, L2RecordSlot::Inline(_))));

        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![fence_of(&evidence), fence_of(&evidence)],
            vec![],
            1_050,
        );
        let hit = load_with_l2(&deps, &cache, &l2).await.expect("hit");
        assert_eq!(deps.strict_calls(), 0);
        assert_eq!(hit, evidence);
    }

    /// HMAC 密钥不可用（未设置/无效）→ fail-closed：L2 读零访问、写零落键，
    /// 直接严格 reader 兜底；显式 write 同样整体跳过。
    #[tokio::test]
    async fn l2_v3_secret_unavailable_bypasses_l2_read_and_write() {
        let evidence = single_record_evidence(1_000, 0, 2_000);
        let cache = fresh_cache();
        let l2 = MemoryL2Store::new();
        let scope = PublishedCardEvidenceScope {
            tenant_id: TENANT,
            card_id: CARD,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        // 读旁路：L2 在场但 mac=None → 零 L2 访问，严格读一次并只回填 L1。
        let deps = FixtureDeps::new(
            vec![Some(EPOCH.into())],
            vec![],
            vec![Ok(evidence.clone())],
            1_050,
        );
        let next = load_evidence_through_cache_with_mac(&deps, &cache, Some(&l2), None, &scope)
            .await
            .expect("strict read");
        assert_eq!(
            deps.strict_calls(),
            1,
            "no-secret must fall back to strict reader"
        );
        assert_eq!(l2.get_calls(), 0, "no-secret reads must not touch L2");
        assert_eq!(l2.set_calls(), 0, "no-secret refills must not write L2");
        assert!(l2.is_empty());
        assert_eq!(next, evidence);

        // 写旁路：显式 write 调用同样跳过（绝不落未认证条目）。
        write_l2_evidence(&l2, None, EPOCH, &evidence).await;
        assert!(l2.is_empty(), "no-secret writes must not create entries");
    }
}
