//! 受保护资源 ownership 解析的进程内记忆读面（default-off，`resource_ownership`
//! 的私有子模块）。
//!
//! 目标：单机组合进程（hub 已安装、通道健康、
//! `auxiliary_authorization_mirror` 已全局安装——复合激活标记，独立 Rabbit
//! hub 不 qualify）把"路由派生键的正常 TenantScoped 解析"从每次一次严格
//! DB 读改为进程内命中；命中值**只来自既有严格 resolver 的已验证正结果**，
//! 本模块零事实构造、零客户端绑定拷贝。
//!
//! ## 与 hub 严格读 token 的原子协议（与 `auxiliary_authorization_mirror`
//! 同源的不变式）
//!
//! - **token 先于 await 捕获，install/return 前复验**：读 token 取自
//!   [`MemoryProjectionHub::strict_read_token`]（含 mutation/health revision，
//!   writer-active 与 uncertain 时为 `None`）。任何 hub 内部变更——包括
//!   projector 安装已发布状态（`bump_scope` 推进 mutation revision）——都会
//!   使旧 token 失配，in-flight 读保守 fail-closed；本模块自身的缓存元数据
//!   安装不触碰 hub，不推进任何 hub revision。
//! - **WriterActive/Uncertain 直接拒绝**：返回 `Unavailable`、零 DB 查询，
//!   绝不回源旧状态放行，绝不放大既有放行面。
//! - **StrictRequired 绕过缓存**：hub 通道不健康（未预热/心跳过期/suspect）
//!   但 source writer 证明仍当前（token 仍可签发）时，不做任何缓存交互，
//!   只做有界严格读 + 返回前最终 token 复验。
//! - **只缓存正向已验证 `TenantScoped`**：`Unresolved` / `Unavailable` 与
//!   一切否定结果**永不缓存**（否定不是授权事实，缓存会伪装权威缺失），
//!   逐次回源既有严格 resolver。
//! - **键 = 完整路由派生身份**：resource/path/method/query_target/
//!   actor_card/actor_user 全量入键，绝不跨键命中；不拷贝任何客户端签名
//!   租户/域头（resolver 本身也不信任它们）。键字符串有界，超界键一律
//!   回落严格读。
//! - **chat 变体完全排除**：`ChatConversation` / `ChatConversationWithoutOwner`
//!   / `ChatMessage` 三类 lookup 读冻结仓 `astral-chat` 的表，其写者不受
//!   hub 栅栏保护（frozen writers unguarded），缓存它们等于无纪元失效的
//!   stale 授权面 —— 这三类完全不走记忆路径，保持既有严格 DB 读。
//! - **容量有界**：entries 上限 + 估算字节上限 + TTL（仅 GC 语义，正确性
//!   完全来自 token 栅栏）；超限拒绝安装（严格结果仍返回，只是不驻留）。
//! - **回填 single-flight**：同键并发只放一个严格回源（scope 上限 1024、
//!   等待/查询各 3s，对齐 hub `strict_refill` 与辅助镜像）；容量耗尽/等待
//!   超时/查询超时一律 fail-closed `Unavailable`，绝不 fallback 旧值，
//!   绝不 race 一个 ALLOW。

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

use crate::memory_projection_hub::{AuxiliaryReadToken, MemoryProjectionHub};
use crate::resource_ownership::ResourceOwnershipResolution;

/// 记忆条目 TTL：仅 GC/容量语义。正确性不依赖 TTL —— hub token 栅栏保证
/// 任何 source mutation / hub 变更后条目不可命中；TTL 只约束无变更时的驻留。
pub(super) const OWNERSHIP_MEMORY_TTL: Duration = Duration::from_secs(300);

/// 条目容量上限（全键条数）。
pub(super) const MAX_OWNERSHIP_MEMORY_ENTRIES: usize = 8_192;
/// 条目估算字节总量上限。
pub(super) const MAX_OWNERSHIP_MEMORY_BYTES: u64 = 8 * 1024 * 1024;
/// 键字符串的单串字节上限（path/resource）；超界键不走记忆路径。
pub(super) const MAX_KEY_STRING_BYTES: usize = 2_048;
/// method 的单串字节上限（HTTP verb 远小于此值）。
pub(super) const MAX_KEY_METHOD_BYTES: usize = 16;

/// single-flight 回填的并发 scope 上限与等待/查询预算（对齐 hub strict_refill
/// 与 `auxiliary_authorization_mirror`）。
pub(super) const MAX_REFILL_SCOPES: usize = 1_024;
pub(super) const REFILL_LOCK_WAIT: Duration = Duration::from_secs(3);
pub(super) const REFILL_QUERY_DEADLINE: Duration = Duration::from_secs(3);

/// fail-closed 语义码（`Unavailable` 携带，由 `PolicyEngine` 拒绝）。
pub(super) const CODE_WRITER_REFUSED: &str =
    "resource_ownership.resolver_writer_active_or_uncertain";
pub(super) const CODE_RACED_REFILL: &str = "resource_ownership.resolver_invalidation_raced_refill";
pub(super) const CODE_RACED_RETURN: &str = "resource_ownership.resolver_invalidation_raced_return";
pub(super) const CODE_REFILL_CAPACITY: &str =
    "resource_ownership.resolver_refill_capacity_exhausted";
pub(super) const CODE_REFILL_WAIT_TIMEOUT: &str = "resource_ownership.resolver_refill_wait_timeout";
pub(super) const CODE_STRICT_TIMEOUT: &str = "resource_ownership.resolver_strict_read_timeout";

pub(super) fn unavailable(code: &'static str) -> ResourceOwnershipResolution {
    ResourceOwnershipResolution::Unavailable { code }
}

/// 记忆全键：resolver 的全部路由派生输入，绝不跨键命中。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct OwnershipMemoryKey {
    pub(super) resource: String,
    pub(super) path: String,
    pub(super) method: String,
    pub(super) query_target_id: Option<i64>,
    pub(super) actor_card_id: Option<i64>,
    pub(super) actor_user_id: Option<i64>,
}

impl OwnershipMemoryKey {
    /// 有界键构造：任一字符串超界返回 `None`（调用方回落严格读，绝不缓存
    /// 无法计量的异常键）。
    pub(super) fn new(
        resource: &str,
        path: &str,
        method: &str,
        query_target_id: Option<i64>,
        actor_card_id: Option<i64>,
        actor_user_id: Option<i64>,
    ) -> Option<Self> {
        if resource.is_empty()
            || method.is_empty()
            || resource.len() > MAX_KEY_STRING_BYTES
            || path.len() > MAX_KEY_STRING_BYTES
            || method.len() > MAX_KEY_METHOD_BYTES
        {
            return None;
        }
        Some(Self {
            resource: resource.to_owned(),
            path: path.to_owned(),
            method: method.to_owned(),
            query_target_id,
            actor_card_id,
            actor_user_id,
        })
    }
}

/// 记忆条目：token 是安装时 hub 严格读状态；命中要求安装 token 与当前读
/// token 完全一致（任何 hub 变更即 miss）。
#[derive(Debug, Clone)]
struct OwnershipMemoryEntry {
    installed_at: Instant,
    token: AuxiliaryReadToken,
    value: ResourceOwnershipResolution,
}

#[derive(Default)]
struct OwnershipMemoryMaps {
    entries: HashMap<OwnershipMemoryKey, OwnershipMemoryEntry>,
    total_bytes: u64,
}

impl OwnershipMemoryMaps {
    fn evict_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.installed_at) <= OWNERSHIP_MEMORY_TTL
        });
        self.total_bytes = self
            .entries
            .keys()
            .map(entry_estimated_bytes)
            .fold(0u64, u64::saturating_add);
    }
}

/// 条目估算字节：键字符串实长 + 常数固定开销（id 对、token、时间戳、哈希
/// 槽位）+ `TenantScoped` 值载荷。上限语义保守即可，正确性来自 token。
fn entry_estimated_bytes(key: &OwnershipMemoryKey) -> u64 {
    (key.resource.len() + key.path.len() + key.method.len()) as u64 + 256 + 64
}

/// 进程级记忆实例（惰性创建；仅当复合激活标记齐备的调用才会触达）。
static GLOBAL_OWNERSHIP_MEMORY: OnceLock<OwnershipMemory> = OnceLock::new();

pub(super) fn global_ownership_memory() -> &'static OwnershipMemory {
    GLOBAL_OWNERSHIP_MEMORY.get_or_init(OwnershipMemory::default)
}

/// 进程内 ownership 记忆读面。克隆共享同一状态（Arc）。
#[derive(Default)]
pub(super) struct OwnershipMemory {
    maps: RwLock<OwnershipMemoryMaps>,
    refills: Mutex<HashMap<OwnershipMemoryKey, Weak<tokio::sync::Mutex<()>>>>,
}

impl OwnershipMemory {
    /// 本地命中判定（纯读锁）：条目在 TTL 内且安装 token 与本次读 token
    /// 一致。任何 hub 变更后 token 失配 → miss（回填同源重读），绝不 serve。
    fn cache_hit(
        &self,
        key: &OwnershipMemoryKey,
        token: &AuxiliaryReadToken,
    ) -> Option<ResourceOwnershipResolution> {
        let maps = self.maps.read().ok()?;
        let entry = maps.entries.get(key)?;
        if entry.installed_at.elapsed() > OWNERSHIP_MEMORY_TTL {
            return None;
        }
        if entry.token != *token {
            return None;
        }
        Some(entry.value.clone())
    }

    /// 安装正向已验证条目；容量不足只拒绝驻留（严格结果仍由调用方返回），
    /// 绝不为安装而逐出有效条目、绝不 suspect hub（本记忆只是加速层）。
    fn install(
        &self,
        key: &OwnershipMemoryKey,
        token: AuxiliaryReadToken,
        value: ResourceOwnershipResolution,
    ) {
        let Ok(mut maps) = self.maps.write() else {
            return;
        };
        maps.evict_expired(Instant::now());
        let existing_bytes = maps
            .entries
            .get(key)
            .map(|_| entry_estimated_bytes(key))
            .unwrap_or(0);
        let projected = maps
            .total_bytes
            .saturating_sub(existing_bytes)
            .saturating_add(entry_estimated_bytes(key));
        if maps.entries.len() >= MAX_OWNERSHIP_MEMORY_ENTRIES
            || projected > MAX_OWNERSHIP_MEMORY_BYTES
        {
            return;
        }
        maps.total_bytes = projected;
        maps.entries.insert(
            key.clone(),
            OwnershipMemoryEntry {
                installed_at: Instant::now(),
                token,
                value,
            },
        );
    }

    fn refill_lock(&self, key: &OwnershipMemoryKey) -> Option<Arc<tokio::sync::Mutex<()>>> {
        let mut scopes = self.refills.lock().ok()?;
        scopes.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = scopes.get(key).and_then(Weak::upgrade) {
            return Some(lock);
        }
        if scopes.len() >= MAX_REFILL_SCOPES {
            return None;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        scopes.insert(key.clone(), Arc::downgrade(&lock));
        Some(lock)
    }

    /// 记忆读协议本体：命中/单飞/超时/token 栅栏全部在此；严格解析以
    /// `strict` 工厂注入（生产入口传既有严格 resolver，同 crate 测试注入
    /// 受控 fake —— 仅私有可见，不构成公开替代权威）。
    ///
    /// 契约：工厂至多被调用一次（single-flight 锁持有者）；工厂 future 由
    /// [`REFILL_QUERY_DEADLINE`] 硬 deadline 包裹，超时即 drop（取消回源）
    /// 并 fail-closed `Unavailable`，绝不二次查询、绝不回落旧值；token 在
    /// await 前已捕获，install 与 return 前各复验一次
    /// [`MemoryProjectionHub::auxiliary_read_matches`]。
    pub(super) async fn serve_or_refill<S, Fut>(
        &self,
        hub: &MemoryProjectionHub,
        token: AuxiliaryReadToken,
        key: OwnershipMemoryKey,
        strict: S,
    ) -> ResourceOwnershipResolution
    where
        S: FnOnce() -> Fut,
        Fut: Future<Output = ResourceOwnershipResolution>,
    {
        if let Some(value) = self.cache_hit(&key, &token) {
            if !hub.auxiliary_read_matches(token) {
                return unavailable(CODE_RACED_RETURN);
            }
            return value;
        }
        let Some(lock) = self.refill_lock(&key) else {
            return unavailable(CODE_REFILL_CAPACITY);
        };
        let _guard = match tokio::time::timeout(REFILL_LOCK_WAIT, lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => return unavailable(CODE_REFILL_WAIT_TIMEOUT),
        };
        if !hub.auxiliary_read_matches(token) {
            return unavailable(CODE_RACED_REFILL);
        }
        if let Some(value) = self.cache_hit(&key, &token) {
            if !hub.auxiliary_read_matches(token) {
                return unavailable(CODE_RACED_RETURN);
            }
            return value;
        }
        let outcome = match tokio::time::timeout(REFILL_QUERY_DEADLINE, strict()).await {
            Ok(outcome) => outcome,
            Err(_) => return unavailable(CODE_STRICT_TIMEOUT),
        };
        // 只有正向已验证 TenantScoped 可驻留；否定结果（Unresolved/
        // Unavailable）不是授权事实，永不缓存。
        if matches!(outcome, ResourceOwnershipResolution::TenantScoped { .. }) {
            if !hub.auxiliary_read_matches(token) {
                return unavailable(CODE_RACED_REFILL);
            }
            self.install(&key, token, outcome.clone());
        }
        if !hub.auxiliary_read_matches(token) {
            return unavailable(CODE_RACED_RETURN);
        }
        outcome
    }

    /// 测试/诊断：当前条目数。
    #[cfg(test)]
    pub(super) fn entry_count(&self) -> usize {
        self.maps.read().map(|maps| maps.entries.len()).unwrap_or(0)
    }

    /// 测试播种：以指定 token 与安装时刻直接放置条目（纯测试用；生产唯一
    /// 安装入口是严格回填）。
    #[cfg(test)]
    pub(super) fn seed_entry_for_test(
        &self,
        key: OwnershipMemoryKey,
        token: AuxiliaryReadToken,
        value: ResourceOwnershipResolution,
        installed_at: Instant,
    ) {
        let mut maps = self.maps.write().expect("ownership memory maps lock");
        maps.entries.insert(
            key,
            OwnershipMemoryEntry {
                installed_at,
                token,
                value,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn tenant_scoped(tenant_id: i64) -> ResourceOwnershipResolution {
        ResourceOwnershipResolution::TenantScoped {
            target_id: Some(7),
            tenant_id,
            domain_id: Some(8),
            owner_id: Some(9),
        }
    }

    fn key(path: &str) -> OwnershipMemoryKey {
        OwnershipMemoryKey::new("identity_users", path, "GET", None, Some(1), Some(2))
            .expect("bounded key")
    }

    fn healthy_hub() -> MemoryProjectionHub {
        let hub = MemoryProjectionHub::default();
        hub.record_channel_heartbeat();
        hub
    }

    fn ready_token(hub: &MemoryProjectionHub) -> AuxiliaryReadToken {
        hub.strict_read_token()
            .expect("healthy writer-free hub issues a token")
    }

    fn assert_unavailable(outcome: ResourceOwnershipResolution, code: &'static str) {
        assert_eq!(outcome, ResourceOwnershipResolution::Unavailable { code });
    }

    // ── token 栅栏：raced install/return 绝不落条目或放行 ────────────────

    #[tokio::test]
    // 仅测试：guard Drop 会清全局 L1 eligibility 缓存（跨测试互斥），按
    // hub 测试同款约束共享 `test_global_state_lock`，std 锁跨 await 为测试
    // 局部取舍（current_thread runtime 内自持，不阻塞自身）。
    #[allow(clippy::await_holding_lock)]
    async fn token_race_during_refill_never_installs_or_serves() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        let factory = || async {
            // 严格回填 await 窗口内发生 source mutation（begin/drop 推进
            // token）：带回来的事实属于旧 revision，绝不安装、绝不返回。
            let writer = hub.begin_source_transaction().expect("writer guard");
            drop(writer);
            tenant_scoped(100)
        };
        let outcome = memory
            .serve_or_refill(&hub, token, key("/users/7"), factory)
            .await;
        assert_unavailable(outcome, CODE_RACED_REFILL);
        assert_eq!(memory.entry_count(), 0, "raced refill must not install");
    }

    #[tokio::test]
    // 仅测试：同上，guard 存活/释放涉及全局缓存失效 hook。
    #[allow(clippy::await_holding_lock)]
    async fn writer_active_race_after_strict_read_refuses_install() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        let (guard_tx, guard_rx) = tokio::sync::oneshot::channel();
        let factory = || async {
            // 写者栅栏仍被持有（随 oneshot 存活到调用返回之后）：安装前复验
            // 必须看到 writer-active。
            let guard = hub.begin_source_transaction().expect("writer guard");
            let _ = guard_tx.send(guard);
            tenant_scoped(100)
        };
        let outcome = memory
            .serve_or_refill(&hub, token, key("/users/7"), factory)
            .await;
        assert!(
            hub.has_active_source_writer(),
            "the guard must still be alive"
        );
        assert_unavailable(outcome, CODE_RACED_REFILL);
        assert_eq!(memory.entry_count(), 0);
        drop(guard_rx);
        assert!(!hub.has_active_source_writer());
    }

    #[tokio::test]
    // 仅测试：同上，begin/drop 推进 token 并触发全局缓存失效 hook。
    #[allow(clippy::await_holding_lock)]
    async fn mutation_after_install_never_serves_the_cached_positive() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let memory = OwnershipMemory::default();
        let memory = &memory;
        let install_token = ready_token(&hub);
        memory.install(&key("/users/7"), install_token, tenant_scoped(100));
        // 安装后发生 mutation：token 变更，同 token 读请求已不存在 —— 旧
        // 条目对任何新 token 都是 miss（回填重读），绝不跨 revision serve。
        let writer = hub.begin_source_transaction().expect("writer guard");
        drop(writer);
        let new_token = ready_token(&hub);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_factory = counter.clone();
        let factory = move || {
            let counter = counter_for_factory.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tenant_scoped(100)
            }
        };
        let outcome = memory
            .serve_or_refill(&hub, new_token, key("/users/7"), factory)
            .await;
        assert_eq!(outcome, tenant_scoped(100));
        assert_eq!(counter.load(Ordering::SeqCst), 1, "stale entry must refill");
    }

    // ── 键边界：changed path / actor 绑定 / 超界 ─────────────────────────

    #[tokio::test]
    async fn changed_path_never_cross_serves() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        memory.install(&key("/users/7"), token, tenant_scoped(100));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_factory = counter.clone();
        let factory = move || {
            let counter = counter_for_factory.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tenant_scoped(200)
            }
        };
        let outcome = memory
            .serve_or_refill(&hub, token, key("/users/8"), factory)
            .await;
        assert_eq!(outcome, tenant_scoped(200), "different path must not reuse");
        assert_eq!(counter.load(Ordering::SeqCst), 1, "path miss must refill");
        assert_eq!(memory.entry_count(), 2);
    }

    #[tokio::test]
    async fn actor_binding_is_part_of_the_key() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        let bound = OwnershipMemoryKey::new(
            "permission_rule",
            "/delegations",
            "POST",
            None,
            Some(1),
            Some(2),
        )
        .unwrap();
        memory.install(&bound, token, tenant_scoped(100));
        let other_actor = OwnershipMemoryKey::new(
            "permission_rule",
            "/delegations",
            "POST",
            None,
            Some(3),
            Some(2),
        )
        .unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_factory = counter.clone();
        let factory = move || {
            let counter = counter_for_factory.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tenant_scoped(300)
            }
        };
        let outcome = memory
            .serve_or_refill(&hub, token, other_actor, factory)
            .await;
        assert_eq!(
            outcome,
            tenant_scoped(300),
            "another actor unit must not reuse the first actor's facts"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn oversized_or_empty_keys_are_rejected() {
        let long_path = format!("/users/{}", "7".repeat(MAX_KEY_STRING_BYTES));
        assert!(
            OwnershipMemoryKey::new("identity_users", &long_path, "GET", None, None, None)
                .is_none()
        );
        assert!(OwnershipMemoryKey::new("", "/users/7", "GET", None, None, None).is_none());
        assert!(
            OwnershipMemoryKey::new("identity_users", "/users/7", "", None, None, None).is_none()
        );
        assert!(
            OwnershipMemoryKey::new("identity_users", "/users/7", "GET", None, None, None)
                .is_some()
        );
    }

    // ── 否定结果永不缓存 ─────────────────────────────────────────────────

    #[tokio::test]
    async fn unresolved_and_unavailable_outcomes_are_never_cached() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        for negative in [
            ResourceOwnershipResolution::Unresolved {
                code: "resource_ownership.user_card_not_found",
            },
            ResourceOwnershipResolution::Unavailable {
                code: "resource_ownership.user_card_lookup_failed",
            },
        ] {
            let negative = negative.clone();
            let factory = move || async move { negative.clone() };
            let outcome = memory
                .serve_or_refill(&hub, token, key("/users/7"), factory)
                .await;
            assert!(matches!(
                outcome,
                ResourceOwnershipResolution::Unresolved { .. }
                    | ResourceOwnershipResolution::Unavailable { .. }
            ));
        }
        assert_eq!(
            memory.entry_count(),
            0,
            "negative outcomes must never be cached"
        );
    }

    // ── single-flight：24 并发同键只有一次严格回源 ───────────────────────

    #[tokio::test]
    async fn twenty_four_concurrent_callers_share_one_strict_resolution() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = Arc::new(OwnershipMemory::default());
        let counter = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(24));
        let mut handles = Vec::new();
        for _ in 0..24 {
            let memory = memory.clone();
            let counter = counter.clone();
            let barrier = barrier.clone();
            let hub = hub.clone();
            handles.push(tokio::spawn(async move {
                let counter = counter.clone();
                let factory = move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        // 拉长回填 await 窗口：其余调用者此刻必须等锁或命中
                        // 已回填条目，绝不并发发起第二次严格解析。
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        tenant_scoped(100)
                    }
                };
                barrier.wait().await;
                memory
                    .serve_or_refill(&hub, token, key("/users/7"), factory)
                    .await
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.expect("caller task join"), tenant_scoped(100));
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "24 same-key callers must share exactly one strict resolution"
        );
        assert_eq!(memory.entry_count(), 1);
    }

    // ── 容量与 TTL（GC 语义）────────────────────────────────────────────

    #[tokio::test]
    async fn capacity_refusal_keeps_entries_bounded() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        for index in 0..MAX_OWNERSHIP_MEMORY_ENTRIES {
            let path = format!("/users/{index}");
            memory.install(&key(&path), token, tenant_scoped(100));
        }
        assert_eq!(memory.entry_count(), MAX_OWNERSHIP_MEMORY_ENTRIES);
        memory.install(&key("/users/overflow"), token, tenant_scoped(100));
        assert_eq!(
            memory.entry_count(),
            MAX_OWNERSHIP_MEMORY_ENTRIES,
            "over-capacity installs must be refused, never evict live entries"
        );
    }

    #[tokio::test]
    async fn expired_entries_are_gced_and_never_served() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        let expired = Instant::now()
            .checked_sub(OWNERSHIP_MEMORY_TTL + Duration::from_secs(1))
            .expect("backdated timestamp");
        memory.seed_entry_for_test(key("/users/7"), token, tenant_scoped(100), expired);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_factory = counter.clone();
        let factory = move || {
            let counter = counter_for_factory.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tenant_scoped(100)
            }
        };
        let outcome = memory
            .serve_or_refill(&hub, token, key("/users/7"), factory)
            .await;
        assert_eq!(outcome, tenant_scoped(100), "expired entry must refill");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        // 回填重装后条目回到新鲜状态。
        assert_eq!(memory.entry_count(), 1);
    }

    // ── single-flight 容量耗尽 fail-closed ───────────────────────────────

    #[tokio::test]
    async fn refill_capacity_exhaustion_fails_closed_without_any_strict_call() {
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let memory = &memory;
        // 占满 single-flight scope 表：全部锁必须同时存活，死条目会被下一次
        // refill_lock 的 retain 清理，只有存活锁才能耗尽容量。
        let held_locks: Vec<_> = (0..MAX_REFILL_SCOPES)
            .map(|index| {
                let path = format!("/users/{index}");
                memory.refill_lock(&key(&path)).expect("scope within cap")
            })
            .collect();
        assert_eq!(held_locks.len(), MAX_REFILL_SCOPES);
        let factory = || async move {
            panic!("capacity-exhausted read must never reach the strict resolver")
        };
        let outcome = memory
            .serve_or_refill(&hub, token, key("/users/last"), factory)
            .await;
        assert_unavailable(outcome, CODE_REFILL_CAPACITY);
    }

    // ── 有界回源的结构钉死（无真实睡眠的超时验证）────────────────────────

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn health_loss_during_refill_or_after_install_cannot_serve() {
        let _test_guard = crate::eligibility::test_global_state_lock();
        let hub = healthy_hub();
        let token = ready_token(&hub);
        let memory = OwnershipMemory::default();
        let factory = || async {
            hub.mark_channel_suspect("ownership refill transport lost");
            tenant_scoped(100)
        };
        assert_unavailable(
            memory
                .serve_or_refill(&hub, token, key("/users/7"), factory)
                .await,
            CODE_RACED_REFILL,
        );
        assert_eq!(memory.entry_count(), 0);

        let other = healthy_hub();
        let token = ready_token(&other);
        memory.install(&key("/users/7"), token, tenant_scoped(100));
        other.mark_channel_suspect("ownership cache transport lost");
        assert_unavailable(
            memory
                .serve_or_refill(&other, token, key("/users/7"), || async {
                    panic!("unsafe hit must not refill")
                })
                .await,
            CODE_RACED_RETURN,
        );
    }

    #[test]
    fn refill_is_bounded_by_deadlines_and_lock_wait() {
        let source = include_str!("memory.rs").replace("\r\n", "\n");
        let production = source
            .split_once(concat!("#[", "cfg(test)]\nmod tests"))
            .unwrap()
            .0;
        assert_eq!(
            production
                .matches("tokio::time::timeout(REFILL_LOCK_WAIT, lock.lock())")
                .count(),
            1,
            "the single-flight lock wait must be deadline-bounded"
        );
        assert_eq!(
            production
                .matches("tokio::time::timeout(REFILL_QUERY_DEADLINE, strict())")
                .count(),
            1,
            "the strict refill must be hard-deadline bounded"
        );
        // install 与 return 前的 token 复验必须同时存在。
        assert_eq!(
            production
                .matches("hub.auxiliary_read_matches(token)")
                .count(),
            5
        );
    }
}
