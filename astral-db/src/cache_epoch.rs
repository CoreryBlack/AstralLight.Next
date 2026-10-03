//! 授权缓存共享时代（cache epoch）
//!
//! 背景：Redis 是 Rust 与 Java 的共享缓存层，Java 契约键（`perm:card:status`、
//! `astral:permission:card`、`permission:ruleset`）不能加 Rust 侧前缀或改格式，
//! 因此 Rust 侧缓存条目无法通过键名空间隔离版本。采用"**载荷内 epoch 字段 +
//! 共享时代键**"方案：键格式完全不变，各缓存载荷（envelope / CardActiveCache）
//! 写入时携带当时的时代值，读取侧与当前共享时代比对，不一致即 miss 重写。
//!
//! 机制：
//! - 共享时代键 [`CACHE_EPOCH_KEY`] 的值是随机 UUID；首次访问以 `SET NX` 写入，
//!   全部实例共享读取。键不设置过期时间（存续直到运维轮换）。
//! - 进程内缓存当前时代值（TTL [`EPOCH_CACHE_TTL`]，60s），避免每请求一次
//!   Redis GET 往返；TTL 过期后下一次访问重新读取（并按需 SETNX）。运维换
//!   时代后各实例最迟一个 TTL 窗口内感知新值。
//! - Redis 不可用时返回 `None`：调用方跳过 epoch 子校验（降级不阻塞），
//!   版本栅栏其余部分（schema_version、manifest 版本组 / 投影三元组）照常生效。
//! - **换时代操作（运维，Exec-L3）**：整库恢复/重建完成后执行
//!   `DEL astral:auth:cache_epoch`。下一次访问重新 SETNX 出新 UUID；所有携带
//!   旧时代的缓存条目在读取侧 epoch 不等 → miss 并随写回自然重写，未被读取的
//!   旧条目按自身 TTL 自然过期。**注意**：恢复/重建必须执行换时代，否则
//!   head 缺失期残留的正缓存（无三元组栅栏保护）仍可按相同时代命中。
//!
//! 测试注记：SETNX 与进程内缓存语义依赖 Redis/进程全局状态（不连真实 Redis），
//! 单测只覆盖纯逻辑拆分（TTL 新鲜度、相等/当前性比较、进程内存取往返），
//! Redis 连接路径保持最薄。
//!
//! # Redis 退役（P3 拆线，本批次接缝）
//!
//! 默认路径（`ASTRAL_REDIS_PROJECTION_COMPAT` 未显式置 `true`，见
//! `crate::eligibility::redis_projection_compat_enabled`）**不触碰 Redis**：
//! 时代改为**进程内 TTL 计数器**（[`current_in_process_epoch`]，TTL
//! [`IN_PROCESS_EPOCH_TTL`]，到期自增）+ 显式旋转函数 [`reset_cache_epoch`]。
//! 内存时代只参与**进程内缓存条目**的版本栅栏（evidence L1 条目的
//! strict-current 校验），不是 durable proof，也不跨节点：跨节点失效语义由
//! 指针对牌/资格头栅栏 + 失效通知承担（不以 TTL alone 作为跨节点证明）。
//! compat adapter 显式开启时保持旧共享时代键（`SETNX`/`DEL` 运维轮换，读
//! 写仅显式开启），旧 `pub` API 形状不变。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[cfg(feature = "e4-observability")]
use sha2::{Digest, Sha256};

/// Redis 共享时代键（全部实例共享；值为随机 UUID，无过期时间）。
pub const CACHE_EPOCH_KEY: &str = "astral:auth:cache_epoch";

/// 进程内时代缓存 TTL：避免每请求一次 GET 往返；运维换时代后最迟该窗口内
/// 全部实例可见（可接受，见模块文档换时代操作）。
const EPOCH_CACHE_TTL: Duration = Duration::from_secs(60);

/// 进程内时代缓存：`(epoch 值, 写入时刻)`。
static CACHED_EPOCH: RwLock<Option<(String, Instant)>> = RwLock::new(None);

#[cfg(feature = "e4-observability")]
fn log_epoch_observation(epoch: &str, source: &'static str) {
    let epoch_sha256 = format!("{:x}", Sha256::digest(epoch.as_bytes()));
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e4",
        event = "cache_epoch_observed",
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        epoch_sha256,
        source,
        rotation_reason = "unproven_external_journal_required",
        "e4 deployment precondition observation"
    );
}

/// 读取当前共享授权缓存时代。
///
/// - **默认路径（Redis 退役）**：返回进程内 TTL 计数器时代（无任何 Redis
///   往返/连接尝试；TTL 到期自增，[`reset_cache_epoch`] 显式旋转）；
/// - **compat adapter（显式开启）**：保持旧语义——进程内缓存新鲜（TTL 内）
///   → 直接返回；否则读 Redis（缺失时 `SET NX` 首写随机 UUID）并刷新进程内
///   缓存；Redis 不可用 → `None`，调用方跳过 epoch 子校验（降级不阻塞）。
pub async fn current_cache_epoch() -> Option<String> {
    if !crate::eligibility::redis_projection_compat_enabled() {
        return Some(current_in_process_epoch());
    }
    if let Some(epoch) = fresh_in_process_epoch() {
        return Some(epoch);
    }
    let epoch = load_or_create_shared_epoch().await?;
    store_in_process_epoch(&epoch);
    Some(epoch)
}

// ───────────────────────── 进程内 TTL 计数器时代（默认路径） ─────────────────────────
//
// Redis 退役后时代只承载"进程内缓存条目的版本栅栏"职责：值稳定（条目可命中）、
// 可旋转（恢复/重建后整体失配）、TTL 到期自增（陈旧条目寿命显式封顶）。它不是
// durable proof，也绝不写入 Redis（compat 关闭时无任何 Redis 尝试）。

/// 进程内时代 TTL：到期自增（TTL counter 语义）。与 compat 模式共享时代的
/// 进程内缓存窗口同一量级（60s），陈旧条目寿命不超过该窗口 + 条目自身 TTL。
pub(crate) const IN_PROCESS_EPOCH_TTL: Duration = Duration::from_secs(60);

/// 进程内时代计数器（单调递增；并发推进多计一位只会造成多余 miss，fail-closed）。
static IN_PROCESS_EPOCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 进程内当前时代：`(计数值, 推进时刻)`。
static IN_PROCESS_EPOCH: RwLock<Option<(u64, Instant)>> = RwLock::new(None);

/// 时代值的确定性编码（纯函数；`inproc-{n}` 命名空间与 compat 共享 UUID 值
/// 天然不相交，防止两条路径的条目互相命中）。
fn in_process_counter_epoch_value(counter: u64) -> String {
    format!("inproc-{counter}")
}

/// 进程内时代条目是否仍在 TTL 内（纯逻辑；`duration_since` 对未来时刻饱和为 0）。
fn in_process_epoch_is_fresh(cached_at: Instant, now: Instant) -> bool {
    now.duration_since(cached_at) < IN_PROCESS_EPOCH_TTL
}

/// 推进进程内时代（计数器 +1 并记录推进时刻），返回新时代值。
fn advance_in_process_epoch() -> String {
    let next = IN_PROCESS_EPOCH_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
    if let Ok(mut guard) = IN_PROCESS_EPOCH.write() {
        *guard = Some((next, Instant::now()));
    }
    in_process_counter_epoch_value(next)
}

/// 当前进程内时代（默认路径唯一时代来源，无 I/O）：TTL 内复用当前值；
/// 未初始化或 TTL 到期 → 自增推进（TTL counter）。写锁中毒时退化为
/// "只读计数器值"（仍单调，条目栅栏照常）。
fn current_in_process_epoch() -> String {
    if let Ok(guard) = IN_PROCESS_EPOCH.read() {
        if let Some((counter, cached_at)) = *guard {
            if in_process_epoch_is_fresh(cached_at, Instant::now()) {
                return in_process_counter_epoch_value(counter);
            }
        }
    }
    advance_in_process_epoch()
}

/// 显式旋转进程内时代（默认路径的换时代操作）：立即推进计数器，全部携带
/// 旧时代的进程内缓存条目在读取侧时代不等 → miss 重填。
///
/// **边界**：本函数只作用于进程内时代，绝不触碰 Redis——compat adapter
/// 显式开启时的时代轮换仍是运维 `DEL astral:auth:cache_epoch`（Exec-L3）；
/// 整库恢复/重建在默认路径下调用本函数即可让本进程条目整体失配。
pub fn reset_cache_epoch() -> String {
    advance_in_process_epoch()
}

/// 从 Redis 读取共享时代（**仅 compat adapter 显式开启且 redis-compat feature
/// 编译时可达**，见 [`current_cache_epoch`]）；缺失时 `SET NX` 首写随机 UUID
/// （并发竞争时读取胜者值）。任何 Redis 失败 → `None`（调用方降级，不阻塞主路径）。
#[cfg(feature = "redis-compat")]
async fn load_or_create_shared_epoch() -> Option<String> {
    let mut conn = crate::eligibility::redis_conn().await?;
    let existing: Option<String> = redis::cmd("GET")
        .arg(CACHE_EPOCH_KEY)
        .query_async(&mut conn)
        .await
        .ok()?;
    if let Some(epoch) = existing {
        #[cfg(feature = "e4-observability")]
        log_epoch_observation(&epoch, "existing");
        return Some(epoch);
    }
    let epoch = uuid::Uuid::new_v4().to_string();
    // SET NX 成功返回 OK（Some(())）；键已被并发写入时返回 nil（None）。
    let created: Option<()> = redis::cmd("SET")
        .arg(CACHE_EPOCH_KEY)
        .arg(&epoch)
        .arg("NX")
        .query_async(&mut conn)
        .await
        .ok()?;
    if created.is_some() {
        #[cfg(feature = "e4-observability")]
        log_epoch_observation(&epoch, "created_set_nx");
        return Some(epoch);
    }
    // 并发竞争：其他实例已先写入 → 读取其值；极小概率值再次被 DEL（换时代）
    // → 返回 None 降级，下一次访问重新 SETNX。
    let winner: Option<String> = redis::cmd("GET")
        .arg(CACHE_EPOCH_KEY)
        .query_async(&mut conn)
        .await
        .ok()?;
    #[cfg(feature = "e4-observability")]
    if let Some(epoch) = winner.as_deref() {
        log_epoch_observation(epoch, "set_nx_race_winner");
    }
    winner
}

/// redis-compat feature 未编译：无共享 Redis 时代可读，返回 `None` —— 调用方
/// 跳过 compat 共享时代子校验，默认路径时代由进程内 TTL 计数器承担（见
/// [`current_cache_epoch`] 与模块文档"Redis 退役"节）。
#[cfg(not(feature = "redis-compat"))]
async fn load_or_create_shared_epoch() -> Option<String> {
    None
}

/// 进程内缓存条目是否仍在 TTL 内（纯逻辑；`duration_since` 对未来时刻饱和为 0）。
fn cached_epoch_is_fresh(cached_at: Instant, now: Instant) -> bool {
    now.duration_since(cached_at) < EPOCH_CACHE_TTL
}

/// 当前进程内缓存的新鲜时代值（未缓存/已过 TTL → `None`）。
fn fresh_in_process_epoch() -> Option<String> {
    let cached = CACHED_EPOCH.read().ok()?;
    let (epoch, cached_at) = cached.as_ref()?;
    if cached_epoch_is_fresh(*cached_at, Instant::now()) {
        return Some(epoch.clone());
    }
    None
}

/// 写入进程内时代缓存（Redis 读到的值总是新鲜起点）。
fn store_in_process_epoch(epoch: &str) {
    if let Ok(mut cached) = CACHED_EPOCH.write() {
        *cached = Some((epoch.to_owned(), Instant::now()));
    }
}

/// 降级语义的 epoch 相等校验（读取侧通用子校验）：任一侧 `None`
/// （当前时代未知 = Redis 降级，或条目未携带时代）→ 跳过子校验放行，
/// 其余版本栅栏照常；两侧均为 `Some` 时必须相等。
#[cfg(feature = "redis-compat")]
pub(crate) fn cache_epoch_matches(current: Option<&str>, entry: Option<&str>) -> bool {
    match (current, entry) {
        (Some(current), Some(entry)) => current == entry,
        _ => true,
    }
}

/// 严格当前性校验（head 缺失的恢复/重建期防线）：条目必须携带与当前共享
/// 时代一致的值；任一侧 `None` 一律不通过（残留正缓存不得在无三元组栅栏
/// 保护的状态下放行）。
pub(crate) fn cache_epoch_is_current(current: Option<&str>, entry: Option<&str>) -> bool {
    match (current, entry) {
        (Some(current), Some(entry)) => current == entry,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "redis-compat")]
    fn epoch_match_is_skipped_only_when_one_side_is_unknown() {
        assert!(cache_epoch_matches(Some("e1"), Some("e1")));
        assert!(!cache_epoch_matches(Some("e1"), Some("e2")));
        // 降级：当前时代未知（Redis 降级）或条目未携带时代 → 跳过子校验
        assert!(cache_epoch_matches(None, Some("e1")));
        assert!(cache_epoch_matches(Some("e1"), None));
        assert!(cache_epoch_matches(None, None));
    }

    #[test]
    fn head_missing_reachability_requires_a_current_entry_epoch() {
        // head 缺失（恢复/重建期）：条目必须携带当前时代才可命中
        assert!(cache_epoch_is_current(Some("e1"), Some("e1")));
        assert!(!cache_epoch_is_current(Some("e1"), Some("e2")));
        // 任一侧未知都不放行：恢复期残留正缓存必须被拦截
        assert!(!cache_epoch_is_current(None, Some("e1")));
        assert!(!cache_epoch_is_current(Some("e1"), None));
        assert!(!cache_epoch_is_current(None, None));
    }

    #[test]
    fn in_process_epoch_cache_honors_ttl_boundary() {
        let cached_at = Instant::now();
        assert!(cached_epoch_is_fresh(cached_at, cached_at));
        assert!(cached_epoch_is_fresh(
            cached_at,
            cached_at + EPOCH_CACHE_TTL - Duration::from_secs(1)
        ));
        // 恰好到达 TTL 与超时 → 不新鲜，下一次访问回源 Redis
        assert!(!cached_epoch_is_fresh(
            cached_at,
            cached_at + EPOCH_CACHE_TTL
        ));
        assert!(!cached_epoch_is_fresh(
            cached_at,
            cached_at + EPOCH_CACHE_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn in_process_epoch_cache_store_then_read_is_fresh() {
        store_in_process_epoch("stored-epoch");
        assert_eq!(fresh_in_process_epoch().as_deref(), Some("stored-epoch"));
    }

    // ============ 进程内 TTL 计数器时代（默认路径，Redis 退役）测试 ============

    #[test]
    fn in_process_counter_epoch_value_is_deterministic_and_namespaced() {
        // 确定性编码；与 compat 共享 UUID 值（非 "inproc-" 前缀）不相交。
        assert_eq!(in_process_counter_epoch_value(7), "inproc-7");
        assert_eq!(
            in_process_counter_epoch_value(u64::MAX),
            "inproc-18446744073709551615"
        );
    }

    #[test]
    fn in_process_epoch_freshness_honors_ttl_boundary() {
        let at = Instant::now();
        assert!(in_process_epoch_is_fresh(at, at));
        assert!(in_process_epoch_is_fresh(
            at,
            at + IN_PROCESS_EPOCH_TTL - Duration::from_secs(1)
        ));
        // 恰好到达 TTL 与超时 → 不新鲜，下一次访问自增推进。
        assert!(!in_process_epoch_is_fresh(at, at + IN_PROCESS_EPOCH_TTL));
        assert!(!in_process_epoch_is_fresh(
            at,
            at + IN_PROCESS_EPOCH_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn reset_cache_epoch_rotates_the_in_memory_epoch_without_redis() {
        // 默认路径：current 稳定可复用（TTL 内）；reset 立即旋转且此后稳定。
        // （进程级全局状态：断言只依赖相对关系，不依赖具体计数值。）
        let first = current_in_process_epoch();
        assert_eq!(current_in_process_epoch(), first);
        let rotated = reset_cache_epoch();
        assert_ne!(rotated, first, "rotation must advance the in-memory epoch");
        assert_eq!(current_in_process_epoch(), rotated);
        assert!(rotated.starts_with("inproc-"));
    }
}
