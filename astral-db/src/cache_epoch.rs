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
/// - 进程内缓存新鲜（TTL 内）→ 直接返回，无 Redis 往返；
/// - 否则读 Redis（缺失时 `SET NX` 首写随机 UUID）并刷新进程内缓存；
/// - Redis 不可用 → `None`，调用方跳过 epoch 子校验（降级不阻塞）。
pub async fn current_cache_epoch() -> Option<String> {
    if let Some(epoch) = fresh_in_process_epoch() {
        return Some(epoch);
    }
    let epoch = load_or_create_shared_epoch().await?;
    store_in_process_epoch(&epoch);
    Some(epoch)
}

/// 从 Redis 读取共享时代；缺失时 `SET NX` 首写随机 UUID（并发竞争时读取
/// 胜者值）。任何 Redis 失败 → `None`（调用方降级，不阻塞主路径）。
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
}
