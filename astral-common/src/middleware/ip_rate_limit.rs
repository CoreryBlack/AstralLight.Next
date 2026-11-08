//! 进程内 per-IP 固定窗口限流器（Gateway 与 Identity 共享的本地防护原语）。
//!
//! 抽取自 `astral-gateway/src/rate_limit.rs` 与 `astral-identity/src/middleware.rs`
//! 的重复实现（taskId `global-authority-20261107-limiter`）；两个消费方保留各自
//! 的 HTTP 装配与 429 出口，计数核心、受信代理匹配与客户端 IP 解析以本模块为
//! 唯一 owner。
//!
//! ## 计数语义（对齐既有两份实现的共同形状）
//!
//! - 1s 固定窗口，cap = `requests_per_second + burst_size`（饱和加法，配置为
//!   `u32` 也不会溢出）；窗口过期就地清零，不重建条目。
//! - `enabled=false` 时按配置放行（运营开关，属文档化的配置性 fail-open）。
//! - 桶带 `last_seen`；超过 GC 触发阈值时按 TTL 回收空闲桶，硬容量满时也强制
//!   回收一次。TTL+GC 约束空闲增长，硬容量约束热键总量。
//! - **硬容量 fail-closed**：容量耗尽时新 key 一律拒绝（429），绝不静默接纳
//!   新桶；已存在 key 的既有预算不受容量压力影响。
//! - 饱和运算：计数、cap、时间差全部饱和（`saturating_add` /
//!   `saturating_duration_since`），时钟异常或计数极限不 panic。
//! - 锁中毒 fail-closed：Mutex 中毒后所有检查一律拒绝，不 panic、不重置状态、
//!   不放行（只记录一次告警，避免日志风暴）。
//! - canonical key：桶 key 是 `std::net::IpAddr`；对端地址不可得（如未注入
//!   `ConnectInfo`）时聚合进单一 `None` 桶（原 `unknown` 单桶语义），绝不把
//!   攻击者可控的原始字符串当桶 key。
//!
//! ## 受信代理与客户端 IP 解析
//!
//! 转发头只在 TCP 对端命中 `gateway.trusted_proxy_ips` 时才被信任；非受信对端
//! 一律按对端地址分桶（伪造 XFF 不能换桶绕过限流）。受信链内解析采用
//! **从右向左第一个非受信地址**语义：链条最右侧由本机受信代理追加，客户端
//! 伪造的最左跳不参与分桶。注意这是对既有"取第一跳"实现的有意收紧（第一跳
//! 恰是客户端可伪造值）；单代理部署下链条只有一项，行为不变。解析失败
//! （链条为空、条目非法）一律回退 TCP 对端地址，不产出新桶 key。
//!
//! 受信代理条目支持三种形式（编译期校验，非法条目丢弃并告警，按 fail-closed
//! 处理）：
//! - 精确地址：`9.9.9.9` / `fd00::1`；
//! - 真实 CIDR：`10.1.2.0/24` / `fd00:1::/64`（按位掩码匹配，主机位容忍并掩
//!   零，前缀长度超界拒绝）；
//! - 遗留点分前缀：`10.1.`（兼容既有配置，见 `TrustedProxyEntry::LegacyPrefix`
//!   的语义说明）。
//!
//! ## 已知边界（刻意保留，不发明跨副本限流）
//!
//! 计数状态是单进程内的：跨副本不做强一致，攻击预算按副本数线性放大。当前
//! 部署中**没有任何组件提供跨副本全局预算**——Gateway 的 `rate_limit` 中间件
//! 同样是进程内本地限流，不构成全局预算；真正的跨副本持久化配额属独立任务
//! （落地前不生效）。本模块只做可用性保护，不参与授权判定、不消费准入栅栏。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::config::RateLimitCfg;

/// 固定窗口长度（对齐既有 Gateway/Identity 实现：1s）。
pub const WINDOW: Duration = Duration::from_secs(1);

/// 桶空闲回收阈值：超过该时长未访问的 key 在 GC 时移除。
pub const BUCKET_TTL: Duration = Duration::from_secs(60);

/// 周期 GC 触发规模：桶数超过该值才考虑 TTL 全扫（配合 `SWEEP_INTERVAL`
/// 节流，避免热路径每请求 O(n) 全扫）。
pub const GC_THRESHOLD: usize = 1024;

/// 周期全扫的最小间隔：达到 GC 触发规模后，两次 TTL 全扫之间至少间隔该时长
///（容量压力下的强制回收不受此间隔约束）。
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// 硬容量上限：桶数达到该值后新 key 一律拒绝（fail-closed）。
///
/// 该值同时约束"全部 key 都热"的场景：TTL 无法回收热键，硬容量保证内存与
/// 分桶规模有界；已存在 key 的既有预算不受影响。
pub const HARD_CAPACITY: usize = 65_536;

/// 桶 key：canonical `IpAddr`；`None` = 对端地址不可得的聚合桶
/// （对齐原 `unknown` 单桶：绝不因缺扩展而 panic，也绝不静默放开）。
pub type ClientKey = Option<IpAddr>;

/// 固定窗口计数器。
struct WindowCounter {
    count: u64,
    window_start: Instant,
    last_seen: Instant,
}

/// 桶表 + 周期回收水位（同一把锁保护，避免为水位引入第二把锁）。
struct BucketTable {
    map: HashMap<ClientKey, WindowCounter>,
    /// 上次 TTL 全扫时间；`None` = 尚未扫过。
    last_sweep: Option<Instant>,
}

/// 进程内 per-IP 固定窗口限流器（Gateway 与 Identity 共享唯一实现）。
pub struct IpRateLimiter {
    config: RateLimitCfg,
    /// cap = rps + burst（构造期饱和计算，避免每请求运算）。
    cap: u64,
    /// 硬容量（桶数上限）；`0` 为退化配置：所有新 key 拒绝（fail-closed）。
    capacity: usize,
    gc_threshold: usize,
    ttl: Duration,
    window: Duration,
    /// 周期全扫最小间隔（容量压力下的强制回收不受此间隔约束）。
    sweep_interval: Duration,
    buckets: Mutex<BucketTable>,
    /// 锁中毒只告警一次，避免拒绝风暴期间的日志洪水。
    fault_logged: AtomicBool,
}

/// 校验限流配置。`Err` 仅用于启动/装配期告警与测试断言；运行时 limiter 对
/// 退化配置按 fail-closed 处理（cap=0 → 全拒），绝不静默放宽。
pub fn validate_rate_limit_config(config: &RateLimitCfg) -> Result<(), &'static str> {
    if !config.enabled {
        return Ok(());
    }
    let cap = (config.requests_per_second as u64).saturating_add(config.burst_size as u64);
    if cap == 0 {
        return Err("RATE_LIMIT_CAPACITY_ZERO");
    }
    if config.requests_per_second == 0 {
        return Err("RATE_LIMIT_STEADY_STATE_ZERO");
    }
    Ok(())
}

impl IpRateLimiter {
    /// 用默认边界构造（对齐既有语义：1s 窗口、60s TTL、1024 GC 阈值、
    /// 65536 硬容量、1s 全扫间隔）。配置退化时记录告警但不 panic。
    pub fn new(config: RateLimitCfg) -> Self {
        Self::with_bounds(
            config,
            HARD_CAPACITY,
            GC_THRESHOLD,
            BUCKET_TTL,
            WINDOW,
            SWEEP_INTERVAL,
        )
    }

    /// 显式指定全部边界（嵌入方/测试用）。`capacity = 0` 表示拒绝所有新 key
    /// （fail-closed 退化态）；`gc_threshold = 0` 表示达到阈值语义即每次检查
    /// 都可回收，但仍受 `sweep_interval` 节流。
    pub fn with_bounds(
        config: RateLimitCfg,
        capacity: usize,
        gc_threshold: usize,
        ttl: Duration,
        window: Duration,
        sweep_interval: Duration,
    ) -> Self {
        if let Err(reason) = validate_rate_limit_config(&config) {
            tracing::warn!(
                reason,
                enabled = config.enabled,
                "degenerate rate limit config; limiter fails closed for the affected cases"
            );
        }
        Self {
            cap: (config.requests_per_second as u64).saturating_add(config.burst_size as u64),
            config,
            capacity,
            gc_threshold,
            ttl,
            window,
            sweep_interval,
            buckets: Mutex::new(BucketTable {
                map: HashMap::new(),
                last_sweep: None,
            }),
            fault_logged: AtomicBool::new(false),
        }
    }

    /// 窗口内未超限返回 true 并消耗 1 个预算；超限/容量耗尽/锁中毒返回 false
    ///（调用方统一 429）。绝不 panic，绝不静默接纳新 key。
    pub fn check(&self, client: ClientKey) -> bool {
        if !self.config.enabled {
            return true;
        }
        let Ok(mut table) = self.buckets.lock() else {
            // 锁中毒：fail-closed（拒绝），不重置、不放行、不 panic。
            if !self.fault_logged.swap(true, Ordering::Relaxed) {
                tracing::warn!("ip rate limiter mutex poisoned; rejecting requests until restart");
            }
            return false;
        };
        let now = Instant::now();

        // 有界周期回收：达到规模阈值且距上次全扫超过 `sweep_interval` 才执行
        // O(n) TTL 全扫；热路径稳态开销为 O(1)（阈值内完全免扫）。
        if table.map.len() > self.gc_threshold
            && table
                .last_sweep
                .is_none_or(|last| now.saturating_duration_since(last) >= self.sweep_interval)
        {
            Self::sweep(&mut table.map, now, self.ttl);
            table.last_sweep = Some(now);
        }
        // 硬容量压力：新 key 前先强制回收一次（不受间隔约束——腾挪空间优先）；
        // 仍满则 fail-closed（热键场景 TTL 无法腾挪，只能拒绝新 key，绝不挤掉
        // 既有桶或静默接纳）。
        if self.capacity == 0
            || (!table.map.contains_key(&client) && table.map.len() >= self.capacity)
        {
            Self::sweep(&mut table.map, now, self.ttl);
            table.last_sweep = Some(now);
            if table.map.len() >= self.capacity {
                return false;
            }
        }

        let counter = table.map.entry(client).or_insert(WindowCounter {
            count: 0,
            window_start: now,
            last_seen: now,
        });
        counter.last_seen = now;
        if now.saturating_duration_since(counter.window_start) > self.window {
            counter.count = 0;
            counter.window_start = now;
        }
        if counter.count >= self.cap {
            return false;
        }
        counter.count = counter.count.saturating_add(1);
        true
    }

    /// 当前桶数（诊断/测试用；锁中毒时返回 0，不 panic）。
    pub fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .map(|table| table.map.len())
            .unwrap_or(0)
    }

    /// 按 TTL 回收空闲桶（时间差饱和，时钟异常不 panic）。
    fn sweep(buckets: &mut HashMap<ClientKey, WindowCounter>, now: Instant, ttl: Duration) {
        buckets.retain(|_, counter| now.saturating_duration_since(counter.last_seen) < ttl);
    }
}

/// 受信代理条目（编译期校验后的形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedProxyEntry {
    /// 精确地址。
    Exact(IpAddr),
    /// 真实 CIDR：按位掩码匹配。主机位容忍（两侧同时掩零）；前缀长度超界
    ///（V4>32 / V6>128）在解析期拒绝。
    Cidr { network: IpAddr, prefix_len: u8 },
    /// 遗留点分前缀（`10.1.`），保留既有部署兼容。语义为对 canonical 渲染做
    /// 字符串前缀匹配（去掉尾部 `.` 后 `starts_with`）——**非八位组对齐**：
    /// `10.1.` 同时命中 `10.10.x.x`，这是既有实现的现状，刻意原样保留、不做
    /// 静默放宽或收紧；新配置应优先使用 CIDR。 bare `.`（空前缀）会被解析期
    /// 拒绝：它等价于信任任意对端，属已登记的安全修复。
    LegacyPrefix(String),
}

/// 编译后的受信代理集合（`gateway.trusted_proxy_ips` 的解析产物）。
///
/// 构造一次、跨请求共享；非法条目不参与匹配（该来源不受信 → 回退对端地址），
/// 并通过 [`TrustedProxySet::invalid_entries`] 暴露给装配点告警。
#[derive(Debug, Clone, Default)]
pub struct TrustedProxySet {
    entries: Vec<TrustedProxyEntry>,
    invalid: Vec<String>,
}

impl TrustedProxySet {
    /// 编译配置条目；trim 后解析，非法条目记入 `invalid`（fail-closed）。
    pub fn compile(configured: &[String]) -> Self {
        let mut entries = Vec::new();
        let mut invalid = Vec::new();
        for raw in configured {
            match parse_trusted_proxy_entry(raw) {
                Ok(entry) => entries.push(entry),
                Err(_) => invalid.push(raw.clone()),
            }
        }
        Self { entries, invalid }
    }

    /// 解析失败被丢弃的原始条目（装配点应告警）。
    pub fn invalid_entries(&self) -> &[String] {
        &self.invalid
    }

    /// 无任何有效受信条目时为 true（此时转发头一律不被信任）。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 对端是否受信。`None`（对端地址不可得）恒为 false：没有对端就没有受信
    /// 依据，转发头一律忽略。
    pub fn matches_peer(&self, peer: ClientKey) -> bool {
        let Some(peer) = peer else { return false };
        self.entries.iter().any(|entry| entry.matches(peer))
    }
}

impl TrustedProxyEntry {
    fn matches(&self, peer: IpAddr) -> bool {
        match self {
            TrustedProxyEntry::Exact(exact) => *exact == peer,
            TrustedProxyEntry::Cidr {
                network,
                prefix_len,
            } => {
                // 家族不同不可能同网；同族则两侧同掩码比较。
                match (network, peer) {
                    (IpAddr::V4(network), IpAddr::V4(peer)) => {
                        mask_v4(u32::from(*network), *prefix_len)
                            == mask_v4(u32::from(peer), *prefix_len)
                    }
                    (IpAddr::V6(network), IpAddr::V6(peer)) => {
                        mask_v6(u128::from(*network), *prefix_len)
                            == mask_v6(u128::from(peer), *prefix_len)
                    }
                    _ => false,
                }
            }
            TrustedProxyEntry::LegacyPrefix(prefix) => peer.to_string().starts_with(prefix),
        }
    }
}

/// 解析单个受信代理条目（trim；空/非法 → `Err`，由调用方 fail-closed）。
fn parse_trusted_proxy_entry(raw: &str) -> Result<TrustedProxyEntry, &'static str> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("TRUSTED_PROXY_ENTRY_EMPTY");
    }
    if let Some((network_part, prefix_part)) = value.rsplit_once('/') {
        let network: IpAddr = network_part
            .trim()
            .parse()
            .map_err(|_| "TRUSTED_PROXY_NETWORK_INVALID")?;
        let prefix_len: u8 = prefix_part
            .trim()
            .parse()
            .map_err(|_| "TRUSTED_PROXY_PREFIX_INVALID")?;
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err("TRUSTED_PROXY_PREFIX_OUT_OF_RANGE");
        }
        return Ok(TrustedProxyEntry::Cidr {
            network,
            prefix_len,
        });
    }
    if let Some(prefix) = value.strip_suffix('.') {
        // 遗留点分前缀：空前缀（裸 "."）等于信任任意对端，拒绝。
        if prefix.is_empty() {
            return Err("TRUSTED_PROXY_PREFIX_EMPTY");
        }
        return Ok(TrustedProxyEntry::LegacyPrefix(prefix.to_string()));
    }
    value
        .parse()
        .map(TrustedProxyEntry::Exact)
        .map_err(|_| "TRUSTED_PROXY_ADDRESS_INVALID")
}

/// V4 掩码（prefix_len 已由解析期保证 ≤ 32；0/32 边界不产生非法移位）。
fn mask_v4(bits: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - prefix_len as u32))
    }
}

/// V6 掩码（prefix_len 已由解析期保证 ≤ 128）。
fn mask_v6(bits: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix_len as u32))
    }
}

/// 解析客户端 IP（Gateway 与 Identity 共享的唯一实现）。
///
/// - 对端地址缺失 → `None`（聚合桶）。
/// - 对端不受信 → 对端地址（转发头整体忽略，伪造不能换桶）。
/// - 对端受信：XFF 存在且非空 → 从右向左取第一个**非受信**地址（最右项由本
///   机受信代理追加，客户端伪造的最左跳不参与）；条目解析失败或整链皆受信 →
///   回退对端地址。XFF 缺失/空白 → `X-Real-IP`（仅接受可解析地址，非法回退
///   对端）；都没有 → 对端地址。
///
/// 返回值恒为 canonical `IpAddr` 或 `None`：攻击者可控的原始头文本永远不会
/// 成为桶 key。
pub fn resolve_client_ip(
    headers: &HeaderMap,
    peer: ClientKey,
    trusted: &TrustedProxySet,
) -> ClientKey {
    let peer = peer?;
    if !trusted.matches_peer(Some(peer)) {
        return Some(peer);
    }
    if let Some(xff) = headers
        .get("X-Forwarded-For")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(client_from_xff(xff, trusted, peer));
    }
    if let Some(real) = headers
        .get("X-Real-IP")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(real.parse().unwrap_or(peer));
    }
    Some(peer)
}

/// XFF 链内解析：从右向左跳过受信内层代理，取第一个非受信地址；条目非法或
/// 整链受信时回退对端地址（绝不把非法文本当桶 key）。
fn client_from_xff(xff: &str, trusted: &TrustedProxySet, peer: IpAddr) -> IpAddr {
    for candidate in xff.split(',').rev() {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }
        match candidate.parse::<IpAddr>() {
            // 受信内层代理追加的跳，继续向左找真实客户端。
            Ok(ip) if trusted.matches_peer(Some(ip)) => continue,
            Ok(ip) => return ip,
            // 非法条目：无法定性，回退对端（fail-safe，不产新桶）。
            Err(_) => return peer,
        }
    }
    peer
}

/// 共享有界 429 响应（Gateway/Identity 同源形状：固定 JSON + Retry-After +
/// X-Trace-Id 回显；不回显任何请求头原文输入）。
pub fn rate_limit_response(req: &Request, default_trace_id: &str) -> Response {
    let trace_id = req
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default_trace_id);
    let body = serde_json::json!({
        "code": 429,
        "message": "Rate limit exceeded",
        "traceId": trace_id,
        "requestPath": req.uri().path(),
        "requestMethod": req.method().as_str(),
        "errorType": "TOO_MANY_REQUESTS",
        "decision": "RATE_LIMIT_EXCEEDED",
        "reasonCode": "RATE_LIMIT_EXCEEDED",
    });
    let mut response = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    response
        .headers_mut()
        .insert("Retry-After", axum::http::HeaderValue::from_static("1"));
    if let Ok(value) = trace_id.parse::<axum::http::HeaderValue>() {
        response.headers_mut().insert("X-Trace-Id", value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn config(enabled: bool, requests_per_second: u32, burst_size: u32) -> RateLimitCfg {
        RateLimitCfg {
            enabled,
            requests_per_second,
            burst_size,
        }
    }

    fn key(value: &str) -> ClientKey {
        Some(value.parse().unwrap())
    }

    fn compile(entries: &[&str]) -> TrustedProxySet {
        let owned: Vec<String> = entries.iter().map(|entry| (*entry).to_string()).collect();
        TrustedProxySet::compile(&owned)
    }

    fn headers_with(xff: Option<&str>, real: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(xff) = xff {
            headers.insert("X-Forwarded-For", xff.parse().unwrap());
        }
        if let Some(real) = real {
            headers.insert("X-Real-IP", real.parse().unwrap());
        }
        headers
    }

    #[test]
    fn caps_per_key_and_isolates_budgets() {
        let limiter = IpRateLimiter::new(config(true, 2, 0));
        assert!(limiter.check(key("10.0.0.1")));
        assert!(limiter.check(key("10.0.0.1")));
        assert!(
            !limiter.check(key("10.0.0.1")),
            "the window cap must fail closed"
        );
        assert!(
            limiter.check(key("10.0.0.2")),
            "budget must be isolated per client"
        );
    }

    #[test]
    fn burst_adds_in_window_headroom() {
        // rps=2 + burst=4：单窗口内允许 6 次，第 7 次拒绝。
        let limiter = IpRateLimiter::new(config(true, 2, 4));
        for _ in 0..6 {
            assert!(limiter.check(key("10.0.0.1")));
        }
        assert!(!limiter.check(key("10.0.0.1")));
        assert!(limiter.check(key("10.0.0.2")), "burst headroom is per key");
    }

    #[test]
    fn disabled_config_admits_all() {
        let limiter = IpRateLimiter::new(config(false, 0, 0));
        for _ in 0..1000 {
            assert!(limiter.check(key("10.0.0.1")));
        }
        assert!(limiter.check(None));
    }

    #[test]
    fn unresolved_peer_aggregates_into_single_none_bucket() {
        let limiter = IpRateLimiter::new(config(true, 2, 0));
        assert!(limiter.check(None));
        assert!(limiter.check(None));
        assert!(
            !limiter.check(None),
            "unresolved peers must share one bounded bucket"
        );
    }

    #[test]
    fn concurrent_checks_consume_exactly_one_budget() {
        let limiter = Arc::new(IpRateLimiter::new(config(true, 16, 0)));
        let target = key("203.0.113.7");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                std::thread::spawn(move || {
                    let mut accepted = 0u32;
                    for _ in 0..200 {
                        if limiter.check(target) {
                            accepted += 1;
                        }
                    }
                    accepted
                })
            })
            .collect();
        let total: u32 = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        assert_eq!(
            total, 16,
            "concurrent checks must consume exactly the configured budget, never over-admit"
        );
        assert_eq!(
            limiter.tracked(),
            1,
            "concurrent checks must share one bucket"
        );
        assert!(limiter.check(key("203.0.113.8")));
    }

    #[test]
    fn hard_capacity_fails_closed_for_novel_keys_while_existing_keys_stay_served() {
        // gc_threshold = usize::MAX：周期回收永不触发；TTL 极长：强制回收也腾
        // 不出空间 → 全部 key 都热的场景必须由硬容量 fail-closed 兜底。
        let limiter = IpRateLimiter::with_bounds(
            config(true, 1000, 0),
            4,
            usize::MAX,
            Duration::from_secs(3600),
            WINDOW,
            SWEEP_INTERVAL,
        );
        let keys: Vec<ClientKey> = (0..4)
            .map(|octet| Some(IpAddr::from([10, 0, 0, octet])))
            .collect();
        for key in &keys {
            assert!(limiter.check(*key));
        }
        assert!(
            limiter.check(keys[0]),
            "existing keys keep their budget under capacity pressure"
        );
        assert!(
            !limiter.check(Some(IpAddr::from([10, 0, 0, 99]))),
            "novel keys must fail closed at hard capacity"
        );
        assert_eq!(
            limiter.tracked(),
            4,
            "novel key must not be admitted at hard capacity"
        );
    }

    #[test]
    fn zero_capacity_is_degenerate_fail_closed() {
        let limiter = IpRateLimiter::with_bounds(
            config(true, 10, 0),
            0,
            GC_THRESHOLD,
            BUCKET_TTL,
            WINDOW,
            SWEEP_INTERVAL,
        );
        assert!(!limiter.check(key("10.0.0.1")));
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn idle_buckets_are_reclaimed_by_ttl_gc() {
        let limiter = IpRateLimiter::with_bounds(
            config(true, 1000, 0),
            2,
            usize::MAX,
            Duration::from_millis(80),
            WINDOW,
            SWEEP_INTERVAL,
        );
        assert!(limiter.check(key("10.0.0.1")));
        assert!(limiter.check(key("10.0.0.2")));
        assert!(
            !limiter.check(key("10.0.0.3")),
            "capacity exhausted before TTL reclaim"
        );
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            limiter.check(key("10.0.0.3")),
            "idle buckets must be reclaimed to free capacity"
        );
        assert_eq!(
            limiter.tracked(),
            1,
            "only the reclaimed slot's new tenant remains"
        );
    }

    #[test]
    fn periodic_sweep_is_interval_gated_not_per_request() {
        let limiter = IpRateLimiter::with_bounds(
            config(true, 1000, 0),
            16,
            1, // 阈值极低：超过 1 桶即满足回收触发条件
            Duration::from_millis(60),
            WINDOW,
            Duration::from_millis(120), // 全扫间隔
        );
        assert!(limiter.check(key("10.0.0.1")));
        assert!(limiter.check(key("10.0.0.2")));
        assert_eq!(limiter.tracked(), 2);
        // 间隔未到：即使桶数超过阈值也不做 O(n) 全扫。
        assert!(limiter.check(key("10.0.0.3")));
        assert_eq!(
            limiter.tracked(),
            3,
            "no sweep may run before the interval elapses"
        );
        std::thread::sleep(Duration::from_millis(140));
        // 间隔到达：下一次检查触发全扫，TTL 过期桶被回收后重建当前 key。
        assert!(limiter.check(key("10.0.0.3")));
        assert_eq!(
            limiter.tracked(),
            1,
            "idle buckets evicted once the sweep interval elapses"
        );
    }

    #[test]
    fn window_expiry_restores_budget() {
        let limiter = IpRateLimiter::with_bounds(
            config(true, 2, 0),
            HARD_CAPACITY,
            GC_THRESHOLD,
            BUCKET_TTL,
            Duration::from_millis(60),
            SWEEP_INTERVAL,
        );
        let target = key("10.0.0.5");
        assert!(limiter.check(target));
        assert!(limiter.check(target));
        assert!(!limiter.check(target));
        std::thread::sleep(Duration::from_millis(90));
        assert!(
            limiter.check(target),
            "fixed window expiry must reset the budget"
        );
    }

    #[test]
    fn saturating_cap_never_overflows_or_panics() {
        let limiter = IpRateLimiter::new(config(true, u32::MAX, u32::MAX));
        let target = key("10.0.0.9");
        for _ in 0..10_000 {
            assert!(limiter.check(target));
        }
    }

    #[test]
    fn poisoned_mutex_fails_closed_without_panic() {
        let limiter = Arc::new(IpRateLimiter::new(config(true, 2, 0)));
        let victim = Arc::clone(&limiter);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = victim.buckets.lock().unwrap();
            panic!("simulated poisoning panic");
        }));
        assert!(
            !limiter.check(key("10.0.0.1")),
            "poisoned lock must fail closed"
        );
        assert!(
            !limiter.check(None),
            "poisoned lock must fail closed for unresolved peers too"
        );
        assert_eq!(
            limiter.tracked(),
            0,
            "tracked() must report 0 on poison instead of panicking"
        );
    }

    #[test]
    fn validate_config_accepts_defaults_and_disabled() {
        assert_eq!(validate_rate_limit_config(&config(true, 100, 200)), Ok(()));
        assert_eq!(validate_rate_limit_config(&config(false, 0, 0)), Ok(()));
    }

    #[test]
    fn validate_config_rejects_degenerate_enabled_configs() {
        assert_eq!(
            validate_rate_limit_config(&config(true, 0, 0)),
            Err("RATE_LIMIT_CAPACITY_ZERO")
        );
        assert_eq!(
            validate_rate_limit_config(&config(true, 0, 5)),
            Err("RATE_LIMIT_STEADY_STATE_ZERO")
        );
    }

    #[test]
    fn trusted_proxy_exact_and_cidr_match_by_network() {
        let trusted = compile(&["9.9.9.9", "10.1.2.0/24", "fd00:1::/64"]);
        assert!(trusted.matches_peer(key("9.9.9.9")));
        assert!(
            trusted.matches_peer(key("10.1.2.77")),
            "/24 must match any host in the network"
        );
        assert!(!trusted.matches_peer(key("10.1.3.77")));
        assert!(trusted.matches_peer(key("fd00:1::5")));
        assert!(
            !trusted.matches_peer(key("fd00:1:0:1::5")),
            "prefix length must be honored"
        );
        assert!(!trusted.matches_peer(None), "missing peer must fail closed");
        assert!(
            !trusted.matches_peer(key("9.9.9.10")),
            "exact entries must not widen"
        );

        // /0 覆盖整个地址族，且不跨族匹配。
        let any_v4 = compile(&["0.0.0.0/0"]);
        assert!(any_v4.matches_peer(key("203.0.113.1")));
        assert!(!any_v4.matches_peer(key("fd00::1")));

        // /32、/128 与精确地址等价（既有兼容）。
        let host = compile(&["9.9.9.9/32", "fd00::1/128"]);
        assert!(host.matches_peer(key("9.9.9.9")));
        assert!(host.matches_peer(key("fd00::1")));
        assert!(!host.matches_peer(key("9.9.9.8")));
    }

    #[test]
    fn cidr_host_bits_are_masked_not_rejected() {
        let trusted = compile(&["10.1.2.3/8"]);
        assert!(trusted.matches_peer(key("10.200.1.1")));
        assert!(!trusted.matches_peer(key("11.0.0.1")));
    }

    #[test]
    fn invalid_trusted_proxy_entries_fail_closed() {
        let trusted = compile(&[
            "",
            "  ",
            "not-an-ip",
            "10.0.0.0/33",
            "10.0.0.0/two",
            "fd00::/300",
        ]);
        assert_eq!(
            trusted.invalid_entries().len(),
            6,
            "every malformed entry must be reported"
        );
        assert!(
            trusted.is_empty(),
            "no valid entry may remain after rejecting malformed input"
        );
        assert!(!trusted.matches_peer(key("10.0.0.1")));
    }

    #[test]
    fn legacy_dotted_prefix_compat_is_preserved() {
        let trusted = compile(&["10.1."]);
        assert!(
            trusted.matches_peer(key("10.1.2.3")),
            "legacy '10.1.' prefix must keep matching"
        );
        assert!(!trusted.matches_peer(key("10.2.0.1")));
        // 裸 "." 曾等价于信任任意对端（既有缺陷），现在解析期拒绝（已登记修复）。
        let bare = compile(&["."]);
        assert_eq!(bare.invalid_entries().len(), 1);
        assert!(!bare.matches_peer(key("1.2.3.4")));
    }

    #[test]
    fn untrusted_peer_forwarded_headers_are_ignored() {
        let trusted = compile(&["9.9.9.9"]);
        let peer: IpAddr = "7.7.7.7".parse().unwrap();
        let headers = headers_with(Some("1.2.3.4"), Some("8.8.8.8"));
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), &trusted),
            Some(peer),
            "spoofed forwarding headers from an untrusted peer must be ignored"
        );
        assert_eq!(
            resolve_client_ip(&HeaderMap::new(), Some(peer), &trusted),
            Some(peer)
        );
    }

    #[test]
    fn trusted_peer_resolves_rightmost_untrusted_xff_hop() {
        let trusted = compile(&["9.9.9.9"]);
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        // 受信代理在链条最右追加真实客户端 IP：从右向左第一个非受信地址才是
        // 客户端；客户端伪造的最左跳不参与分桶。
        let headers = headers_with(Some("1.2.3.4, 5.6.7.8"), None);
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), &trusted),
            key("5.6.7.8"),
            "client-forged leftmost hops must not decide the bucket"
        );
        // 多层受信代理：内层受信跳跳过，继续向左。
        let chained = headers_with(Some("1.2.3.4, 9.9.9.9"), None);
        assert_eq!(
            resolve_client_ip(&chained, Some(peer), &trusted),
            key("1.2.3.4")
        );
        // 整链皆受信（代理间流量）→ 回退对端地址。
        let all_trusted = headers_with(Some("9.9.9.9"), None);
        assert_eq!(
            resolve_client_ip(&all_trusted, Some(peer), &trusted),
            Some(peer)
        );
        // 非法条目绝不成为桶 key：回退对端。
        let garbage = headers_with(Some("garbage"), None);
        assert_eq!(
            resolve_client_ip(&garbage, Some(peer), &trusted),
            Some(peer)
        );
        // XFF 缺失 → X-Real-IP；非法 X-Real-IP → 对端；XFF 空白 → X-Real-IP 兜底。
        assert_eq!(
            resolve_client_ip(&headers_with(None, Some("8.8.8.8")), Some(peer), &trusted),
            key("8.8.8.8")
        );
        assert_eq!(
            resolve_client_ip(&headers_with(None, Some("nope")), Some(peer), &trusted),
            Some(peer)
        );
        assert_eq!(
            resolve_client_ip(
                &headers_with(Some("  "), Some("8.8.8.8")),
                Some(peer),
                &trusted
            ),
            key("8.8.8.8")
        );
        // 都没有 → 对端地址。
        assert_eq!(
            resolve_client_ip(&HeaderMap::new(), Some(peer), &trusted),
            Some(peer)
        );
    }

    #[test]
    fn missing_connect_info_aggregates_into_unresolved_bucket() {
        let trusted = compile(&["9.9.9.9"]);
        assert_eq!(resolve_client_ip(&HeaderMap::new(), None, &trusted), None);
        assert_eq!(
            resolve_client_ip(&headers_with(Some("1.2.3.4"), None), None, &trusted),
            None,
            "no peer means no trust basis; forwarded input never becomes a key"
        );
    }

    #[test]
    fn rate_limit_response_keeps_bounded_429_contract() {
        let request = Request::builder()
            .uri("/api/v1/auth/verification/send")
            .header("x-request-id", "trace-42")
            .body(Body::empty())
            .unwrap();
        let response = rate_limit_response(&request, "fallback-trace");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["Retry-After"], "1");
        assert_eq!(response.headers()["X-Trace-Id"], "trace-42");

        // 缺 x-request-id → 默认 trace id（各消费方注入自己的前缀）。
        let anonymous = Request::builder().uri("/x").body(Body::empty()).unwrap();
        let response = rate_limit_response(&anonymous, "fallback-trace");
        assert_eq!(response.headers()["X-Trace-Id"], "fallback-trace");
    }

    #[test]
    fn mask_helpers_cover_boundary_prefix_lengths() {
        assert_eq!(mask_v4(u32::from(Ipv4Addr::LOCALHOST), 0), 0);
        assert_eq!(
            mask_v4(u32::from(Ipv4Addr::LOCALHOST), 32),
            u32::from(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(mask_v6(u128::from(Ipv6Addr::LOCALHOST), 0), 0);
        assert_eq!(
            mask_v6(u128::from(Ipv6Addr::LOCALHOST), 128),
            u128::from(Ipv6Addr::LOCALHOST)
        );
    }
}
