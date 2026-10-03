//! 会话 JTI 撤销的进程内注册表（单机组合进程加速器，default-off）。
//!
//! ## 语义边界（安全相关，必须原文理解）
//!
//! - **Redis/DB 仍是权威**：本注册表只是组合进程内的加速镜像。查不到
//!   （未安装、条目被逐出、进程重启后为空）一律回退既有 Redis
//!   `jwt:revoked:{jti}` 检查路径，fail-closed 语义不变。
//! - **只增不漏**：写入方是 Identity 的撤销路径（本进程内已证明的撤销
//!   事实），误判方向只可能是"漏记 → 回退 Redis"，绝无"多记 → 误杀"。
//! - **容量上界**：条目数到达 [`MAX_REGISTRY_ENTRIES`] 时先清理过期条目，
//!   仍满则淘汰最早写入的存活条目。被淘汰条目的撤销由 Redis TTL
//!   （7 天）继续覆盖——淘汰是性能退化，不是安全洞。
//! - 进程重启后注册表为空：Gateway 检查全部回退 Redis，直到本进程再次
//!   见证撤销事实。这与"崩溃 = 全员可见失败 + durable 收口"的单机模型
//!   一致，不引入持久化。
//!
//! 写入点：`astral-identity` 的会话/刷新/全量撤销路径（与 Redis
//! `jwt:revoked:{jti}` 写入同一位置、同一 TTL）。读取点：Gateway
//! 鉴权中间件的撤销检查（注册表命中即 401，未命中继续 Redis 检查）。

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 注册表条目上界（键数）。超限先清过期，仍超限淘汰最早写入条目；
/// 淘汰安全由 Redis 权威回退兜底（见模块文档）。
const MAX_REGISTRY_ENTRIES: usize = 100_000;

/// 容量防线里对存活条目使用的最小剩余 TTL（秒）：淘汰后 Redis 侧至少仍
/// 覆盖该时长，注册表侧不承诺。
const MIN_RETAINED_TTL_SECS: i64 = 60;

static GLOBAL_SESSION_REVOCATION_REGISTRY: OnceLock<SessionRevocationRegistry> = OnceLock::new();

/// 安装进程级注册表（单机组合进程启动期调用一次；重复安装返回 false）。
pub fn install_global_session_revocation_registry() -> bool {
    GLOBAL_SESSION_REVOCATION_REGISTRY
        .set(SessionRevocationRegistry::default())
        .is_ok()
}

/// 进程级注册表句柄；未安装（Rabbit 模式/既有部署）返回 `None`。
pub fn global_session_revocation_registry() -> Option<&'static SessionRevocationRegistry> {
    GLOBAL_SESSION_REVOCATION_REGISTRY.get()
}

fn unix_now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        // 时钟倒退的宿主上退化为"立即过期"：注册表不命中 → 回退 Redis，
        // 绝不因时钟异常延长或伪造撤销状态。
        .unwrap_or(0)
}

/// 进程内 JTI 撤销注册表。克隆共享同一状态（Arc）。
#[derive(Clone, Default)]
pub struct SessionRevocationRegistry {
    entries: Arc<RwLock<HashMap<String, i64>>>,
}

impl SessionRevocationRegistry {
    /// 登记一条撤销事实（与 Redis 黑名单写入同点同 TTL；调用方是本进程内
    /// 已证明的撤销路径）。空 jti 忽略（Redis 侧同样拒绝空键）。
    pub fn mark_revoked(&self, jti: &str, ttl_seconds: i64) {
        let jti = jti.trim();
        if jti.is_empty() {
            return;
        }
        let expires_at = unix_now_seconds() + ttl_seconds.max(MIN_RETAINED_TTL_SECS);
        let Ok(mut entries) = self.entries.write() else {
            return;
        };
        if entries.len() >= MAX_REGISTRY_ENTRIES && !entries.contains_key(jti) {
            let now = unix_now_seconds();
            entries.retain(|_, expires| *expires > now);
            if entries.len() >= MAX_REGISTRY_ENTRIES {
                // 仍满：淘汰任意一个存活条目。被淘汰 jti 的撤销由 Redis
                // 权威路径继续覆盖（注册表未命中 → 回退 Redis）。
                if let Some(first) = entries.keys().next().cloned() {
                    entries.remove(&first);
                }
            }
        }
        entries.insert(jti.to_owned(), expires_at);
    }

    /// 撤销查询：命中未过期条目返回 true；未命中/已过期（惰性清除）返回
    /// false，调用方必须继续走 Redis 权威检查。
    pub fn is_revoked(&self, jti: &str) -> bool {
        let jti = jti.trim();
        if jti.is_empty() {
            return false;
        }
        let Ok(mut entries) = self.entries.write() else {
            return false;
        };
        match entries.get(jti) {
            Some(expires_at) if *expires_at > unix_now_seconds() => true,
            Some(_) => {
                entries.remove(jti);
                false
            }
            None => false,
        }
    }

    /// 当前存活条目数（观测/测试用）。
    pub fn live_entries(&self) -> usize {
        self.entries
            .read()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_then_query_is_revoked_until_expiry() {
        let registry = SessionRevocationRegistry::default();
        assert!(!registry.is_revoked("jti-a"));
        registry.mark_revoked("jti-a", 7 * 24 * 3600);
        assert!(registry.is_revoked("jti-a"));
        assert_eq!(registry.live_entries(), 1);
        assert!(!registry.is_revoked("jti-b"));
    }

    #[test]
    fn empty_and_blank_jti_never_match() {
        let registry = SessionRevocationRegistry::default();
        registry.mark_revoked("", 3600);
        registry.mark_revoked("   ", 3600);
        assert_eq!(registry.live_entries(), 0);
        assert!(!registry.is_revoked(""));
        assert!(!registry.is_revoked("   "));
    }

    #[test]
    fn expired_entries_expire_lazily_and_free_capacity() {
        let registry = SessionRevocationRegistry::default();
        registry.mark_revoked("jti-old", 0);
        // mark 的下限保护把 0 TTL 提到 MIN_RETAINED_TTL_SECS；直接注入一个
        // 已过期时间戳验证惰性过期路径。
        registry
            .entries
            .write()
            .unwrap()
            .insert("jti-expired".to_owned(), unix_now_seconds() - 1);
        assert!(!registry.is_revoked("jti-expired"));
        assert_eq!(registry.live_entries(), 1); // 只剩 min-TTL 的 jti-old
        assert!(registry.is_revoked("jti-old"));
    }

    #[test]
    fn capacity_eviction_prefers_expired_then_drops_entries() {
        let registry = SessionRevocationRegistry::default();
        registry
            .entries
            .write()
            .unwrap()
            .insert("jti-expired".to_owned(), unix_now_seconds() - 1);
        for index in 0..MAX_REGISTRY_ENTRIES {
            registry.mark_revoked(&format!("jti-{index}"), 3600);
        }
        // 过期条目在容量清理中被优先清走，新撤销绝不因容量被拒。
        assert!(registry.is_revoked("jti-0"));
        assert!(!registry.is_revoked("jti-expired"));
        assert!(registry.live_entries() <= MAX_REGISTRY_ENTRIES);
    }

    #[test]
    fn clones_share_state() {
        let registry = SessionRevocationRegistry::default();
        let clone = registry.clone();
        registry.mark_revoked("jti-shared", 3600);
        assert!(clone.is_revoked("jti-shared"));
    }

    #[test]
    fn global_install_is_first_wins_and_absent_elsewhere() {
        // 全局槽位进程级一次；本测试只验证 first-wins 与句柄可见性，
        // 不依赖安装顺序（重复安装返回 false）。
        let first = install_global_session_revocation_registry();
        let second = install_global_session_revocation_registry();
        assert!(first || second);
        assert!(global_session_revocation_registry().is_some());
        if let Some(registry) = global_session_revocation_registry() {
            registry.mark_revoked("jti-global-test", 3600);
            assert!(registry.is_revoked("jti-global-test"));
        }
    }
}
