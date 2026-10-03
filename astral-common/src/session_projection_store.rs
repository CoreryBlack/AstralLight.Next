//! Redis-free 会话投影存储（strict durable facts + 有界进程内镜像）。
//!
//! ## 背景
//!
//! 历史 Gateway 会话有效性判定依赖 Redis 三类键：`jwt:revoked:{jti}` 黑名单、
//! `access:jti:{jti}` 标量存活投影与 `access:grant:{jti}` 版本化 grant。本模块
//! 把同一批判定迁移到 **MySQL strict durable facts**（`auth_session_jti_index`
//! × `auth_device_session` × `auth_token_family` × `user_card` × `identity_card`），
//! 并提供**有界进程内镜像**作为可选加速器；Redis 退化为显式配置的
//! default-off 兼容 adapter。
//!
//! ## 安全语义（必须原文理解）
//!
//! - **未命中绝不放行**：镜像命中撤销事实 → 立即拒绝；镜像未命中/过期/驱逐/
//!   suspect → 必须回退 strict DB 读取。任何路径都不以"缓存未命中"推导 ACTIVE。
//! - **positive allow 的安装边界**：镜像 active grant 只能在
//!   [`MirrorPolicy::VerifiedPositive`] 下参与放行。独立（多写者）Gateway
//!   **没有** SessionRevoked fanout 订阅与单写者保证，必须保持
//!   [`MirrorPolicy::DenyOnly`]（撤销 marker 可加速，ALLOW 每请求 strict DB），
//!   直到自身拥有完整的 channel proof/watermark。组合进程（单写者，global
//!   LocalBus/hub 安装方）经显式配置开启 VerifiedPositive。
//! - **源回收后即拒绝**：ALLOW 只能来自 durable 事实（jti index ACTIVE +
//!   session ACTIVE + family ACTIVE + 卡绑定逐项一致 + 未过期），DB 侧撤销
//!   （status='DELETED'/REVOKED）下一请求立即生效。
//! - **逐项绑定**：session id / version / epoch / user / identity card /
//!   user card / tenant / domain / expiry 任何一项与 durable 事实不一致一律
//!   拒绝（见 [`evaluate_access_fact`]，UTC epoch 绑定）。
//! - **镜像只承载已证明事实**：写入方仅限"本进程已完成 durable proof 写入并
//!   经 strict DB 复核"的签发路径（见 astral-db
//!   `install_verified_access_grant`）。镜像有 TTL、容量上界与 GC；suspect
//!   （含永久 suspect 开关）后 positive cache 全部旁路，只保留 deny 加速。
//! - **单调时钟**：镜像条目 TTL 与 suspect 窗口使用 [`std::time::Instant`]
//!   单调时钟（墙钟倒退绝不延长活跃条目）；durable expiry 绑定仍用 UTC epoch
//!   （[`evaluate_access_fact`]，与 JWT/DB 时间域一致）。
//! - **故障 fail-closed**：strict DB 读取失败返回 [`SessionProjectionDecision::Unavailable`]，
//!   调用方（Gateway）必须拒绝（503），不得降级放行。
//!
//! ## 与既有 `session_revocation_registry` 的关系
//!
//! 既有注册表是"撤销加速 deny"（命中即拒、未命中继续权威检查），语义不变且
//! 继续可用；本模块的镜像在其之上补齐"活跃 grant 加速 allow"（仅
//! VerifiedPositive 策略），并同样遵循"未命中回退 strict DB"。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// 镜像默认条目容量上界（grants 与 revoked 各自独立计数）。
pub const DEFAULT_MIRROR_MAX_ENTRIES: usize = 100_000;
/// 镜像活跃 grant 默认 TTL（秒）。到期后未命中 → 回退 strict DB。
pub const DEFAULT_MIRROR_GRANT_TTL_SECS: u64 = 900;
/// 容量防线里对存活条目使用的最小剩余 TTL（秒）。
const MIN_RETAINED_TTL_SECS: u64 = 60;

/// suspect 状态编码（AtomicU8）：0 = 健康，1 = 限时 suspect，2 = 永久 suspect。
const SUSPECT_HEALTHY: u8 = 0;
const SUSPECT_TIMED: u8 = 1;
const SUSPECT_PERMANENT: u8 = 2;

/// 镜像放行策略。
///
/// - [`MirrorPolicy::DenyOnly`]（默认/安全）：镜像只承载撤销 marker（命中即
///   拒）；ALLOW 一律 strict DB。适用于独立多写者 Gateway。
/// - [`MirrorPolicy::VerifiedPositive`]：镜像 active grant 命中且逐项绑定
///   一致时可放行。**仅限**显式配置 + 单写者组合进程（见模块文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorPolicy {
    DenyOnly,
    VerifiedPositive,
}

/// Gateway 鉴权侧用于与 durable 事实逐项绑定的 claims 事实集。
///
/// 字段与 `astral_common::middleware::JwtClaims` 的会话命名空间一一对应；
/// 单独建模以避免本模块依赖中间件类型（Identity 签发侧也复用同一绑定语义）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionBindContext {
    pub user_id: i64,
    pub session_id: i64,
    pub session_version: i64,
    pub session_epoch: i64,
    pub token_family_id: i64,
    pub principal_kind: &'static str,
    pub identity_card_id: Option<i64>,
    pub user_card_id: Option<i64>,
    pub user_card_tenant_id: Option<i64>,
    pub user_card_domain_id: Option<i64>,
    /// JWT `exp`（epoch second）。
    pub expires_at_epoch_second: i64,
}

/// strict DB 侧返回的 durable 会话事实（单行 JOIN 结果）。
///
/// 由 astral-db 的 MySQL source 组装；字段语义与 DDL 列一一对应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSessionDurableFact {
    pub session_id: i64,
    pub user_id: i64,
    pub session_version: i64,
    pub session_epoch: i64,
    pub family_id: i64,
    pub current_user_card_id: Option<i64>,
    pub user_card_tenant_id: Option<i64>,
    pub user_card_domain_id: Option<i64>,
    pub jti_status: String,
    pub session_status: String,
    pub session_state: String,
    pub family_status: Option<String>,
    pub user_card_status: Option<String>,
    /// `auth_session_jti_index.expires_at`（epoch second）；NULL 视为未证明。
    pub jti_expires_at_epoch_second: Option<i64>,
}

/// 会话判定结果。
///
/// - `Allow`：durable（或 VerifiedPositive 镜像内已证明的）事实与绑定上下文
///   逐项一致且未过期。
/// - `Deny`：事实存在但任一项不一致/已撤销/已过期——拒绝并给出稳定 reason。
/// - `Unavailable`：权威读取失败（DB 错误/超时）。调用方必须 fail-closed。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProjectionDecision {
    Allow,
    Deny(&'static str),
    Unavailable,
}

impl SessionProjectionDecision {
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// `lookup_grant` 的"镜像未命中"哨兵：store 层据此回退 strict DB（对调用方
/// 不可见，外部 reason 集合不含该值）。
const MIRROR_MISS: &str = "__MIRROR_MISS__";

/// 评估 durable 事实与绑定上下文是否逐项一致（纯函数，安全核心）。
///
/// 任一不足（状态非 ACTIVE、version/epoch/user/card/tenant/domain/expiry 不
/// 绑定、jti 未证明过期时间）→ `Err(reason)`。未知状态一律拒绝（fail-closed）。
/// expiry 绑定使用 UTC epoch（与 JWT/DB 时间域一致）。
pub fn evaluate_access_fact(
    fact: &AccessSessionDurableFact,
    bind: &SessionBindContext,
) -> Result<(), &'static str> {
    if fact.jti_status != "ACTIVE" {
        return Err("TOKEN_REVOKED");
    }
    let Some(jti_expires_at) = fact.jti_expires_at_epoch_second else {
        return Err("SESSION_NOT_FOUND");
    };
    let now = utc_now_seconds();
    if jti_expires_at <= now || bind.expires_at_epoch_second <= now {
        return Err("TOKEN_EXPIRED");
    }
    if bind.expires_at_epoch_second > jti_expires_at {
        // JWT 自称比 durable 证明活得更久：证明面不足，拒绝。
        return Err("TOKEN_EXPIRED");
    }
    if fact.session_status != "ACTIVE" || fact.session_state != "ACTIVE" {
        return Err("SESSION_NOT_FOUND");
    }
    if fact.session_id != bind.session_id
        || fact.user_id != bind.user_id
        || fact.session_version != bind.session_version
        || fact.session_epoch != bind.session_epoch
        || fact.family_id != bind.token_family_id
    {
        return Err("SESSION_CONTEXT_MISMATCH");
    }
    match fact.family_status.as_deref() {
        Some("ACTIVE") => {}
        // family 是会话的 durable 父事实：缺失/过期/撤销/未知状态全部拒绝。
        _ => return Err("TOKEN_REVOKED"),
    }
    if bind.identity_card_id.is_none() || bind.identity_card_id.unwrap_or(0) <= 0 {
        return Err("SESSION_CONTEXT_MISMATCH");
    }
    // identity_card 存在性与 ACTIVE 由 source JOIN 保证（JOIN 不上 → 无行 → Deny）。
    if bind.principal_kind == "APP_USER" {
        if fact.current_user_card_id.is_some()
            || fact.user_card_status.is_some()
            || bind.user_card_id.is_some()
            || bind.user_card_tenant_id.is_some()
            || bind.user_card_domain_id.is_some()
        {
            return Err("SESSION_CONTEXT_MISMATCH");
        }
        return Ok(());
    }
    if bind.principal_kind != "PLATFORM_USER" {
        return Err("SESSION_CONTEXT_MISMATCH");
    }
    let Some(user_card_id) = bind.user_card_id.filter(|value| *value > 0) else {
        return Err("SESSION_CONTEXT_MISMATCH");
    };
    if fact.current_user_card_id != Some(user_card_id) {
        return Err("SESSION_CONTEXT_MISMATCH");
    }
    if fact.user_card_status.as_deref() != Some("ACTIVE") {
        return Err("SESSION_NOT_FOUND");
    }
    if bind.user_card_tenant_id.is_none()
        || bind.user_card_domain_id.is_none()
        || fact.user_card_tenant_id != bind.user_card_tenant_id
        || fact.user_card_domain_id != bind.user_card_domain_id
    {
        return Err("SESSION_CONTEXT_MISMATCH");
    }
    Ok(())
}

/// strict 会话事实源（由 astral-db 提供 MySQL 实现）。
///
/// `Err` 表示权威读取失败（连接/超时/SQL 错误）→ 调用方必须 Unavailable；
/// `Ok(None)` 表示 durable 事实不存在（JOIN 不上，含 identity/user card
/// 失活）→ 调用方必须 Deny。绝不把 Err 折算成 None。
#[async_trait]
pub trait AccessSessionSource: Send + Sync {
    async fn load_access_fact(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> Result<Option<AccessSessionDurableFact>, String>;

    async fn load_access_fact_with_validity(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> Result<Option<VerifiedAccessSessionFact>, String> {
        self.load_access_fact(jti, bind).await.map(|fact| {
            fact.map(|fact| VerifiedAccessSessionFact {
                fact,
                cache_valid_until_epoch_second: None,
            })
        })
    }
}

/// A strict source must prove all physical expiry limits before enabling caching.
pub struct VerifiedAccessSessionFact {
    pub fact: AccessSessionDurableFact,
    pub cache_valid_until_epoch_second: Option<i64>,
}

fn evaluate_verified_access_fact(
    verified: &VerifiedAccessSessionFact,
    bind: &SessionBindContext,
) -> Result<(), &'static str> {
    evaluate_access_fact(&verified.fact, bind)?;
    if verified
        .cache_valid_until_epoch_second
        .is_some_and(|deadline| deadline <= utc_now_seconds())
    {
        return Err("SESSION_NOT_FOUND");
    }
    Ok(())
}

/// 签发侧登记的活跃 grant（仅本进程已完成 durable proof 写入 + strict DB
/// 复核后调用；见 astral-db `install_verified_access_grant`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedAccessGrant {
    pub jti: String,
    pub session_id: i64,
    pub session_version: i64,
    pub session_epoch: i64,
    pub user_id: i64,
    pub token_family_id: i64,
    pub identity_card_id: Option<i64>,
    pub user_card_id: Option<i64>,
    pub user_card_tenant_id: Option<i64>,
    pub user_card_domain_id: Option<i64>,
    pub principal_kind: &'static str,
    /// access token 过期时间（epoch second），镜像 TTL 不得超过它。
    pub expires_at_epoch_second: i64,
}

impl IssuedAccessGrant {
    pub fn matches_bind(&self, bind: &SessionBindContext) -> bool {
        self.binds_match(bind)
    }

    fn binds_match(&self, bind: &SessionBindContext) -> bool {
        self.user_id == bind.user_id
            && self.session_id == bind.session_id
            && self.session_version == bind.session_version
            && self.session_epoch == bind.session_epoch
            && self.token_family_id == bind.token_family_id
            && self.principal_kind == bind.principal_kind
            && self.identity_card_id == bind.identity_card_id
            && self.user_card_id == bind.user_card_id
            && self.user_card_tenant_id == bind.user_card_tenant_id
            && self.user_card_domain_id == bind.user_card_domain_id
            && self.expires_at_epoch_second >= bind.expires_at_epoch_second
    }
}

#[derive(Debug, Clone)]
struct MirrorGrant {
    grant: IssuedAccessGrant,
    /// 镜像条目自身的过期时刻（单调时钟；受 grant TTL 上限与配置 TTL 约束）。
    mirror_expires_at: Instant,
}

#[derive(Debug, Default)]
struct MirrorInner {
    grants: HashMap<String, MirrorGrant>,
    revoked: HashMap<String, Instant>,
}

/// 有界进程内会话镜像（TTL + 容量 + GC + suspect 栅栏，单调时钟）。
///
/// - **deny 永远安全**：撤销 marker 命中即拒；任何策略下都启用。
/// - **grant 侧（仅 VerifiedPositive）**：条目由签发路径在本进程 durable
///   proof 落库并 strict 复核后写入；绑定不一致直接 Deny（伪造 claims 不因
///   镜像存在而放行）。
/// - **suspect**：限时（ [`Self::mark_suspect_for_secs`]）或永久
///   （[`Self::mark_suspect_permanent`]，positive cache 旁路开关）；
///   锁中毒保持 positive cache 不可用；限时 suspect 清除已有正向条目，
///   窗口结束后也必须重新严格验证。撤销 marker 不受影响。
#[derive(Debug)]
pub struct SessionProjectionMirror {
    inner: RwLock<MirrorInner>,
    grant_ttl: Duration,
    max_entries: usize,
    suspect_state: AtomicU8,
    /// 限时 suspect 截止（单调时钟）；permanent suspect 时忽略。
    suspect_until: Mutex<Option<Instant>>,
}

impl Default for SessionProjectionMirror {
    fn default() -> Self {
        Self::new(DEFAULT_MIRROR_GRANT_TTL_SECS, DEFAULT_MIRROR_MAX_ENTRIES)
    }
}

impl SessionProjectionMirror {
    pub fn new(grant_ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            inner: RwLock::new(MirrorInner::default()),
            grant_ttl: Duration::from_secs(grant_ttl_secs.clamp(1, DEFAULT_MIRROR_GRANT_TTL_SECS)),
            max_entries: max_entries.clamp(1, DEFAULT_MIRROR_MAX_ENTRIES),
            suspect_state: AtomicU8::new(SUSPECT_HEALTHY),
            suspect_until: Mutex::new(None),
        }
    }

    /// positive allow 是否当前可用（healthy + VerifiedPositive 由 store 层
    /// 叠加判断；此处只表达镜像自身的 suspect 健康度）。
    fn grant_mirror_healthy(&self) -> bool {
        match self.suspect_state.load(Ordering::Acquire) {
            SUSPECT_PERMANENT => false,
            SUSPECT_TIMED => {
                let Ok(until) = self.suspect_until.lock().map(|guard| *guard) else {
                    self.mark_suspect_permanent();
                    return false;
                };
                match until {
                    Some(deadline) if Instant::now() < deadline => false,
                    // 限时窗口已过：恢复健康。
                    _ => self
                        .suspect_state
                        .compare_exchange(
                            SUSPECT_TIMED,
                            SUSPECT_HEALTHY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok(),
                }
            }
            _ => true,
        }
    }

    /// 限时 suspect：窗口内 grant 查询全部 Miss（回退 strict DB）。
    pub fn mark_suspect_for_secs(&self, seconds: u64) {
        self.invalidate_all_grants();
        if self.suspect_state.load(Ordering::Acquire) == SUSPECT_PERMANENT {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(Duration::from_secs(seconds.max(1))) else {
            self.mark_suspect_permanent();
            return;
        };
        let Ok(mut guard) = self.suspect_until.lock() else {
            self.mark_suspect_permanent();
            return;
        };
        *guard = Some(deadline);
        let mut state = self.suspect_state.load(Ordering::Acquire);
        while state != SUSPECT_PERMANENT {
            match self.suspect_state.compare_exchange_weak(
                state,
                SUSPECT_TIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => state = current,
            }
        }
    }

    /// 永久 suspect：positive cache 全部旁路（显式配置开关；撤销 marker 的
    /// deny 加速保持可用）。
    pub fn mark_suspect_permanent(&self) {
        self.suspect_state
            .store(SUSPECT_PERMANENT, Ordering::Release);
    }

    /// 登记撤销事实：立即失效对应 grant 并记录 revoked 条目（同点写入
    /// `session_revocation_registry` 由调用方完成，这里只管镜像）。
    pub fn mark_revoked(&self, jti: &str, ttl_seconds: u64) {
        let jti = jti.trim();
        if jti.is_empty() || jti.len() > 255 {
            return;
        }
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(ttl_seconds.max(MIN_RETAINED_TTL_SECS)))
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(7 * 24 * 3600));
        let Ok(mut inner) = self.inner.write() else {
            self.mark_suspect_for_secs(60);
            return;
        };
        inner.grants.remove(jti);
        gc_revoked(&mut inner.revoked, self.max_entries);
        inner.revoked.insert(jti.to_owned(), expires_at);
    }

    /// Discard positive facts after a source writer changes their binding scope.
    pub fn invalidate_all_grants(&self) {
        match self.inner.write() {
            Ok(mut inner) => inner.grants.clear(),
            Err(_) => self.mark_suspect_permanent(),
        }
    }

    /// 会话级事件失效：按 session_id 失效全部 grant 条目（撤销方没有逐
    /// jti 清单时的保守失效；漏失效只会退化为镜像滞后 → strict DB 兜底）。
    pub fn invalidate_session(&self, session_id: i64) {
        let Ok(mut inner) = self.inner.write() else {
            self.mark_suspect_for_secs(60);
            return;
        };
        inner
            .grants
            .retain(|_, entry| entry.grant.session_id != session_id);
    }

    /// 登记活跃 grant（签发侧 durable proof 落库并复核后调用）。同 session
    /// 旧 epoch 条目一并失效（epoch fencing 的镜像侧投影）。
    pub fn install_grant(&self, grant: IssuedAccessGrant) {
        self.install_grant_until(grant, i64::MAX);
    }

    pub fn install_grant_until(&self, grant: IssuedAccessGrant, valid_until: i64) {
        if grant.jti.trim().is_empty() || grant.jti.len() > 255 {
            return;
        }
        let Ok(mut inner) = self.inner.write() else {
            self.mark_suspect_permanent();
            return;
        };
        if inner.grants.values().any(|entry| {
            entry.grant.session_id == grant.session_id
                && entry.grant.session_epoch > grant.session_epoch
        }) {
            return;
        }
        // epoch fencing：同 session 的旧 epoch grant 全部失效。
        inner.grants.retain(|_, entry| {
            entry.grant.session_id != grant.session_id
                || entry.grant.session_epoch >= grant.session_epoch
        });
        // 镜像 TTL 不得超过 access token 自身的过期上界。
        let now_epoch = utc_now_seconds();
        let token_lifetime = grant
            .expires_at_epoch_second
            .min(valid_until)
            .saturating_sub(now_epoch);
        if token_lifetime <= 0 {
            return;
        }
        let mirror_expires_at = Instant::now()
            + self
                .grant_ttl
                .min(Duration::from_secs(token_lifetime as u64));
        gc_grants(&mut inner.grants, self.max_entries);
        gc_revoked(&mut inner.revoked, self.max_entries);
        inner.grants.insert(
            grant.jti.trim().to_owned(),
            MirrorGrant {
                grant,
                mirror_expires_at,
            },
        );
    }

    /// 撤销查询：命中未过期条目 → true（deny 方向，任何策略/suspect 下启用）。
    pub fn lookup_revoked(&self, jti: &str) -> bool {
        let jti = jti.trim();
        if jti.is_empty() {
            return false;
        }
        let Ok(mut inner) = self.inner.write() else {
            return false;
        };
        match inner.revoked.get(jti) {
            Some(expires_at) if *expires_at > Instant::now() => true,
            Some(_) => {
                inner.revoked.remove(jti);
                false
            }
            None => false,
        }
    }

    /// grant 查询：命中且绑定一致且未过期 → `Allow`；命中但不一致 →
    /// `Deny`；未命中/过期/suspect → Miss 哨兵（store 层回退 strict DB）。
    pub fn lookup_grant(&self, jti: &str, bind: &SessionBindContext) -> SessionProjectionDecision {
        let jti = jti.trim();
        if jti.is_empty() {
            return SessionProjectionDecision::Deny("SESSION_NOT_FOUND");
        }
        if !self.grant_mirror_healthy() {
            return SessionProjectionDecision::Deny(MIRROR_MISS);
        }
        let Ok(mut inner) = self.inner.write() else {
            self.mark_suspect_for_secs(60);
            return SessionProjectionDecision::Deny(MIRROR_MISS);
        };
        match inner.grants.get(jti) {
            Some(entry)
                if entry.mirror_expires_at > Instant::now()
                    && entry.grant.expires_at_epoch_second > utc_now_seconds()
                    && bind.expires_at_epoch_second > utc_now_seconds() =>
            {
                if entry.grant.binds_match(bind) {
                    SessionProjectionDecision::Allow
                } else {
                    SessionProjectionDecision::Deny("SESSION_CONTEXT_MISMATCH")
                }
            }
            Some(_) => {
                inner.grants.remove(jti);
                SessionProjectionDecision::Deny(MIRROR_MISS)
            }
            None => SessionProjectionDecision::Deny(MIRROR_MISS),
        }
    }

    /// 观测计数（测试/诊断用）。
    pub fn live_entries(&self) -> (usize, usize) {
        self.inner
            .read()
            .map(|inner| (inner.grants.len(), inner.revoked.len()))
            .unwrap_or((0, 0))
    }
}

fn gc_grants(grants: &mut HashMap<String, MirrorGrant>, max_entries: usize) {
    if grants.len() < max_entries {
        return;
    }
    let now = Instant::now();
    grants.retain(|_, entry| entry.mirror_expires_at > now);
    while grants.len() >= max_entries {
        // 仍满：淘汰任意存活条目。被淘汰 jti 的判定退化为 strict DB 读取，
        // 是性能退化不是安全洞。
        let Some(victim) = grants.keys().next().cloned() else {
            break;
        };
        grants.remove(&victim);
    }
}

fn gc_revoked(revoked: &mut HashMap<String, Instant>, max_entries: usize) {
    if revoked.len() < max_entries {
        return;
    }
    let now = Instant::now();
    revoked.retain(|_, expires_at| *expires_at > now);
    while revoked.len() >= max_entries {
        let Some(victim) = revoked.keys().next().cloned() else {
            break;
        };
        revoked.remove(&victim);
    }
}

/// UTC epoch second（仅用于 durable expiry 绑定；镜像 TTL 一律单调时钟）。
fn utc_now_seconds() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => i64::MAX,
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SessionRefillKey {
    jti: String,
    bind: SessionBindContext,
}

#[derive(Default)]
struct SessionRefills {
    locks: Mutex<HashMap<SessionRefillKey, Weak<tokio::sync::Mutex<()>>>>,
}

impl SessionRefills {
    fn lock_for(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> Option<Arc<tokio::sync::Mutex<()>>> {
        if jti.len() > 255 {
            return None;
        }
        let mut locks = self.locks.lock().ok()?;
        locks.retain(|_, lock| lock.strong_count() != 0);
        let key = SessionRefillKey {
            jti: jti.to_owned(),
            bind: bind.clone(),
        };
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return Some(lock);
        }
        if locks.len() >= 1024 {
            return None;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        Some(lock)
    }
}

/// 组合存储：strict source（必选）+ 有界镜像（可选加速器）+ 镜像放行策略。
pub struct SessionProjectionStore {
    source: Arc<dyn AccessSessionSource>,
    mirror: Option<SessionProjectionMirror>,
    policy: MirrorPolicy,
    refills: SessionRefills,
}

impl SessionProjectionStore {
    pub fn new(
        source: Arc<dyn AccessSessionSource>,
        mirror: Option<SessionProjectionMirror>,
        policy: MirrorPolicy,
    ) -> Self {
        Self {
            source,
            mirror,
            policy,
            refills: SessionRefills::default(),
        }
    }

    pub fn mirror(&self) -> Option<&SessionProjectionMirror> {
        self.mirror.as_ref()
    }

    /// positive allow 是否被策略允许（观测/安装侧守卫用）。
    pub fn mirror_positive_allowed(&self) -> bool {
        self.policy == MirrorPolicy::VerifiedPositive && self.mirror.is_some()
    }

    /// Gateway 会话判定主路径：
    /// 1. 镜像撤销 marker 命中 → Deny（已证明撤销事实，任何策略下启用）；
    /// 2. 仅 VerifiedPositive：镜像 grant 命中且绑定一致 → Allow（健康 +
    ///    未过期 + 逐项绑定）；
    /// 3. 其余一律 strict DB：`Err` → Unavailable，`Ok(None)` → Deny，
    ///    `Ok(Some)` → [`evaluate_access_fact`] 逐项绑定后 Allow/Deny。
    pub async fn verify_access(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> SessionProjectionDecision {
        if let Some(mirror) = &self.mirror {
            if mirror.lookup_revoked(jti) {
                return SessionProjectionDecision::Deny("TOKEN_REVOKED");
            }
            if self.policy == MirrorPolicy::VerifiedPositive {
                match mirror.lookup_grant(jti, bind) {
                    SessionProjectionDecision::Allow => return SessionProjectionDecision::Allow,
                    SessionProjectionDecision::Deny(MIRROR_MISS) => {}
                    SessionProjectionDecision::Deny(reason) => {
                        return SessionProjectionDecision::Deny(reason)
                    }
                    SessionProjectionDecision::Unavailable => {}
                }
            }
        }
        self.verify_access_strict(jti, bind).await
    }

    /// Verify durable facts when the host cannot prove its positive mirror current.
    pub async fn verify_access_strict(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> SessionProjectionDecision {
        if let Some(mirror) = &self.mirror {
            if mirror.lookup_revoked(jti) {
                return SessionProjectionDecision::Deny("TOKEN_REVOKED");
            }
        }
        let decision = match tokio::time::timeout(
            Duration::from_secs(3),
            self.source.load_access_fact_with_validity(jti, bind),
        )
        .await
        {
            Ok(Ok(Some(verified))) => match evaluate_verified_access_fact(&verified, bind) {
                Ok(()) => SessionProjectionDecision::Allow,
                Err(reason) => SessionProjectionDecision::Deny(reason),
            },
            Ok(Ok(None)) => SessionProjectionDecision::Deny("SESSION_NOT_FOUND"),
            Ok(Err(_)) | Err(_) => SessionProjectionDecision::Unavailable,
        };
        if self
            .mirror
            .as_ref()
            .is_some_and(|mirror| mirror.lookup_revoked(jti))
        {
            return SessionProjectionDecision::Deny("TOKEN_REVOKED");
        }
        decision
    }

    /// Refill positive facts only while the host's writer and health token stays current.
    pub async fn verify_access_with_fence<F>(
        &self,
        jti: &str,
        bind: &SessionBindContext,
        fence_current: F,
    ) -> SessionProjectionDecision
    where
        F: Fn() -> bool,
    {
        if !fence_current() {
            return SessionProjectionDecision::Unavailable;
        }
        if let Some(hit) = self.mirror_decision(jti, bind) {
            return if fence_current() {
                hit
            } else {
                SessionProjectionDecision::Unavailable
            };
        }
        let Some(lock) = self.refills.lock_for(jti, bind) else {
            return SessionProjectionDecision::Unavailable;
        };
        let Ok(_guard) = tokio::time::timeout(Duration::from_secs(3), lock.lock()).await else {
            return SessionProjectionDecision::Unavailable;
        };
        if !fence_current() {
            return SessionProjectionDecision::Unavailable;
        }
        if let Some(hit) = self.mirror_decision(jti, bind) {
            return if fence_current() {
                hit
            } else {
                SessionProjectionDecision::Unavailable
            };
        }
        let read = tokio::time::timeout(
            Duration::from_secs(3),
            self.source.load_access_fact_with_validity(jti, bind),
        )
        .await;
        if !fence_current() {
            return SessionProjectionDecision::Unavailable;
        }
        let decision = match read {
            Ok(Ok(Some(verified))) => match evaluate_verified_access_fact(&verified, bind) {
                Ok(()) => {
                    if let Some(valid_until) = verified.cache_valid_until_epoch_second {
                        if self.policy == MirrorPolicy::VerifiedPositive {
                            if let Some(mirror) = &self.mirror {
                                mirror.install_grant_until(grant_from_bind(jti, bind), valid_until);
                            }
                        }
                    }
                    SessionProjectionDecision::Allow
                }
                Err(reason) => SessionProjectionDecision::Deny(reason),
            },
            Ok(Ok(None)) => SessionProjectionDecision::Deny("SESSION_NOT_FOUND"),
            Ok(Err(_)) | Err(_) => SessionProjectionDecision::Unavailable,
        };
        if !fence_current() {
            if let Some(mirror) = &self.mirror {
                mirror.invalidate_all_grants();
            }
            return SessionProjectionDecision::Unavailable;
        }
        let decision = self.mirror_decision(jti, bind).unwrap_or(decision);
        if fence_current() {
            decision
        } else {
            SessionProjectionDecision::Unavailable
        }
    }

    fn mirror_decision(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> Option<SessionProjectionDecision> {
        let mirror = self.mirror.as_ref()?;
        if mirror.lookup_revoked(jti) {
            return Some(SessionProjectionDecision::Deny("TOKEN_REVOKED"));
        }
        if self.policy == MirrorPolicy::VerifiedPositive {
            match mirror.lookup_grant(jti, bind) {
                SessionProjectionDecision::Deny(MIRROR_MISS)
                | SessionProjectionDecision::Unavailable => {}
                decision => return Some(decision),
            }
        }
        None
    }

    /// 签发侧登记：durable proof 已落库并 strict 复核后调用（DenyOnly 策略
    /// 下跳过 grant 登记，只保留撤销 marker 通道）。
    pub fn note_grant_installed(&self, grant: IssuedAccessGrant) {
        if self.policy != MirrorPolicy::VerifiedPositive {
            return;
        }
        if let Some(mirror) = &self.mirror {
            mirror.install_grant(grant);
        }
    }

    /// 撤销侧登记：durable 关闭已发生后调用。镜像 + 既有
    /// `session_revocation_registry` 同点登记（deny 加速，任何策略下启用）。
    pub fn note_revocation(&self, jti: &str, ttl_seconds: u64) {
        if let Some(mirror) = &self.mirror {
            mirror.mark_revoked(jti, ttl_seconds);
        }
        if let Some(registry) =
            crate::session_revocation_registry::global_session_revocation_registry()
        {
            registry.mark_revoked(jti, ttl_seconds as i64);
        }
    }

    /// 会话级事件失效（无逐 jti 清单时的保守镜像失效）。
    pub fn note_session_invalidated(&self, session_id: i64) {
        if let Some(mirror) = &self.mirror {
            mirror.invalidate_session(session_id);
        }
    }
}

fn grant_from_bind(jti: &str, bind: &SessionBindContext) -> IssuedAccessGrant {
    IssuedAccessGrant {
        jti: jti.to_owned(),
        session_id: bind.session_id,
        session_version: bind.session_version,
        session_epoch: bind.session_epoch,
        user_id: bind.user_id,
        token_family_id: bind.token_family_id,
        identity_card_id: bind.identity_card_id,
        user_card_id: bind.user_card_id,
        user_card_tenant_id: bind.user_card_tenant_id,
        user_card_domain_id: bind.user_card_domain_id,
        principal_kind: bind.principal_kind,
        expires_at_epoch_second: bind.expires_at_epoch_second,
    }
}

static GLOBAL_SESSION_PROJECTION_STORE: std::sync::OnceLock<Arc<SessionProjectionStore>> =
    std::sync::OnceLock::new();

/// 安装进程级会话投影存储（Gateway/组合进程启动期调用一次；first-wins）。
pub fn install_global_session_projection_store(store: Arc<SessionProjectionStore>) -> bool {
    GLOBAL_SESSION_PROJECTION_STORE.set(store).is_ok()
}

/// 进程级存储句柄；未安装（strict-only 或测试）返回 `None`。
pub fn global_session_projection_store() -> Option<&'static Arc<SessionProjectionStore>> {
    GLOBAL_SESSION_PROJECTION_STORE.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind(
        user_card: Option<i64>,
        tenant: Option<i64>,
        domain: Option<i64>,
    ) -> SessionBindContext {
        SessionBindContext {
            user_id: 42,
            session_id: 7,
            session_version: 2,
            session_epoch: 3,
            token_family_id: 11,
            principal_kind: "PLATFORM_USER",
            identity_card_id: Some(10),
            user_card_id: user_card,
            user_card_tenant_id: tenant,
            user_card_domain_id: domain,
            expires_at_epoch_second: utc_now_seconds() + 600,
        }
    }

    fn active_fact(
        card: Option<i64>,
        tenant: Option<i64>,
        domain: Option<i64>,
    ) -> AccessSessionDurableFact {
        AccessSessionDurableFact {
            session_id: 7,
            user_id: 42,
            session_version: 2,
            session_epoch: 3,
            family_id: 11,
            current_user_card_id: card,
            user_card_tenant_id: tenant,
            user_card_domain_id: domain,
            jti_status: "ACTIVE".into(),
            session_status: "ACTIVE".into(),
            session_state: "ACTIVE".into(),
            family_status: Some("ACTIVE".into()),
            user_card_status: card.map(|_| "ACTIVE".to_string()),
            jti_expires_at_epoch_second: Some(utc_now_seconds() + 1200),
        }
    }

    fn issued(jti: &str, epoch: i64) -> IssuedAccessGrant {
        IssuedAccessGrant {
            jti: jti.into(),
            session_id: 7,
            session_version: 2,
            session_epoch: epoch,
            user_id: 42,
            token_family_id: 11,
            identity_card_id: Some(10),
            user_card_id: Some(40),
            user_card_tenant_id: Some(20),
            user_card_domain_id: Some(30),
            principal_kind: "PLATFORM_USER",
            expires_at_epoch_second: utc_now_seconds() + 600,
        }
    }

    #[test]
    fn evaluate_access_fact_binds_every_dimension() {
        assert!(evaluate_access_fact(
            &active_fact(Some(40), Some(20), Some(30)),
            &bind(Some(40), Some(20), Some(30))
        )
        .is_ok());

        // epoch 回退（旧 token 打新 epoch 后的 session 行）必须拒绝。
        let mut stale_epoch = active_fact(Some(40), Some(20), Some(30));
        stale_epoch.session_epoch = 4;
        assert_eq!(
            evaluate_access_fact(&stale_epoch, &bind(Some(40), Some(20), Some(30))),
            Err("SESSION_CONTEXT_MISMATCH")
        );

        // version 回退同理。
        let mut stale_version = active_fact(Some(40), Some(20), Some(30));
        stale_version.session_version = 3;
        assert_eq!(
            evaluate_access_fact(&stale_version, &bind(Some(40), Some(20), Some(30))),
            Err("SESSION_CONTEXT_MISMATCH")
        );

        // 撤销（jti index DELETED）必须拒绝。
        let mut revoked = active_fact(Some(40), Some(20), Some(30));
        revoked.jti_status = "DELETED".into();
        assert_eq!(
            evaluate_access_fact(&revoked, &bind(Some(40), Some(20), Some(30))),
            Err("TOKEN_REVOKED")
        );

        // family 撤销/缺失必须拒绝（未知状态 fail-closed）。
        for family in [None, Some("REVOKED"), Some("EXPIRED"), Some("WEIRD")] {
            let mut fact = active_fact(Some(40), Some(20), Some(30));
            fact.family_status = family.map(str::to_owned);
            assert_eq!(
                evaluate_access_fact(&fact, &bind(Some(40), Some(20), Some(30))),
                Err("TOKEN_REVOKED"),
                "family={family:?}"
            );
        }

        // 租户绑定不一致必须拒绝。
        assert_eq!(
            evaluate_access_fact(
                &active_fact(Some(40), Some(21), Some(30)),
                &bind(Some(40), Some(20), Some(30))
            ),
            Err("SESSION_CONTEXT_MISMATCH")
        );

        // JWT 比 durable 证明活得更久必须拒绝。
        let mut long_jwt = bind(Some(40), Some(20), Some(30));
        long_jwt.expires_at_epoch_second = utc_now_seconds() + 3600;
        assert_eq!(
            evaluate_access_fact(&active_fact(Some(40), Some(20), Some(30)), &long_jwt),
            Err("TOKEN_EXPIRED")
        );

        // App 会话禁止携带 user-card 上下文。
        let mut app_bind = bind(None, None, None);
        app_bind.principal_kind = "APP_USER";
        assert!(evaluate_access_fact(&active_fact(None, None, None), &app_bind).is_ok());
        assert_eq!(
            evaluate_access_fact(&active_fact(Some(40), Some(20), Some(30)), &app_bind),
            Err("SESSION_CONTEXT_MISMATCH")
        );
    }

    #[test]
    fn mirror_grant_allow_requires_full_binding() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("jti-a", 3));
        assert!(mirror
            .lookup_grant("jti-a", &bind(Some(40), Some(20), Some(30)))
            .is_allow());
        // 任一维度漂移 → Deny（绝不静默 miss 后放行）。
        assert_eq!(
            mirror.lookup_grant("jti-a", &bind(Some(41), Some(20), Some(30))),
            SessionProjectionDecision::Deny("SESSION_CONTEXT_MISMATCH")
        );
        // 未命中 → Miss 哨兵（store 层回退 strict DB）。
        assert_eq!(
            mirror.lookup_grant("jti-b", &bind(Some(40), Some(20), Some(30))),
            SessionProjectionDecision::Deny(MIRROR_MISS)
        );
    }

    #[test]
    fn mirror_revocation_hits_immediately_and_invalidates_grant() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("jti-r", 3));
        assert!(mirror
            .lookup_grant("jti-r", &bind(Some(40), Some(20), Some(30)))
            .is_allow());
        mirror.mark_revoked("jti-r", 3600);
        assert!(mirror.lookup_revoked("jti-r"));
        assert_eq!(
            mirror.lookup_grant("jti-r", &bind(Some(40), Some(20), Some(30))),
            SessionProjectionDecision::Deny(MIRROR_MISS)
        );
    }

    #[test]
    fn mirror_epoch_rotation_invalidates_older_epoch_entries() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("old", 2));
        mirror.install_grant(issued("new", 3));
        let (grants, _) = mirror.live_entries();
        assert_eq!(grants, 1, "older epoch entry must be evicted by rotation");
        assert_eq!(
            mirror.lookup_grant("old", &bind(Some(40), Some(20), Some(30))),
            SessionProjectionDecision::Deny(MIRROR_MISS)
        );
    }

    #[test]
    fn mirror_suspect_forces_strict_db_fallback_but_keeps_deny() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("jti-s", 3));
        mirror.mark_revoked("jti-d", 3600);
        mirror.mark_suspect_for_secs(60);
        assert_eq!(
            mirror.lookup_grant("jti-s", &bind(Some(40), Some(20), Some(30))),
            SessionProjectionDecision::Deny(MIRROR_MISS),
            "suspect mirror must never allow"
        );
        // deny 方向不受 suspect 影响（保守拒绝始终安全）。
        assert!(mirror.lookup_revoked("jti-d"));
    }

    #[test]
    fn mirror_permanent_suspect_bypasses_positive_cache() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("jti-p", 3));
        mirror.mark_suspect_permanent();
        assert_eq!(
            mirror.lookup_grant("jti-p", &bind(Some(40), Some(20), Some(30))),
            SessionProjectionDecision::Deny(MIRROR_MISS)
        );
        assert!(!mirror.grant_mirror_healthy());
    }

    #[test]
    fn mirror_capacity_gc_keeps_fresh_entries() {
        let mirror = SessionProjectionMirror::new(60, 8);
        for index in 0..16 {
            mirror.install_grant(IssuedAccessGrant {
                jti: format!("jti-{index}"),
                session_id: index,
                session_version: 1,
                session_epoch: 1,
                user_id: 42,
                token_family_id: 11,
                identity_card_id: Some(10),
                user_card_id: Some(40),
                user_card_tenant_id: Some(20),
                user_card_domain_id: Some(30),
                principal_kind: "PLATFORM_USER",
                expires_at_epoch_second: utc_now_seconds() + 600,
            });
        }
        let (grants, _) = mirror.live_entries();
        assert!(grants <= 8, "mirror must stay bounded: {grants}");
    }

    #[tokio::test]
    async fn deny_only_policy_never_allows_from_mirror() {
        let mirror = SessionProjectionMirror::default();
        let store = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: None,
                fail: false,
            }),
            Some(mirror),
            MirrorPolicy::DenyOnly,
        );
        store.note_grant_installed(issued("deny-only", 3));
        // 独立多写者 Gateway（DenyOnly）：镜像 grant 不参与放行，strict DB
        // （fake source 返回 None）拒绝。
        assert_eq!(
            store
                .verify_access("deny-only", &bind(Some(40), Some(20), Some(30)))
                .await,
            SessionProjectionDecision::Deny("SESSION_NOT_FOUND")
        );
        // 撤销 marker 加速仍生效。
        store.note_revocation("denied", 3600);
        assert_eq!(
            store
                .verify_access("denied", &bind(Some(40), Some(20), Some(30)))
                .await,
            SessionProjectionDecision::Deny("TOKEN_REVOKED")
        );
    }

    /// 内存 fake source：验证 store 组合路径（命中→strict DB 回退）。
    struct FakeSource {
        fact: Option<AccessSessionDurableFact>,
        fail: bool,
    }

    #[async_trait]
    impl AccessSessionSource for FakeSource {
        async fn load_access_fact(
            &self,
            _jti: &str,
            _bind: &SessionBindContext,
        ) -> Result<Option<AccessSessionDurableFact>, String> {
            if self.fail {
                Err("db down".into())
            } else {
                Ok(self.fact.clone())
            }
        }
    }

    #[tokio::test]
    async fn store_without_mirror_falls_back_to_strict_source_on_miss() {
        let store = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: Some(active_fact(Some(40), Some(20), Some(30))),
                fail: false,
            }),
            None,
            MirrorPolicy::DenyOnly,
        );
        assert!(store
            .verify_access("jti", &bind(Some(40), Some(20), Some(30)))
            .await
            .is_allow());
    }

    #[tokio::test]
    async fn store_maps_source_error_to_unavailable_and_missing_to_deny() {
        let down = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: None,
                fail: true,
            }),
            None,
            MirrorPolicy::DenyOnly,
        );
        assert_eq!(
            down.verify_access("jti", &bind(Some(40), Some(20), Some(30)))
                .await,
            SessionProjectionDecision::Unavailable
        );
        let absent = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: None,
                fail: false,
            }),
            None,
            MirrorPolicy::DenyOnly,
        );
        assert_eq!(
            absent
                .verify_access("jti", &bind(Some(40), Some(20), Some(30)))
                .await,
            SessionProjectionDecision::Deny("SESSION_NOT_FOUND")
        );
    }

    struct ControlledVerifiedSource {
        calls: std::sync::atomic::AtomicUsize,
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl ControlledVerifiedSource {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    #[async_trait]
    impl AccessSessionSource for ControlledVerifiedSource {
        async fn load_access_fact(
            &self,
            _jti: &str,
            _bind: &SessionBindContext,
        ) -> Result<Option<AccessSessionDurableFact>, String> {
            Ok(Some(active_fact(Some(40), Some(20), Some(30))))
        }

        async fn load_access_fact_with_validity(
            &self,
            jti: &str,
            bind: &SessionBindContext,
        ) -> Result<Option<VerifiedAccessSessionFact>, String> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            Ok(self
                .load_access_fact(jti, bind)
                .await?
                .map(|fact| VerifiedAccessSessionFact {
                    fact,
                    cache_valid_until_epoch_second: Some(utc_now_seconds() + 600),
                }))
        }
    }

    #[tokio::test]
    async fn fenced_refill_holds_singleflight_until_verified_fact_is_installed() {
        let source = Arc::new(ControlledVerifiedSource::new());
        let store = Arc::new(SessionProjectionStore::new(
            source.clone(),
            Some(SessionProjectionMirror::default()),
            MirrorPolicy::VerifiedPositive,
        ));
        let request = bind(Some(40), Some(20), Some(30));
        let mut readers = Vec::new();
        for _ in 0..24 {
            let store = store.clone();
            let request = request.clone();
            readers.push(tokio::spawn(async move {
                store
                    .verify_access_with_fence("one-refill", &request, || true)
                    .await
            }));
        }
        source.entered.acquire().await.unwrap().forget();
        for _ in 0..24 {
            tokio::task::yield_now().await;
        }
        assert_eq!(source.calls.load(Ordering::Acquire), 1);
        source.release.add_permits(1);
        for reader in readers {
            assert_eq!(reader.await.unwrap(), SessionProjectionDecision::Allow);
        }
        assert_eq!(source.calls.load(Ordering::Acquire), 1);
        assert_eq!(store.mirror().unwrap().live_entries().0, 1);
    }

    #[tokio::test]
    async fn invalidation_while_refill_waits_never_serves_or_installs_old_allow() {
        let source = Arc::new(ControlledVerifiedSource::new());
        let store = Arc::new(SessionProjectionStore::new(
            source.clone(),
            Some(SessionProjectionMirror::default()),
            MirrorPolicy::VerifiedPositive,
        ));
        let current = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let reader = {
            let store = store.clone();
            let current = current.clone();
            tokio::spawn(async move {
                store
                    .verify_access_with_fence("raced", &bind(Some(40), Some(20), Some(30)), || {
                        current.load(Ordering::Acquire)
                    })
                    .await
            })
        };
        source.entered.acquire().await.unwrap().forget();
        current.store(false, Ordering::Release);
        source.release.add_permits(1);
        assert_eq!(
            reader.await.unwrap(),
            SessionProjectionDecision::Unavailable
        );
        assert_eq!(store.mirror().unwrap().live_entries().0, 0);
    }

    #[tokio::test]
    async fn cancelled_refill_releases_owner_and_allows_one_new_attempt() {
        let source = Arc::new(ControlledVerifiedSource::new());
        let store = Arc::new(SessionProjectionStore::new(
            source.clone(),
            Some(SessionProjectionMirror::default()),
            MirrorPolicy::VerifiedPositive,
        ));
        let leader = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .verify_access_with_fence(
                        "cancelled",
                        &bind(Some(40), Some(20), Some(30)),
                        || true,
                    )
                    .await
            })
        };
        source.entered.acquire().await.unwrap().forget();
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());
        source.release.add_permits(1);
        assert_eq!(
            store
                .verify_access_with_fence("cancelled", &bind(Some(40), Some(20), Some(30)), || true)
                .await,
            SessionProjectionDecision::Allow,
        );
        assert_eq!(source.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn unproven_physical_expiry_never_installs_a_positive_refill() {
        let store = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: Some(active_fact(Some(40), Some(20), Some(30))),
                fail: false,
            }),
            Some(SessionProjectionMirror::default()),
            MirrorPolicy::VerifiedPositive,
        );
        assert_eq!(
            store
                .verify_access_with_fence(
                    "no-expiry-proof",
                    &bind(Some(40), Some(20), Some(30)),
                    || true
                )
                .await,
            SessionProjectionDecision::Allow
        );
        assert_eq!(store.mirror().unwrap().live_entries().0, 0);
    }

    #[test]
    fn verified_physical_expiry_rejects_allow_even_without_a_cache_install() {
        let bind = bind(Some(40), Some(20), Some(30));
        let mut verified = VerifiedAccessSessionFact {
            fact: active_fact(Some(40), Some(20), Some(30)),
            cache_valid_until_epoch_second: Some(utc_now_seconds() - 1),
        };
        assert_eq!(
            evaluate_verified_access_fact(&verified, &bind),
            Err("SESSION_NOT_FOUND")
        );
        verified.cache_valid_until_epoch_second = Some(utc_now_seconds() + 60);
        assert!(evaluate_verified_access_fact(&verified, &bind).is_ok());
        verified.cache_valid_until_epoch_second = None;
        assert!(evaluate_verified_access_fact(&verified, &bind).is_ok());
    }

    #[test]
    fn clearing_positive_grants_preserves_revocation_markers() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("positive", 3));
        mirror.mark_revoked("revoked", 3600);
        mirror.invalidate_all_grants();
        assert_eq!(mirror.live_entries(), (0, 1));
        assert!(mirror.lookup_revoked("revoked"));
    }

    #[test]
    fn late_old_epoch_cannot_displace_a_new_session_epoch() {
        let mirror = SessionProjectionMirror::default();
        mirror.install_grant(issued("new", 4));
        mirror.install_grant(issued("old", 3));
        assert_eq!(mirror.live_entries().0, 1);
        assert_eq!(
            mirror.lookup_grant("old", &bind(Some(40), Some(20), Some(30))),
            SessionProjectionDecision::Deny(MIRROR_MISS)
        );
    }

    #[test]
    fn physical_validity_bounds_mirror_lifetime() {
        let mirror = SessionProjectionMirror::new(900, 8);
        mirror.install_grant_until(issued("expired-card", 3), utc_now_seconds() - 1);
        assert_eq!(mirror.live_entries().0, 0);
        let before = Instant::now();
        mirror.install_grant_until(issued("short-card", 3), utc_now_seconds() + 2);
        let guard = mirror.inner.read().unwrap();
        let entry = guard.grants.get("short-card").unwrap();
        assert!(entry.mirror_expires_at <= before + Duration::from_secs(3));
    }

    #[tokio::test]
    async fn strict_read_still_rejects_known_revocations() {
        let store = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: Some(active_fact(Some(40), Some(20), Some(30))),
                fail: false,
            }),
            Some(SessionProjectionMirror::default()),
            MirrorPolicy::VerifiedPositive,
        );
        store.note_revocation("revoked", 3600);
        assert_eq!(
            store
                .verify_access_strict("revoked", &bind(Some(40), Some(20), Some(30)))
                .await,
            SessionProjectionDecision::Deny("TOKEN_REVOKED")
        );
    }

    #[tokio::test]
    async fn store_verified_positive_hit_short_circuits_but_miss_goes_strict() {
        let mirror = SessionProjectionMirror::default();
        let store = SessionProjectionStore::new(
            Arc::new(FakeSource {
                fact: None,
                fail: false,
            }),
            Some(mirror),
            MirrorPolicy::VerifiedPositive,
        );
        store.note_grant_installed(issued("fast", 3));
        // Source 返回"不存在"——VerifiedPositive 镜像命中仍允许（已证明事实），
        // miss 则 Deny。
        assert!(store
            .verify_access("fast", &bind(Some(40), Some(20), Some(30)))
            .await
            .is_allow());
        assert_eq!(
            store
                .verify_access("slow", &bind(Some(40), Some(20), Some(30)))
                .await,
            SessionProjectionDecision::Deny("SESSION_NOT_FOUND")
        );
    }
}
