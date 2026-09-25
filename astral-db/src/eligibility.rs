//! 公共卡资格校验服务（CardEligibilityService）
//!
//! 物理双卡权威资格校验与时间感知投影版本缓存的单点实现：
//! - `verify_platform_card_pair`：签发侧（identity login/refresh/switch-card）权威校验，
//!   单条 JOIN 同时验证两条事实线路 + 对应关系证明 + user_card 组织有效性；
//! - `check_cached`：运行期资格检查（Chat WebSocket / PolicyEngine `check_card_active` 复用），
//!   时间感知 `perm:card:active:{card_id}` 缓存 + 权威 SQL 回退。
//!
//! 权威语义（与 `物理双卡权限链路设计_V1.0.md` D1 对齐）：
//! - identity_card 只承担身份事实（归属/状态/过期），**不读取/比较** tenant/domain；
//! - user_card 独立承载组织事实（tenant/domain），组织有效性由
//!   `tenant` ACTIVE + `tenant_domain_map` ACTIVE + `uc.tenant_id/domain_id` 非空保证；
//! - 对应关系证明：`identity_card.user_id == user_card.user_id == 请求 user_id`。
//!
//! 缓存版本切换：`perm:card:active` 的投影门禁从 CARD head 切换到
//! `aggregate_type='ELIGIBILITY'` head（`load_eligibility_projection_gate`）。
//! 载荷携带 `projection_type: "ELIGIBILITY"`；缺失/错误类型/旧 scalar 一律 miss 回 SQL。
//!
//! 恢复/重建期防线（`crate::cache_epoch` 共享时代）：载荷 v2 起携带
//! `schema_version` + `cache_epoch`。head 缺失时三元组栅栏无从比对，残留
//! 正缓存仅当条目携带当前共享时代才可命中；整库恢复/重建后运维
//! `DEL astral:auth:cache_epoch` 换时代，旧条目全部 miss 并按 TTL 过期。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use astral_types::{
    CardEligibility, CardEligibilityCheckOptions, PlatformCardPairRequest, PolicyError,
    ProjectionAggregate,
};
use policy_engine::ProjectionGate;
use redis::AsyncCommands;
use sqlx::MySqlPool;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::cache_epoch::{cache_epoch_is_current, cache_epoch_matches};
use crate::repository::CardActiveContext;

/// 旧 JSON 载荷缺失 `projection_type` 字段时的默认值（显式 miss）。
const LEGACY_PROJECTION_TYPE: &str = "LEGACY";

/// `perm:card:active:{card_id}` 载荷 schema 版本。v2 引入 `schema_version` +
/// `cache_epoch`（共享时代栅栏，见 `crate::cache_epoch`）；v1 旧 JSON（无该
/// 字段）反序列化默认 0 ≠ 当前 → 读取侧显式 miss 并被重写覆盖。v3 随迁移
/// 20260831000001 移除 `projected_generation` 栅栏（旧链状态列退役），版本
/// 栅栏收敛为 (source_generation, revoke_fence)；v2 载荷读取侧显式 miss。
const CARD_ACTIVE_CACHE_SCHEMA: i64 = 3;

/// 时间感知的 `perm:card:active:{card_id}` 缓存载荷。
///
/// 物理上下文字段是故意冗余的：key 只有 user-card ID，命中前必须再次
/// 确认请求者没有把同一张卡套用到其他用户、身份卡或租户域。
/// `projection_type` 标识载荷归属的投影聚合类型：只有
/// `ProjectionAggregate::Eligibility.as_str()` 的载荷且投影版本匹配才可命中；
/// 缺失（旧 JSON）/错误类型/旧 scalar 一律 miss。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CardActiveCache {
    valid: bool,
    expires_at: Option<i64>,
    source_generation: i64,
    revoke_fence: i64,
    user_id: i64,
    identity_card_id: i64,
    user_card_id: i64,
    user_card_tenant_id: i64,
    user_card_domain_id: i64,
    /// 旧 JSON（无该字段）默认 `"LEGACY"` → 显式 miss，防止旧载荷命中新语义。
    #[serde(default = "legacy_projection_type")]
    projection_type: String,
    /// 旧 JSON（无该字段）默认 0 ≠ 当前 schema → 显式 miss，防止旧载荷命中新语义。
    #[serde(default)]
    schema_version: i64,
    /// 写入时刻的共享缓存时代（`crate::cache_epoch`）；旧 JSON 默认 None。
    #[serde(default)]
    cache_epoch: Option<String>,
}

fn legacy_projection_type() -> String {
    LEGACY_PROJECTION_TYPE.to_string()
}

/// 权威双卡 JOIN 行（与 `物理双卡权限链路设计_V1.0.md` §4.1.1 单条权威 SQL 对齐）。
type CardActiveRow = (
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<PrimitiveDateTime>,
    i64,
    Option<PrimitiveDateTime>,
    String,
    String,
    String,
);

/// 卡资格校验服务。
///
/// 采用无状态关联函数形式（pool 由调用方传入），便于各业务模块直接复用。
#[derive(Debug, Clone, Copy, Default)]
pub struct CardEligibilityService;

impl CardEligibilityService {
    /// 签发侧权威卡资格校验。
    ///
    /// 通过返回携带组织事实的 `CardEligibility`（tenant/domain 唯一来源为 user_card）；
    /// 不满足任意一条事实线路/对应关系/组织有效性 → `PolicyError::NotEligible`；
    /// DB 查询失败 → `PolicyError::Repository`（fail-closed，不可默认 ALLOW）。
    pub async fn verify_platform_card_pair(
        pool: &MySqlPool,
        request: &PlatformCardPairRequest,
    ) -> Result<CardEligibility, PolicyError> {
        if !request.is_positive() {
            return Err(PolicyError::NotEligible(format!(
                "non-positive platform card pair request: user_id={}, identity_card_id={}, user_card_id={}",
                request.user_id, request.identity_card_id, request.user_card_id
            )));
        }
        let row = query_card_active_row(
            pool,
            request.user_id,
            request.identity_card_id,
            request.user_card_id,
        )
        .await
        .map_err(|e| PolicyError::Repository(format!("dual-card pair query failed: {e}")))?;
        let Some((
            card_user_id,
            user_card_id,
            card_tenant_id,
            card_domain_id,
            user_card_valid_until,
            identity_card_id,
            identity_expires_at,
            identity_status,
            tenant_status,
            domain_mapping_status,
        )) = row
        else {
            return Err(PolicyError::NotEligible(format!(
                "platform card pair not found or ineligible: user_id={}, identity_card_id={}, user_card_id={}",
                request.user_id, request.identity_card_id, request.user_card_id
            )));
        };

        // 对应关系证明：JOIN 已强制 ic.user_id = uc.user_id，此处按请求 ID 复核。
        if card_user_id != request.user_id
            || user_card_id != request.user_card_id
            || identity_card_id != request.identity_card_id
        {
            return Err(PolicyError::NotEligible(
                "platform card pair identity mismatch".into(),
            ));
        }
        if identity_status != "ACTIVE"
            || tenant_status != "ACTIVE"
            || domain_mapping_status != "ACTIVE"
        {
            return Err(PolicyError::NotEligible(format!(
                "platform card pair status not active: identity_status={identity_status}, tenant_status={tenant_status}, domain_mapping_status={domain_mapping_status}"
            )));
        }
        let Some(user_card_tenant_id) = card_tenant_id else {
            return Err(PolicyError::NotEligible("user_card tenant is null".into()));
        };
        let Some(user_card_domain_id) = card_domain_id else {
            return Err(PolicyError::NotEligible("user_card domain is null".into()));
        };

        Ok(CardEligibility {
            identity_card_id,
            user_card_id,
            user_card_tenant_id,
            user_card_domain_id,
            effective_expiry: effective_expiry(identity_expires_at, user_card_valid_until),
        })
    }

    /// 运行期资格检查（L1 进程内缓存 + 时间感知 Redis 缓存 + 权威 SQL 回退）。
    ///
    /// - **L1 进程内正缓存**（卡点 1：资格检查 L1 化，10 万 QPS 下收敛 Redis
    ///   命令与 ELIGIBILITY head 点查）：仅服务 `require_projection_ready=false`
    ///   的 PolicyEngine CARD_CONTEXT 路径，命中免 Redis 读 + 免 head 点查；
    ///   只缓存 valid=true 正向结果，TTL 5s（取舍见 [`l1_card_active_lookup`]）；
    /// - require_projection_ready=true（Chat WebSocket revalidate）**不参与
    ///   L1**：L1 只缓存 valid 事实、不缓存 gate READY 事实，ready 判定必须
    ///   逐请求读取 ELIGIBILITY head，保持原 Redis/DB 协议不变；
    /// - 缓存只优化成功结果；任何缓存异常/版本不匹配/时代不匹配/到期都会回到
    ///   同一条权威 SQL；
    /// - ELIGIBILITY head 缺失（legacy 库 / 恢复重建期）→ gate=None，不改变
    ///   引擎最终语义；此时残留正缓存仅当条目携带当前共享时代（`cache_epoch`）
    ///   才可命中，恢复期旧条目被时代栅栏拦截；`require_projection_ready=true`
    ///   且 head 未 READY → 直接拒绝；
    /// - 权威 SQL 失败 → `PolicyError::Repository`，不可默认 ALLOW。
    pub async fn check_cached(
        pool: &MySqlPool,
        context: &CardActiveContext,
        options: CardEligibilityCheckOptions,
    ) -> Result<bool, PolicyError> {
        if !context.is_positive() {
            return Ok(false);
        }
        let now_instant = Instant::now();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // L1 命中：TTL 内 + 物理上下文一致 + 未到自然到期 → 直接放行（免 Redis、
        // 免 head 点查）。require=true 路径不走 L1（见上）。
        if l1_applies_to(&options) && l1_card_active_lookup(context, now_instant, now) == Some(true)
        {
            return Ok(true);
        }
        let gate = load_eligibility_projection_gate(pool, context.user_card_id).await?;
        if options.require_projection_ready && !gate.is_some_and(|gate| gate.ready) {
            return Ok(false);
        }
        // 共享缓存时代：Redis 降级时为 None → epoch 子校验跳过，其余栅栏照常。
        let cache_epoch = crate::cache_epoch::current_cache_epoch().await;
        let (valid, expires_at) = if let Some(cached) =
            read_active_cache(context, gate.as_ref(), cache_epoch.as_deref(), now).await
        {
            (cached.valid, cached.expires_at)
        } else {
            let row = query_card_active_row(
                pool,
                context.user_id,
                context.identity_card_id,
                context.user_card_id,
            )
            .await;
            let (valid, expires_at) = match row {
                Ok(Some((
                    card_user_id,
                    user_card_id,
                    card_tenant_id,
                    card_domain_id,
                    user_card_valid_until,
                    identity_card_id,
                    identity_expires_at,
                    identity_status,
                    tenant_status,
                    domain_mapping_status,
                ))) => {
                    let valid = card_user_id == context.user_id
                        && user_card_id == context.user_card_id
                        && card_tenant_id == Some(context.user_card_tenant_id)
                        && card_domain_id == Some(context.user_card_domain_id)
                        && identity_card_id == context.identity_card_id
                        && identity_status == "ACTIVE"
                        && tenant_status == "ACTIVE"
                        && domain_mapping_status == "ACTIVE";
                    (
                        valid,
                        effective_expiry(identity_expires_at, user_card_valid_until),
                    )
                }
                Ok(None) => (false, None),
                Err(error) => {
                    return Err(PolicyError::Repository(format!(
                        "dual-card context query failed: {error}"
                    )));
                }
            };
            if valid {
                write_active_cache(
                    context,
                    gate.as_ref(),
                    cache_epoch,
                    expires_at,
                    now,
                    options.base_ttl_seconds,
                    options.jitter_max_seconds,
                )
                .await;
            }
            (valid, expires_at)
        };
        // L1 回填：只缓存正结果；require=true 路径不回填（见上）。
        if valid && l1_applies_to(&options) {
            l1_card_active_insert(context, expires_at, now_instant, now);
        }
        Ok(valid)
    }
}

/// 权威物理双卡 JOIN（单条 SQL）。
///
/// 覆盖全部校验项，无需应用侧二次查询：
/// - platform_user ACTIVE 且未删除（对应关系证明锚点）；
/// - identity_card 归属/状态 ACTIVE/expires_at 未过期（身份线路，**不读 tenant/domain**）；
/// - user_card 归属/ACTIVE/非模板/valid_from/valid_until 窗口（授权线路）；
/// - user_card tenant/domain 非空 + tenant ACTIVE + tenant_domain_map ACTIVE（组织线路）。
async fn query_card_active_row(
    pool: &MySqlPool,
    user_id: i64,
    identity_card_id: i64,
    user_card_id: i64,
) -> Result<Option<CardActiveRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT uc.user_id, uc.card_id, uc.tenant_id, uc.domain_id, uc.valid_until, \
                ic.card_id, ic.expires_at, ic.status, t.status, \
                COALESCE(tdm.status, 'INACTIVE') \
         FROM user_card uc \
         INNER JOIN identity_card ic ON ic.user_id = uc.user_id \
         INNER JOIN platform_user pu ON pu.user_id = uc.user_id \
                                    AND pu.status = 'ACTIVE' \
                                    AND pu.deleted_at IS NULL \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id \
         LEFT JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                                        AND tdm.domain_id = uc.domain_id \
                                        AND tdm.status = 'ACTIVE' \
         WHERE uc.card_id = ? AND uc.user_id = ? \
           AND uc.card_status = 'ACTIVE' \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
           AND ic.card_id = ? AND ic.user_id = ? AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
           AND t.status = 'ACTIVE' \
           AND uc.tenant_id IS NOT NULL AND uc.domain_id IS NOT NULL",
    )
    .bind(user_card_id)
    .bind(user_id)
    .bind(identity_card_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// 读取资格投影版本栅栏（`aggregate_type='ELIGIBILITY'`）。
///
/// 旧链状态列已随迁移 20260831000001 退役：栅栏收敛为
/// (source_generation, revoke_fence)——source mutation 与 head 代次/围栏
/// 推进在同一 source 事务提交，因此任一未消费事件都必然表现为栅栏失配
/// → 缓存 miss 回权威 SQL（fail-closed 不依赖 worker 消费证明）。
/// head 缺失返回 `None`，但要求投影就绪的调用方必须将其视为拒绝；
/// 查询失败向上游暴露（fail-closed）。与 CARD gate 互不干扰。
pub(crate) async fn load_eligibility_projection_gate(
    pool: &MySqlPool,
    user_card_id: i64,
) -> Result<Option<ProjectionGate>, PolicyError> {
    let sql = format!(
        "SELECT source_generation, revoke_fence \
         FROM authorization_projection_head \
         WHERE aggregate_type = '{}' AND aggregate_id = ?",
        ProjectionAggregate::Eligibility.as_str()
    );
    let row: Option<(i64, i64)> = sqlx::query_as(&sql)
        .bind(user_card_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| PolicyError::Repository(e.to_string()))?;

    Ok(row.map(|(source_generation, revoke_fence)| ProjectionGate {
        ready: source_generation > 0,
        source_generation,
        revoke_fence,
    }))
}

/// 自然到期时间：`min(identity.expires_at, user_card.valid_until)`（unix 秒）。
fn effective_expiry(
    identity_expires_at: Option<PrimitiveDateTime>,
    user_card_valid_until: Option<PrimitiveDateTime>,
) -> Option<i64> {
    [identity_expires_at, user_card_valid_until]
        .into_iter()
        .flatten()
        .map(|value| value.assume_utc().unix_timestamp())
        .min()
}

/// 缓存 TTL：以自然到期时间为上限截断（读侧到期检查的保守补充），抖动防雪崩。
fn active_cache_ttl(
    expires_at: Option<i64>,
    now: i64,
    base_ttl_seconds: u64,
    jitter_max_seconds: u64,
) -> Option<u64> {
    let base = ttl_with_jitter(base_ttl_seconds.max(1), jitter_max_seconds);
    match expires_at {
        Some(expires_at) => {
            let remaining = expires_at.saturating_sub(now);
            (remaining > 0).then(|| base.min(remaining as u64).max(1))
        }
        None => Some(base),
    }
}

/// 缓存命中判定：schema/时代/投影类型栅栏、物理上下文/投影版本匹配、
/// 且读取侧时间未越过自然到期时间。
fn cached_active_result(
    cached: &CardActiveCache,
    context: &CardActiveContext,
    gate: Option<&ProjectionGate>,
    current_epoch: Option<&str>,
    now: i64,
) -> Option<bool> {
    if !cached.matches_projection()
        || !cached.matches_context(context)
        || !cached.matches_gate(gate, current_epoch)
    {
        return None;
    }
    if cached.valid
        && cached
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
    {
        return None;
    }
    Some(cached.valid)
}

/// 读取资格缓存。任何异常（Redis 不可用/解析失败/类型不匹配/版本不匹配/时代
/// 不匹配/到期）都返回 None → 调用方回权威 SQL；命中返回经验证的完整条目
/// （读取方需要 `expires_at` 做 L1 回填的自然到期截断）。
async fn read_active_cache(
    context: &CardActiveContext,
    gate: Option<&ProjectionGate>,
    current_epoch: Option<&str>,
    now: i64,
) -> Option<CardActiveCache> {
    let mut conn = redis_conn().await?;
    let key = format!("perm:card:active:{}", context.user_card_id);
    let raw = conn.get::<_, Option<String>>(&key).await.ok()??;
    let cached = serde_json::from_str::<CardActiveCache>(&raw).ok()?;
    cached_active_result(&cached, context, gate, current_epoch, now).map(|_| cached)
}

/// 写资格缓存（fire-and-forget，失败仅 warning；只缓存成功结果）。
async fn write_active_cache(
    context: &CardActiveContext,
    gate: Option<&ProjectionGate>,
    cache_epoch: Option<String>,
    expires_at: Option<i64>,
    now: i64,
    base_ttl_seconds: u64,
    jitter_max_seconds: u64,
) {
    let Some(ttl) = active_cache_ttl(expires_at, now, base_ttl_seconds, jitter_max_seconds) else {
        return;
    };
    let Some(mut conn) = redis_conn().await else {
        return;
    };
    let key = format!("perm:card:active:{}", context.user_card_id);
    let cached = CardActiveCache {
        valid: true,
        expires_at,
        source_generation: gate.map_or(0, |gate| gate.source_generation),
        revoke_fence: gate.map_or(0, |gate| gate.revoke_fence),
        user_id: context.user_id,
        identity_card_id: context.identity_card_id,
        user_card_id: context.user_card_id,
        user_card_tenant_id: context.user_card_tenant_id,
        user_card_domain_id: context.user_card_domain_id,
        projection_type: ProjectionAggregate::Eligibility.as_str().to_string(),
        schema_version: CARD_ACTIVE_CACHE_SCHEMA,
        cache_epoch,
    };
    let Ok(payload) = serde_json::to_string(&cached) else {
        return;
    };
    if let Err(error) = conn.set_ex::<_, _, ()>(&key, payload, ttl).await {
        tracing::warn!(card_id = context.user_card_id, %error, "active card cache write failed");
    }
}

// ============================== L1 进程内资格缓存 ==============================
//
// 【卡点 1：资格检查 L1 化】10 万 QPS 目标下，每请求一次 `perm:card:active`
// Redis 读 + 一次 ELIGIBILITY head 点查超出单实例命令预算，因此在 Redis 层
// 之前增加进程内 L1 正缓存。
//
// 语义与显式取舍：
// - **只缓存 valid=true 正向结果**（与 Redis 层同语义）；负结果/错误一律走原
//   协议（Redis → head 栅栏 → 权威 SQL），fail-closed 不变；
// - **TTL 5 秒**：禁用/撤销等状态变更的**跨实例**放行窗口显式上限 ≤5s；同进程
//   状态变更通过 [`evict_l1_card_active_cache`] 即时失效（hook 于
//   `evict_eligibility_gate_cache` / `evict_card_cache_for_tenant`，覆盖
//   user_card 状态变更与 ELIGIBILITY 投影 worker 的全部调用点）；跨实例依赖
//   5s TTL 自然过期，这是本缓存的核心安全取舍，不接受更长的 TTL；
// - **require_projection_ready=true（Chat）不参与 L1**：L1 只缓存 valid 事实、
//   不缓存 gate READY 事实；ready 判定必须逐请求读取 ELIGIBILITY head；
// - **容量边界 + GC**：`L1_CARD_ACTIVE_MAX_ENTRIES` 上限；插入时超限先清理
//   过期条目，仍超限则整体清空（粗粒度有界保证；清空只损失命中率，不损失
//   正确性—— miss 回原协议）；
// - L1 锁中毒视为 miss（降级原协议），不扩大授权。

/// L1 适用性判定（纯函数）：只在 `require_projection_ready=false`（PolicyEngine
/// CARD_CONTEXT 路径）参与 L1。require=true（Chat revalidate）必须逐请求验证
/// ELIGIBILITY head READY——L1 只缓存 valid 事实、不缓存 gate READY 事实，
/// L1 命中不等于 gate ready。
fn l1_applies_to(options: &CardEligibilityCheckOptions) -> bool {
    !options.require_projection_ready
}

/// L1 进程内资格缓存 TTL：5 秒（跨实例状态变更放行窗口的显式上限）。
const L1_CARD_ACTIVE_TTL: Duration = Duration::from_secs(5);

/// L1 容量上限（条数）。单条为一张卡的轻量上下文（约 60 字节），上限约束
/// 进程内存有界；真实负载下条目 ≈ 5s 窗口内的活跃卡数，65_536 覆盖 10 万 QPS
/// 级热点卡集。
const L1_CARD_ACTIVE_MAX_ENTRIES: usize = 65_536;

/// L1 条目：只存正结果（valid 恒为 true，不设字段），携带完整物理上下文供
/// 命中复核（与 Redis 层 `matches_context` 同语义），以及自然到期时间。
#[derive(Debug, Clone)]
struct L1CardActiveEntry {
    user_id: i64,
    identity_card_id: i64,
    user_card_tenant_id: i64,
    user_card_domain_id: i64,
    /// 自然到期时间：`min(identity.expires_at, user_card.valid_until)`（unix 秒）。
    expires_at: Option<i64>,
    /// 填充时刻（单调时钟），用于 5s TTL 判定。
    cached_at: Instant,
}

type L1CardActiveStore = RwLock<HashMap<i64, L1CardActiveEntry>>;

static L1_CARD_ACTIVE_CACHE: OnceLock<L1CardActiveStore> = OnceLock::new();

fn l1_card_active_store() -> &'static L1CardActiveStore {
    L1_CARD_ACTIVE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// L1 命中判定：TTL 内 + 物理上下文一致 + 未越过自然到期时间。
fn l1_card_active_entry_is_fresh(
    entry: &L1CardActiveEntry,
    context: &CardActiveContext,
    now_instant: Instant,
    now_unix: i64,
) -> bool {
    if now_instant.duration_since(entry.cached_at) > L1_CARD_ACTIVE_TTL {
        return false;
    }
    // key 只有 user_card_id，命中前必须再次确认请求者没有把同一张卡套用到
    // 其他用户、身份卡或租户域（与 Redis 层 matches_context 同语义）。
    if entry.user_id != context.user_id
        || entry.identity_card_id != context.identity_card_id
        || entry.user_card_tenant_id != context.user_card_tenant_id
        || entry.user_card_domain_id != context.user_card_domain_id
    {
        return false;
    }
    if entry
        .expires_at
        .is_some_and(|expires_at| now_unix >= expires_at)
    {
        return false;
    }
    true
}

/// L1 读取：命中返回 `Some(true)`（正缓存语义）；TTL 过期/上下文不一致/自然
/// 到期/锁中毒/未缓存一律 `None` → 调用方走原协议（fail-closed）。
fn l1_card_active_lookup(
    context: &CardActiveContext,
    now_instant: Instant,
    now_unix: i64,
) -> Option<bool> {
    let store = l1_card_active_store();
    let guard = store.read().ok()?;
    let entry = guard.get(&context.user_card_id)?;
    l1_card_active_entry_is_fresh(entry, context, now_instant, now_unix).then_some(true)
}

/// 插入时容量 GC 判定（纯函数）：达到上限即触发 GC（先清过期，腾位失败再
/// 整体清空——有界保证优先于命中率）。
fn l1_card_active_gc_needed(entry_count: usize, max_entries: usize) -> bool {
    entry_count >= max_entries
}

/// L1 回填：只缓存正结果；`now_instant`/`now_unix` 由调用方在同一请求内传递，
/// 保证 TTL 与自然到期判定使用同一时钟基线。
fn l1_card_active_insert(
    context: &CardActiveContext,
    expires_at: Option<i64>,
    now_instant: Instant,
    now_unix: i64,
) {
    l1_card_active_insert_with_limit(
        l1_card_active_store(),
        context,
        expires_at,
        now_instant,
        now_unix,
        L1_CARD_ACTIVE_MAX_ENTRIES,
    );
}

/// 带容量上限的插入实现（`store` 参数化便于测试隔离）。
fn l1_card_active_insert_with_limit(
    store: &L1CardActiveStore,
    context: &CardActiveContext,
    expires_at: Option<i64>,
    now_instant: Instant,
    now_unix: i64,
    max_entries: usize,
) {
    let Ok(mut guard) = store.write() else {
        return;
    };
    if l1_card_active_gc_needed(guard.len(), max_entries) {
        // 先清过期（保留仍新鲜的热点），腾位失败再整体清空。
        guard.retain(|_, entry| {
            now_instant.duration_since(entry.cached_at) <= L1_CARD_ACTIVE_TTL
                && entry
                    .expires_at
                    .is_none_or(|expires_at| now_unix < expires_at)
        });
        if guard.len() >= max_entries {
            guard.clear();
        }
    }
    guard.insert(
        context.user_card_id,
        L1CardActiveEntry {
            user_id: context.user_id,
            identity_card_id: context.identity_card_id,
            user_card_tenant_id: context.user_card_tenant_id,
            user_card_domain_id: context.user_card_domain_id,
            expires_at,
            cached_at: now_instant,
        },
    );
}

/// 同进程 L1 资格缓存即时失效（状态变更 evict 入口）。
///
/// 由 `astral-trustgraph` 的 `evict_eligibility_gate_cache` /
/// `evict_card_cache_for_tenant` 在全部同进程资格变更点同步调用（ELIGIBILITY
/// 投影 worker、user_card update/delete 等）；跨实例失效依赖 5s TTL 自然过期
/// （显式取舍，见模块文档）。锁中毒时静默放弃——条目将由 TTL 过期兜底。
pub fn evict_l1_card_active_cache(user_card_id: i64) {
    if let Some(store) = L1_CARD_ACTIVE_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.remove(&user_card_id);
        }
    }
}

/// 进程级 Redis 连接池（runtime 边界安全版）。
///
/// **池化动机**：`ConnectionManager` Clone 共享同一条多路复用连接，按轮转在
/// 池内派发。此前"每操作 `Client::open` + `get_connection_manager`"的模式让
/// 每次 Redis 操作付出完整 TCP 握手、用完即弃：真实压测中 Redis
/// total_connections 达 74.5 万+，服务端 TIME_WAIT 波次性耗尽临时端口，请求
/// 路径被建连 RTT 串行化（~770 QPS 硬顶 + 周期性秒级塌陷）。
///
/// **runtime 边界**：`ConnectionManager` 的连接驱动任务被 spawn 在**构建它的
/// 那个 Tokio runtime** 上，runtime 结束（测试/嵌入方顺序创建新 runtime）时
/// 驱动随 runtime 一起死亡——跨 runtime 复用只会让每条命令立刻失败，调用方按
/// fail-closed 语义降级（缓存 miss 回 SQL、L2 旁路、epoch 未知），且 redis 的
/// 自愈重连只在"首条失败命令之后"触发，永远追不上"每个新 runtime 第一批
/// 操作"。因此池条目携带**所属 runtime 存活哨兵**：构建时在当前 runtime 上
/// spawn 一个持有 `Arc<()>` 的永久 pending 任务，池内只保留 `Weak`；runtime
/// 结束 → 任务被 drop → 强引用归零 → `Weak::upgrade()` 失败 → 池判定过期，
/// 下一次 [`redis_conn`] 在**当前** runtime 重建（try_lock 串行化 + 有界超时）
/// 并原子替换全局池。单
/// runtime 服务内哨兵始终存活，热路径与旧 OnceLock 方案等价（读锁 + weak
/// 升级 + Arc clone），重建整个进程生命周期内每个 runtime 至多一次。多个
/// **同时存活**的 runtime 共用本模块（罕见嵌入形态）时，池归属首个构建它的
/// runtime；`ConnectionManager` 的命令路径经 channel/oneshot 与驱动任务通信
/// （跨 runtime await 成立），redis 的重连任务又 spawn 在命令发起方的当前
/// runtime 上，因此仍可用，不构成正确性风险。
struct RedisConnPool {
    connections: Vec<redis::aio::ConnectionManager>,
    /// 所属 Tokio runtime 的存活哨兵：任务持有强引用，池内只留弱引用。
    owner_runtime: Weak<()>,
}

impl RedisConnPool {
    /// 所属 runtime 是否仍存活；已结束 → 连接驱动全部死亡，池必须重建。
    fn owner_runtime_is_alive(&self) -> bool {
        self.owner_runtime.upgrade().is_some()
    }
}

/// 全局连接池（可替换）：读多写少，`RwLock` 足够。不可用时调用方语义不变
/// （降级 DB-only）；池未建立或刚失效时失败不缓存，后续调用重试。
static REDIS_CONN_POOL: RwLock<Option<Arc<RedisConnPool>>> = RwLock::new(None);

/// 池重建串行锁（`try_lock` 语义）：并发调用方同时发现池过期时只允许一个执行
/// 重建；其余调用方**立即降级 DB-only，绝不在锁上排队**（F5 修复 1a：Redis
/// 黑洞时旧实现的 `lock().await` 会把全进程 `redis_conn()` 调用方级联挂起）。
static REDIS_CONN_POOL_BUILD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

static REDIS_CONN_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// 单条连接的建立与响应超时（F5 修复 1a，对齐 redis-rs 1.5 默认值）：
/// `connection_timeout`（1s）约束建连握手，`response_timeout`（500ms）约束
/// 池内**既有**连接上的每条命令——黑洞形态必须在有界时间内变成错误。显式
/// 写死是对"依赖隐式默认"的防漂移锁定。
const REDIS_CONN_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const REDIS_CONN_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// 重建失败冷却窗口（F5 修复 1a）：把对宕机 Redis 的重建尝试频率上界钉在
/// 1 次/秒，防止恢复瞬间的重建风暴冲击本机与网络。
const REDIS_CONN_BUILD_COOLDOWN: Duration = Duration::from_secs(1);

/// 上次池重建失败的 UNIX 毫秒时间戳；0 表示无失败记录。
static REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS: AtomicU64 = AtomicU64::new(0);

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// 池大小：单条多路复用连接在本机 docker 桥 RTT（~0.17ms）下 ops/s 上限
/// ~6K；8 条并发管线可支撑数万 ops/s，同时不至于用过多连接冲击 Redis。
const REDIS_CONN_POOL_SIZE: usize = 8;

/// 获取共享 Redis 连接管理器（失败返回 None，调用方应降级到 DB-only）。
pub(crate) async fn redis_conn() -> Option<redis::aio::ConnectionManager> {
    if let Some(conn) = pooled_connection() {
        return Some(conn);
    }
    let pool = rebuild_redis_conn_pool().await?;
    let index = REDIS_CONN_CURSOR.fetch_add(1, Ordering::Relaxed) % pool.connections.len();
    Some(pool.connections[index].clone())
}

/// 从当前池轮转取一条连接；池不存在或所属 runtime 已结束 → `None`（触发
/// 在当前 runtime 上重建）。
fn pooled_connection() -> Option<redis::aio::ConnectionManager> {
    let guard = REDIS_CONN_POOL.read().ok()?;
    let pool = guard.as_ref()?;
    if !pool.owner_runtime_is_alive() {
        return None;
    }
    let index = REDIS_CONN_CURSOR.fetch_add(1, Ordering::Relaxed) % pool.connections.len();
    Some(pool.connections[index].clone())
}

/// 在当前 runtime 重建连接池并原子替换全局池。
///
/// F5 修复 1a 的三条硬边界：
/// - **try_lock fail-fast**：其他调用方正在重建 → 本次调用直接返回 `None`
///   （降级 DB-only），绝不在构建锁上排队等待。
/// - **锁内只允许有界 await**：建连并行执行且每条连接受 [`REDIS_CONN_CONNECT_TIMEOUT`]
///   约束，构建锁的最长持有时长 ≤ 该超时，锁永不成为无限等待的载体。
/// - **失败冷却**：重建失败记录 [`REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS`]，
///   冷却窗口内的后续调用直接降级，不发起任何网络尝试。
///
/// 任一连接建立失败 → `None`，不缓存半成品，冷却期满后由后续调用整体重试。
async fn rebuild_redis_conn_pool() -> Option<Arc<RedisConnPool>> {
    let last_failure_ms = REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.load(Ordering::Relaxed);
    if last_failure_ms > 0 {
        let elapsed_ms = unix_millis().saturating_sub(last_failure_ms);
        if elapsed_ms < REDIS_CONN_BUILD_COOLDOWN.as_millis() as u64 {
            return None;
        }
    }
    let Ok(_build_guard) = REDIS_CONN_POOL_BUILD.try_lock() else {
        return None;
    };
    // 双检：拿锁期间其他调用方可能已完成重建。
    {
        let guard = REDIS_CONN_POOL.read().ok()?;
        if let Some(pool) = guard.as_ref() {
            if pool.owner_runtime_is_alive() {
                return Some(Arc::clone(pool));
            }
        }
    }
    let redis_url = std::env::var("REDIS_URL")
        .or_else(|_| std::env::var("ASTRAL_REDIS_URL"))
        .unwrap_or_else(|_| "redis://localhost:6379".into());
    let client = redis::Client::open(redis_url.as_str()).ok()?;
    // 并行建连（JoinSet）：单条失败即整体失败（不缓存半成品），总时长受
    // REDIS_CONN_CONNECT_TIMEOUT 约束。
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..REDIS_CONN_POOL_SIZE {
        let client = client.clone();
        join_set.spawn(async move {
            let config = redis::aio::ConnectionManagerConfig::new()
                .set_response_timeout(Some(REDIS_CONN_RESPONSE_TIMEOUT))
                .set_connection_timeout(Some(REDIS_CONN_CONNECT_TIMEOUT))
                // 首次建连单次尝试、快速失败：默认 6 次重试会把单次建连周期
                // 拉长到 13-20s，叠加构建锁排队正是 F5 的放大器。重建节奏由
                // 失败冷却承担（1 次/秒），连接丢失后的逐命令重连同样单次
                // 尝试 + 超时 → 错误 → L2 miss 回源（best-effort 缓存层的
                // 正确自愈形态）。
                .set_number_of_retries(0);
            redis::aio::ConnectionManager::new_with_config(client, config).await
        });
    }
    let mut connections = Vec::with_capacity(REDIS_CONN_POOL_SIZE);
    let mut any_failure = false;
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok(connection)) => connections.push(connection),
            Ok(Err(_)) | Err(_) => any_failure = true,
        }
    }
    if any_failure {
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(unix_millis(), Ordering::Relaxed);
        return None;
    }
    // 哨兵 spawn 失败（无 runtime 上下文等，理论上建连成功则必不发生）→
    // 不缓存无法判定归属 runtime 的池，冷却期满后由后续调用整体重试。
    let owner_runtime = spawn_pool_runtime_sentinel()?;
    let pool = Arc::new(RedisConnPool {
        connections,
        owner_runtime,
    });
    // 写锁中毒时跳过缓存：本次调用仍返回可用连接，下一次调用重建。
    if let Ok(mut guard) = REDIS_CONN_POOL.write() {
        *guard = Some(Arc::clone(&pool));
    }
    Some(pool)
}

/// 在当前 runtime 上 spawn 池存活哨兵：任务持有强 `Arc<()>` 并永久 pending，
/// runtime 结束时任务被 drop → 强引用归零 → 池内弱引用失效 → 池判定过期。
fn spawn_pool_runtime_sentinel() -> Option<Weak<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    let alive = Arc::new(());
    let weak = Arc::downgrade(&alive);
    runtime.spawn(async move {
        // 强引用随任务移入，直至 runtime 关闭（任务被 drop）时释放。
        let _keep_alive_until_runtime_shutdown = alive;
        std::future::pending::<()>().await;
    });
    Some(weak)
}

/// 带抖动的 TTL：base + 基于时间戳的伪随机偏移，防止缓存雪崩。
pub(crate) fn ttl_with_jitter(base: u64, jitter_max: u64) -> u64 {
    let jitter = if jitter_max > 0 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        nanos % jitter_max
    } else {
        0
    };
    base + jitter
}

impl CardActiveCache {
    /// 载荷必须明确归属 ELIGIBILITY 投影类型才可参与命中判定。
    fn matches_projection(&self) -> bool {
        self.projection_type == ProjectionAggregate::Eligibility.as_str()
    }

    fn matches_context(&self, context: &CardActiveContext) -> bool {
        self.user_id == context.user_id
            && self.identity_card_id == context.identity_card_id
            && self.user_card_id == context.user_card_id
            && self.user_card_tenant_id == context.user_card_tenant_id
            && self.user_card_domain_id == context.user_card_domain_id
    }

    /// 投影 + 时代栅栏：
    /// - schema 版本不匹配 → miss（v2 旧载荷读取侧显式重写覆盖）；
    /// - head 存在：(source_generation, revoke_fence) 逐项匹配，且共享时代
    ///   一致（任一侧未知 = Redis 降级，跳过 epoch 子校验，代次栅栏照常）；
    /// - head 缺失（恢复/重建期或 legacy 库）：残留正缓存完全不受代次栅栏
    ///   保护，仅当条目携带当前共享时代才可命中——整库恢复/重建后运维换时代，
    ///   旧条目全部 miss（见 `crate::cache_epoch` 换时代操作）。
    fn matches_gate(&self, gate: Option<&ProjectionGate>, current_epoch: Option<&str>) -> bool {
        if self.schema_version != CARD_ACTIVE_CACHE_SCHEMA {
            return false;
        }
        match gate {
            Some(gate) => {
                self.source_generation == gate.source_generation
                    && self.revoke_fence == gate.revoke_fence
                    && cache_epoch_matches(current_epoch, self.cache_epoch.as_deref())
            }
            None => cache_epoch_is_current(current_epoch, self.cache_epoch.as_deref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::CardActiveContext;
    use astral_types::PlatformCardPairRequest;
    use time::{Date, Month, Time};

    /// 测试夹具共享时代（读写两侧一致即为"当前时代"）。
    const TEST_EPOCH: &str = "epoch-1";

    fn context() -> CardActiveContext {
        CardActiveContext {
            user_id: 7,
            identity_card_id: 70,
            user_card_id: 700,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
        }
    }

    fn gate(source_generation: i64, revoke_fence: i64) -> ProjectionGate {
        ProjectionGate {
            ready: source_generation > 0,
            source_generation,
            revoke_fence,
        }
    }

    fn cache(gate: &ProjectionGate) -> CardActiveCache {
        CardActiveCache {
            valid: true,
            expires_at: None,
            source_generation: gate.source_generation,
            revoke_fence: gate.revoke_fence,
            user_id: 7,
            identity_card_id: 70,
            user_card_id: 700,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
            projection_type: ProjectionAggregate::Eligibility.as_str().to_string(),
            schema_version: CARD_ACTIVE_CACHE_SCHEMA,
            cache_epoch: Some(TEST_EPOCH.to_string()),
        }
    }

    #[test]
    fn active_cache_round_trip_preserves_physical_binding_and_versions() {
        let entry = CardActiveCache {
            valid: true,
            expires_at: Some(2_000),
            source_generation: 3,
            revoke_fence: 1,
            user_id: 7,
            identity_card_id: 70,
            user_card_id: 700,
            user_card_tenant_id: 10,
            user_card_domain_id: 20,
            projection_type: ProjectionAggregate::Eligibility.as_str().to_string(),
            schema_version: CARD_ACTIVE_CACHE_SCHEMA,
            cache_epoch: Some(TEST_EPOCH.to_string()),
        };
        let encoded = serde_json::to_string(&entry).unwrap();
        let decoded: CardActiveCache = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.matches_context(&context()));
        assert!(decoded.matches_gate(Some(&gate(3, 1)), Some(TEST_EPOCH)));
        assert!(decoded.matches_projection());
        assert_eq!(decoded.schema_version, CARD_ACTIVE_CACHE_SCHEMA);
        assert_eq!(decoded.cache_epoch.as_deref(), Some(TEST_EPOCH));
        assert!(decoded.expires_at.unwrap() > 1_000);
    }

    #[test]
    fn legacy_string_cache_value_is_not_a_valid_entry() {
        // 旧 scalar（1/0）解析失败 → miss。
        assert!(serde_json::from_str::<CardActiveCache>("1").is_err());
        assert!(serde_json::from_str::<CardActiveCache>("0").is_err());
    }

    #[test]
    fn legacy_json_without_projection_type_is_rejected_on_read() {
        // 旧 JSON 载荷（无 projection_type 字段）默认 LEGACY → 读取侧显式 miss。
        let legacy_payload = r#"{
            "valid": true,
            "expires_at": null,
            "source_generation": 3,
            "projected_generation": 3,
            "revoke_fence": 1,
            "user_id": 7,
            "identity_card_id": 70,
            "user_card_id": 700,
            "user_card_tenant_id": 10,
            "user_card_domain_id": 20
        }"#;
        let decoded: CardActiveCache = serde_json::from_str(legacy_payload).unwrap();
        assert!(!decoded.matches_projection());
        assert_eq!(
            cached_active_result(
                &decoded,
                &context(),
                Some(&gate(3, 1)),
                Some(TEST_EPOCH),
                1_000
            ),
            None
        );
    }

    #[test]
    fn v1_payload_with_projection_type_but_without_schema_or_epoch_is_rejected() {
        // v1 载荷（上线前的现行格式：有 projection_type，无 schema_version /
        // cache_epoch）：反序列化 schema 默认 0 ≠ 当前 → head 存在与缺失均 miss。
        let v1_payload = r#"{
            "valid": true,
            "expires_at": null,
            "source_generation": 3,
            "projected_generation": 3,
            "revoke_fence": 1,
            "user_id": 7,
            "identity_card_id": 70,
            "user_card_id": 700,
            "user_card_tenant_id": 10,
            "user_card_domain_id": 20,
            "projection_type": "ELIGIBILITY"
        }"#;
        let decoded: CardActiveCache = serde_json::from_str(v1_payload).unwrap();
        assert!(decoded.matches_projection());
        assert!(decoded.matches_context(&context()));
        assert_eq!(decoded.schema_version, 0);
        assert_eq!(decoded.cache_epoch, None);
        assert!(!decoded.matches_gate(Some(&gate(3, 1)), Some(TEST_EPOCH)));
        assert_eq!(
            cached_active_result(
                &decoded,
                &context(),
                Some(&gate(3, 1)),
                Some(TEST_EPOCH),
                1_000
            ),
            None
        );
        // head 缺失（恢复期）同样不放行：schema 栅栏先于 epoch 栅栏。
        assert_eq!(
            cached_active_result(&decoded, &context(), None, Some(TEST_EPOCH), 1_000),
            None
        );
    }

    #[test]
    fn wrong_projection_type_does_not_hit() {
        let current_gate = gate(3, 1);
        let mut entry = cache(&current_gate);
        entry.projection_type = "CARD".to_string();
        assert!(!entry.matches_projection());
        assert_eq!(
            cached_active_result(
                &entry,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                1_000
            ),
            None
        );
    }

    #[test]
    fn active_cache_rejects_context_and_projection_mismatches() {
        let entry = cache(&gate(3, 1));
        let mut other_context = context();
        other_context.user_card_domain_id = 21;
        assert!(!entry.matches_context(&other_context));
        assert!(!entry.matches_gate(Some(&gate(4, 1)), Some(TEST_EPOCH)));
        assert!(!entry.matches_gate(Some(&gate(3, 2)), Some(TEST_EPOCH)));
    }

    #[test]
    fn schema_version_mismatch_always_misses_even_with_matching_epoch() {
        let current_gate = gate(3, 1);
        let mut legacy = cache(&current_gate);
        legacy.schema_version = CARD_ACTIVE_CACHE_SCHEMA - 1;
        assert!(!legacy.matches_gate(Some(&current_gate), Some(TEST_EPOCH)));
        assert!(!legacy.matches_gate(None, Some(TEST_EPOCH)));
        assert_eq!(
            cached_active_result(
                &legacy,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                1_000
            ),
            None
        );
    }

    #[test]
    fn epoch_gate_matrix_covers_head_present_and_missing() {
        let current_gate = gate(3, 1);
        let entry = cache(&current_gate);

        // head 存在：epoch 一致 → 命中；两侧均已知但不等 → miss；
        // 任一侧未知（Redis 降级/条目未携带）→ 跳过 epoch 子校验，三元组照常。
        assert!(entry.matches_gate(Some(&current_gate), Some(TEST_EPOCH)));
        assert!(!entry.matches_gate(Some(&current_gate), Some("rotated-epoch")));
        assert!(entry.matches_gate(Some(&current_gate), None));
        let mut no_epoch = entry.clone();
        no_epoch.cache_epoch = None;
        assert!(no_epoch.matches_gate(Some(&current_gate), Some(TEST_EPOCH)));
        assert_eq!(
            cached_active_result(
                &entry,
                &context(),
                Some(&current_gate),
                Some("rotated-epoch"),
                1_000
            ),
            None
        );

        // head 缺失（恢复/重建期）：仅当条目携带当前时代才可命中；
        // 换时代后旧条目、降级期未知时代一律 miss。
        assert!(entry.matches_gate(None, Some(TEST_EPOCH)));
        assert!(!entry.matches_gate(None, Some("rotated-epoch")));
        assert!(!entry.matches_gate(None, None));
        assert!(!no_epoch.matches_gate(None, Some(TEST_EPOCH)));
        assert!(!no_epoch.matches_gate(None, None));
        assert_eq!(
            cached_active_result(&entry, &context(), None, Some("rotated-epoch"), 1_000),
            None
        );
    }

    #[test]
    fn active_cache_payload_requires_all_fields() {
        assert!(serde_json::from_str::<CardActiveCache>("not-json").is_err());
        assert!(
            serde_json::from_str::<CardActiveCache>(r#"{"valid":true,"expires_at":null}"#).is_err()
        );
    }

    #[test]
    fn active_cache_hit_requires_valid_context_and_projection_versions() {
        let current_gate = gate(3, 1);
        let entry = cache(&current_gate);
        assert_eq!(
            cached_active_result(
                &entry,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                1_000
            ),
            Some(true)
        );

        let mut fields = [
            |entry: &mut CardActiveCache| entry.user_id = 8,
            |entry: &mut CardActiveCache| entry.identity_card_id = 71,
            |entry: &mut CardActiveCache| entry.user_card_id = 701,
            |entry: &mut CardActiveCache| entry.user_card_tenant_id = 11,
            |entry: &mut CardActiveCache| entry.user_card_domain_id = 21,
        ];
        for mutate in &mut fields {
            let mut mismatched = entry.clone();
            mutate(&mut mismatched);
            assert_eq!(
                cached_active_result(
                    &mismatched,
                    &context(),
                    Some(&current_gate),
                    Some(TEST_EPOCH),
                    1_000
                ),
                None
            );
        }

        for mismatched_gate in [gate(4, 1), gate(3, 2)] {
            assert_eq!(
                cached_active_result(
                    &entry,
                    &context(),
                    Some(&mismatched_gate),
                    Some(TEST_EPOCH),
                    1_000
                ),
                None
            );
        }
        // head 缺失（legacy 库）：条目携带当前时代 → 保留缓存收益。
        assert_eq!(
            cached_active_result(&entry, &context(), None, Some(TEST_EPOCH), 1_000),
            Some(true)
        );
    }

    #[test]
    fn inactive_cache_entry_is_a_deny_only_when_compatible() {
        let current_gate = gate(3, 1);
        let mut entry = cache(&current_gate);
        entry.valid = false;
        assert_eq!(
            cached_active_result(
                &entry,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                1_000
            ),
            Some(false)
        );

        let mut stale = entry.clone();
        stale.revoke_fence = 2;
        assert_eq!(
            cached_active_result(
                &stale,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                1_000
            ),
            None
        );
    }

    #[test]
    fn effective_expiry_uses_the_earliest_physical_card_deadline() {
        let identity_expiry = PrimitiveDateTime::new(
            Date::from_calendar_date(2026, Month::August, 10).unwrap(),
            Time::MIDNIGHT,
        );
        let user_card_expiry = PrimitiveDateTime::new(
            Date::from_calendar_date(2026, Month::August, 9).unwrap(),
            Time::MIDNIGHT,
        );
        assert_eq!(
            effective_expiry(Some(identity_expiry), Some(user_card_expiry)),
            Some(user_card_expiry.assume_utc().unix_timestamp())
        );
        assert_eq!(
            effective_expiry(None, Some(user_card_expiry)),
            Some(user_card_expiry.assume_utc().unix_timestamp())
        );
        assert_eq!(effective_expiry(None, None), None);
    }

    #[test]
    fn active_cache_expiry_is_checked_at_read_time() {
        // 有效但已到期：读取侧必须 miss 回 SQL。
        let current_gate = gate(3, 1);
        let mut entry = cache(&current_gate);
        entry.expires_at = Some(1_000);
        assert_eq!(
            cached_active_result(
                &entry,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                1_000
            ),
            None
        );
        assert_eq!(
            cached_active_result(
                &entry,
                &context(),
                Some(&current_gate),
                Some(TEST_EPOCH),
                999
            ),
            Some(true)
        );
    }

    #[test]
    fn cache_ttl_never_outlives_card_expiry() {
        assert_eq!(active_cache_ttl(Some(1_010), 1_000, 300, 0), Some(10));
        assert_eq!(active_cache_ttl(Some(999), 1_000, 300, 0), None);
        assert_eq!(active_cache_ttl(None, 1_000, 300, 0), Some(300));
    }

    #[test]
    fn request_requires_all_positive_fields() {
        let valid = PlatformCardPairRequest {
            user_id: 7,
            identity_card_id: 70,
            user_card_id: 700,
        };
        assert!(valid.is_positive());
        let mut invalid = valid;
        invalid.user_card_id = 0;
        assert!(!invalid.is_positive());
    }

    // ========================= L1 进程内资格缓存测试 =========================
    //
    // L1 store 是进程级全局静态；本组测试通过互斥锁串行 + 独立 key 段隔离，
    // 每个用例开始前清空 store，结束时随作用域自然结束，互不干扰。

    use std::sync::{Mutex, MutexGuard};

    static L1_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn l1_test_guard() -> MutexGuard<'static, ()> {
        L1_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 测试专用 L1 key 段（避免与其他用例/真实卡 ID 冲突）。
    fn l1_test_key(ordinal: i64) -> CardActiveContext {
        CardActiveContext {
            user_id: 9_100_000,
            identity_card_id: 9_200_000,
            user_card_id: 9_300_000 + ordinal,
            user_card_tenant_id: 9_400_000,
            user_card_domain_id: 9_500_000,
        }
    }

    fn l1_reset_store() {
        l1_card_active_store().write().unwrap().clear();
    }

    fn l1_entry_count() -> usize {
        l1_card_active_store().read().unwrap().len()
    }

    fn backdated_instant(seconds_ago: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(seconds_ago))
            .expect("backdated instant must stay within the monotonic clock range")
    }

    #[test]
    fn l1_applies_only_to_the_policy_engine_require_false_path() {
        // require 两配置行为：require=false（PolicyEngine）参与 L1；
        // require=true（Chat revalidate）不参与——L1 只缓存 valid 事实，
        // 不缓存 gate READY 事实。
        assert!(l1_applies_to(&CardEligibilityCheckOptions {
            base_ttl_seconds: 300,
            jitter_max_seconds: 60,
            require_projection_ready: false,
        }));
        assert!(!l1_applies_to(&CardEligibilityCheckOptions {
            base_ttl_seconds: 30,
            jitter_max_seconds: 5,
            require_projection_ready: true,
        }));
    }

    #[test]
    fn l1_hit_within_ttl_serves_positive_result() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(1);
        l1_card_active_insert(&context, None, Instant::now(), 1_000);
        // L1 命中 → Some(true)（免 Redis / 免 head 点查，由调用方协议保证）。
        assert_eq!(
            l1_card_active_lookup(&context, Instant::now(), 1_000),
            Some(true)
        );
    }

    #[test]
    fn l1_misses_when_never_cached_or_evicted() {
        let _guard = l1_test_guard();
        l1_reset_store();
        // 未缓存 → None → 调用方走原协议（fail-closed 保持）。
        assert_eq!(
            l1_card_active_lookup(&l1_test_key(2), Instant::now(), 1_000),
            None
        );
        let context = l1_test_key(2);
        l1_card_active_insert(&context, None, Instant::now(), 1_000);
        evict_l1_card_active_cache(context.user_card_id);
        // 同进程状态变更 evict 后 → 立即 miss（原协议重验）。
        assert_eq!(l1_card_active_lookup(&context, Instant::now(), 1_000), None);
    }

    #[test]
    fn l1_entry_expires_after_five_second_ttl() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(3);
        // 直接插入带过期时刻的条目：cached_at 回拨 6s > TTL 5s → miss。
        l1_card_active_insert_with_limit(
            l1_card_active_store(),
            &context,
            None,
            backdated_instant(6),
            1_000,
            L1_CARD_ACTIVE_MAX_ENTRIES,
        );
        assert_eq!(l1_card_active_lookup(&context, Instant::now(), 1_000), None);
        // TTL 内（4s 前）仍命中。
        l1_card_active_insert_with_limit(
            l1_card_active_store(),
            &context,
            None,
            backdated_instant(4),
            1_000,
            L1_CARD_ACTIVE_MAX_ENTRIES,
        );
        assert_eq!(
            l1_card_active_lookup(&context, Instant::now(), 1_000),
            Some(true)
        );
    }

    #[test]
    fn l1_hit_respects_natural_expiry() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(4);
        let now_unix = 2_000_i64;
        // 已越过自然到期（min(identity, user_card) 截止）→ 读取侧必须 miss。
        l1_card_active_insert(&context, Some(now_unix - 1), Instant::now(), now_unix);
        assert_eq!(
            l1_card_active_lookup(&context, Instant::now(), now_unix),
            None
        );
        // 未到期 → 命中。
        l1_card_active_insert(&context, Some(now_unix + 100), Instant::now(), now_unix);
        assert_eq!(
            l1_card_active_lookup(&context, Instant::now(), now_unix),
            Some(true)
        );
        // 自然到期未知（两张实体卡都无截止）→ 仅受 5s TTL 约束。
        l1_card_active_insert(&context, None, Instant::now(), now_unix);
        assert_eq!(
            l1_card_active_lookup(&context, Instant::now(), now_unix),
            Some(true)
        );
    }

    #[test]
    fn l1_rejects_any_context_field_mismatch() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(5);
        l1_card_active_insert(&context, None, Instant::now(), 1_000);
        let mut fields = [
            |ctx: &mut CardActiveContext| ctx.user_id = 9_100_001,
            |ctx: &mut CardActiveContext| ctx.identity_card_id = 9_200_001,
            |ctx: &mut CardActiveContext| ctx.user_card_tenant_id = 9_400_001,
            |ctx: &mut CardActiveContext| ctx.user_card_domain_id = 9_500_001,
        ];
        for mutate in &mut fields {
            let mut mismatched = context;
            mutate(&mut mismatched);
            // 上下文任一字段不一致 → miss（与 Redis 层 matches_context 同语义，
            // 防止同一张卡被套用到其他用户/身份卡/租户域）。
            assert_eq!(
                l1_card_active_lookup(&mismatched, Instant::now(), 1_000),
                None
            );
        }
    }

    #[test]
    fn evict_l1_card_active_cache_removes_only_the_target_card() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let first = l1_test_key(6);
        let second = l1_test_key(7);
        l1_card_active_insert(&first, None, Instant::now(), 1_000);
        l1_card_active_insert(&second, None, Instant::now(), 1_000);
        evict_l1_card_active_cache(first.user_card_id);
        assert_eq!(l1_card_active_lookup(&first, Instant::now(), 1_000), None);
        assert_eq!(
            l1_card_active_lookup(&second, Instant::now(), 1_000),
            Some(true)
        );
    }

    #[test]
    fn l1_insert_is_capacity_bounded() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let store = l1_card_active_store();
        let max_entries = 3;
        for ordinal in 0..4 {
            l1_card_active_insert_with_limit(
                store,
                &l1_test_key(10 + ordinal),
                None,
                Instant::now(),
                1_000,
                max_entries,
            );
            assert!(
                l1_entry_count() <= max_entries,
                "L1 store must stay capacity-bounded, got {} entries",
                l1_entry_count()
            );
        }
        // 容量淘汰后最近插入的条目仍在（有界且可用）。
        assert_eq!(
            l1_card_active_lookup(&l1_test_key(13), Instant::now(), 1_000),
            Some(true)
        );
    }

    // ===================== Redis 连接池 runtime 边界测试 =====================
    //
    // `ConnectionManager` 无法在无 Redis 环境构造；本组测试覆盖修复的核心机制
    // ——池条目的"所属 runtime 存活哨兵"生命周期：runtime 存活 → 哨兵存活
    // （池复用快路径）；runtime 结束（顺序 #[tokio::test] / 嵌入方的现实形态）
    // → 哨兵死亡 → 池必须判定过期并在新 runtime 重建。真实 Redis 下的跨
    // runtime 全链路由 tests/evidence_cache_redis_integration.rs（顺序 runtime
    // runbook）覆盖。

    /// 构造一个 current-thread 测试 runtime 并在其上下文内执行 `f`。
    fn with_current_thread_runtime<T>(f: impl FnOnce() -> T) -> (tokio::runtime::Runtime, T) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread test runtime must build");
        let output = {
            let _enter = runtime.enter();
            f()
        };
        (runtime, output)
    }

    #[test]
    fn pool_runtime_sentinel_stays_alive_while_its_runtime_lives() {
        let (runtime, weak) = with_current_thread_runtime(|| {
            spawn_pool_runtime_sentinel().expect("sentinel must spawn inside a runtime context")
        });
        assert!(
            weak.upgrade().is_some(),
            "sentinel must stay alive while its owning runtime lives (pool reuse fast path)"
        );
        runtime.shutdown_timeout(Duration::from_secs(1));
        assert!(
            weak.upgrade().is_none(),
            "sentinel must die with its runtime so redis_conn rebuilds on the next runtime"
        );
    }

    #[test]
    fn pool_runtime_sentinel_dies_when_its_runtime_is_dropped() {
        // 顺序 #[tokio::test] 的现实形态：runtime 随作用域直接 drop（未显式
        // shutdown）→ 哨兵任务随 runtime 一起被 drop → 弱引用失效。
        let weak = {
            let (_runtime, weak) = with_current_thread_runtime(|| {
                spawn_pool_runtime_sentinel().expect("sentinel must spawn inside a runtime context")
            });
            weak
        };
        assert!(
            weak.upgrade().is_none(),
            "dropping the owning runtime must drop the sentinel task and kill the weak pointer"
        );
    }

    #[test]
    fn pool_staleness_is_decided_by_the_runtime_sentinel() {
        // 悬空弱引用（无所属 runtime 存活证据）→ 池必须判过期，绝不跨 runtime
        // 复用死连接。
        let stale = RedisConnPool {
            connections: Vec::new(),
            owner_runtime: Weak::new(),
        };
        assert!(!stale.owner_runtime_is_alive());
    }

    #[test]
    fn redis_conn_without_runtime_context_returns_none() {
        // 无 Tokio runtime 上下文：哨兵无法 spawn（建连同样需要 runtime）→
        // 必须返回 None 降级 DB-only，绝不 panic、绝不缓存半成品。
        // （直接在非 async 测试线程上调用，验证 spawn 前置守卫。）
        assert!(spawn_pool_runtime_sentinel().is_none());
    }

    // ===================== F5 修复 1a：池构建有界性测试 =====================

    /// 构建路径测试互斥：本组测试触碰全局构建锁与失败冷却时间戳，串行执行
    /// 以避免并行测试互相污染冷却状态。
    static BUILD_PATH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn block_on_current_thread<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread test runtime must build")
            .block_on(future)
    }

    #[test]
    fn pool_build_fails_fast_when_another_build_is_in_flight() {
        let _serial = BUILD_PATH_TEST_LOCK.lock().unwrap();
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(0, Ordering::Relaxed);
        // 他人持有构建锁（正在重建）→ try_lock fail-fast，绝不排队。
        // （旧实现 lock().await 会在这里无限等待——F5 第一现场的机制面。）
        let holder = REDIS_CONN_POOL_BUILD
            .try_lock()
            .expect("test must own the build lock");
        let started = Instant::now();
        let result = block_on_current_thread(async { rebuild_redis_conn_pool().await });
        assert!(result.is_none(), "in-flight rebuild must degrade to None");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "rebuild must fail fast on a held build lock, never queue on it"
        );
        drop(holder);
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn pool_build_cooldown_short_circuits_without_network() {
        let _serial = BUILD_PATH_TEST_LOCK.lock().unwrap();
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(0, Ordering::Relaxed);
        // 刚刚失败过 → 冷却窗口内的重建直接降级，不发起任何网络尝试。
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(unix_millis(), Ordering::Relaxed);
        let started = Instant::now();
        let result = block_on_current_thread(async { rebuild_redis_conn_pool().await });
        assert!(result.is_none(), "cooldown window must degrade to None");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "cooldown must short-circuit before any connection attempt"
        );
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn connection_manager_setup_times_out_against_silent_server() {
        let _serial = BUILD_PATH_TEST_LOCK.lock().unwrap();
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(0, Ordering::Relaxed);
        // 确定性黑洞替身：TCP 可 accept 但服务端永不读写（docker stop 后
        // docker-proxy 仍 accept 的 F5 形态）。URL 携带密码 → 建连握手发送
        // AUTH → 无响应 → 必须在 REDIS_CONN_CONNECT_TIMEOUT 内失败，而非永久 pending。
        // （直接驱动与 rebuild 相同的建连形态，验证超时边界机制本身。）
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener must bind");
        let port = listener.local_addr().expect("bound addr").port();
        // 静默服务端线程 accept 后持有连接且不读写；accept 阻塞随测试进程
        // 退出回收，无需 join。
        let _silent = std::thread::spawn(move || {
            let mut held_sockets = Vec::new();
            for stream in listener.incoming().flatten() {
                held_sockets.push(stream);
            }
        });
        let url = format!("redis://:cooldown-test@127.0.0.1:{port}");
        let started = Instant::now();
        let result = block_on_current_thread(async move {
            let client = redis::Client::open(url.as_str()).expect("test url must parse");
            let config = redis::aio::ConnectionManagerConfig::new()
                .set_response_timeout(Some(REDIS_CONN_RESPONSE_TIMEOUT))
                .set_connection_timeout(Some(REDIS_CONN_CONNECT_TIMEOUT))
                .set_number_of_retries(0);
            redis::aio::ConnectionManager::new_with_config(client, config).await
        });
        assert!(
            result.is_err(),
            "silent server must time out, never connect"
        );
        assert!(
            started.elapsed()
                >= REDIS_CONN_CONNECT_TIMEOUT.saturating_sub(Duration::from_millis(200)),
            "failure must come from the timeout path, not an instant refusal"
        );
        assert!(
            started.elapsed() < REDIS_CONN_CONNECT_TIMEOUT + Duration::from_secs(3),
            "build must be bounded by the configured timeout plus slack"
        );
        REDIS_CONN_POOL_LAST_BUILD_FAILURE_MS.store(0, Ordering::Relaxed);
    }
}
