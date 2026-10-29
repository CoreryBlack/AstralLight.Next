//! 公共卡资格校验服务（CardEligibilityService）。
//!
//! `verify_platform_card_pair` 与 `check_cached` 共用权威物理双卡 JOIN：同时
//! 验证身份卡、用户卡、两者关系及用户卡租户/域有效性。正向进程内缓存只优化
//! 物理资格读取，不是授权证据；正式授权仍须由 PolicyEngine 独立读取 CURRENT
//! V6 published evidence。
//!
//! L1 正资格条目有 5 秒 TTL、容量上限、自然到期检查、物理上下文复核、每卡失效
//! 纪元，以及填充时的 ELIGIBILITY `source_generation`/`revoke_fence`。命中前后
//! 的 head 栅栏必须一致；head 缺失只可代表物理事实结果，不能替代授权 evidence。
//! L1 head 镜像仅在健康失效通道下参与；readiness 仍由独立 default-off wire 门控。
//!
//! hub 读栅栏对 source writer / unknown 状态 fail-closed，并对 Ready token 的
//! fetch/refill/install/final 阶段做同 token 复核。严格 DB 读取或栅栏查询失败时
//! 返回错误，不把未知状态当作有效资格。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use astral_types::{
    CardEligibility, CardEligibilityCheckOptions, PlatformCardPairRequest, PolicyError,
    ProjectionAggregate,
};
use sqlx::MySqlPool;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::memory_projection_hub::{AuxiliaryReadGate, AuxiliaryReadToken, MemoryProjectionHub};
use crate::repository::CardActiveContext;

// ===================== eligibility-read-fence-20261002：hub 读栅栏 =====================
//
// L1 正缓存的**原子 token 前后判定**：`check_cached` 对 hub 门（WriterActive /
// Uncertain / StrictRequired / Ready）的处置分类（纯函数，便于单测）：
//
// - **WriterActive / Uncertain** → `Reject`：source 事实不可证明（存在未闭合
//   source writer / 存疑态），直接 `PolicyError`，绝不回旧缓存或旧 SQL 结果
//   放行；
// - **StrictRequired**（warming / 通道非 Healthy / blocked）→ `StrictVerified`：
//   绕过 L1 正缓存（读与装都不参与），严格 head + 严格 DB，返回前以
//   `strict_read_token()` 最终重验 —— timer 健康不是 proof，但 health 差不
//   阻断：只要无 writer/unknown 且 health_revision / auxiliary epoch /
//   mutation_revision 整体相同（hub `strict_read_matches` 契约）；
// - **Ready(token)** → `TokenFenced`：L1 / head 参与但必须**同 token**
//   fetch / refill / install / final，任一环节 token 漂移即不接受旧 ALLOW；
// - **hub 未安装** → `StandalonePhysical`：原生物理资格缓存，TTL/自然到期/
//   per-card 纪元/有界 GC 与两次权威 head 读取共同约束；不提供授权 evidence。
enum L1ReadFenceAction {
    Reject(&'static str),
    StrictVerified,
    TokenFenced,
    StandalonePhysical,
}

fn l1_read_fence_action(gate: Option<AuxiliaryReadGate>) -> L1ReadFenceAction {
    match gate {
        Some(AuxiliaryReadGate::WriterActive) => {
            L1ReadFenceAction::Reject("code=eligibility.read_fence.source_writer_active")
        }
        Some(AuxiliaryReadGate::Uncertain) => {
            L1ReadFenceAction::Reject("code=eligibility.read_fence.source_uncertain")
        }
        Some(AuxiliaryReadGate::StrictRequired) => L1ReadFenceAction::StrictVerified,
        Some(AuxiliaryReadGate::Ready(_)) => L1ReadFenceAction::TokenFenced,
        None => L1ReadFenceAction::StandalonePhysical,
    }
}

/// Process-local view of the physical ELIGIBILITY projection head.
///
/// This is intentionally DB-local: a physical eligibility fact is not an
/// authorization result and does not belong in the policy-engine port surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EligibilityProjectionGate {
    ready: bool,
    source_generation: i64,
    revoke_fence: i64,
}

/// 资格 head 的 generation 与 revoke fence 是 L1 正资格条目的版本栅栏。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EligibilityFence {
    source_generation: i64,
    revoke_fence: i64,
}

impl From<&EligibilityProjectionGate> for EligibilityFence {
    fn from(gate: &EligibilityProjectionGate) -> Self {
        Self {
            source_generation: gate.source_generation,
            revoke_fence: gate.revoke_fence,
        }
    }
}

impl EligibilityFence {
    fn matches_gate(self, gate: Option<&EligibilityProjectionGate>) -> bool {
        match gate {
            Some(gate) => {
                gate.ready
                    && self.source_generation == gate.source_generation
                    && self.revoke_fence == gate.revoke_fence
            }
            None => self.source_generation == 0 && self.revoke_fence == 0,
        }
    }
}

fn eligibility_fence(gate: Option<&EligibilityProjectionGate>) -> EligibilityFence {
    gate.map(EligibilityFence::from)
        .unwrap_or(EligibilityFence {
            source_generation: 0,
            revoke_fence: 0,
        })
}

/// 单次 head 读取的版本栅栏必须与缓存条目相同；无 head 只能与无 head 相配。
fn eligibility_fence_matches(
    entry: EligibilityFence,
    gate: Option<&EligibilityProjectionGate>,
) -> bool {
    entry.matches_gate(gate)
}

/// 缓存命中要求前后 head 读取及已缓存版本完全一致。任一 SQL 读取失败由调用方
/// 作为错误传播，而不是当成 head 缺失或允许旧正结果。
fn eligibility_gate_stable(
    before: Option<&EligibilityProjectionGate>,
    after: Option<&EligibilityProjectionGate>,
) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => {
            before.ready
                && after.ready
                && before.source_generation == after.source_generation
                && before.revoke_fence == after.revoke_fence
        }
        (None, None) => true,
        _ => false,
    }
}

fn strict_eligibility_fence_matches(
    captured: EligibilityFence,
    before: Option<&EligibilityProjectionGate>,
    after: Option<&EligibilityProjectionGate>,
) -> bool {
    eligibility_gate_stable(before, after) && eligibility_fence_matches(captured, after)
}

/// Compare the exact hub token captured before reading eligibility state. Never
/// replace it with a fresh end-of-request token, which would hide an intervening
/// source mutation.
fn l1_hub_read_token_matches(hub: &MemoryProjectionHub, captured: AuxiliaryReadToken) -> bool {
    hub.strict_read_matches(captured)
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

    /// 运行期资格检查（有界进程内正缓存 + ELIGIBILITY head 栅栏 + 权威双卡 SQL）。
    ///
    /// L1 仅服务 `require_projection_ready=false` 的物理资格事实；每次可能从 L1
    /// 返回正结果的请求仍读取 ELIGIBILITY head，并在返回前复读 head，要求前后
    /// `source_generation`/`revoke_fence` 稳定且与条目一致。无 head 表示只验证
    /// 物理事实，不代表正式授权或 V6 evidence ready。`require_projection_ready=true`
    /// 保持逐请求要求 head READY；本实现不改变其默认值或启用额外兼容开关。
    ///
    /// 缓存异常、代次/撤权栅栏不一致、自然到期、per-card epoch 推进均回到权威
    /// 双卡 SQL；head 读取失败直接返回错误。缓存只存正资格、具备 5 秒 TTL 和
    /// 有界容量/GC。Ready hub 路径保留同 token fetch/refill/install/final，其他
    /// 路径仍以前后 head 栅栏闭合 L1 命中竞态。
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
        let hub = crate::memory_projection_hub::memory_projection_hub();
        let action = l1_read_fence_action(hub.map(|hub| hub.auxiliary_read_gate()));
        if let L1ReadFenceAction::Reject(code) = action {
            return Err(PolicyError::Repository(code.to_owned()));
        }
        // fenced 路径的 source token：StrictRequired 与 Ready 均无 writer/
        // unknown ⇒ token 必为 Some；分类后竞态进入 writer 活跃（None）按
        // Reject 同处置。
        let fenced: Option<(&MemoryProjectionHub, AuxiliaryReadToken)> = match action {
            L1ReadFenceAction::Reject(code) => {
                return Err(PolicyError::Repository(code.to_owned()));
            }
            L1ReadFenceAction::StrictVerified | L1ReadFenceAction::TokenFenced => {
                let Some(hub) = hub else {
                    return Err(PolicyError::Repository(
                        "code=eligibility.read_fence.internal; hub disappeared mid-flight".into(),
                    ));
                };
                let token = hub.strict_read_token().ok_or_else(|| {
                    PolicyError::Repository(
                        "code=eligibility.read_fence.source_writer_active".into(),
                    )
                })?;
                Some((hub, token))
            }
            L1ReadFenceAction::StandalonePhysical => None,
        };
        // 正缓存可能参与物理资格读取，但每次命中必须先获取权威资格 head，
        // 不能仅凭 per-card 本地 epoch 在跨实例场景跳过 generation/revoke-fence。
        let l1_allowed = matches!(
            action,
            L1ReadFenceAction::TokenFenced | L1ReadFenceAction::StandalonePhysical
        );
        let l1_epoch_before = if l1_allowed {
            l1_card_epoch_checked(context.user_card_id)
        } else {
            None
        };
        // ELIGIBILITY head 获取（R3 接缝：健康门 + readiness 显式 wire 门，
        // 叠加 hub 读栅栏）：
        // - 通道健康（hub 在场 + monitored + fresh heartbeat + 非 warming）
        //   且读栅栏 Ready → L1 head 快照优先（随失效事件失效），miss 回填走
        //   严格 reader（同 token + 同纪元安装，见 refill_checked）；
        // - 通道缺失/unknown/Unmonitored/存疑/StrictRequired → strict 逐请求
        //   head 读（现行协议，零窗口；Unmonitored 绝不 warm 资格缓存）；
        // - require=true（readiness）：仅当 wire 旗标
        //   `ASTRAL_ELIGIBILITY_READY_HEAD_CACHE` 显式开启（source same-tx
        //   失效通知生命周期接线完成并登记后）才允许 L1 head 参与 READY 判定；
        //   默认 wire-off 保持逐请求严格 head 读——未证明的 cache 绝不回答
        //   READY，wire-off 路径也不回填（readiness 探针保留）。
        let head_cache_allowed = l1_allowed && l1_eligibility_head_cache_permitted(hub);
        let cached_positive_candidate = if l1_allowed && l1_applies_to(&options) {
            l1_card_active_snapshot(context, l1_epoch_before, now_instant, now)
        } else {
            None
        };
        // A potential physical-positive hit uses an authoritative initial head read;
        // the optional mirror must never stand in for the first side of its fence.
        let head_from_cache = cached_positive_candidate.is_none()
            && l1_head_serves(
                head_cache_allowed,
                options.require_projection_ready,
                eligibility_ready_head_cache_wired(),
            );
        let mut gate = if cached_positive_candidate.is_some() {
            load_eligibility_projection_gate(pool, context.user_card_id).await?
        } else if head_from_cache {
            match l1_eligibility_head_lookup(context.user_card_id, now_instant) {
                Some(gate) => Some(gate),
                None => {
                    let gate = load_eligibility_projection_gate(pool, context.user_card_id).await?;
                    // 同 token refill：严格 head 读取与回填之间 token 漂移或
                    // 纪元推进 → 取回的 head 可能是变更前事实，不安装。
                    let stable = match &fenced {
                        None => true,
                        Some((hub, token)) => l1_hub_read_token_matches(hub, *token),
                    };
                    if stable {
                        l1_eligibility_head_refill_checked(
                            context.user_card_id,
                            gate.as_ref(),
                            now_instant,
                            l1_epoch_before,
                        );
                    }
                    gate
                }
            }
        } else {
            load_eligibility_projection_gate(pool, context.user_card_id).await?
        };
        if options.require_projection_ready && !gate.is_some_and(|gate| gate.ready) {
            return Ok(false);
        }

        // L1 正资格命中必须由两个新的数据库 head 读取闭合：前读与缓存条目
        // generation/revoke_fence 一致，后读与前读一致，且同一请求开始时捕获的
        // hub token / per-card epoch 仍稳定。不能以 L1 head mirror 或末尾新 token
        // 替代 durable source head 的最终复核。
        if l1_allowed && l1_applies_to(&options) {
            if let Some(entry_fence) = cached_positive_candidate
                .filter(|candidate| eligibility_fence_matches(*candidate, gate.as_ref()))
            {
                let before = gate;
                let after = load_eligibility_projection_gate(pool, context.user_card_id).await?;
                let stable_head =
                    strict_eligibility_fence_matches(entry_fence, before.as_ref(), after.as_ref());
                let stable_epoch = l1_epoch_before.is_some()
                    && l1_card_epoch_checked(context.user_card_id) == l1_epoch_before;
                let stable_entry = l1_card_active_candidate_still_matches(
                    context,
                    entry_fence,
                    after.as_ref(),
                    l1_epoch_before,
                    now_instant,
                    now,
                );
                // Last operation before returning a positive cache hit: compare the
                // same request-start token after head/epoch/entry rechecks.
                let stable_hub = match &fenced {
                    Some((hub, token)) => l1_hub_read_token_matches(hub, *token),
                    None => true,
                };
                gate = after;
                if stable_head && stable_epoch && stable_entry && stable_hub {
                    return Ok(true);
                }
            }
        }

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
        // L1 回填：只缓存正结果；require=true 路径不回填（l1_applies_to）；
        // StrictRequired 不回填（l1_allowed=false）；以读取前纪元戳记 +
        // 安装后复核（latefill 修复），纪元不可读时不安装（安全 miss）。
        if valid && l1_allowed && l1_applies_to(&options) {
            l1_card_active_install_checked(
                context,
                expires_at,
                gate.as_ref(),
                now_instant,
                now,
                l1_epoch_before,
            );
        }
        // 返回前同 token 终验（final fence）：fetch 与返回之间 token 漂移 =
        // 期间发生 mutation，SQL 结果可能是变更前事实 —— 绝不放行旧 ALLOW
        // （deny/false 不构成授权放行，无需栅栏）。
        if valid {
            if let Some((hub, token)) = &fenced {
                if !l1_hub_read_token_matches(hub, *token) {
                    return Err(PolicyError::Repository(
                        "code=eligibility.read_fence.token_drift; racing stale allow rejected"
                            .into(),
                    ));
                }
            }
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
async fn load_eligibility_projection_gate(
    pool: &MySqlPool,
    user_card_id: i64,
) -> Result<Option<EligibilityProjectionGate>, PolicyError> {
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

    Ok(row.map(
        |(source_generation, revoke_fence)| EligibilityProjectionGate {
            ready: source_generation > 0,
            source_generation,
            revoke_fence,
        },
    ))
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

// ============================== L1 进程内资格缓存 ==============================
//
// Native positive L1 avoids repeated physical dual-card row queries. A positive
// candidate still pays two authoritative ELIGIBILITY-head reads before it can
// return, trading cache-hit latency for a closed generation/revoke-fence race.
//
// 语义与显式取舍：
// - **只缓存 valid=true 正向结果**（逐字段复核物理上下文）；负结果/错误一律走原
//   协议（DB head 栅栏 → 权威 SQL），fail-closed 不变；
// - **TTL 5 秒**：限制物理资格条目驻留；每次正命中还必须前后读取权威
//   ELIGIBILITY head，并与条目的 generation/revoke-fence 对牌。跨实例 source
//   mutation 必须推进该 head，TTL 和本地失效纪元都不能代替这项持久证明；
//   无 head 只提供物理资格事实，不能证明 V6 授权 READY；
// - **require_projection_ready=true（Chat）不参与 L1**：L1 只缓存 valid 事实、
//   不缓存 gate READY 事实；ready 判定必须逐请求读取 ELIGIBILITY head；
// - **容量边界 + GC**：`L1_CARD_ACTIVE_MAX_ENTRIES` 上限；插入时超限先清理
//   过期条目，仍超限则整体清空（粗粒度有界保证；清空只损失命中率，不损失
//   正确性—— miss 回原协议）；
// - **per-card 失效纪元（epoch）**：每卡一个单调计数器（[`l1_card_epoch`]），
//   条目携带填充时刻的纪元值，读取侧与当前纪元逐项比对；[`evict_l1_card_active_cache`]
//   推进纪元 → 竞争窗口内迟到的旧条目即使未被及时删除也必然 miss（fail-closed）。
//   纪元是进程内失效辅助信号，不改变 durable proof，也不作为跨节点证明
//   （跨节点仍须前后权威 head 版本对牌；TTL 仅限制驻留，失效通知加速清理）；
// - L1 锁中毒视为 miss（降级原协议），不扩大授权。

/// L1 适用性判定（纯函数）：只在 `require_projection_ready=false`（PolicyEngine
/// CARD_CONTEXT 路径）参与 L1。require=true（Chat revalidate）必须逐请求验证
/// ELIGIBILITY head READY——L1 只缓存 valid 事实、不缓存 gate READY 事实，
/// L1 命中不等于 gate ready。
fn l1_applies_to(options: &CardEligibilityCheckOptions) -> bool {
    !options.require_projection_ready
}

/// L1 进程内资格缓存 TTL：5 秒；正命中仍须通过两次权威 head 读取。
const L1_CARD_ACTIVE_TTL: Duration = Duration::from_secs(5);

/// L1 容量上限（条数）。单条为一张卡的轻量上下文（约 60 字节），上限约束
/// 进程内存有界；真实负载下条目 ≈ 5s 窗口内的活跃卡数，65_536 覆盖 10 万 QPS
/// 级热点卡集。
const L1_CARD_ACTIVE_MAX_ENTRIES: usize = 65_536;

/// L1 条目：只存正结果（valid 恒为 true，不设字段），携带完整物理上下文供
/// 命中复核（逐字段复核物理上下文）、填充时刻的 per-card 失效
/// 纪元，以及自然到期时间。
#[derive(Debug, Clone)]
struct L1CardActiveEntry {
    user_id: i64,
    identity_card_id: i64,
    user_card_tenant_id: i64,
    user_card_domain_id: i64,
    /// 自然到期时间：`min(identity.expires_at, user_card.valid_until)`（unix 秒）。
    expires_at: Option<i64>,
    /// 填充时刻的 ELIGIBILITY generation/revoke fence；head 版本变化即 miss。
    fence: EligibilityFence,
    /// 填充时刻（单调时钟），用于 5s TTL 判定。
    cached_at: Instant,
    /// 填充时刻的 per-card 失效身份（全局单调 token，[`l1_card_epoch_checked`]）；
    /// evict/GC 推进后旧条目身份不可复用命中。
    epoch: u64,
}

type L1CardActiveStore = RwLock<HashMap<i64, L1CardActiveEntry>>;

static L1_CARD_ACTIVE_CACHE: OnceLock<L1CardActiveStore> = OnceLock::new();

/// per-card 失效身份映射：`user_card_id → 全局单调 token`（缺失 = 取全局
/// floor；token 由全局序列分配，**永不回绕复用**）。
type L1CardEpochStore = RwLock<HashMap<i64, u64>>;

static L1_CARD_EPOCHS: OnceLock<L1CardEpochStore> = OnceLock::new();

/// 全局单调 token 序列：每次 invalidate（bump）分配一个**从未使用过**的
/// 身份（eligibility-read-fence-20261002 epochgcfix：杜绝 GC 重置 → missing
/// 回到旧值 → 旧 captured 延迟安装回生的 ABA）。
static L1_CARD_EPOCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// 全局 floor：missing 卡的当前身份（初始 0 = 从未失效）。GC 时在**写锁内**
/// 先推进到已分配最大身份、再清空映射（与读取互斥，无 ABA 窗口）；单调不减。
static L1_CARD_EPOCH_FLOOR: AtomicU64 = AtomicU64::new(0);

/// token 序列耗尽（u64::MAX 溢出）→ L1 缓存**永久禁用**（checked 恒 `None`，
/// 全部安全 miss 冷态；实际不可达，防御性闭环）。
static L1_CARD_EPOCH_EXHAUSTED: AtomicBool = AtomicBool::new(false);

fn l1_card_epoch_store() -> &'static L1CardEpochStore {
    L1_CARD_EPOCHS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 从全局序列分配一个新身份（溢出 → 置耗尽位并返回 `None`）。
fn l1_alloc_epoch_token() -> Option<u64> {
    if L1_CARD_EPOCH_EXHAUSTED.load(Ordering::Relaxed) {
        return None;
    }
    match L1_CARD_EPOCH_SEQ.fetch_add(1, Ordering::Relaxed) {
        u64::MAX => {
            L1_CARD_EPOCH_EXHAUSTED.store(true, Ordering::Relaxed);
            None
        }
        prev => Some(prev + 1),
    }
}

/// 当前 per-card 失效身份（读取侧 checked 形态）：
///
/// - **token 序列耗尽 → `None`**：L1 永久禁用（全部安全 miss 冷态）；
/// - **锁中毒 → `None`**：读取/安装/回填侧一律安全 miss（
///   `Some(entry.epoch)` 严格比对），绝不因同值放行（lockpoison fail-closed）；
/// - 健康锁下：映射命中 → 该卡最近一次 invalidate 的身份；缺失 → 全局
///   floor（从未失效/已被 GC）。floor 单调不减且身份由全局序列分配 ——
///   GC 清空映射后旧 captured 身份（< floor）绝不复用命中（无 ABA）。
fn l1_card_epoch_checked(user_card_id: i64) -> Option<u64> {
    if L1_CARD_EPOCH_EXHAUSTED.load(Ordering::Relaxed) {
        return None;
    }
    let guard = l1_card_epoch_store().read().ok()?;
    // floor 读取必须落在同一读锁临界区内：GC 在写锁内"先推进 floor、再清空
    // 映射"，与读取互斥 —— 不存在 "映射已清 / floor 未推进" 的中间态。
    Some(
        guard
            .get(&user_card_id)
            .copied()
            .unwrap_or_else(|| L1_CARD_EPOCH_FLOOR.load(Ordering::Relaxed)),
    )
}

/// 纪元映射有界 GC 判定（纯函数）：超过上限即整体重置（有界保证优先于
/// 命中率；重置 = floor 推进 + 清空映射，身份永不回绕，见
/// [`bump_l1_card_epoch`]）。
fn l1_card_epoch_gc_needed(len: usize, max_entries: usize) -> bool {
    len > max_entries
}

/// 纪元映射容量上限（`user_card_id → u64`，单条约 24B；与 L1 正缓存/head
/// 同一量级预算）。
const L1_CARD_EPOCH_MAX_ENTRIES: usize = 65_536;

/// 清空两个 L1 正缓存存储（epoch 强制安全 miss 的连带动作；两个存储是独立
/// 锁，epoch 锁中毒时仍可尝试清空）。
fn l1_force_clear_positive_caches() {
    if let Some(store) = L1_CARD_ACTIVE_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.clear();
        }
    }
    if let Some(store) = L1_ELIGIBILITY_HEAD_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.clear();
        }
    }
}

/// 测试专用全局状态串行锁（`cfg(test)`，仅供测试，不触碰任何生产锁）：L1
/// 全局状态（两个存储 + 纪元映射/floor/序列）与 hub guard 的
/// `invalidate_positive_read_caches` hook 会跨测试清空彼此状态 —— 本 crate
/// 内 L1 纯测试与 hub 测试（memory_projection_hub）共同持有本锁串行化
/// （hub 侧接线由 main 处理）。
#[cfg(test)]
pub(crate) fn test_global_state_lock() -> std::sync::MutexGuard<'static, ()> {
    static TEST_GLOBAL_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TEST_GLOBAL_STATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 推进 per-card 失效身份（evict 入口调用；进程内失效辅助信号）：从全局
/// 序列分配**全新身份**写入映射 —— 旧条目（更小身份）读取侧必然 miss。
///
/// - **写锁中毒**：无法写映射 → floor 推进到本次新身份（missing 卡全部
///   进入新身份）+ 强制清空两个 L1 存储；此后读取为 `None`，安装/回填持续
///   跳过（RwLock 中毒不可恢复 → L1 冷态，fail-closed 优先于命中率）；
/// - **有界 GC**：映射超过 [`L1_CARD_EPOCH_MAX_ENTRIES`] → floor 先推进到
///   本次新身份、再清空映射（**同一写锁临界区内完成**，与读取互斥，无
///   "映射已清/floor 未推进" 的 ABA 窗口）。GC 只损失命中率：所有旧条目
///   身份 < floor，绝无回绕复用命中。
fn bump_l1_card_epoch(user_card_id: i64) {
    let Some(token) = l1_alloc_epoch_token() else {
        // 序列耗尽：永久禁用（checked 恒 None）+ 清空现存条目（防御性）。
        l1_force_clear_positive_caches();
        return;
    };
    let Ok(mut guard) = l1_card_epoch_store().write() else {
        L1_CARD_EPOCH_FLOOR.fetch_max(token, Ordering::Relaxed);
        l1_force_clear_positive_caches();
        return;
    };
    guard.insert(user_card_id, token);
    if l1_card_epoch_gc_needed(guard.len(), L1_CARD_EPOCH_MAX_ENTRIES) {
        L1_CARD_EPOCH_FLOOR.fetch_max(token, Ordering::Relaxed);
        guard.clear();
    }
}

fn l1_card_active_store() -> &'static L1CardActiveStore {
    L1_CARD_ACTIVE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// L1 命中判定：TTL 内 + per-card 失效纪元一致 + 物理上下文一致 + 未越过自然
/// 到期时间 + ELIGIBILITY generation/revoke fence 一致。
fn l1_card_active_entry_is_fresh(
    entry: &L1CardActiveEntry,
    context: &CardActiveContext,
    epoch_before: Option<u64>,
    now_instant: Instant,
    now_unix: i64,
) -> bool {
    if now_instant.duration_since(entry.cached_at) > L1_CARD_ACTIVE_TTL {
        return false;
    }
    // per-card 失效纪元：evict 推进后（含竞争窗口内未被及时删除的旧条目）miss。
    // Must match the request-start capture; reading a new epoch here could bless a
    // stale candidate after an intervening invalidation.
    if epoch_before != Some(entry.epoch)
        || l1_card_epoch_checked(context.user_card_id) != epoch_before
    {
        return false;
    }
    // key 只有 user_card_id，命中前必须再次确认请求者没有把同一张卡套用到
    // 其他用户、身份卡或租户域（与 进程内 L1 matches_context 同语义）。
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

/// Return only a fresh positive L1 candidate whose stored head fence matches the
/// authoritative gate already read by this request. A missing gate can validate
/// only the physical-fact sentinel and is never evidence for authorization.
fn l1_card_active_snapshot(
    context: &CardActiveContext,
    epoch_before: Option<u64>,
    now_instant: Instant,
    now_unix: i64,
) -> Option<EligibilityFence> {
    let expected_epoch = epoch_before?;
    let store = l1_card_active_store();
    let guard = store.read().ok()?;
    let entry = guard.get(&context.user_card_id)?;
    if entry.epoch != expected_epoch
        || !l1_card_active_entry_is_fresh(entry, context, epoch_before, now_instant, now_unix)
    {
        return None;
    }
    Some(entry.fence)
}

fn l1_card_active_candidate(
    context: &CardActiveContext,
    gate: Option<&EligibilityProjectionGate>,
    epoch_before: Option<u64>,
    now_instant: Instant,
    now_unix: i64,
) -> Option<EligibilityFence> {
    let entry_fence = l1_card_active_snapshot(context, epoch_before, now_instant, now_unix)?;
    eligibility_fence_matches(entry_fence, gate).then_some(entry_fence)
}

/// Capture the exact currently installed entry identity for a post-read recheck.
/// The same immutable gate and request-start epoch are passed to both checks.
fn l1_card_active_candidate_still_matches(
    context: &CardActiveContext,
    fence: EligibilityFence,
    gate: Option<&EligibilityProjectionGate>,
    epoch_before: Option<u64>,
    now_instant: Instant,
    now_unix: i64,
) -> bool {
    l1_card_active_candidate(context, gate, epoch_before, now_instant, now_unix) == Some(fence)
}

/// Read a test fixture through the same physical freshness/gate predicate as the
/// production path; production separately verifies authoritative before/after gates.
#[cfg(test)]
fn l1_card_active_lookup(
    context: &CardActiveContext,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    now_unix: i64,
) -> Option<bool> {
    let entry_fence = {
        let store = l1_card_active_store();
        let guard = store.read().ok()?;
        guard.get(&context.user_card_id)?.fence
    };
    if !eligibility_fence_matches(entry_fence, gate) {
        return None;
    }
    l1_card_active_candidate(
        context,
        gate,
        l1_card_epoch_checked(context.user_card_id),
        now_instant,
        now_unix,
    )
    .map(|_| true)
}

/// 插入时容量 GC 判定（纯函数）：达到上限即触发 GC（先清过期，腾位失败再
/// 整体清空——有界保证优先于命中率）。
fn l1_card_active_gc_needed(entry_count: usize, max_entries: usize) -> bool {
    entry_count >= max_entries
}

/// L1 安装（**读取前纪元 + 安装后复核**的稳定形态，latefill 竞争修复）：
///
/// - `epoch_before` 必须是调用方在**读取 source 之前**捕获的纪元
///   （[`l1_card_epoch_checked`]）；锁中毒（`None`）→ 不安装（安全 miss）。
///   修复点：旧实现以**安装时刻**的当前纪元戳记 —— 读取与安装之间发生的
///   evict/失效推进会被"装成新"，把变更前旧 row 当作新条目放行最长一个
///   TTL 窗口（eligibility-read-fence-20261002）；
/// - 安装后复核：纪元已推进（并发 evict/失效竞争）→ 立即移除刚安装的条目
///   （只移除自己戳记纪元的条目，不误删并发写入的新纪元条目）；
/// - `between` 在"安装完成"与"安装后复核"之间执行一次：纯单测注入竞争
///   （evict/bump）的内部 generic seam，非业务旁路。
/// - `now_instant`/`now_unix` 由调用方在同一请求内传递，保证 TTL 与自然到期
///   判定使用同一时钟基线；只缓存正结果（调用方保证）。
fn l1_card_active_install_checked_with<F>(
    context: &CardActiveContext,
    expires_at: Option<i64>,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    now_unix: i64,
    epoch_before: Option<u64>,
    between: F,
) -> bool
where
    F: FnOnce(),
{
    let Some(epoch) = epoch_before else {
        // 纪元不可读（锁中毒）→ 不安装（安全 miss）。
        return false;
    };
    l1_card_active_insert_with_fence_epoch(
        context,
        expires_at,
        eligibility_fence(gate),
        now_instant,
        now_unix,
        L1_CARD_ACTIVE_MAX_ENTRIES,
        epoch,
    );
    between();
    match l1_card_epoch_checked(context.user_card_id) {
        Some(current) if current == epoch => true,
        _ => {
            // 安装期间纪元推进 → 本条目可能承载变更前事实，立即撤销安装。
            if let Ok(mut guard) = l1_card_active_store().write() {
                if guard
                    .get(&context.user_card_id)
                    .is_some_and(|entry| entry.epoch == epoch)
                {
                    guard.remove(&context.user_card_id);
                }
            }
            false
        }
    }
}

/// 生产安装入口（无注入；语义见 [`l1_card_active_install_checked_with`]）。
fn l1_card_active_install_checked(
    context: &CardActiveContext,
    expires_at: Option<i64>,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    now_unix: i64,
    epoch_before: Option<u64>,
) -> bool {
    l1_card_active_install_checked_with(
        context,
        expires_at,
        gate,
        now_instant,
        now_unix,
        epoch_before,
        || {},
    )
}

/// 测试辅助：以当前纪元安装（保持旧用例形态；返回安装是否存活）。
#[cfg(test)]
fn l1_card_active_insert_with_gate(
    context: &CardActiveContext,
    expires_at: Option<i64>,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    now_unix: i64,
) -> bool {
    l1_card_active_install_checked(
        context,
        expires_at,
        gate,
        now_instant,
        now_unix,
        l1_card_epoch_checked(context.user_card_id),
    )
}

#[cfg(test)]
fn l1_card_active_insert(
    context: &CardActiveContext,
    expires_at: Option<i64>,
    now_instant: Instant,
    now_unix: i64,
) -> bool {
    l1_card_active_insert_with_gate(context, expires_at, None, now_instant, now_unix)
}

/// 带容量上限与显式 fence/纪元的插入实现（`epoch` 为**读取前捕获**值；
/// 测试可注入陈旧纪元验证 fail-closed miss）。
fn l1_card_active_insert_with_fence_epoch(
    context: &CardActiveContext,
    expires_at: Option<i64>,
    fence: EligibilityFence,
    now_instant: Instant,
    now_unix: i64,
    max_entries: usize,
    epoch: u64,
) {
    let Ok(mut guard) = l1_card_active_store().write() else {
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
            fence,
            cached_at: now_instant,
            epoch,
        },
    );
}

/// 同进程 L1 资格缓存即时失效（状态变更 evict 入口）。
///
/// 由 `astral-trustgraph` 的 `evict_eligibility_gate_cache` /
/// `evict_card_cache_for_tenant` 在全部同进程资格变更点同步调用（ELIGIBILITY
/// 投影 worker、user_card update/delete 等），并由 `astral-trustgraph`
/// projection_worker 的 ELIGIBILITY 通道直接绑定（失效事件驱动）。
///
/// 本函数同时失效三件事（`eligibility_invalidated` 失效事件的进程内语义）：
/// 1. L1 卡正缓存条目（既有语义）；
/// 2. L1 ELIGIBILITY head 缓存条目（R3 接缝：资格头随失效事件失效）；
/// 3. **per-card 失效纪元推进**：竞争窗口内迟到的旧条目即使未被及时删除也
///    必然 miss（fail-closed）。
///
/// 跨实例正命中仍须通过前后权威 head 版本对牌；TTL 只限制驻留，本地纪元
/// 不作为跨节点证明。锁中毒时放弃本地删除，后续读取仍执行 durable head
/// 复核并受 TTL、自然到期和物理上下文约束。
pub fn evict_l1_card_active_cache(user_card_id: i64) {
    if let Some(store) = L1_CARD_ACTIVE_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.remove(&user_card_id);
        }
    }
    if let Some(store) = L1_ELIGIBILITY_HEAD_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.remove(&user_card_id);
        }
    }
    bump_l1_card_epoch(user_card_id);
}

/// 写路径批量清空 L1 资格缓存（会话/资格 proof gate 接缝）：由
/// `SourceTransactionGuard` begin/drop 调用，消除各类 card/tenant mutation
/// 遗漏清空的 5s 正向 cache 窗口（单一收口点，替代逐调用点枚举）。
///
/// 边界（与 [`evict_l1_card_active_cache`] 的逐卡语义互补）：
/// - 只清空 `L1_CARD_ACTIVE_CACHE` 与 `L1_ELIGIBILITY_HEAD_CACHE` 两个
///   进程内条目存储的全部条目；静态未初始化时 no-op（无缓存即无窗口）；
/// - 不动 cache epoch、不触碰 memory hub、不承担任何 durable 失效职责
///   （跨节点失效仍由指针对牌/资格头栅栏 + 失效通知承担，见模块文档）；
/// - 不推进 per-card 纪元（全量清空后纪元增量无意义，语义等价整体 miss）；
/// - 锁中毒按“本次未清”处理；调用方的 durable gate 不依赖本地清理成功，
///   正命中仍须前后权威 head 对牌，TTL 只承担条目驻留上限。
pub fn evict_all_l1_card_active_caches() {
    if let Some(store) = L1_CARD_ACTIVE_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.clear();
        }
    }
    if let Some(store) = L1_ELIGIBILITY_HEAD_CACHE.get() {
        if let Ok(mut guard) = store.write() {
            guard.clear();
        }
    }
}

// ========================= L1 ELIGIBILITY head 缓存（R3 接缝） =========================
//
// 架构方案 R3 修订（Rust内存权威读面与失效通道架构方案_V0.1 §8）：
// `ELIGIBILITY READY 逐请求读 head（禁止缓存）→ L1 资格头本地判定`，补偿机制为
// "通知驱动 + 回填走严格 reader（其探针保留）"。本节提供该接缝的**层内实现**：
//
// - **随失效事件失效**：[`evict_l1_card_active_cache`]（全部同进程资格变更点 +
//   投影 worker ELIGIBILITY 通道）同时删除 head 条目并推进 per-card 纪元；
// - **健康门（fail-closed）**：仅在失效通知通道健康时参与——hub 在场且
//   `channel_is_healthy()`（monitored + fresh heartbeat + 非 warming，
//   [`l1_eligibility_head_cache_permitted`]）。hub 缺失（健康监控缺少/unknown）、
//   Unmonitored（supervisor 未心跳）、sticky suspect / 心跳过期 / warming
//   → 一律 strict 逐请求 head 读（现行协议，零窗口），L1 head 条目绝不放行，
//   Unmonitored 绝不 warm 资格缓存；
// - **readiness（require=true）= 健康门 + 显式 wire 门**：wire 旗标
//   `ASTRAL_ELIGIBILITY_READY_HEAD_CACHE` default-off——只有 source same-tx
//   失效通知生命周期（Agent7 durable invalidation intent 同事务 + commit 后
//   dispatch + 消费驱动 evict）接线并登记后才开启；wire-off 时 require=true
//   保持逐请求严格 head 读（探针保留），不读也不回填 L1 head；
// - **TTL 只是驻留上限，不是跨节点证明**：head 条目 TTL 5s（与 L1 正缓存同
//   量级），回填走严格 reader [`load_eligibility_projection_gate`]；
// - 容量边界 + GC 与 L1 正缓存同语义（超限先清过期，腾位失败整体清空）。

/// L1 head 条目：`load_eligibility_projection_gate` 严格读的产物快照。
#[derive(Debug, Clone)]
struct L1EligibilityHeadEntry {
    source_generation: i64,
    revoke_fence: i64,
    ready: bool,
    /// 填充时刻的 per-card 失效纪元；evict 推进后旧条目 miss。
    epoch: u64,
    /// 填充时刻（单调时钟），用于 5s TTL 判定。
    cached_at: Instant,
}

type L1EligibilityHeadStore = RwLock<HashMap<i64, L1EligibilityHeadEntry>>;

static L1_ELIGIBILITY_HEAD_CACHE: OnceLock<L1EligibilityHeadStore> = OnceLock::new();

fn l1_eligibility_head_store() -> &'static L1EligibilityHeadStore {
    L1_ELIGIBILITY_HEAD_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// L1 head 缓存 TTL（驻留上限；不是跨节点证明，失效以事件 + 纪元为准）。
const L1_ELIGIBILITY_HEAD_TTL: Duration = Duration::from_secs(5);

/// L1 head 容量上限（条数，单条约 48 字节；与 L1 正缓存同一量级预算）。
const L1_ELIGIBILITY_HEAD_MAX_ENTRIES: usize = 65_536;

/// L1 head 缓存参与判定（健康门，纯逻辑；`hub` 生产传
/// `crate::memory_projection_hub::memory_projection_hub()`）：
///
/// - hub 缺失（健康监控缺少/unknown）→ `false`：无通知驱动的健康证据，一律
///   strict 逐请求 head 读（fail-closed，本接缝在未装配 hub 的部署中保持
///   现行协议不变）；
/// - hub 在场但 **Unmonitored**（supervisor 尚未心跳）→ `false`：Unmonitored
///   绝不 warm/serve 资格缓存（`channel_is_healthy()` 要求显式
///   `Healthy` + fresh heartbeat + 非 warming，见 hub 契约）；
/// - hub 在场且 sticky suspect / 心跳过期 / warming / 锁中毒 → `false`：
///   存疑态回退现行逐请求协议（R1/R2 存疑回退同向）；
/// - hub 在场且通道健康（monitored + fresh heartbeat + !warming）→ `true`。
///
/// require=true（readiness）另有显式 wire 旗标门
/// [`eligibility_ready_head_cache_wired`]（default-off，source same-tx 通知
/// 接线后开启），见 [`check_cached`]。
fn l1_eligibility_head_cache_permitted(hub: Option<&MemoryProjectionHub>) -> bool {
    hub.is_some_and(|hub| hub.channel_is_healthy())
}

/// head 缓存参与组合判定（纯函数）：健康门 + readiness wire 门。
/// require=false：通道健康即可参与；require=true（readiness）：健康**且**
/// wire 旗标显式开启（source same-tx 通知接线完成）——缺一即 strict 逐请求
/// head 读。
fn l1_head_serves(
    head_cache_allowed: bool,
    require_projection_ready: bool,
    ready_wire_on: bool,
) -> bool {
    head_cache_allowed && (!require_projection_ready || ready_wire_on)
}

/// L1 head 读取：TTL 内 + per-card 纪元一致 → 严格 reader 快照；其余一律
/// `None` → 调用方回严格 head 读（fail-closed）。调用方必须先通过
/// [`l1_eligibility_head_cache_permitted`] 健康门。
fn l1_eligibility_head_lookup(
    user_card_id: i64,
    now_instant: Instant,
) -> Option<EligibilityProjectionGate> {
    let store = l1_eligibility_head_store();
    let guard = store.read().ok()?;
    let entry = guard.get(&user_card_id)?;
    if now_instant.duration_since(entry.cached_at) > L1_ELIGIBILITY_HEAD_TTL
        // 锁中毒 → `None` ≠ `Some(entry.epoch)` → miss（安全 miss）。
        || l1_card_epoch_checked(user_card_id) != Some(entry.epoch)
    {
        return None;
    }
    Some(EligibilityProjectionGate {
        ready: entry.ready,
        source_generation: entry.source_generation,
        revoke_fence: entry.revoke_fence,
    })
}

/// L1 head 回填（严格 reader 成功后调用；只缓存调用方传入的 gate 快照，
/// 绝不改写；`epoch` 为**读取前捕获**的 per-card 纪元——安装后复核见
/// [`l1_eligibility_head_refill_checked`]）。容量超限先清过期，仍超限整体
/// 清空（清空只损失命中率）。
fn l1_eligibility_head_refill(
    user_card_id: i64,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    epoch: u64,
) {
    let Some(gate) = gate else {
        // head 缺失（legacy 库/恢复期）：不缓存否定态，下一次请求继续严格读。
        return;
    };
    let Ok(mut guard) = l1_eligibility_head_store().write() else {
        return;
    };
    if guard.len() >= L1_ELIGIBILITY_HEAD_MAX_ENTRIES {
        guard.retain(|_, entry| {
            now_instant.duration_since(entry.cached_at) <= L1_ELIGIBILITY_HEAD_TTL
        });
        if guard.len() >= L1_ELIGIBILITY_HEAD_MAX_ENTRIES {
            guard.clear();
        }
    }
    guard.insert(
        user_card_id,
        L1EligibilityHeadEntry {
            source_generation: gate.source_generation,
            revoke_fence: gate.revoke_fence,
            ready: gate.ready,
            epoch,
            cached_at: now_instant,
        },
    );
}

/// L1 head 回填（**读取前纪元 + 安装后复核**的稳定形态，语义同
/// [`l1_card_active_install_checked_with`]）：
///
/// - `epoch_before` 为调用方在读取严格 head **之前**捕获的纪元；锁中毒
///   （`None`）→ 不回填（安全 miss）；
/// - 安装后纪元已推进（并发 evict/失效竞争）→ 立即移除刚回填的条目
///   （只移除自己戳记纪元的条目）；
/// - token 稳定性由调用方另行保证（hub fenced 路径的同 token refill 门）。
fn l1_eligibility_head_refill_checked(
    user_card_id: i64,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    epoch_before: Option<u64>,
) -> bool {
    let Some(epoch) = epoch_before else {
        return false;
    };
    let Some(gate) = gate else {
        // head 缺失（legacy 库/恢复期）：不缓存否定态，无需安装亦无条目可失效。
        return true;
    };
    l1_eligibility_head_refill(user_card_id, Some(gate), now_instant, epoch);
    match l1_card_epoch_checked(user_card_id) {
        Some(current) if current == epoch => true,
        _ => {
            if let Ok(mut guard) = l1_eligibility_head_store().write() {
                if guard
                    .get(&user_card_id)
                    .is_some_and(|entry| entry.epoch == epoch)
                {
                    guard.remove(&user_card_id);
                }
            }
            false
        }
    }
}

/// 带容量上限的 head 回填（测试隔离用；显式纪元戳记；生产走
/// [`l1_eligibility_head_refill_checked`]）。
#[cfg(test)]
fn l1_eligibility_head_refill_with_limit(
    user_card_id: i64,
    gate: Option<&EligibilityProjectionGate>,
    now_instant: Instant,
    max_entries: usize,
    epoch: u64,
) {
    let Some(gate) = gate else {
        return;
    };
    let Ok(mut guard) = l1_eligibility_head_store().write() else {
        return;
    };
    if guard.len() >= max_entries {
        guard.retain(|_, entry| {
            now_instant.duration_since(entry.cached_at) <= L1_ELIGIBILITY_HEAD_TTL
        });
        if guard.len() >= max_entries {
            guard.clear();
        }
    }
    guard.insert(
        user_card_id,
        L1EligibilityHeadEntry {
            source_generation: gate.source_generation,
            revoke_fence: gate.revoke_fence,
            ready: gate.ready,
            epoch,
            cached_at: now_instant,
        },
    );
}

fn strict_bool_or_false(raw: Option<&str>) -> bool {
    match raw {
        None => false,
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            // 未知值绝不启用（宁可少缓存，不可误开路径）。
            _ => false,
        },
    }
}

/// require=true（readiness）L1 head 参与的显式 wire 旗标 env（default-off）。
///
/// **只有 source same-tx 失效通知生命周期（Agent7 的 durable invalidation
/// intent 同事务落盘 + commit 后 dispatch + 通知消费驱动 `evict_l1_card_active_cache`）
/// 完成接线并登记后**才允许置 `true`：在此之前 L1 head 绝不回答 READY，
/// 未证明的 cache 不参与 readiness（R3 修订的启用前置，见模块文档）。
pub const ELIGIBILITY_READY_HEAD_CACHE_ENV: &str = "ASTRAL_ELIGIBILITY_READY_HEAD_CACHE";

/// 进程级冻结的 readiness wire 旗标（default-off）：`false` = require=true
/// 保持逐请求严格 head 读（探针保留）。
pub(crate) fn eligibility_ready_head_cache_wired() -> bool {
    static RESOLVED: OnceLock<bool> = OnceLock::new();
    *RESOLVED.get_or_init(|| {
        strict_bool_or_false(
            std::env::var(ELIGIBILITY_READY_HEAD_CACHE_ENV)
                .ok()
                .as_deref(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::CardActiveContext;
    use astral_types::{
        PlatformCardPairRequest, PolicyContext, PublishedCardAuthorization,
        PublishedCardEvidenceScope,
    };

    #[derive(Default)]
    struct PhysicalPositiveWithoutEvidence {
        card_checks: std::sync::atomic::AtomicUsize,
        evidence_reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl policy_engine::RuleRepository for PhysicalPositiveWithoutEvidence {
        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            self.card_checks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }

        async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
            Ok(false)
        }

        async fn load_published_card_authorization(
            &self,
            _scope: &PublishedCardEvidenceScope,
        ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
            self.evidence_reads
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

    #[tokio::test]
    async fn default_physical_eligibility_without_current_evidence_stays_pending() {
        // The default false option means the physical ELIGIBILITY head is not a
        // readiness requirement; it never grants permission or bypasses V6 evidence.
        assert!(!CardEligibilityCheckOptions::default().require_projection_ready);
        let repo = PhysicalPositiveWithoutEvidence::default();
        let context = PolicyContext::builder()
            .user_id(Some(7))
            .card_id(Some(700))
            .tenant_id(Some(10))
            .domain_id(Some(20))
            .resource(Some("learn_subject".to_owned()))
            .action("read".to_owned())
            .build();

        let decision = policy_engine::PolicyEngine::new()
            .evaluate(&context, &repo)
            .await;

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            repo.card_checks.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "physical eligibility positive must be observed first"
        );
        assert_eq!(
            repo.evidence_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "formal authorization must still request CURRENT V6 evidence"
        );
    }

    fn gate(source_generation: i64, revoke_fence: i64) -> EligibilityProjectionGate {
        EligibilityProjectionGate {
            ready: source_generation > 0,
            source_generation,
            revoke_fence,
        }
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
        // 与 hub 侧测试共享同一把 cfg(test) 全局状态锁（pub(crate) 发布）。
        let _shared = super::test_global_state_lock();
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
        // per-card 失效纪元与 L1 head 条目同属本测试组的进程级状态，一并清空，
        // 保证每个用例从同一基线开始（纪元归零 = 未失效）。
        l1_card_epoch_store().write().unwrap().clear();
        l1_eligibility_head_store().write().unwrap().clear();
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
        l1_card_active_insert_with_gate(&context, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        // L1 命中 → Some(true)（仅测试候选命中；生产命中仍执行 DB head 双读）。
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );
        let cached_epoch = l1_card_epoch_checked(context.user_card_id);
        assert_eq!(
            l1_card_active_snapshot(&context, cached_epoch, Instant::now(), 1_000,),
            Some(EligibilityFence {
                source_generation: 5,
                revoke_fence: 2,
            })
        );
        let cached = l1_card_active_snapshot(
            &context,
            l1_card_epoch_checked(context.user_card_id),
            Instant::now(),
            1_000,
        )
        .expect("candidate remains physically fresh");
        assert!(!eligibility_fence_matches(cached, Some(&gate(6, 2))));
        assert!(!eligibility_fence_matches(cached, Some(&gate(5, 3))));
        assert!(eligibility_fence_matches(cached, Some(&gate(5, 2))));
    }

    #[test]
    fn l1_misses_when_never_cached_or_evicted() {
        let _guard = l1_test_guard();
        l1_reset_store();
        // 未缓存 → None → 调用方走原协议（fail-closed 保持）。
        assert_eq!(
            l1_card_active_lookup(&l1_test_key(2), None, Instant::now(), 1_000),
            None
        );
        let context = l1_test_key(2);
        l1_card_active_insert(&context, None, Instant::now(), 1_000);
        evict_l1_card_active_cache(context.user_card_id);
        // 同进程状态变更 evict 后 → 立即 miss（原协议重验）。
        assert_eq!(
            l1_card_active_lookup(&context, None, Instant::now(), 1_000),
            None
        );
    }

    #[test]
    fn l1_entry_expires_after_five_second_ttl() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(3);
        // 直接插入带过期时刻的条目：cached_at 回拨 6s > TTL 5s → miss。
        // （身份戳记取当前动态值；本用例只考察 TTL 栅栏。）
        l1_card_active_insert_with_fence_epoch(
            &context,
            None,
            EligibilityFence {
                source_generation: 5,
                revoke_fence: 2,
            },
            backdated_instant(6),
            1_000,
            L1_CARD_ACTIVE_MAX_ENTRIES,
            l1_card_epoch_checked(context.user_card_id).unwrap_or(0),
        );
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            None
        );
        // TTL 内（4s 前）仍命中。
        l1_card_active_insert_with_fence_epoch(
            &context,
            None,
            EligibilityFence {
                source_generation: 5,
                revoke_fence: 2,
            },
            backdated_instant(4),
            1_000,
            L1_CARD_ACTIVE_MAX_ENTRIES,
            l1_card_epoch_checked(context.user_card_id).unwrap_or(0),
        );
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
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
        l1_card_active_insert_with_gate(
            &context,
            Some(now_unix - 1),
            Some(&gate(5, 2)),
            Instant::now(),
            now_unix,
        );
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), now_unix),
            None
        );
        // 未到期 → 命中。

        l1_card_active_insert_with_gate(
            &context,
            Some(now_unix + 100),
            Some(&gate(5, 2)),
            Instant::now(),
            now_unix,
        );
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), now_unix),
            Some(true)
        );
        // 自然到期未知（两张实体卡都无截止）→ 仅受 5s TTL 约束。
        l1_card_active_insert_with_gate(
            &context,
            None,
            Some(&gate(5, 2)),
            Instant::now(),
            now_unix,
        );
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), now_unix),
            Some(true)
        );
    }

    #[test]
    fn eligibility_gate_stability_rejects_generation_and_revoke_advances() {
        let previous = gate(5, 2);
        assert!(strict_eligibility_fence_matches(
            EligibilityFence::from(&previous),
            Some(&previous),
            Some(&previous),
        ));
        assert!(!strict_eligibility_fence_matches(
            EligibilityFence::from(&previous),
            Some(&previous),
            Some(&gate(6, 2)),
        ));
        assert!(!strict_eligibility_fence_matches(
            EligibilityFence::from(&previous),
            Some(&previous),
            Some(&gate(5, 3)),
        ));
    }

    #[test]
    fn eligibility_gate_stability_rejects_one_missing_head() {
        assert!(strict_eligibility_fence_matches(
            EligibilityFence {
                source_generation: 0,
                revoke_fence: 0,
            },
            None,
            None,
        ));
        assert!(!strict_eligibility_fence_matches(
            EligibilityFence {
                source_generation: 0,
                revoke_fence: 0,
            },
            Some(&gate(5, 2)),
            None,
        ));
        assert!(!eligibility_fence_matches(
            EligibilityFence {
                source_generation: 0,
                revoke_fence: 0,
            },
            Some(&EligibilityProjectionGate {
                ready: false,
                source_generation: 0,
                revoke_fence: 0,
            }),
        ));
    }

    #[test]
    fn l1_rejects_any_context_field_mismatch() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(5);
        l1_card_active_insert_with_gate(&context, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        let mut fields = [
            |ctx: &mut CardActiveContext| ctx.user_id = 9_100_001,
            |ctx: &mut CardActiveContext| ctx.identity_card_id = 9_200_001,
            |ctx: &mut CardActiveContext| ctx.user_card_tenant_id = 9_400_001,
            |ctx: &mut CardActiveContext| ctx.user_card_domain_id = 9_500_001,
        ];
        for mutate in &mut fields {
            let mut mismatched = context;
            mutate(&mut mismatched);
            // 上下文任一字段不一致 → miss（与 进程内 L1 matches_context 同语义，
            // 防止同一张卡被套用到其他用户/身份卡/租户域）。
            assert_eq!(
                l1_card_active_lookup(&mismatched, Some(&gate(5, 2)), Instant::now(), 1_000),
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
        l1_card_active_insert_with_gate(&first, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        l1_card_active_insert_with_gate(&second, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        evict_l1_card_active_cache(first.user_card_id);
        assert_eq!(
            l1_card_active_lookup(&first, Some(&gate(5, 2)), Instant::now(), 1_000),
            None
        );
        assert_eq!(
            l1_card_active_lookup(&second, Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );
    }

    #[test]
    fn l1_insert_is_capacity_bounded() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let max_entries = 3;
        for ordinal in 0..4 {
            let key = l1_test_key(10 + ordinal);
            let epoch = l1_card_epoch_checked(key.user_card_id).unwrap_or(0);
            l1_card_active_insert_with_fence_epoch(
                &key,
                None,
                EligibilityFence {
                    source_generation: 5,
                    revoke_fence: 2,
                },
                Instant::now(),
                1_000,
                max_entries,
                epoch,
            );
            assert!(
                l1_entry_count() <= max_entries,
                "L1 store must stay capacity-bounded, got {} entries",
                l1_entry_count()
            );
        }
        // 容量淘汰后最近插入的条目仍在（有界且可用）。
        assert_eq!(
            l1_card_active_lookup(&l1_test_key(13), Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );
    }

    // ================= per-card 失效纪元（epoch）测试 =================

    #[test]
    fn evict_bumps_the_per_card_epoch_and_stale_epoch_entries_miss() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(20);
        let before = l1_card_epoch_checked(context.user_card_id).expect("healthy epoch lock");
        l1_card_active_insert_with_gate(&context, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        assert_eq!(l1_card_epoch_checked(context.user_card_id), Some(before));
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );

        evict_l1_card_active_cache(context.user_card_id);
        // evict 推进身份：失效事件在进程内可观测（全局单调 token 严格递增）。
        let after = l1_card_epoch_checked(context.user_card_id).expect("healthy epoch lock");
        assert!(
            after > before,
            "evict must assign a fresh monotonic identity (got {before} -> {after})"
        );

        // 竞争窗口模拟：evict 之后才落入 store 的旧纪元条目（epoch=0）必须
        // miss（fail-closed，绝不因迟到插入复活旧授权事实）。
        l1_card_active_insert_with_fence_epoch(
            &context,
            None,
            EligibilityFence {
                source_generation: 5,
                revoke_fence: 2,
            },
            Instant::now(),
            1_000,
            L1_CARD_ACTIVE_MAX_ENTRIES,
            0,
        );
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            None
        );

        // 新纪元 refill（以当前纪元戳记）恢复命中。
        l1_card_active_insert_with_gate(&context, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );
    }

    #[test]
    fn per_card_epochs_are_isolated_across_cards() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let first = l1_test_key(21);
        let second = l1_test_key(22);
        l1_card_active_insert_with_gate(&first, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        l1_card_active_insert_with_gate(&second, None, Some(&gate(5, 2)), Instant::now(), 1_000);
        // 只失效 first：second 的纪元与命中不受影响（租户/卡隔离）。
        evict_l1_card_active_cache(first.user_card_id);
        // 只失效 first：first 拿到全新身份，second 保持原身份（卡间隔离）。
        let first_after = l1_card_epoch_checked(first.user_card_id).expect("healthy epoch lock");
        let second_after = l1_card_epoch_checked(second.user_card_id).expect("healthy epoch lock");
        assert!(first_after > second_after);
        assert_eq!(
            l1_card_active_lookup(&second, Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );
    }

    // ================= L1 ELIGIBILITY head 缓存（R3 接缝）测试 =================

    fn head_gate() -> EligibilityProjectionGate {
        gate(5, 2)
    }

    fn head_refill(card_id: i64, gate: &EligibilityProjectionGate) {
        l1_eligibility_head_refill(
            card_id,
            Some(gate),
            Instant::now(),
            l1_card_epoch_checked(card_id).unwrap_or(0),
        );
    }

    #[test]
    fn l1_head_refill_then_lookup_serves_the_strict_snapshot() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let card_id = l1_test_key(30).user_card_id;
        head_refill(card_id, &head_gate());
        let served = l1_eligibility_head_lookup(card_id, Instant::now()).expect("fresh head hit");
        assert_eq!(served.source_generation, 5);
        assert_eq!(served.revoke_fence, 2);
        assert!(served.ready);
    }

    #[test]
    fn l1_head_misses_for_unknown_cards_and_other_cards() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let card_id = l1_test_key(31).user_card_id;
        // 未填充 → miss（回严格 reader）。
        assert!(l1_eligibility_head_lookup(card_id, Instant::now()).is_none());
        // 卡隔离：别的卡的 head 绝不服务本卡（键控隔离）。
        let other = l1_test_key(32).user_card_id;
        head_refill(other, &head_gate());
        assert!(l1_eligibility_head_lookup(card_id, Instant::now()).is_none());
    }

    #[test]
    fn l1_head_is_invalidated_by_the_invalidation_event() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(33);
        head_refill(context.user_card_id, &head_gate());
        assert!(l1_eligibility_head_lookup(context.user_card_id, Instant::now()).is_some());
        // 失效事件（evict_l1_card_active_cache）删除 head 条目并推进纪元 →
        // 下一次读回严格 reader（fail-closed），绝不放行旧资格头。
        evict_l1_card_active_cache(context.user_card_id);
        assert!(l1_eligibility_head_lookup(context.user_card_id, Instant::now()).is_none());
        // 竞争窗口：旧纪元的 head 条目同样 miss（epoch 栅栏）。
        let Ok(mut guard) = l1_eligibility_head_store().write() else {
            panic!("head store lock");
        };
        guard.insert(
            context.user_card_id,
            L1EligibilityHeadEntry {
                source_generation: 5,
                revoke_fence: 2,
                ready: true,
                epoch: 0,
                cached_at: Instant::now(),
            },
        );
        drop(guard);
        assert!(l1_eligibility_head_lookup(context.user_card_id, Instant::now()).is_none());
    }

    #[test]
    fn l1_head_expires_after_its_ttl() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let card_id = l1_test_key(34).user_card_id;
        // 直接插入回拨 6s 的条目（> TTL 5s）→ miss；4s 前仍命中。
        let Ok(mut guard) = l1_eligibility_head_store().write() else {
            panic!("head store lock");
        };
        guard.insert(
            card_id,
            L1EligibilityHeadEntry {
                source_generation: 5,
                revoke_fence: 2,
                ready: true,
                epoch: l1_card_epoch_checked(card_id).unwrap_or(0),
                cached_at: backdated_instant(6),
            },
        );
        drop(guard);
        assert!(l1_eligibility_head_lookup(card_id, Instant::now()).is_none());
        let Ok(mut guard) = l1_eligibility_head_store().write() else {
            panic!("head store lock");
        };
        guard.get_mut(&card_id).unwrap().cached_at = backdated_instant(4);
        drop(guard);
        assert!(l1_eligibility_head_lookup(card_id, Instant::now()).is_some());
    }

    #[test]
    fn l1_head_refill_skips_missing_gate_and_is_capacity_bounded() {
        let _guard = l1_test_guard();
        l1_reset_store();
        // head 缺失（legacy/恢复期）不缓存否定态。
        l1_eligibility_head_refill(l1_test_key(35).user_card_id, None, Instant::now(), 0);
        assert!(l1_eligibility_head_store().read().unwrap().is_empty());

        let max_entries = 3;
        let now = Instant::now();
        for ordinal in 0..5 {
            let card_id = l1_test_key(40 + ordinal).user_card_id;
            l1_eligibility_head_refill_with_limit(
                card_id,
                Some(&head_gate()),
                now,
                max_entries,
                l1_card_epoch_checked(card_id).unwrap_or(0),
            );
            assert!(l1_eligibility_head_store().read().unwrap().len() <= max_entries);
        }
    }

    // ============ eligibility-read-fence-20261002：读取前纪元 + 安装后复核 ============

    #[test]
    fn latefill_install_race_is_removed_by_post_install_check() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(7);
        // 正常安装（读取前捕获当前身份，安装后未推进）→ 存活且命中。
        let captured = l1_card_epoch_checked(context.user_card_id).expect("healthy epoch lock");
        assert!(l1_card_active_install_checked_with(
            &context,
            None,
            Some(&gate(5, 2)),
            Instant::now(),
            1_000,
            Some(captured),
            || {}
        ));
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            Some(true)
        );
        evict_l1_card_active_cache(context.user_card_id);
        // 注入竞争（between seam）：安装完成与安装后复核之间发生 evict（身份
        // 推进）→ 刚安装的条目承载变更前事实，必须被撤销（绝不"装成新"）。
        assert!(!l1_card_active_install_checked_with(
            &context,
            None,
            Some(&gate(5, 2)),
            Instant::now(),
            1_001,
            Some(captured),
            || {
                bump_l1_card_epoch(context.user_card_id);
            }
        ));
        assert_eq!(
            l1_card_active_lookup(&context, None, Instant::now(), 1_001),
            None
        );
    }

    #[test]
    fn install_skips_entirely_when_epoch_is_unreadable() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(8);
        // 纪元不可读（None，锁中毒语义）→ 不安装（安全 miss，绝不 0 同值放行）。
        assert!(!l1_card_active_install_checked_with(
            &context,
            None,
            None,
            Instant::now(),
            1_000,
            None,
            || {}
        ));
        assert_eq!(
            l1_card_active_lookup(&context, None, Instant::now(), 1_000),
            None
        );
    }

    #[test]
    fn head_refill_with_stale_epoch_is_removed_by_post_install_check() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(9);
        // 正常回填（读取前捕获当前身份）→ 命中。
        let captured = l1_card_epoch_checked(context.user_card_id).expect("healthy epoch lock");
        assert!(l1_eligibility_head_refill_checked(
            context.user_card_id,
            Some(&gate(5, 2)),
            Instant::now(),
            Some(captured)
        ));
        assert!(l1_eligibility_head_lookup(context.user_card_id, Instant::now()).is_some());
        // evict 推进身份；随后以"读取前身份 = captured"（变更前捕获）回填 →
        // 安装后复核发现身份已推进 → 撤销安装（绝不把变更前 head 装成新）。
        evict_l1_card_active_cache(context.user_card_id);
        assert!(!l1_eligibility_head_refill_checked(
            context.user_card_id,
            Some(&gate(5, 2)),
            Instant::now(),
            Some(captured)
        ));
        assert!(l1_eligibility_head_lookup(context.user_card_id, Instant::now()).is_none());
    }

    /// 测试 seam：直达 GC 语义（floor 推进到已分配最大身份 + 清空映射），
    /// 免构造 65k 条目；语义与 [`bump_l1_card_epoch`] 的 GC 分支一致。
    #[cfg(test)]
    fn l1_card_epoch_gc_for_test(new_floor: u64) {
        L1_CARD_EPOCH_FLOOR.fetch_max(new_floor, Ordering::Relaxed);
        if let Ok(mut guard) = l1_card_epoch_store().write() {
            guard.clear();
        }
    }

    #[test]
    fn gc_must_not_reuse_identity_for_delayed_install_aba() {
        let _guard = l1_test_guard();
        l1_reset_store();
        let context = l1_test_key(11);
        // old captured：变更前 DB 结果携带的读取前身份。
        let captured = l1_card_epoch_checked(context.user_card_id).expect("healthy epoch lock");
        // target evict：该卡分配全新身份。
        bump_l1_card_epoch(context.user_card_id);
        let evicted = l1_card_epoch_checked(context.user_card_id).expect("healthy epoch lock");
        assert!(evicted > captured);
        // map GC：floor 推进到已分配最大身份 + 清空映射（缺失读取取 floor）。
        l1_card_epoch_gc_for_test(evicted);
        // delayed install：GC 之后才落地的旧 captured 结果 —— floor > captured，
        // 安装后复核必然失败，旧事实不可回生（ABA 修复点）。
        assert!(!l1_card_active_install_checked_with(
            &context,
            None,
            Some(&gate(5, 2)),
            Instant::now(),
            1_000,
            Some(captured),
            || {}
        ));
        assert_eq!(
            l1_card_active_lookup(&context, Some(&gate(5, 2)), Instant::now(), 1_000),
            None
        );
        // 连续 false：重试延迟安装同样拒绝（身份不因重试而复用）。
        assert!(!l1_card_active_install_checked_with(
            &context,
            None,
            Some(&gate(5, 2)),
            Instant::now(),
            1_001,
            Some(captured),
            || {}
        ));
        assert_eq!(
            l1_card_active_lookup(&context, None, Instant::now(), 1_001),
            None
        );
    }

    #[test]
    fn fence_classifier_maps_hub_gate_fail_closed() {
        // 本测试的 hub writer begin/drop 会触发全局
        // `invalidate_positive_read_caches`（清空 L1 存储）——与其他触碰 L1
        // 全局状态的测试经 l1_test_guard 串行化，避免并行竞争。
        let _guard = l1_test_guard();
        // WriterActive / Uncertain → 直接 PolicyError（Reject）。
        assert!(matches!(
            l1_read_fence_action(Some(AuxiliaryReadGate::WriterActive)),
            L1ReadFenceAction::Reject(_)
        ));
        assert!(matches!(
            l1_read_fence_action(Some(AuxiliaryReadGate::Uncertain)),
            L1ReadFenceAction::Reject(_)
        ));
        // StrictRequired → 绕过正缓存严格直读 + 返回前 source token 终验。
        assert!(matches!(
            l1_read_fence_action(Some(AuxiliaryReadGate::StrictRequired)),
            L1ReadFenceAction::StrictVerified
        ));
        // Ready → 同 token fetch/refill/install/final。用真实 hub 生命周期验证
        // （AuxiliaryReadToken 含私有字段，不可字面构造）：warming（未心跳）→
        // StrictRequired；心跳后 → Ready。
        let hub = MemoryProjectionHub::default();
        assert!(matches!(
            l1_read_fence_action(Some(hub.auxiliary_read_gate())),
            L1ReadFenceAction::StrictVerified
        ));
        hub.record_channel_heartbeat();
        assert!(matches!(
            l1_read_fence_action(Some(hub.auxiliary_read_gate())),
            L1ReadFenceAction::TokenFenced
        ));
        let captured = hub.strict_read_token().expect("capture original token");
        assert!(l1_hub_read_token_matches(&hub, captured));
        hub.apply_auxiliary_invalidation()
            .expect("invalidation advances the hub token");
        assert!(
            !l1_hub_read_token_matches(&hub, captured),
            "the request-start token must not be replaced after a source mutation"
        );
        // source writer 活跃 → Reject（直接 PolicyError 处置）。
        let guard = hub
            .begin_org_source_transaction()
            .expect("first writer must acquire");
        assert!(matches!(
            l1_read_fence_action(Some(hub.auxiliary_read_gate())),
            L1ReadFenceAction::Reject(_)
        ));
        drop(guard);
        // hub 未安装 → 既有 5s scope（latefill 修复后）。
        assert!(matches!(
            l1_read_fence_action(None),
            L1ReadFenceAction::StandalonePhysical
        ));
    }

    #[test]
    fn epoch_gc_bound_is_threshold_exclusive() {
        assert!(!l1_card_epoch_gc_needed(0, L1_CARD_EPOCH_MAX_ENTRIES));
        assert!(l1_card_epoch_gc_needed(
            L1_CARD_EPOCH_MAX_ENTRIES + 1,
            L1_CARD_EPOCH_MAX_ENTRIES
        ));
    }

    // ================= 健康门（suspect/unknown fail-closed）测试 =================

    #[test]
    fn l1_head_cache_is_fail_closed_without_a_healthy_channel() {
        // hub 缺失（健康监控缺少/unknown）→ strict：L1 head 绝不参与。
        assert!(!l1_eligibility_head_cache_permitted(None));

        // hub 在场且健康（monitored + fresh heartbeat + 非 warming）→ 参与。
        let healthy = MemoryProjectionHub::default();
        healthy.record_channel_heartbeat();
        assert!(healthy.channel_is_healthy());
        assert!(l1_eligibility_head_cache_permitted(Some(&healthy)));

        // sticky suspect（心跳无法清除）→ strict 回退现行逐请求协议。
        let suspect = MemoryProjectionHub::default();
        suspect.record_channel_heartbeat();
        suspect.mark_channel_suspect("channel lost");
        suspect.record_channel_heartbeat();
        assert!(suspect.channel_is_suspect());
        assert!(!suspect.channel_is_healthy());
        assert!(!l1_eligibility_head_cache_permitted(Some(&suspect)));

        // Unmonitored（hub 在场但 supervisor 尚未心跳）→ strict：绝不 warm
        // 资格缓存——`channel_is_healthy()` 要求显式 Healthy + fresh heartbeat
        // + 非 warming，Unmonitored/未知健康一律不参与。
        let silent = MemoryProjectionHub::default();
        assert!(!silent.channel_is_healthy());
        assert!(!l1_eligibility_head_cache_permitted(Some(&silent)));
    }

    #[test]
    fn readiness_head_cache_requires_health_and_the_explicit_wire_flag() {
        // 组合判定（纯函数）：require=false 健康即可；require=true 必须
        // 健康 **且** wire 显式开启（source same-tx 通知接线后）；
        // 任何一门不满足 → strict 逐请求 head 读。
        assert!(l1_head_serves(true, false, false));
        assert!(l1_head_serves(true, false, true));
        assert!(l1_head_serves(true, true, true));
        assert!(
            !l1_head_serves(true, true, false),
            "wire off → readiness 保持严格逐请求 head 读"
        );
        assert!(!l1_head_serves(false, false, false));
        assert!(
            !l1_head_serves(false, true, true),
            "通道非健康 → 即使 wire on 也不参与"
        );
        assert!(!l1_head_serves(false, false, true));
    }

    #[test]
    fn ready_head_wire_flag_resolver_is_strict_and_default_off() {
        // default-off：缺失/非法一律关闭（未证明的 cache 绝不启用 readiness）。
        assert!(!strict_bool_or_false(None));
        assert!(!strict_bool_or_false(Some("")));
        assert!(!strict_bool_or_false(Some("1")));
        assert!(!strict_bool_or_false(Some("yes")));
        assert!(strict_bool_or_false(Some("true")));
        assert!(strict_bool_or_false(Some("TRUE")));
        assert!(strict_bool_or_false(Some(" true ")));
        assert!(!strict_bool_or_false(Some("false")));
        // 测试进程未设置 env → 进程级旗标保持 off。
        assert!(
            !eligibility_ready_head_cache_wired(),
            "wire flag must stay default-off unless explicitly opted in"
        );
    }
}
