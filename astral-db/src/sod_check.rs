//! SoD 冲突检查（供权限中间件集成）
//!
//! 宿主请求路径在权限检查通过后调用，防止持有互斥权限的卡访问敏感资源；
//! 原生授权写入另走 grant-time 校验，在写入前拒绝互斥授权。
//! 对齐 Java `SodService.checkDynamicSoD()` + `SodService.checkStaticSoD()`。
//!
//! STATIC: 预定义的互斥权限对（如"审批者"+"提交者"）
//! DYNAMIC: 运行时条件脚本求值（如 resourceOwnerId == currentUserId）
//!
//! ## 读路径门禁（fail-closed）
//!
//! 所有 SoD 权限比对必须先取得可读的卡级已发布授权证据（published card
//! evidence）：严格 reader 在单个短事务内按租户键控的当前指针（FOR UPDATE）
//! 锁定并整链校验卡作用域全部已发布聚合。指针缺失/非 READY（`NotReady`）、
//! 链校验失败或读取期间指针漂移（`Corrupt`，含 `pointer_moved_under_read`）、
//! scope 合同拒绝（`InvalidRequest`）、`user_card.tenant_id` 缺失或非正时，
//! 本模块返回数据库错误而不是"无冲突"结果；调用方（中间件/授权链）对 Err
//! 一律拒绝请求（503/fail-closed）。"读取后复核"语义由 reader 事务 +
//! FOR UPDATE + 指针一致性校验天然接管，本模块不读取旧快照或 raw 授权源。
//!
//! 证据读取统一经 [`crate::evidence_cache::
//! cached_load_published_card_grant_evidence`]（进程内 evidence 缓存 + 指针
//! 对牌）：命中前提是当前指针版本组 + 缓存时代与填充时刻逐项相等（命中前
//! 复读一次栅栏未漂移），miss/漂移回源严格 reader，错误族与直读完全一致；
//! 这是**经验证的读层**而非 cache 回退——校验失败一律回源报错，绝不放行。
//! 细节见 `crate::evidence_cache` 模块文档。
//!
//! ## sod_policy 进程缓存（读链规模化）
//!
//! STATIC/DYNAMIC 两类 ACTIVE 策略的全量读取经进程级缓存（TTL 30s，单条目
//! 全量快照；DYNAMIC 的 resource_type/action_code 过滤在内存执行，谓词与原
//! SQL 等价，见 [`dynamic_policy_matches_request`]）。失效方式：本进程内
//! sod_policy 写路径（trustgraph `SqlxSodRepository` 的 create/update/delete）
//! 写入成功后调用 [`evict_sod_policy_cache`]，本进程立即生效；跨实例无广播，
//! 最迟一个 TTL 窗口内感知。缓存 miss/DB 错误一律回源直查并原样上抛
//! （fail-closed 语义不变），错误结果绝不入缓存。
//!
//! ### 撤销传播窗口标注（缓存 → 撤销路径 → 兜底层）
//!
//! 本缓存只承载 sod_policy 策略列表（SoD 判定的**输入**），不承载任何授权
//! 撤销信号：卡授权的撤销/禁用走 evidence 指针双读对牌（真读 DB、零窗口），
//! 与本缓存完全无关。窗口内的方向性影响仅限策略表自身的变更传播：
//! - 新增/激活策略（收紧语义）在 stale 窗口内可能尚未参与冲突判定
//!   （**放行方向，最危险**；≤TTL 30s 上限）；
//! - 停用/删除策略（放宽语义）在 stale 窗口内仍参与判定（多拒绝，安全方向）。
//!
//! 策略写入为低频管理操作，30s 失效窗口为显式接受的取舍（策略表撤销/
//! 变更无 pointer 对牌兜底——它是独立于授权账本的输入表，evict 钩子只覆盖
//! 本进程写路径，跨实例依赖 TTL）。
//!
//! ## 复合进程（单机内存镜像）宿主读面（additive，default-off）
//!
//! 组合进程安装 `memory_projection_hub` + 辅助授权镜像后，宿主 SoD 走
//! context-aware 入口（[`check_sod_conflict_with_context`] /
//! [`load_org_sod_admission_mirrored`]），warm 态（镜像已预热、hub 健康、
//! 无活跃 source writer、策略快照 token 绑定未变）实现**零 DB**：
//! - 卡级 published evidence：`hub.try_memory_evidence`（与 durable 同源的
//!   纯装配函数 + 读前/读后 token 对牌）；scope 只用服务端 ctx（tenant 由
//!   PolicyEngine 已鉴权，card-tenant 绑定由 hub durable card index 命中
//!   再证明；miss 一律回退既有 durable 链，绝不放大读面）；
//! - org 准入证据：复用辅助镜像 `load_org_authorization`（与引擎 evaluate
//!   同一 strict read contract / single-flight / 纪元栅栏），`Ready` 证据
//!   进入与 fresh DB 读完全相同的 provenance 对牌解析器；
//! - sod_policy 快照：进程缓存条目绑定 hub 严格读 token（单一写者下精确
//!   失效——任何 source mutation 推进 token，下一次读取即回填），warm 态
//!   零 DB；writer-active/unknown 一律 fail-closed，绝不以并发/未知 source
//!   状态放行；非 composite 保留既有 TTL 30s 语义不变。
//!
//! ### published-evidence 合同
//!
//! 宿主 SoD 路径（[`check_sod_conflict_with_context`] /
//! [`check_sod_conflict_with_context_and_org`]，cold durable 回退与 warm 记忆路径**同一
//! 合同**）及原生授权写入路径 [`check_grant_sod_conflict`] 只把经过严格校验的
//! 已发布 `effective_grants` 视为持有授权。未发布 source rows 不参与 SoD；所有
//! 路径共用同一 native conflict evaluator，不提供 raw-source 诊断或授权回退。
//!
//! 策略快照回填（各模式共用）全部有界：`LIMIT cap+1` 探针（超限
//! fail-closed）、快照字节预算、3s 查询 deadline、进程级 single-flight
//! 有界锁等待；composite 回填前后经 hub 严格 token 对牌（读前取 token、
//! 读后复核，竞争即报错，绝不缓存竞争产物）。
//!
//! ### 冷启动首轮安全 Pending（可重试）
//!
//! 镜像 warm 回填/发布安装会推进 hub mutation token：安装后**首个**请求的
//! 策略缓存必然 miss → 走有界回填（或回填窗口内 fail-closed）。这是一次
//! **安全 Pending**，不是故障：客户端重试即可——重试请求会以安装后的 token
//! 重新捕获基线并以安装后事实重新评估授权；已放弃的首轮请求绝不以安装前
//! 事实放行（栅栏复核比较的是 evaluate 前捕获的旧 token，**不存在任何
//! "末尾重采样 token 覆盖旧读"的路径**），也不折算成放行。

use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use astral_types::org_scope::{
    org_action_matches, org_contribution_matches_request, org_decode_segment_content,
    org_resource_matches, OrgAdmissionEvidence, OrgAdmissionResult, OrgBranchKind,
    OrgBranchProvenance, OrgContribution, OrgReadRequest, OrgSubjectFilter,
};
use astral_types::{
    build_resource_key, DomainScopeRequirement, PolicyContext, PolicyDecision,
    PublishedCardAuthorization, PublishedCardEvidenceScope, ResourceOwnershipScope,
};
use policy_engine::org_admission::OrgAuthorityRead;
use sqlx::MySqlPool;

use crate::authorization_projection_repository::AuthorizationEvidenceError;
use crate::auxiliary_authorization_mirror::auxiliary_authorization_mirror;
use crate::evidence_cache::cached_load_published_card_grant_evidence;
use crate::memory_projection_hub::{
    memory_projection_hub, AuxiliaryReadToken, MemoryEvidenceOutcome,
};
use crate::org_scope_repository::{OrgAdmissionQuery, OrgScopeRepository, SqlxOrgScopeRepository};

/// Result from a deny-only SoD conflict check.
#[derive(Debug)]
pub struct SodCheckResult {
    pub has_conflict: bool,
    pub conflict_policy: Option<String>,
    pub conflict_permission: Option<String>,
    pub conflict_type: Option<String>, // "STATIC" | "DYNAMIC"
}

/// Complete, locked source before-image for a direct-rule UPDATE SoD check.
///
/// The repository constructs this only from the `permission_rule` + `user_card`
/// rows read `FOR UPDATE`. The transaction-level gate re-locks the card, checks
/// both tenant columns plus user/domain, then proves that exactly one published
/// record has this stable DIRECT identity and the same authorization content.
/// Rule tenant is compared to the separately locked card tenant as well as the
/// card's fresh transaction lock; domain is reconciled against the source card.
/// CREATE must pass `None`; callers cannot select an arbitrary grant id to omit.
#[derive(Debug, Clone, Copy)]
pub struct DirectGrantSodUpdateBeforeImage<'a> {
    pub rule_tenant_id: Option<i64>,
    pub source_card_tenant_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub card_id: i64,
    pub user_id: i64,
    pub rule_id: i64,
    pub source_type: &'a str,
    pub enabled: Option<i32>,
    pub effect: &'a str,
    pub resource_type: &'a str,
    pub resource_id: Option<i64>,
    pub action_code: &'a str,
    pub condition_json: Option<&'a str>,
    pub valid_from: Option<&'a str>,
    pub valid_to: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, sqlx::FromRow)]
struct LockedSodCardScope {
    card_id: i64,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    user_id: Option<i64>,
}

/// Validate that the source-row tenant and card tenant agree with the current
/// locked card before any pending/evidence reads or source mutation proceed.
fn validate_direct_update_scope(
    before: &DirectGrantSodUpdateBeforeImage<'_>,
    locked_card: LockedSodCardScope,
    requested_card_id: i64,
) -> Result<i64, &'static str> {
    if requested_card_id <= 0
        || before.card_id != requested_card_id
        || locked_card.card_id != requested_card_id
    {
        return Err("sod_grant_update_card_scope_mismatch");
    }
    let Some(rule_tenant_id) = before.rule_tenant_id.filter(|tenant| *tenant > 0) else {
        return Err("sod_grant_update_rule_tenant_missing");
    };
    let Some(source_card_tenant_id) = before.source_card_tenant_id.filter(|tenant| *tenant > 0)
    else {
        return Err("sod_grant_update_source_card_tenant_missing");
    };
    let Some(locked_tenant_id) = locked_card.tenant_id.filter(|tenant| *tenant > 0) else {
        return Err("sod_grant_update_locked_card_tenant_missing");
    };
    if rule_tenant_id != source_card_tenant_id || source_card_tenant_id != locked_tenant_id {
        return Err("sod_grant_update_tenant_scope_mismatch");
    }
    if before.domain_id.is_some_and(|domain_id| domain_id <= 0)
        || before.domain_id != locked_card.domain_id
    {
        return Err("sod_grant_update_domain_scope_mismatch");
    }
    if before.user_id <= 0 || locked_card.user_id != Some(before.user_id) {
        return Err("sod_grant_update_user_scope_mismatch");
    }
    if before.rule_id <= 0 || before.source_type != "MANUAL" || before.enabled.unwrap_or(1) != 1 {
        return Err("sod_grant_update_source_identity_unusable");
    }
    Ok(locked_tenant_id)
}

/// Prove the unique published before-image for an update. The result is only the
/// stable identity to omit from STATIC conflict matching; every other grant and
/// all DYNAMIC checks remain unchanged.
fn prove_direct_update_self_exclusion(
    evidence: &PublishedCardAuthorization,
    before: &DirectGrantSodUpdateBeforeImage<'_>,
    locked_card: LockedSodCardScope,
    requested_card_id: i64,
) -> Result<astral_types::GrantId, &'static str> {
    let tenant_id = validate_direct_update_scope(before, locked_card, requested_card_id)?;
    if !before.effect.trim().eq_ignore_ascii_case("ALLOW")
        || before.resource_type.trim().is_empty()
        || before.action_code.trim().is_empty()
    {
        return Err("sod_grant_update_before_image_unrepresentable");
    }
    crate::grant_ledger::reject_unrepresentable_condition(
        before.condition_json,
        "direct rule update SoD before-image",
    )
    .map_err(|_| "sod_grant_update_before_image_unrepresentable")?;

    let facts = crate::grant_ledger::DirectRuleLedgerFacts {
        tenant_id: Some(tenant_id),
        domain_id: before.domain_id,
        card_id: before.card_id,
        user_id: before.user_id,
        rule_id: before.rule_id,
        resource: before.resource_type,
        resource_id: before.resource_id,
        action: before.action_code,
        condition_json: before.condition_json,
        valid_from: before.valid_from,
        valid_to: before.valid_to,
    };
    let grant_id = crate::grant_ledger::derive_direct_identity(&facts)
        .map_err(|_| "sod_grant_update_identity_invalid")?;
    let expected_resource =
        crate::grant_ledger::canonical_resource_key(before.resource_type, before.resource_id)
            .map_err(|_| "sod_grant_update_before_image_unrepresentable")?;
    let expected_validity =
        crate::grant_ledger::parse_validity_window(before.valid_from, before.valid_to)
            .map_err(|_| "sod_grant_update_before_image_unrepresentable")?;
    let expected_tenant = astral_types::TenantScope::new(tenant_id, before.domain_id)
        .map_err(|_| "sod_grant_update_before_image_scope_invalid")?;
    let card_identity = before.card_id.to_string();
    let rule_identity = before.rule_id.to_string();

    if evidence.tenant_id != tenant_id || evidence.card_id != before.card_id {
        return Err("sod_grant_update_evidence_scope_mismatch");
    }
    // Include the derived id and the source-entry locator in the candidate set:
    // a corrupt/mis-provenanced duplicate is ambiguity, never an excuse to skip it.
    let candidates: Vec<_> = evidence
        .records
        .iter()
        .filter(|record| {
            record.grant.grant_id == grant_id
                || (record.aggregate_id == before.card_id
                    && record.grant.provenance.source_entry.as_deref()
                        == Some(rule_identity.as_str()))
        })
        .collect();
    if candidates.len() != 1 {
        return Err("sod_grant_update_published_identity_missing_or_ambiguous");
    }
    let record = candidates[0];
    let grant = &record.grant;
    let exact_before_image = record.aggregate_type == crate::grant_ledger::DIRECT_AGGREGATE_TYPE
        && record.aggregate_id == before.card_id
        && grant.grant_id == grant_id
        && grant.state == astral_types::GrantState::Active
        && grant.source_kind == astral_types::GrantSourceKind::Direct
        && grant.binding_layer == astral_types::BindingLayer::None
        && grant.tenant == expected_tenant
        && grant.card_id == before.card_id
        && grant.user_id == before.user_id
        && grant.resource == expected_resource
        && grant.action == before.action_code.trim()
        && grant.effect == astral_types::GrantEffect::Allow
        && grant.validity == expected_validity
        && grant.provenance.source_id == card_identity
        && grant.provenance.source_entry.as_deref() == Some(rule_identity.as_str())
        && grant.provenance.binding_id.is_none()
        && grant.provenance.delegation_id.is_none()
        && grant.provenance.operation_id == record.operation_id
        && grant.provenance.event_id.as_deref() == Some(record.event_id.as_str());
    if !exact_before_image {
        return Err("sod_grant_update_published_before_image_mismatch");
    }
    if evidence
        .effective_grants
        .iter()
        .filter(|grant| grant.grant_id == grant_id)
        .count()
        > 1
    {
        return Err("sod_grant_update_effective_identity_ambiguous");
    }
    Ok(grant_id)
}

/// 解析 scoped resource key 为 plain resource type：`type:*` 与 `type:id` 均返回
/// `type`，plain key 原样返回。
///
/// 语义对齐 `permission_query::parse_resource_type`（Java `parseResourceKey`）：
/// 按**最后一个**冒号截断。SoD 策略里的权限对（如 `approval:submit`）使用
/// plain type + action 形状；已发布 evidence 的 `grant.resource` 是 scoped key
/// （`type:*` / `type:id`），必须先归一为 plain type 再比较——旧实现把 partner
/// 的 plain type 直接绑定到快照 scoped key 比较，形状错位导致 STATIC 冲突
/// 永不命中（漏报），本函数是切换后的修复点。
pub fn sod_resource_type_from_scoped_key(resource_key: &str) -> String {
    match resource_key.rfind(':') {
        Some(idx) => resource_key[..idx].to_string(),
        None => resource_key.to_string(),
    }
}

/// 判定一条已生效 grant 是否命中 SoD 互斥伙伴权限（pure，无 I/O）。
///
/// grant 侧 resource 是 scoped key，先经 [`sod_resource_type_from_scoped_key`]
/// 归一为 plain type 再与伙伴 plain type 精确比较；action 精确比较。
/// STATIC 冲突 evaluator 与 `sod_repository::card_has_permission` 共用本函数，
/// 保证两条读路径的归一化语义一致。
pub fn sod_partner_matches_grant(
    grant_resource: &str,
    grant_action: &str,
    partner_type: &str,
    partner_action: &str,
) -> bool {
    sod_resource_type_from_scoped_key(grant_resource) == partner_type
        && grant_action == partner_action
}

/// 解析 SoD 读路径 evidence scope 的租户定位输入（`user_card.tenant_id`）。
///
/// 对齐 `permission_query::load_card_tenants` 的定位语义：tenant 只用于定位
/// 租户键控的当前指针行，不是授权事实；reader 内部会复核指针租户戳与 scope
/// 一致，陈旧租户只会 fail closed（`Corrupt`），不可能放行其它租户的数据。
/// 行缺失或 tenant 空/非正 → fail-closed 报错（稳定前缀
/// `sod_card_tenant_missing;`），绝不折算成"无冲突"放行。
pub async fn sod_load_card_tenant(pool: &MySqlPool, card_id: i64) -> Result<i64, sqlx::Error> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT tenant_id FROM user_card WHERE card_id = ?")
            .bind(card_id)
            .fetch_optional(pool)
            .await?;
    let tenant_id = row.and_then(|(tenant_id,)| tenant_id).unwrap_or(0);
    if tenant_id <= 0 {
        tracing::warn!(
            card_id,
            tenant_id,
            "sod read path denied: card tenant missing or non-positive"
        );
        return Err(sod_gate_error(&sod_card_tenant_missing_message(
            card_id, tenant_id,
        )));
    }
    Ok(tenant_id)
}

/// 卡租户缺失/非正的稳定错误消息（供审计关联/错误分类使用）。
fn sod_card_tenant_missing_message(card_id: i64, tenant_id: i64) -> String {
    format!("sod_card_tenant_missing;card_id={card_id};tenant_id={tenant_id}")
}

/// 将 published card evidence 读取失败映射为 SoD 稳定错误前缀消息。
///
/// - `NotReady`（指针缺失/非 READY/超扇出上限）→ `sod_card_evidence_not_ready;`
/// - `Corrupt`（链校验失败/`pointer_moved_under_read`）→ `sod_card_evidence_corrupt;`
/// - `InvalidRequest`（scope 合同拒绝）→ `sod_card_evidence_invalid_scope;`
/// - `Query` 属 DB 传输错误，调用方应原样上抛；此处仅作防御性兜底前缀。
pub fn sod_evidence_error_message(card_id: i64, error: &AuthorizationEvidenceError) -> String {
    match error {
        AuthorizationEvidenceError::NotReady(detail) => {
            format!("sod_card_evidence_not_ready;card_id={card_id};detail={detail}")
        }
        AuthorizationEvidenceError::Corrupt(detail) => {
            format!("sod_card_evidence_corrupt;card_id={card_id};detail={detail}")
        }
        AuthorizationEvidenceError::InvalidRequest(detail) => {
            format!("sod_card_evidence_invalid_scope;card_id={card_id};detail={detail}")
        }
        AuthorizationEvidenceError::Query(query) => {
            format!("sod_card_evidence_query_failed;card_id={card_id};detail={query}")
        }
    }
}

/// Ready 证据合同校验失败的稳定错误消息（`Corrupt` 族，形状矛盾的证据
/// 绝不让其参与冲突判定）。SoD 检查与 `sod_repository::load_card_evidence`
/// 共用，保证两条读路径的 Corrupt 错误形状一致。
pub fn sod_evidence_contract_message(
    card_id: i64,
    contract_error: impl std::fmt::Display,
) -> String {
    format!("sod_card_evidence_corrupt;card_id={card_id};detail={contract_error}")
}

// ─────────────────────────────────────────────────────────────────────────────
// sod_policy 进程级缓存（读链规模化：每请求 2 次 sod_policy 全量读收敛）
// ─────────────────────────────────────────────────────────────────────────────

/// Both modes expire after 30s; composite entries also require their source
/// token to match. Cross-instance legacy invalidation still relies on TTL.
const SOD_POLICY_CACHE_TTL: Duration = Duration::from_secs(30);

/// ACTIVE 策略快照单类行数上限：回填 SQL 取 `cap+1` 探针行，读满 cap+1 即
/// 判定超容量并 fail-closed（绝不把 LIMIT 截断的部分快照冒充全量读面）。
/// sod_policy 为管理端低频输入表，4096 远超现实规模；超限属异常态，拒绝
/// 服务优于截断漏报（新收紧策略被截断 = 放行方向）。
const SOD_POLICY_SNAPSHOT_ROW_CAP: usize = 4096;
/// Maximum size of a stored dynamic condition script in bytes.
pub const MAX_DYNAMIC_CONDITION_SCRIPT_BYTES: usize = 512;

/// 快照字节预算（近似**内容**字节：仅统计字符串字段长度，不含 allocator/
/// 对象头等内存开销，也**不是** RSS 上界——进程内存影响另有镜像容量合同
/// 约束）：超预算 fail-closed，防止异常膨胀行把进程内存拖成无界。
const SOD_POLICY_SNAPSHOT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// 回填查询硬 deadline：超时取消查询并 fail-closed（错误绝不入缓存）。
/// 与镜像 strict refill 的 `REFILL_QUERY_DEADLINE` 同域（3s）。
const SOD_POLICY_QUERY_DEADLINE: Duration = Duration::from_secs(3);

/// single-flight 锁等待上限：并发 miss 只放一个回源，其余有界等待后
/// fail-closed（不无限排队、不并发重复回源）。
const SOD_POLICY_REFILL_LOCK_WAIT: Duration = Duration::from_secs(3);

/// SoD 策略快照（单条目全量缓存）：全量 ACTIVE STATIC 策略 + 全量 ACTIVE
/// DYNAMIC 策略。DYNAMIC 的 resource_type/action_code 过滤在读取侧内存执行
/// （谓词与原 SQL 等价，见 [`dynamic_policy_matches_request`]），一次缓存
/// 同时消除两条每请求 sod_policy 读。
#[derive(Debug, Clone, Default)]
struct SodPolicySnapshot {
    static_policies: Vec<StaticPolicy>,
    dynamic_policies: Vec<DynamicPolicy>,
}

/// A composite snapshot requires both a matching source token and a fresh
/// TTL. A legacy snapshot carries no token and uses the same TTL.
#[derive(Debug, Clone)]
struct SodPolicyCacheEntry {
    snapshot: SodPolicySnapshot,
    cached_at: Instant,
    source: Option<AuxiliaryReadToken>,
}

static SOD_POLICY_CACHE: OnceLock<RwLock<Option<SodPolicyCacheEntry>>> = OnceLock::new();

fn sod_policy_cache() -> &'static RwLock<Option<SodPolicyCacheEntry>> {
    SOD_POLICY_CACHE.get_or_init(|| RwLock::new(None))
}

/// 进程级 single-flight 回源锁（全快照单条目，无需按 key 分桶）。
static SOD_POLICY_REFILL_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn sod_policy_refill_lock() -> &'static tokio::sync::Mutex<()> {
    SOD_POLICY_REFILL_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// 缓存条目新鲜度（纯逻辑；`duration_since` 对未来时刻饱和为 0，恰好到达
/// TTL 即不新鲜，对齐 `cache_epoch` 的边界语义）。
fn sod_policy_cache_is_fresh(cached_at: Instant, now: Instant) -> bool {
    now.duration_since(cached_at) < SOD_POLICY_CACHE_TTL
}

/// 服务判定（纯逻辑，可单测钉死矩阵）：hub 安装时只认 token 绑定条目，
/// 且**同时要求 TTL 新鲜**（TTL 是既有缓存/_gc 合同的条目寿命上界——过期
/// 一律触发回填，绝不因 token 未变就信任过期条目）；hub 未安装时沿用既有
/// TTL 语义。模式/条目不匹配（如 composite 读到未绑定条目）一律 miss 回填。
fn sod_policy_entry_serves(
    hub_installed: bool,
    entry_bound: bool,
    token_matches: bool,
    ttl_fresh: bool,
) -> bool {
    match (hub_installed, entry_bound) {
        (true, true) => token_matches && ttl_fresh,
        // composite 读到未绑定条目 / 非 composite 读到绑定条目：模式错位，
        // 不服务（回填会以当前模式重新绑定）。
        (true, false) | (false, true) => false,
        (false, false) => ttl_fresh,
    }
}

/// 回源判定（纯逻辑）：composite 模式要求 hub 严格读 token **当前可读**；
/// writer-active/unknown（token 不可读）→ `Blocked`（fail-closed，绝不以
/// 并发/未知 source 状态回源或放行）。非 composite → `Legacy`（既有行为）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SodPolicyRefillOutcome {
    Bound,
    Legacy,
    Blocked,
}

fn sod_policy_refill_outcome(
    hub_installed: bool,
    strict_token_readable: bool,
) -> SodPolicyRefillOutcome {
    match (hub_installed, strict_token_readable) {
        (true, true) => SodPolicyRefillOutcome::Bound,
        (true, false) => SodPolicyRefillOutcome::Blocked,
        (false, _) => SodPolicyRefillOutcome::Legacy,
    }
}

/// 生产读取入口：composite（hub 安装）只服务 token 绑定且未漂移的条目；
/// 非 composite 走既有 TTL 语义。miss/模式错位一律回源（回源侧负责
/// writer-active/unknown 的 fail-closed）。
///
/// hub 严格读 token 在此**只采样一次**，条目匹配是对该采样值的纯比较
/// （绝不多次采样后再判定，避免采样间隙 writer 进出的竞争）。
fn serve_sod_policy_snapshot() -> Option<SodPolicySnapshot> {
    let hub = memory_projection_hub();
    let current = hub.and_then(|hub| hub.strict_read_token());
    let cached = sod_policy_cache().read().ok()?;
    let entry = cached.as_ref()?;
    let token_matches = match (entry.source, current) {
        (Some(bound), Some(current)) => bound == current,
        _ => false,
    };
    let serves = sod_policy_entry_serves(
        hub.is_some(),
        entry.source.is_some(),
        token_matches,
        sod_policy_cache_is_fresh(entry.cached_at, Instant::now()),
    );
    serves.then(|| entry.snapshot.clone())
}

/// 写入进程缓存（非 composite 回填 + 单测使用；错误结果绝不缓存）。锁中毒
/// 时静默跳过（缓存侧任何异常只意味着下一次读回源直查，绝不影响
/// fail-closed 语义）。
fn store_sod_policy_snapshot(snapshot: SodPolicySnapshot) {
    if let Ok(mut cached) = sod_policy_cache().write() {
        *cached = Some(SodPolicyCacheEntry {
            snapshot,
            cached_at: Instant::now(),
            source: None,
        });
    }
}

/// 写入 token 绑定条目（composite 回填专用；调用方必须已完成回填后的
/// strict token 复核）。
fn store_sod_policy_snapshot_bound(snapshot: SodPolicySnapshot, token: AuxiliaryReadToken) {
    if let Ok(mut cached) = sod_policy_cache().write() {
        *cached = Some(SodPolicyCacheEntry {
            snapshot,
            cached_at: Instant::now(),
            source: Some(token),
        });
    }
}

/// 主动失效 SoD 策略进程缓存（sod_policy 写路径 evict 钩子：本进程内立即
/// 生效；composite 模式另有 source writer 栅栏推进 token 的精确失效，此
/// 钩子保留为双保险；其它实例由 TTL 兜底，见模块文档失效窗口记录）。
pub fn evict_sod_policy_cache() {
    if let Ok(mut cached) = sod_policy_cache().write() {
        *cached = None;
    }
}

/// 快照字节预算（纯逻辑）：字符串字段总长近似值（饱和累加，行内容虽来自
/// 有界 VARCHAR 列，仍不允许任何加法 panic/回绕），用于有界回填判定。
fn sod_policy_snapshot_bytes(snapshot: &SodPolicySnapshot) -> usize {
    snapshot
        .static_policies
        .iter()
        .map(|policy| {
            policy
                .policy_name
                .len()
                .saturating_add(policy.permission_a.as_deref().map_or(0, str::len))
                .saturating_add(policy.permission_b.as_deref().map_or(0, str::len))
        })
        .chain(snapshot.dynamic_policies.iter().map(|policy| {
            policy
                .policy_name
                .len()
                .saturating_add(policy.condition_script.as_deref().map_or(0, str::len))
                .saturating_add(policy.resource_type.as_deref().map_or(0, str::len))
                .saturating_add(policy.action_code.as_deref().map_or(0, str::len))
        }))
        .fold(0usize, usize::saturating_add)
}

/// 有界快照装配（纯逻辑）：cap+1 探针超限或字节预算超限 → fail-closed，
/// 绝不把截断/膨胀快照当作全量 ACTIVE 输入（截断新收紧策略 = 放行方向）。
fn bounded_sod_policy_snapshot(
    static_policies: Vec<StaticPolicy>,
    dynamic_policies: Vec<DynamicPolicy>,
) -> Result<SodPolicySnapshot, sqlx::Error> {
    if static_policies.len() > SOD_POLICY_SNAPSHOT_ROW_CAP
        || dynamic_policies.len() > SOD_POLICY_SNAPSHOT_ROW_CAP
    {
        return Err(sod_gate_error(&format!(
            "sod_policy_snapshot_capacity_exceeded;cap={SOD_POLICY_SNAPSHOT_ROW_CAP}"
        )));
    }
    let snapshot = SodPolicySnapshot {
        static_policies,
        dynamic_policies,
    };
    let bytes = sod_policy_snapshot_bytes(&snapshot);
    if bytes > SOD_POLICY_SNAPSHOT_MAX_BYTES {
        return Err(sod_gate_error(&format!(
            "sod_policy_snapshot_byte_budget_exceeded;bytes={bytes};max={SOD_POLICY_SNAPSHOT_MAX_BYTES}"
        )));
    }
    Ok(snapshot)
}

/// 读取 SoD 策略全量快照（缓存服务优先，miss 回源；DB 错误原样上抛，
/// 绝不折算成"无冲突"，错误结果绝不入缓存）。
async fn load_sod_policy_snapshot(pool: &MySqlPool) -> Result<SodPolicySnapshot, sqlx::Error> {
    if let Some(snapshot) = serve_sod_policy_snapshot() {
        return Ok(snapshot);
    }
    refill_sod_policy_snapshot(pool).await
}

/// 有界 single-flight 回源（composite 与非 composite 共用）：
/// - composite：回源前 hub 严格读 token 必须可读（writer-active/unknown →
///   fail-closed，绝不回源或放行）；取 token → 有界查询 → 复核 token 未漂移
///   → 绑定安装；漂移即报错，竞争产物绝不入缓存。
/// - 非 composite：既有 TTL 语义（条目不绑定 token）。
/// - 查询 `LIMIT cap+1` 有界 + 3s deadline + 快照字节预算；single-flight
///   全局锁有界等待（超时 fail-closed，不无限排队）。
async fn refill_sod_policy_snapshot(pool: &MySqlPool) -> Result<SodPolicySnapshot, sqlx::Error> {
    let hub = memory_projection_hub();
    // hub 严格读 token 在回源前**只采样一次**（绝不允许先 `is_some` 判定再
    // 二次采样——两次采样之间存在 writer 进出，二次 expect 会 panic/竞争）；
    // 之后一切判定都是对该捕获值的纯比较。
    let captured = hub.and_then(|hub| hub.strict_read_token());
    let bound_token = match sod_policy_refill_outcome(hub.is_some(), captured.is_some()) {
        SodPolicyRefillOutcome::Blocked => {
            return Err(sod_gate_error(
                "sod_policy_source_state_unavailable;writer_active_or_unknown",
            ));
        }
        SodPolicyRefillOutcome::Bound => captured,
        SodPolicyRefillOutcome::Legacy => None,
    };

    let _guard = tokio::time::timeout(SOD_POLICY_REFILL_LOCK_WAIT, sod_policy_refill_lock().lock())
        .await
        .map_err(|_| sod_gate_error("sod_policy_refill_lock_wait_timeout"))?;
    // 等锁期间其它请求可能已完成回源；重新服务判定（composite 下 token 绑定
    // 未漂移的条目仍然有效）。
    if let Some(snapshot) = serve_sod_policy_snapshot() {
        return Ok(snapshot);
    }

    let read: Result<(Vec<StaticPolicy>, Vec<DynamicPolicy>), sqlx::Error> =
        tokio::time::timeout(SOD_POLICY_QUERY_DEADLINE, async {
            let static_policies = sqlx::query_as::<_, StaticPolicy>(&format!(
                "SELECT policy_name, permission_a, permission_b \
             FROM sod_policy WHERE conflict_type='STATIC' AND status='ACTIVE' LIMIT {}",
                SOD_POLICY_SNAPSHOT_ROW_CAP + 1
            ))
            .fetch_all(pool)
            .await?;
            let dynamic_policies = sqlx::query_as::<_, DynamicPolicy>(&format!(
                "SELECT policy_name, condition_script, resource_type, action_code \
             FROM sod_policy WHERE conflict_type='DYNAMIC' AND status='ACTIVE' LIMIT {}",
                SOD_POLICY_SNAPSHOT_ROW_CAP + 1
            ))
            .fetch_all(pool)
            .await?;
            Ok((static_policies, dynamic_policies))
        })
        .await
        .map_err(|_| sod_gate_error("sod_policy_query_deadline_exceeded"))?;
    let (static_policies, dynamic_policies) = read?;
    let snapshot = bounded_sod_policy_snapshot(static_policies, dynamic_policies)?;

    match (hub, bound_token) {
        (Some(hub), Some(token)) => {
            // 回填后复核（after-read）：查询窗口内 source 零 mutation 才允许
            // 绑定安装；漂移即报错，竞争产物绝不入缓存。
            if !hub.strict_read_matches(token) {
                return Err(sod_gate_error("sod_policy_source_mutation_raced_read"));
            }
            store_sod_policy_snapshot_bound(snapshot.clone(), token);
            // 安装后终检（after-install/final）：只比较已绑定 token，绝不重采
            // 新 token 覆盖旧读；install 后又发生 mutation → 本次返回仍
            // fail-closed，条目随 token 漂移在下次 serve 一并 miss 回源。
            if !hub.strict_read_matches(token) {
                return Err(sod_gate_error("sod_policy_source_mutation_raced_install"));
            }
        }
        _ => store_sod_policy_snapshot(snapshot.clone()),
    }
    Ok(snapshot)
}

/// 已由 PolicyEngine 确认的组织 ALLOW 重新进入 SoD 拒绝层时携带的证据。
///
/// 这不是授权输入：组织 ALLOW 的唯一事实仍是 `PolicyEngine.evaluate()` 内的
/// publication/node/membership 双读准入。该结构只让宿主 SoD 在其既有的
/// deny-only 静态互斥检查中看见同一张卡已持有的组织贡献；任何 provenance
/// 或 publication 对牌失败都返回错误，并由调用方拒绝请求。
#[derive(Debug, Clone)]
pub struct OrgSodAdmission {
    pub evidence: OrgAdmissionEvidence,
    pub provenance: OrgBranchProvenance,
}

struct OrgSodInput<'a> {
    context: &'a PolicyContext,
    admission: &'a OrgSodAdmission,
}

fn org_contribution_matches_provenance(
    contribution: &OrgContribution,
    evidence: &OrgAdmissionEvidence,
    provenance: &OrgBranchProvenance,
) -> bool {
    let branch_kind = if contribution.subject.is_some() {
        OrgBranchKind::Personal
    } else {
        OrgBranchKind::Shared
    };
    contribution.grant_ref == provenance.grant_ref
        && contribution.provenance.origin_tenant_id == provenance.source_tenant_id
        && contribution.provenance.operation_id == provenance.approval_operation_id
        && contribution.scope.resource_tenant_id == provenance.resource_tenant_id
        && branch_kind == provenance.branch_kind
        && evidence.publication.tenant_id == provenance.receiving_tenant_id
        && evidence.publication.root_tenant_id == provenance.root_tenant_id
        && evidence.membership.membership_id == provenance.membership_id
        && evidence.membership.revision == provenance.membership_revision
        && evidence.publication.generation == provenance.publication_generation
        && evidence.publication.manifest_digest_hex == provenance.manifest_digest_hex
}

fn org_sod_contribution_matches_partner(
    contribution: &OrgContribution,
    partner_type: &str,
    partner_action: &str,
) -> bool {
    (contribution.scope.resource == "*"
        || sod_resource_type_from_scoped_key(&contribution.scope.resource) == partner_type)
        && org_action_matches(partner_action, &contribution.scope.action)
}

fn org_sod_contributions(
    tenant_id: i64,
    card_id: i64,
    user_id: i64,
    resource_type: &str,
    action_code: &str,
    input: &OrgSodInput<'_>,
) -> Result<Vec<OrgContribution>, sqlx::Error> {
    let context = input.context;
    let evidence = &input.admission.evidence;
    let provenance = &input.admission.provenance;
    evidence.validate().map_err(|error| {
        sod_gate_error(&format!("org_scope_sod_evidence_invalid;detail={error}"))
    })?;
    provenance.validate().map_err(|error| {
        sod_gate_error(&format!("org_scope_sod_provenance_invalid;detail={error}"))
    })?;
    if context.card_id != Some(card_id)
        || context.user_id != Some(user_id)
        || context.tenant_id != Some(tenant_id)
        || context.resource.as_deref() != Some(resource_type)
        || context.action != action_code
        || context.identity_card_id != Some(evidence.membership.identity_card_id)
        || evidence.node.tenant_id != tenant_id
        || evidence.membership.user_id != user_id
        || evidence.membership.card_id != card_id
    {
        return Err(sod_gate_error("org_scope_sod_context_mismatch"));
    }

    // Current target facts must match the same resolver classification consumed
    // by `policy_engine::org_admission::request`. External tenant-owned
    // requests never borrow the actor card tenant/domain; internal typed calls
    // retain the old fixture-compatible interpretation only.
    let (request_resource_tenant_id, request_domain_id) = match context.resource_ownership_scope {
        ResourceOwnershipScope::TenantScoped => (
            context
                .resource_tenant_id
                .ok_or_else(|| sod_gate_error("org_scope_sod_request_invalid"))?,
            context.resource_domain_id,
        ),
        ResourceOwnershipScope::Internal => (
            context
                .resource_tenant_id
                .or(context.tenant_id)
                .ok_or_else(|| sod_gate_error("org_scope_sod_request_invalid"))?,
            context.resource_domain_id.or(context.domain_id),
        ),
        ResourceOwnershipScope::Global
        | ResourceOwnershipScope::Unresolved
        | ResourceOwnershipScope::Unavailable => {
            return Err(sod_gate_error("org_scope_sod_request_invalid"));
        }
    };
    let current_request = OrgReadRequest {
        resource: build_resource_key(resource_type, context.target_id),
        action: action_code.to_owned(),
        resource_tenant_id: request_resource_tenant_id,
        domain_id: request_domain_id,
        now_unix_seconds: evidence.checked_at_unix,
    };
    if current_request.validate().is_err() {
        return Err(sod_gate_error("org_scope_sod_request_invalid"));
    }

    let mut selected_is_stable = false;
    let mut contributions = Vec::new();
    for segment in &evidence.publication.segments {
        let content = org_decode_segment_content(segment).map_err(|error| {
            sod_gate_error(&format!("org_scope_sod_segment_invalid;detail={error}"))
        })?;
        for contribution in content.contributions {
            let filter = if contribution.subject.is_some() {
                OrgSubjectFilter::PersonalOf { user_id, card_id }
            } else {
                OrgSubjectFilter::SharedOnly
            };
            // 持有判定按贡献自身的权威 resource tenant（已发布 evidence 经
            // `org_decode_segment_content` 合同校验的正值事实），而不是
            // actor/card 租户——与组织准入按发布事实评估贡献的语义一致。
            // 用 actor 租户会把 scope.resource_tenant_id 不同的组织贡献整体
            // 滤掉：STATIC 持有比对看不到它们，当前请求也因 selected 不稳定
            // 而 fail-closed 报错。主体过滤/domain 严格相等/有效期过滤不变。
            let holding_request = OrgReadRequest {
                resource: contribution.scope.resource.clone(),
                action: contribution.scope.action.clone(),
                resource_tenant_id: contribution.scope.resource_tenant_id,
                domain_id: contribution.scope.domain_id,
                now_unix_seconds: evidence.checked_at_unix,
            };
            if !org_contribution_matches_request(&contribution, &holding_request, filter) {
                continue;
            }
            if org_contribution_matches_provenance(&contribution, evidence, provenance) {
                selected_is_stable =
                    org_resource_matches(&current_request.resource, &contribution.scope.resource)
                        && org_action_matches(&current_request.action, &contribution.scope.action)
                        && org_contribution_matches_request(
                            &contribution,
                            &current_request,
                            filter,
                        );
            }
            contributions.push(contribution);
        }
    }
    if !selected_is_stable {
        return Err(sod_gate_error("org_scope_sod_provenance_stale"));
    }
    Ok(contributions)
}

/// Native pre-grant SoD validation for a card-level grant.
///
/// This is intentionally a grant-time API, not the post-ALLOW request check.
/// It derives tenant scope from `user_card`, requires strict card-level
/// published evidence, and evaluates the active STATIC/DYNAMIC policies with
/// no user or resource-owner facts. Missing evidence, unavailable dependencies,
/// unsupported conditions, or an active dynamic policy requiring absent facts
/// return `Err`; none are interpreted as a conflict-free grant.
///
/// If a memory projection hub is installed, the entire read is fenced by one
/// captured source token. An unavailable token or any change to that exact
/// token before return fails closed.
pub async fn check_grant_sod_conflict(
    pool: &MySqlPool,
    card_id: i64,
    resource_type: &str,
    action_code: &str,
) -> Result<SodCheckResult, sqlx::Error> {
    let hub = memory_projection_hub();
    let fence = match hub {
        Some(hub) => Some(hub.strict_read_token().ok_or_else(|| {
            sod_gate_error("sod_grant_source_state_unavailable;writer_active_or_unknown")
        })?),
        None => None,
    };

    let result = tokio::time::timeout(
        SOD_POLICY_QUERY_DEADLINE,
        check_published_sod_conflict(pool, card_id, None, resource_type, action_code, None, None),
    )
    .await
    .map_err(|_| sod_gate_error("sod_grant_query_deadline_exceeded"))??;

    if let (Some(hub), Some(fence)) = (hub, fence) {
        if !hub.strict_read_matches(fence) {
            return Err(sod_gate_error("sod_grant_source_mutation_raced_read"));
        }
    }
    Ok(result)
}

const GRANT_SOD_PENDING_SQL: &str = "SELECT delta_event_id FROM authorization_delta_event \
    WHERE tenant_id = ? AND (card_id = ? OR card_id IS NULL) \
      AND status <> 'SUCCEEDED' AND event_type IN ('ADD', 'UPDATE', 'REMOVE', 'REVOKE') \
    ORDER BY delta_event_id LIMIT 1 FOR UPDATE";

/// Revalidate a direct grant in its source transaction, before source mutation.
///
/// The card lock serializes card writers. The current delta read rejects every
/// unpublished contribution, including additive work invisible to the published
/// frontier. Locks follow card → delta → pointer; the strict reader and current
/// policy reads use this transaction only, without caches or pool acquisition.
/// Missing authoritative dynamic-condition facts remain a refusal.
pub async fn check_grant_sod_conflict_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    resource_type: &str,
    action_code: &str,
    update_before_image: Option<DirectGrantSodUpdateBeforeImage<'_>>,
) -> Result<SodCheckResult, sqlx::Error> {
    tokio::time::timeout(SOD_POLICY_QUERY_DEADLINE, async {
        let locked_card = sqlx::query_as::<_, LockedSodCardScope>(
            "SELECT card_id, user_id, tenant_id, domain_id FROM user_card WHERE card_id = ? \
             AND card_status = 'ACTIVE' \
             AND (valid_from IS NULL OR valid_from <= UTC_TIMESTAMP()) \
             AND (valid_until IS NULL OR valid_until >= UTC_TIMESTAMP()) FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(locked_scope) = locked_card else {
            return Err(sod_gate_error("sod_grant_locked_card_unavailable"));
        };
        if card_id <= 0
            || locked_scope.card_id != card_id
            || locked_scope.tenant_id.is_none_or(|tenant| tenant <= 0)
            || locked_scope.user_id.is_none_or(|user| user <= 0)
            || locked_scope.domain_id.is_some_and(|domain| domain <= 0)
        {
            return Err(sod_gate_error("sod_grant_locked_card_scope_invalid"));
        }
        let tenant_id = if let Some(before_image) = update_before_image.as_ref() {
            validate_direct_update_scope(before_image, locked_scope, card_id)
                .map_err(sod_gate_error)?
        } else {
            // CREATE has no source rule before-image; retain its strict card-only
            // check and do not derive or omit any published grant.
            locked_scope
                .tenant_id
                .expect("positive card tenant checked above")
        };
        let pending: Option<i64> = sqlx::query_scalar(GRANT_SOD_PENDING_SQL)
            .bind(tenant_id)
            .bind(card_id)
            .fetch_optional(&mut **tx)
            .await?;
        if pending.is_some() {
            return Err(sod_gate_error("sod_grant_unpublished_source_pending"));
        }
        let scope = PublishedCardEvidenceScope {
            tenant_id,
            card_id,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        let evidence = crate::load_published_card_grant_evidence_in_tx(tx, &scope)
            .await
            .map_err(|error| match error {
                AuthorizationEvidenceError::Query(error) => error,
                other => sod_gate_error(&sod_evidence_error_message(card_id, &other)),
            })?;
        evidence
            .validate()
            .map_err(|error| sod_gate_error(&sod_evidence_contract_message(card_id, &error)))?;
        let self_excluded_grant = update_before_image
            .as_ref()
            .map(|before_image| {
                prove_direct_update_self_exclusion(&evidence, before_image, locked_scope, card_id)
                    .map_err(sod_gate_error)
            })
            .transpose()?;
        let static_policies = sqlx::query_as::<_, StaticPolicy>(&format!(
            "SELECT policy_name, permission_a, permission_b FROM sod_policy \
             WHERE conflict_type = 'STATIC' AND status = 'ACTIVE' \
             ORDER BY policy_id LIMIT {} FOR SHARE",
            SOD_POLICY_SNAPSHOT_ROW_CAP + 1,
        ))
        .fetch_all(&mut **tx)
        .await?;
        let dynamic_policies = sqlx::query_as::<_, DynamicPolicy>(&format!(
            "SELECT policy_name, condition_script, resource_type, action_code FROM sod_policy \
             WHERE conflict_type = 'DYNAMIC' AND status = 'ACTIVE' \
             ORDER BY policy_id LIMIT {} FOR SHARE",
            SOD_POLICY_SNAPSHOT_ROW_CAP + 1,
        ))
        .fetch_all(&mut **tx)
        .await?;
        let snapshot = bounded_sod_policy_snapshot(static_policies, dynamic_policies)?;
        evaluate_sod_conflicts(
            &format!("{resource_type}:{action_code}"),
            &evidence,
            &snapshot,
            None,
            resource_type,
            action_code,
            None,
            None,
            self_excluded_grant,
        )
    })
    .await
    .map_err(|_| sod_gate_error("sod_grant_transaction_deadline_exceeded"))?
}

/// ADDITIVE canonical 宿主 ORG 复核入口（冷/热同一 published-only 持有合同，
/// 含 composite 栅栏）：org provenance 判定的 deny-only 复核走
/// `check_sod_conflict_with_context_inner`——复合进程 warm 态（内存镜像 +
/// token 绑定策略快照）零 DB，cold durable 回退与 warm 同一持有语义；宿主
/// 应使用本入口，不提供 raw-source 诊断或扫描路径。
pub async fn check_sod_conflict_with_context_and_org(
    pool: &MySqlPool,
    ctx: &PolicyContext,
    admission: &OrgSodAdmission,
    resource_owner_id: Option<i64>,
) -> Result<SodCheckResult, sqlx::Error> {
    let (Some(_card_id), Some(_user_id), Some(_resource_type)) =
        (ctx.card_id, ctx.user_id, ctx.resource.as_deref())
    else {
        return Err(sod_gate_error("org_scope_sod_context_missing"));
    };
    check_sod_conflict_with_context_inner(pool, ctx, Some(admission), resource_owner_id).await
}

/// Context-aware host SoD entry (deny-only, without ORG provenance).
///
/// Call after `PolicyEngine` ALLOW with the complete, validated `PolicyContext`;
/// resource/owner facts must be resolved server-side, never taken from client
/// headers. Composite warm reads use the memory mirror and token-bound policy
/// snapshot; a miss or unavailable mirror defers to the strict durable reader.
/// Every failure is fail-closed, and held grants come only from validated
/// published evidence.
///
/// Evidence scope uses server-side context facts: the tenant was authenticated
/// by `PolicyEngine`, and the hub's durable card index proves card/tenant binding.
pub async fn check_sod_conflict_with_context(
    pool: &MySqlPool,
    ctx: &PolicyContext,
    resource_owner_id: Option<i64>,
) -> Result<SodCheckResult, sqlx::Error> {
    check_sod_conflict_with_context_inner(pool, ctx, None, resource_owner_id).await
}

async fn check_sod_conflict_with_context_inner(
    pool: &MySqlPool,
    ctx: &PolicyContext,
    admission: Option<&OrgSodAdmission>,
    resource_owner_id: Option<i64>,
) -> Result<SodCheckResult, sqlx::Error> {
    let Some(card_id) = ctx.card_id else {
        return Err(sod_gate_error("sod_context_missing"));
    };
    let Some(resource_type) = ctx.resource.as_deref() else {
        return Err(sod_gate_error("sod_context_missing"));
    };
    let org_input = admission.map(|admission| OrgSodInput {
        context: ctx,
        admission,
    });
    // 宿主 context 入口自带准入栅栏（pub 入口可能不经宿主中间件调用）：
    // hub 严格读 token 在此**只采样一次**，warm 记忆路径与 cold durable 回退
    // 的整个读取/评估窗口都由同一个捕获栅栏终检（只比较，绝不重采新 token
    // 覆盖旧读）。
    // hub 已安装而栅栏不可得（writer-active / source outcome unknown /
    // worker 失效旗标）→ 直接 Err fail-closed：**不回落** durable 严格链，
    // 绝不以"无栅栏"状态消费任何授权读取（含 cold 回退）。
    if let Some(hub) = memory_projection_hub() {
        let Some(fence) = hub.strict_read_token() else {
            return Err(sod_gate_error(
                "sod_context_source_state_unavailable;writer_active_or_unknown",
            ));
        };
        if let Some(result) = try_check_sod_conflict_from_memory(
            pool,
            hub,
            fence,
            ctx,
            org_input.as_ref(),
            resource_type,
            resource_owner_id,
        )
        .await?
        {
            return Ok(result);
        }
        // cold durable 回退（canonical 合同：PublishedEvidenceOnly，与 warm
        // 同一持有语义）；读取窗口之后同一栅栏终检——漂移 fail-closed。
        let result = tokio::time::timeout(
            SOD_POLICY_QUERY_DEADLINE,
            check_published_sod_conflict(
                pool,
                card_id,
                ctx.user_id,
                resource_type,
                &ctx.action,
                resource_owner_id,
                org_input,
            ),
        )
        .await
        .map_err(|_| sod_gate_error("sod_context_query_deadline_exceeded"))??;
        if !hub.strict_read_matches(fence) {
            return Err(sod_gate_error("sod_context_source_mutation_raced_read"));
        }
        return Ok(result);
    }
    // 非 composite（hub 未安装）：既有 durable 严格链，行为不变。
    check_published_sod_conflict(
        pool,
        card_id,
        ctx.user_id,
        resource_type,
        &ctx.action,
        resource_owner_id,
        org_input,
    )
    .await
}

/// 复合进程 warm 记忆读取路径（ADDITIVE）：hub 安装 + 记忆证据命中时零 DB
/// 完成冲突判定。任何 defer（未预热/pending 命中/通道不健康/scope 未命中）
/// 返回 `Ok(None)`，调用方回落 durable 严格链——绝不以记忆 miss 折算
/// "无冲突"。栅栏由调用方（context 入口）捕获一次并传入；本函数不做任何
/// token 采样，只在返回前比较传入栅栏。
///
/// - evidence scope 只用服务端 ctx 事实（tenant 由 PolicyEngine 鉴权；
///   card-tenant 绑定由 hub durable card index 命中再证明，miss 即回退）；
/// - `Serve` 产物再过一次合同校验（与 durable 路径同纵深防御）；
/// - 策略快照经 token 绑定缓存服务（warm 零 DB；writer-active/unknown
///   fail-closed）；
/// - raw `permission_rule` 扫描不执行（canonical 冷/热同一持有合同，见
///   模块文档 BREAKING CHANGE 登记）。
async fn try_check_sod_conflict_from_memory(
    pool: &MySqlPool,
    hub: &crate::memory_projection_hub::MemoryProjectionHub,
    fence: AuxiliaryReadToken,
    ctx: &PolicyContext,
    org_input: Option<&OrgSodInput<'_>>,
    resource_type: &str,
    resource_owner_id: Option<i64>,
) -> Result<Option<SodCheckResult>, sqlx::Error> {
    let (Some(tenant_id), Some(card_id)) = (ctx.tenant_id, ctx.card_id) else {
        return Ok(None);
    };
    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    };
    let evidence = match hub.try_memory_evidence(&scope) {
        MemoryEvidenceOutcome::Serve(evidence) => evidence,
        MemoryEvidenceOutcome::DeferToDurable => return Ok(None),
    };
    if evidence.tenant_id != tenant_id || evidence.card_id != card_id {
        return Err(sod_gate_error("sod_memory_evidence_scope_mismatch"));
    }
    if let Err(contract_error) = evidence.validate() {
        tracing::warn!(
            card_id,
            error = %contract_error,
            "sod memory path denied: mirrored evidence failed contract validation"
        );
        return Err(sod_gate_error(&sod_evidence_contract_message(
            card_id,
            &contract_error,
        )));
    }
    let org_contributions = match org_input {
        Some(input) => {
            let user_id = ctx
                .user_id
                .ok_or_else(|| sod_gate_error("org_scope_sod_context_missing"))?;
            Some(org_sod_contributions(
                tenant_id,
                card_id,
                user_id,
                resource_type,
                &ctx.action,
                input,
            )?)
        }
        None => None,
    };
    let snapshot = load_sod_policy_snapshot(pool).await?;
    let perm_key = format!("{resource_type}:{}", ctx.action);
    let result = evaluate_sod_conflicts(
        &perm_key,
        &evidence,
        &snapshot,
        org_contributions.as_deref(),
        resource_type,
        &ctx.action,
        ctx.user_id,
        resource_owner_id,
        None,
    )?;
    // after-eval 终检：记忆读面 + 策略快照 + 评估窗口内 source 零 mutation
    // 才允许返回记忆路径结果（只比较已捕获栅栏，绝不重采新 token 覆盖旧读）；
    // 漂移 → fail-closed，宿主必须拒绝请求。
    if !hub.auxiliary_read_matches(fence) {
        return Err(sod_gate_error("sod_memory_source_mutation_raced_read"));
    }
    Ok(Some(result))
}

/// 从已确认的 `PolicyDecision` 装配宿主 SoD 复核输入（shared，供
/// TrustGraph/Identity/Monitor 宿主中间件统一接线，消除本地重复实现）。
///
/// - 决策未携带 org provenance（非 ORG 判定）→ `Ok(None)`：调用方对本次请求
///   走普通 context-aware 宿主 SoD 纯 deny-only 路径，行为不变；
/// - ORG 判定但 `PolicyContext` 缺失租户/用户/卡/身份卡任一事实 →
///   `sod_gate_error("org_scope_sod_context_missing")`（fail-closed）；
/// - fresh 准入证据读取返回业务 Pending → `sod_gate_error`（稳定前缀
///   `org_scope_sod_evidence_pending;`，携带 pending machine code）；
/// - 基础设施错误 → `sod_gate_error`（稳定前缀
///   `org_scope_sod_evidence_unavailable;`）。
///
/// 语义与组织准入一致：本函数不产生任何授权事实，只把 `PolicyEngine` 已确认
/// ALLOW 的 provenance 与 fresh publication/membership evidence 重新装配，交给
/// context-aware ORG 宿主检查做 deny-only 的 STATIC 互斥复核；provenance 或
/// publication 对牌失败沿错误返回，由调用方拒绝请求（503/fail-closed）。
pub async fn load_org_sod_admission(
    pool: &MySqlPool,
    ctx: &PolicyContext,
    decision: &PolicyDecision,
) -> Result<Option<OrgSodAdmission>, sqlx::Error> {
    let Some(provenance) = decision.org_provenance.clone() else {
        return Ok(None);
    };
    let (Some(tenant_id), Some(user_id), Some(card_id), Some(identity_card_id)) = (
        ctx.tenant_id,
        ctx.user_id,
        ctx.card_id,
        ctx.identity_card_id,
    ) else {
        return Err(sod_gate_error("org_scope_sod_context_missing"));
    };
    let repository = SqlxOrgScopeRepository::new(pool.clone());
    let query = OrgAdmissionQuery {
        tenant_id,
        user_id,
        card_id,
        identity_card_id: Some(identity_card_id),
        now_unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    org_sod_admission_outcome(repository.load_admission_evidence(&query).await, provenance)
}

/// [`load_org_sod_admission`] 的 additive context-aware 宿主入口（复合进程
/// 内存镜像读面）：ORG 判定的准入证据优先复用辅助镜像
/// `load_org_authorization`——与 `PolicyEngine.evaluate()` 完全同一 strict
/// read contract（hub 健康门、single-flight、3s deadline、纪元栅栏、有界
/// 回填），warm 命中零 DB；`Ready` 证据进入与 fresh DB 读**完全相同**的
/// context-aware ORG provenance 对牌解析器，不产生任何新授权事实。
///
/// 映射（fail-closed，与 `org_sod_admission_outcome` 同向）：
/// - 镜像 `Ready(evidence)` → 与 fresh DB 读同源的 `OrgSodAdmission`；
/// - 镜像 `Pending { code }` → `org_scope_sod_evidence_pending;`（fail-closed）；
/// - 镜像 `Unavailable { code }` → `org_scope_sod_evidence_unavailable;`
///   （fail-closed，基础设施失败不洗白成业务 pending）；
/// - 镜像 `None`（hub `StrictRequired`：未 warm/通道不健康/心跳过期）及
///   `Disabled`/`Unmanaged`（与 ORG provenance 判定相悖的罕见状态）→ 回落
///   既有 fresh DB 严格读，由权威路径裁决（同一次 fresh 严格读，与旧入口
///   一致）。
/// - hub 或辅助镜像未安装（非 composite）→ 直接走 fresh DB 读（不变）。
pub async fn load_org_sod_admission_mirrored(
    pool: &MySqlPool,
    ctx: &PolicyContext,
    decision: &PolicyDecision,
) -> Result<Option<OrgSodAdmission>, sqlx::Error> {
    let Some(provenance) = decision.org_provenance.clone() else {
        return Ok(None);
    };
    let (Some(tenant_id), Some(user_id), Some(card_id), Some(identity_card_id)) = (
        ctx.tenant_id,
        ctx.user_id,
        ctx.card_id,
        ctx.identity_card_id,
    ) else {
        return Err(sod_gate_error("org_scope_sod_context_missing"));
    };
    let hub = memory_projection_hub();
    let fence = match hub {
        Some(hub) => Some(hub.strict_read_token().ok_or_else(|| {
            sod_gate_error("org_scope_sod_source_state_unavailable;writer_active_or_unknown")
        })?),
        None => None,
    };
    if let Some(hub) = hub {
        if let Some(mirror) = auxiliary_authorization_mirror() {
            match mirror.load_org_authorization(hub, ctx).await {
                Some(OrgAuthorityRead::Ready(evidence)) => match fence {
                    Some(token) if hub.strict_read_matches(token) => {
                        return Ok(Some(OrgSodAdmission {
                            evidence: *evidence,
                            provenance,
                        }));
                    }
                    _ => {
                        return Err(sod_gate_error("org_scope_sod_source_mutation_raced_read"));
                    }
                },
                Some(OrgAuthorityRead::Pending { code }) => {
                    return Err(sod_gate_error(&format!(
                        "org_scope_sod_evidence_pending;code={code}"
                    )));
                }
                Some(OrgAuthorityRead::Unavailable { code }) => {
                    return Err(sod_gate_error(&format!(
                        "org_scope_sod_evidence_unavailable;code={code}"
                    )));
                }
                // None = StrictRequired；Disabled/Unmanaged 与 ORG provenance
                // 相悖 → 一律回落权威 fresh DB 读（下方原路径）。
                Some(OrgAuthorityRead::Disabled | OrgAuthorityRead::Unmanaged) | None => {}
            }
        }
    }
    let repository = SqlxOrgScopeRepository::new(pool.clone());
    let query = OrgAdmissionQuery {
        tenant_id,
        user_id,
        card_id,
        identity_card_id: Some(identity_card_id),
        now_unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    let result = tokio::time::timeout(
        SOD_POLICY_QUERY_DEADLINE,
        repository.load_admission_evidence(&query),
    )
    .await
    .map_err(|_| sod_gate_error("org_scope_sod_query_deadline_exceeded"))?;
    if let (Some(hub), Some(token)) = (hub, fence) {
        if !hub.strict_read_matches(token) {
            return Err(sod_gate_error("org_scope_sod_source_mutation_raced_read"));
        }
    }
    org_sod_admission_outcome(result, provenance)
}

/// fresh 准入证据读取结果的 SoD 门禁映射（纯逻辑，稳定错误码可在无 DB 的
/// 单测中钉死）：EVIDENCE → 装配 `OrgSodAdmission`；业务 Pending →
/// `org_scope_sod_evidence_pending;`（携带 machine code）；基础设施错误 →
/// `org_scope_sod_evidence_unavailable;`。所有 Err 沿 [`sod_gate_error`]
/// 进入调用方 503/fail-closed，绝不折算成"无冲突"放行。
fn org_sod_admission_outcome(
    outcome: Result<OrgAdmissionResult, astral_types::AstralError>,
    provenance: OrgBranchProvenance,
) -> Result<Option<OrgSodAdmission>, sqlx::Error> {
    match outcome {
        Ok(OrgAdmissionResult::Evidence(evidence)) => Ok(Some(OrgSodAdmission {
            evidence: *evidence,
            provenance,
        })),
        Ok(OrgAdmissionResult::Pending { code, .. }) => Err(sod_gate_error(&format!(
            "org_scope_sod_evidence_pending;code={}",
            code.as_machine_code()
        ))),
        Err(error) => Err(sod_gate_error(&format!(
            "org_scope_sod_evidence_unavailable;detail={error}"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn check_published_sod_conflict(
    pool: &MySqlPool,
    card_id: i64,
    user_id: Option<i64>,
    resource_type: &str,
    action_code: &str,
    resource_owner_id: Option<i64>,
    org_input: Option<OrgSodInput<'_>>,
) -> Result<SodCheckResult, sqlx::Error> {
    let perm_key = format!("{resource_type}:{action_code}");

    // === tenant 定位输入（fail-closed，先于任何冲突判定） ===
    // user_card 行缺失或 tenant_id 空/非正 → 授权状态未知 → 报错；
    // 调用方对 Err 一律拒绝。
    let tenant_id = sod_load_card_tenant(pool, card_id).await?;

    // === 卡级 published evidence 门禁（fail-closed，先于任何冲突判定） ===
    // 卡级 lens：不按 user 收窄、不限 domain（对齐 load_card_permission_summaries
    // 的卡级语义）。读取经进程内 evidence 缓存 + 指针对牌（miss/漂移回源）：
    // 严格 reader 在单短事务内 FOR UPDATE 锁定当前指针并复核未漂移；
    // evidence 不可用（NotReady/Corrupt/合同拒绝）→ 报错，绝不映射成"无冲突"。
    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    };
    let evidence = match cached_load_published_card_grant_evidence(pool, &scope).await {
        Ok(evidence) => evidence,
        // DB 传输错误原样上抛（→ 503/fail-closed），不改写错误族。
        Err(AuthorizationEvidenceError::Query(query)) => return Err(query),
        Err(other) => {
            tracing::warn!(
                card_id,
                tenant_id,
                error = %other,
                "sod read path denied: published card evidence gate is not readable"
            );
            return Err(sod_gate_error(&sod_evidence_error_message(card_id, &other)));
        }
    };
    // 纵深防御：reader 产物再过一次合同校验（对齐 load_card_permission_summaries）；
    // Ready 证据若自相矛盾 → Corrupt 族报错，绝不让形状矛盾的证据参与冲突判定。
    if let Err(contract_error) = evidence.validate() {
        tracing::warn!(
            card_id,
            error = %contract_error,
            "sod read path denied: published card evidence failed contract validation"
        );
        return Err(sod_gate_error(&sod_evidence_contract_message(
            card_id,
            &contract_error,
        )));
    }

    let org_contributions = match org_input {
        Some(input) => {
            let user_id = user_id.ok_or_else(|| sod_gate_error("org_scope_sod_context_missing"))?;
            Some(org_sod_contributions(
                tenant_id,
                card_id,
                user_id,
                resource_type,
                action_code,
                &input,
            )?)
        }
        None => None,
    };

    // === STATIC 策略检查 ===
    //
    // 新链 evidence 数据源（已发布的 CARD 授权证据）：
    // - `effective_grants` 只含"当前有效授权集合"中的生效 ALLOW grant
    //   （ACTIVE + 统一 UTC 时钟下窗口有效 + tenant/card 完整性验证 + 卡级
    //   lens）；状态/窗口判定已由 reader 完成，这里不再重复。
    // - 来源覆盖面（语义决策）：包含全部来源（DIRECT/APPROVAL/RULE_SET/
    //   DELEGATION）的生效 ALLOW——SoD 关心"卡实际持有的权限组合"，来源无关；
    //   旧实现只读卡规则快照、看不到 RULE_SET/DELEGATION 是旧卡快照能力限制
    //   而非语义选择。切换后冲突检测变严（漏报减少），属修复；
    //   【上线灰度观察项】关注 RULE_SET/DELEGATION 来源带来的新增冲突告警量。
    // - resource_key 形状修复：grant.resource 是 scoped key（`type:*` /
    //   `type:id`），旧实现把 partner 的 plain type（parts[0]）直接绑定到
    //   scoped key 比较，形状错位导致永不命中；现在经
    //   [`sod_partner_matches_grant`] 先归一为 plain type 再比较。
    // - raw `permission_rule` 不属于发布过的持有授权，不作为 SoD 输入；
    //   Static 冲突只按 evidence.effective_grants 和组织已发布贡献判断。
    // 全量 ACTIVE 策略快照（composite：hub 严格读 token 绑定缓存，warm 零 DB；
    // 非 composite：TTL 30s；miss/DB 错误回源有界 single-flight 直查，fail-closed
    // 不变，错误绝不入缓存）。STATIC 与 DYNAMIC 两个检查段共用同一快照。
    let snapshot = load_sod_policy_snapshot(pool).await?;

    // 冲突判定只依赖已发布 evidence 和纯动态条件检查，无额外 source 查询。
    evaluate_sod_conflicts(
        &perm_key,
        &evidence,
        &snapshot,
        org_contributions.as_deref(),
        resource_type,
        action_code,
        user_id,
        resource_owner_id,
        None,
    )
}

/// STATIC + DYNAMIC 冲突评估（pure，无 I/O）。
///
/// STATIC 持有判定来自已发布 evidence 的 `effective_grants`
/// （resource_key 归一化后匹配）与已发布组织贡献；DYNAMIC 只按请求维度过滤
/// 策略并执行支持的精确脚本。缺失 authoritative facts 或 unsupported 脚本
/// 由既有 dynamic evaluator fail-closed。
#[allow(clippy::too_many_arguments)]
fn evaluate_sod_conflicts(
    perm_key: &str,
    evidence: &PublishedCardAuthorization,
    snapshot: &SodPolicySnapshot,
    org_contributions: Option<&[OrgContribution]>,
    resource_type: &str,
    action_code: &str,
    user_id: Option<i64>,
    resource_owner_id: Option<i64>,
    self_excluded_grant: Option<astral_types::GrantId>,
) -> Result<SodCheckResult, sqlx::Error> {
    let mut conflict: Option<SodCheckResult> = None;
    {
        for policy in &snapshot.static_policies {
            let is_a = policy.permission_a.as_deref() == Some(perm_key);
            let is_b = policy.permission_b.as_deref() == Some(perm_key);
            if !is_a && !is_b {
                continue;
            }

            let partner = if is_a {
                &policy.permission_b
            } else {
                &policy.permission_a
            };
            let partner = match partner {
                Some(p) => p,
                None => continue,
            };

            let parts: Vec<&str> = partner.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }

            // 生效授权匹配（in-memory，零额外 I/O）：任一生效 grant 命中即冲突。
            let mut has_conflict = evidence.effective_grants.iter().any(|grant| {
                Some(grant.grant_id) != self_excluded_grant
                    && sod_partner_matches_grant(&grant.resource, &grant.action, parts[0], parts[1])
            });
            if !has_conflict {
                has_conflict = org_contributions.is_some_and(|contributions| {
                    contributions.iter().any(|contribution| {
                        org_sod_contribution_matches_partner(contribution, parts[0], parts[1])
                    })
                });
            }
            if has_conflict {
                conflict = Some(SodCheckResult {
                    has_conflict: true,
                    conflict_policy: Some(policy.policy_name.clone()),
                    conflict_permission: Some(partner.clone()),
                    conflict_type: Some("STATIC".into()),
                });
                break;
            }
        }
    }

    // === DYNAMIC 策略检查（对齐 Java SodService.checkDynamicSoD） ===
    if conflict.is_none() {
        for policy in snapshot
            .dynamic_policies
            .iter()
            .filter(|policy| dynamic_policy_matches_request(policy, resource_type, action_code))
        {
            let script = policy.condition_script.as_deref().ok_or_else(|| {
                sod_condition_error("active dynamic SoD policy has no condition script")
            })?;
            if script.len() > MAX_DYNAMIC_CONDITION_SCRIPT_BYTES {
                return Err(sod_condition_error(
                    "active dynamic SoD condition exceeds the configured script limit",
                ));
            }

            // 评估条件脚本（仅支持 exact resourceOwnerId == currentUserId 语法）。
            let triggered = evaluate_dynamic_condition(script, user_id, resource_owner_id)?;

            if triggered {
                conflict = Some(SodCheckResult {
                    has_conflict: true,
                    conflict_policy: Some(policy.policy_name.clone()),
                    conflict_permission: Some(format!("DYNAMIC: {}", script)),
                    conflict_type: Some("DYNAMIC".into()),
                });
                break;
            }
        }
    }

    Ok(conflict.unwrap_or(SodCheckResult {
        has_conflict: false,
        conflict_policy: None,
        conflict_permission: None,
        conflict_type: None,
    }))
}

/// STATIC 策略行
#[derive(Debug, Clone, sqlx::FromRow)]
struct StaticPolicy {
    policy_name: String,
    permission_a: Option<String>,
    permission_b: Option<String>,
}

/// DYNAMIC 策略行（含请求侧过滤维度：缓存条目携带全量行，resource_type/
/// action_code 过滤在内存执行，见 [`dynamic_policy_matches_request`]）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct DynamicPolicy {
    policy_name: String,
    condition_script: Option<String>,
    resource_type: Option<String>,
    action_code: Option<String>,
}

/// DYNAMIC 策略的请求侧过滤（纯逻辑）：谓词与缓存前直查 SQL 的
/// `(resource_type IS NULL OR resource_type = ?) AND (action_code IS NULL
/// OR action_code = ?)` 对齐。
///
/// 注记：MySQL ci collation 下 SQL `=` 对 ASCII 大小写不敏感；内存过滤按
/// ASCII 大小写不敏感比较，对规范小写标识符（ResourceRegistry 同源的
/// resource type / action code）两者匹配集逐项一致；策略行由管理端以规范
/// 标识符写入，非 ASCII 变体的极端差异为记录在案的残余风险。
fn dynamic_policy_matches_request(
    policy: &DynamicPolicy,
    resource_type: &str,
    action_code: &str,
) -> bool {
    let resource_matches = policy
        .resource_type
        .as_deref()
        .is_none_or(|stored| stored.eq_ignore_ascii_case(resource_type));
    let action_matches = policy
        .action_code
        .as_deref()
        .is_none_or(|stored| stored.eq_ignore_ascii_case(action_code));
    resource_matches && action_matches
}

/// 将 SoD 门禁失败映射为数据库错误，沿现有调用链进入 503/fail-closed。
pub fn sod_gate_error(message: &str) -> sqlx::Error {
    sqlx::Error::Configuration(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.to_string(),
    )))
}

/// 将动态 SoD 语义错误映射为数据库错误，沿现有调用链进入 503/fail-closed。
fn sod_condition_error(message: &str) -> sqlx::Error {
    sqlx::Error::Configuration(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.to_string(),
    )))
}

/// Validate the only supported DYNAMIC SoD expression before persisting a policy.
///
/// The grammar is exactly `resourceOwnerId == currentUserId`, with optional
/// whitespace between tokens. Unknown operators or trailing tokens are rejected.
pub fn validate_dynamic_sod_condition_script(
    script: &str,
) -> Result<(), astral_types::AstralError> {
    if parse_dynamic_condition(script).is_some() {
        Ok(())
    } else {
        Err(astral_types::AstralError::Validation(
            "condition_script must match resourceOwnerId == currentUserId".into(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DynamicCondition {
    ResourceOwnerEqualsCurrentUser,
}

fn parse_dynamic_condition(script: &str) -> Option<DynamicCondition> {
    let remainder = script.trim().strip_prefix("resourceOwnerId")?.trim_start();
    let remainder = remainder.strip_prefix("==")?.trim_start();
    let remainder = remainder.strip_prefix("currentUserId")?.trim();
    remainder
        .is_empty()
        .then_some(DynamicCondition::ResourceOwnerEqualsCurrentUser)
}

/// Evaluate the exact DYNAMIC SoD expression grammar. Unknown expressions and
/// missing authenticated/authoritative facts fail closed.
fn evaluate_dynamic_condition(
    script: &str,
    user_id: Option<i64>,
    resource_owner_id: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let condition = parse_dynamic_condition(script)
        .ok_or_else(|| sod_condition_error("unrecognized active dynamic SoD condition script"))?;
    match condition {
        DynamicCondition::ResourceOwnerEqualsCurrentUser => {
            let (Some(uid), Some(oid)) = (user_id, resource_owner_id) else {
                return Err(sod_condition_error(
                    "dynamic SoD owner condition requires authoritative owner fact",
                ));
            };
            Ok(uid == oid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ORG_SCOPE 复核 fixtures 需要的额外合同类型/构造入口。
    use astral_types::org_scope::{
        org_build_segment, org_manifest_digest_hex, OrgDependency, OrgGrantRef,
        OrgManifestDigestMaterial, OrgMembership, OrgNode, OrgPendingCode, OrgProvenance,
        OrgPublication, OrgRootActivation, OrgScope, OrgScopeKey, OrgSegmentContent, OrgSubject,
    };
    use astral_types::{
        BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantIdentityKey, GrantProvenance,
        GrantRevision, GrantSourceKind, GrantState, PublicationSeal,
        PublishedAggregateManifestSummary, PublishedCardAuthorization,
        PublishedCardAuthorizationGate, PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
        VerifiedPublishedGrantRecord,
    };

    // ===== resource_key 归一化（scoped key → plain type） =====

    #[test]
    fn scoped_resource_keys_normalize_to_plain_type() {
        // 通配 scoped key → plain type
        assert_eq!(sod_resource_type_from_scoped_key("approval:*"), "approval");
        // 具体 id scoped key → plain type
        assert_eq!(sod_resource_type_from_scoped_key("approval:42"), "approval");
        // plain key 原样返回
        assert_eq!(sod_resource_type_from_scoped_key("approval"), "approval");
        // 多段 key：与 permission_query::parse_resource_type 一致按最后一个冒号截断
        assert_eq!(
            sod_resource_type_from_scoped_key("doc:report:7"),
            "doc:report"
        );
        // 归一结果必须与 scoped 原文不同（旧实现的直接字符串比较正是漏报根因）
        assert_ne!(
            sod_resource_type_from_scoped_key("approval:*"),
            "approval:*"
        );
    }

    // ===== STATIC partner 归一匹配 =====

    fn published_sod_grant(resource: &str, action: &str, seed: u32) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&format!("00000000-0000-4000-8000-{seed:012}"))
                .expect("valid fixture grant id"),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Direct,
            binding_layer: BindingLayer::None,
            tenant: TenantScope::new(7, None).expect("valid fixture tenant"),
            card_id: 17,
            user_id: 42,
            resource: resource.to_owned(),
            action: action.to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: "card-17".to_owned(),
                source_entry: Some(format!("entry-{seed}")),
                binding_id: None,
                delegation_id: None,
                operation_id: "sod-fixture-operation".to_owned(),
                event_id: Some("sod-fixture-event".to_owned()),
                actor_user_id: None,
            },
        }
    }

    fn published_sod_evidence(grants: Vec<CanonicalGrant>) -> PublishedCardAuthorization {
        let record_count = grants.len();
        let records = grants
            .iter()
            .enumerate()
            .map(|(index, grant)| VerifiedPublishedGrantRecord {
                aggregate_type: "USER_CARD".to_owned(),
                aggregate_id: 17,
                publication_generation: 1,
                revoke_fence: 0,
                manifest_id: 101,
                event_id: "sod-fixture-event".to_owned(),
                operation_id: "sod-fixture-operation".to_owned(),
                semantic_hash_hex: "a".repeat(64),
                dependency_hash_hex: "b".repeat(64),
                compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
                segment_ordinal: 0,
                position_in_segment: index as u64,
                grant: grant.clone(),
                accepted_into_effective_set: true,
                unaccepted_reason: None,
            })
            .collect();
        let manifest = PublishedAggregateManifestSummary {
            seal: PublicationSeal::from_unix_seconds(1_700_000_000).expect("valid fixture seal"),
            tenant_id: 7,
            card_id: 17,
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            manifest_id: 101,
            generation: 1,
            source_generation: 1,
            projected_generation: 1,
            revoke_fence: 0,
            cas_version: 1,
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            manifest_digest_hex: "c".repeat(64),
            compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
            event_id: "sod-fixture-event".to_owned(),
            operation_id: "sod-fixture-operation".to_owned(),
            parent_manifest_id: None,
            segment_count: 1,
            declared_grant_row_count: record_count as u64,
        };
        PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 17,
            read_unix_seconds: 1_700_000_000,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: record_count,
                effective_grant_count: record_count,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![manifest],
            records,
            effective_grants: grants,
        }
    }

    fn direct_update_before_image(rule_id: i64) -> DirectGrantSodUpdateBeforeImage<'static> {
        DirectGrantSodUpdateBeforeImage {
            rule_tenant_id: Some(7),
            source_card_tenant_id: Some(7),
            domain_id: None,
            card_id: 17,
            user_id: 42,
            rule_id,
            source_type: "MANUAL",
            enabled: Some(1),
            effect: "ALLOW",
            resource_type: "approval",
            resource_id: None,
            action_code: "approve",
            condition_json: None,
            valid_from: None,
            valid_to: None,
        }
    }

    fn locked_sod_card_scope() -> LockedSodCardScope {
        LockedSodCardScope {
            card_id: 17,
            tenant_id: Some(7),
            domain_id: None,
            user_id: Some(42),
        }
    }

    fn direct_grant_for_rule(rule_id: i64, resource: &str, action: &str) -> CanonicalGrant {
        let grant_id = GrantIdentityKey::direct(
            TenantScope::new(7, None).unwrap(),
            "17",
            &rule_id.to_string(),
        )
        .unwrap()
        .derive_grant_id()
        .unwrap();
        CanonicalGrant {
            grant_id,
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Direct,
            binding_layer: BindingLayer::None,
            tenant: TenantScope::new(7, None).unwrap(),
            card_id: 17,
            user_id: 42,
            resource: astral_types::build_resource_key(resource, None),
            action: action.to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: "17".to_owned(),
                source_entry: Some(rule_id.to_string()),
                binding_id: None,
                delegation_id: None,
                operation_id: "sod-fixture-operation".to_owned(),
                event_id: Some("sod-fixture-event".to_owned()),
                actor_user_id: None,
            },
        }
    }

    fn sod_static_policy(permission_a: &str, permission_b: &str) -> StaticPolicy {
        StaticPolicy {
            policy_name: "exclusive-review-submit".to_owned(),
            permission_a: Some(permission_a.to_owned()),
            permission_b: Some(permission_b.to_owned()),
        }
    }

    #[test]
    fn direct_update_excludes_only_exact_self_grant_and_keeps_second_conflicting_grant() {
        let before = direct_update_before_image(101);
        let self_grant = direct_grant_for_rule(101, "approval", "approve");
        let second_grant = direct_grant_for_rule(102, "approval", "approve");
        let identity = prove_direct_update_self_exclusion(
            &published_sod_evidence(vec![self_grant.clone()]),
            &before,
            locked_sod_card_scope(),
            17,
        )
        .expect("the exact published direct before-image must be provable");
        assert_eq!(identity, self_grant.grant_id);

        let policies = SodPolicySnapshot {
            static_policies: vec![sod_static_policy("approval:submit", "approval:approve")],
            dynamic_policies: Vec::new(),
        };
        let only_self = published_sod_evidence(vec![self_grant.clone()]);
        only_self
            .validate()
            .expect("valid current published before-image");
        let create_conflict = evaluate_sod_conflicts(
            "approval:submit",
            &only_self,
            &policies,
            None,
            "approval",
            "submit",
            None,
            None,
            None,
        )
        .expect("CREATE retains every held grant");
        assert!(create_conflict.has_conflict);
        let no_self_conflict = evaluate_sod_conflicts(
            "approval:submit",
            &only_self,
            &policies,
            None,
            "approval",
            "submit",
            None,
            None,
            Some(identity),
        )
        .expect("the proven self identity alone is omitted from STATIC matching");
        assert!(!no_self_conflict.has_conflict);

        let self_and_second = published_sod_evidence(vec![self_grant, second_grant]);
        let remaining_conflict = evaluate_sod_conflicts(
            "approval:submit",
            &self_and_second,
            &policies,
            None,
            "approval",
            "submit",
            None,
            None,
            Some(identity),
        )
        .expect("other published grants must remain in STATIC matching");
        assert!(remaining_conflict.has_conflict);
    }

    #[test]
    fn direct_update_scope_and_wrong_exclusion_fail_closed() {
        let before = direct_update_before_image(101);
        assert!(validate_direct_update_scope(&before, locked_sod_card_scope(), 17).is_ok());
        assert!(validate_direct_update_scope(&before, locked_sod_card_scope(), 18).is_err());

        let mismatched_rule_tenant = DirectGrantSodUpdateBeforeImage {
            rule_tenant_id: Some(8),
            ..before
        };
        assert!(
            validate_direct_update_scope(&mismatched_rule_tenant, locked_sod_card_scope(), 17)
                .is_err()
        );
        let mismatched_card_tenant = DirectGrantSodUpdateBeforeImage {
            source_card_tenant_id: Some(8),
            ..before
        };
        assert!(
            validate_direct_update_scope(&mismatched_card_tenant, locked_sod_card_scope(), 17)
                .is_err()
        );
        let mismatched_domain = DirectGrantSodUpdateBeforeImage {
            domain_id: Some(88),
            ..before
        };
        assert!(
            validate_direct_update_scope(&mismatched_domain, locked_sod_card_scope(), 17).is_err()
        );

        let mut wrong_grant = direct_grant_for_rule(101, "approval", "review");
        let wrong_id = wrong_grant.grant_id;
        wrong_grant.provenance.source_entry = Some("102".to_owned());
        let mut wrong_evidence = published_sod_evidence(vec![wrong_grant]);
        wrong_evidence.records[0].grant.grant_id = wrong_id;
        assert!(prove_direct_update_self_exclusion(
            &wrong_evidence,
            &before,
            locked_sod_card_scope(),
            17
        )
        .is_err());

        let other_grant = direct_grant_for_rule(102, "approval", "approve");
        assert!(prove_direct_update_self_exclusion(
            &published_sod_evidence(vec![other_grant]),
            &before,
            locked_sod_card_scope(),
            17
        )
        .is_err());
    }

    #[test]
    fn published_static_grant_conflict_is_detected_from_valid_card_evidence() {
        let evidence =
            published_sod_evidence(vec![published_sod_grant("approval:*", "approve", 1)]);
        evidence
            .validate()
            .expect("fixture is valid published evidence");
        let snapshot = SodPolicySnapshot {
            static_policies: vec![sod_static_policy("approval:submit", "approval:approve")],
            dynamic_policies: Vec::new(),
        };

        let result = evaluate_sod_conflicts(
            "approval:submit",
            &evidence,
            &snapshot,
            None,
            "approval",
            "submit",
            None,
            None,
            None,
        )
        .expect("published STATIC policy evaluation succeeds");
        assert!(result.has_conflict);
        assert_eq!(
            result.conflict_policy.as_deref(),
            Some("exclusive-review-submit")
        );
        assert_eq!(
            result.conflict_permission.as_deref(),
            Some("approval:approve")
        );
        assert_eq!(result.conflict_type.as_deref(), Some("STATIC"));
    }

    #[test]
    fn empty_published_evidence_has_no_static_conflict() {
        let evidence = published_sod_evidence(Vec::new());
        evidence
            .validate()
            .expect("empty published evidence is valid");
        let snapshot = SodPolicySnapshot {
            static_policies: vec![sod_static_policy("approval:submit", "approval:approve")],
            dynamic_policies: Vec::new(),
        };
        let result = evaluate_sod_conflicts(
            "approval:submit",
            &evidence,
            &snapshot,
            None,
            "approval",
            "submit",
            None,
            None,
            None,
        )
        .expect("published-only evaluation succeeds");
        assert!(!result.has_conflict);
    }

    #[test]
    fn grant_dynamic_policy_with_missing_user_or_owner_facts_fails_closed() {
        let evidence = published_sod_evidence(Vec::new());
        let snapshot = SodPolicySnapshot {
            static_policies: Vec::new(),
            dynamic_policies: vec![DynamicPolicy {
                policy_name: "owner-only".to_owned(),
                condition_script: Some("resourceOwnerId == currentUserId".to_owned()),
                resource_type: Some("approval".to_owned()),
                action_code: Some("submit".to_owned()),
            }],
        };
        for (user_id, owner_id) in [(None, None), (Some(42), None), (None, Some(42))] {
            assert!(evaluate_sod_conflicts(
                "approval:submit",
                &evidence,
                &snapshot,
                None,
                "approval",
                "submit",
                user_id,
                owner_id,
                None,
            )
            .is_err());
        }
    }

    #[test]
    fn partner_matching_uses_normalized_resource_type_and_exact_action() {
        // scoped key 归一后命中 plain partner
        assert!(sod_partner_matches_grant(
            "approval:*",
            "submit",
            "approval",
            "submit"
        ));
        assert!(sod_partner_matches_grant(
            "approval:42",
            "submit",
            "approval",
            "submit"
        ));
        // plain grant 同样命中
        assert!(sod_partner_matches_grant(
            "approval", "submit", "approval", "submit"
        ));
        // action 不匹配 → 不命中
        assert!(!sod_partner_matches_grant(
            "approval:*",
            "review",
            "approval",
            "submit"
        ));
        // 归一后 type 不匹配 → 不命中
        assert!(!sod_partner_matches_grant(
            "audit:*", "submit", "approval", "submit"
        ));
    }

    // ===== evidence 门禁错误形状（稳定前缀 + 错误族） =====

    #[test]
    fn sod_evidence_error_message_keeps_stable_family_prefixes() {
        let not_ready = AuthorizationEvidenceError::NotReady(
            "code=published_card_evidence.current_pointer_missing;tenant=1;card=7".into(),
        );
        let message = sod_evidence_error_message(7, &not_ready);
        assert!(message.starts_with("sod_card_evidence_not_ready;"));
        assert!(message.contains("card_id=7"));
        assert!(message.contains("current_pointer_missing"));

        let corrupt = AuthorizationEvidenceError::Corrupt(
            "code=published_card_evidence.pointer_moved_under_read".into(),
        );
        let message = sod_evidence_error_message(8, &corrupt);
        assert!(message.starts_with("sod_card_evidence_corrupt;"));
        assert!(message.contains("card_id=8"));
        assert!(message.contains("pointer_moved_under_read"));

        let invalid = AuthorizationEvidenceError::InvalidRequest(
            "code=published_card_evidence.invalid_scope;detail=non-positive tenant".into(),
        );
        let message = sod_evidence_error_message(9, &invalid);
        assert!(message.starts_with("sod_card_evidence_invalid_scope;"));
        assert!(message.contains("card_id=9"));
    }

    #[test]
    fn sod_evidence_contract_failure_keeps_corrupt_prefix() {
        let message = sod_evidence_contract_message(11, "gate counters disagree");
        assert!(message.starts_with("sod_card_evidence_corrupt;"));
        assert!(message.contains("card_id=11"));
        assert!(message.contains("gate counters disagree"));
    }

    #[test]
    fn sod_card_tenant_missing_message_is_stable() {
        // 行缺失（tenant 记 0）
        let message = sod_card_tenant_missing_message(13, 0);
        assert!(message.starts_with("sod_card_tenant_missing;"));
        assert!(message.contains("card_id=13"));
        assert!(message.contains("tenant_id=0"));

        // tenant 非正
        let message = sod_card_tenant_missing_message(14, -3);
        assert!(message.starts_with("sod_card_tenant_missing;"));
        assert!(message.contains("tenant_id=-3"));
    }

    #[test]
    fn sod_gate_error_is_configuration_family_with_message_preserved() {
        let error = sod_gate_error("sod_card_evidence_not_ready;card_id=17");
        match error {
            sqlx::Error::Configuration(boxed) => {
                let message = boxed.to_string();
                assert!(
                    message.contains("sod_card_evidence_not_ready"),
                    "gate failure must keep the stable prefix, got: {message}"
                );
                assert!(message.contains("card_id=17"));
            }
            other => panic!("gate failure must map onto sqlx::Error::Configuration, got {other:?}"),
        }
    }

    // ===== 形状守卫（evidence 调用顺序 + 旧链读取清除） =====

    /// Shape guard: the pre-grant and host paths derive the card tenant and pass
    /// through the strict cache-aware published-evidence reader before policy
    /// evaluation; unreadable evidence cannot become a conflict-free result.
    #[test]
    fn sod_paths_require_published_evidence_before_evaluation() {
        let source = include_str!("sod_check.rs");
        let body = fn_body_after(source, "async fn check_published_sod_conflict(");
        let tenant = body
            .find("sod_load_card_tenant(pool, card_id)")
            .expect("tenant resolution must exist");
        let scope = body
            .find("PublishedCardEvidenceScope {")
            .expect("card-level evidence scope construction must exist");
        let reader = body
            .find("cached_load_published_card_grant_evidence(pool, &scope)")
            .expect("evidence reads must use the pointer-fenced cache entry");
        let validate = body
            .find("evidence.validate()")
            .expect("evidence must be revalidated");
        let evaluate = body
            .find("evaluate_sod_conflicts(")
            .expect("published evidence must feed the pure evaluator");
        assert!(tenant < scope && scope < reader && reader < validate && validate < evaluate);
        assert!(!body.contains("permission_rule_snapshot"));
        assert!(!body.contains("FROM permission_rule WHERE"));
    }

    /// Full production-source guard: obsolete CARD-head and legacy snapshot
    /// reads are absent; published evidence is the only SoD grant source.
    #[test]
    fn legacy_head_gate_and_snapshot_reads_are_gone_from_sod_check() {
        let source = include_str!("sod_check.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module must be separable");

        assert!(
            !production.contains("permission_rule_snapshot"),
            "legacy snapshot table must not be read by SoD any more"
        );
        assert!(
            !production.contains("authorization_projection_head"),
            "legacy CARD head gate must not be read by SoD any more"
        );
        assert!(!production.contains("ensure_sod_card_gate_readable"));
        assert!(!production.contains("ensure_sod_card_gate_unchanged"));
        assert!(!production.contains("SOD_STATIC_CONFLICT_SQL"));
        assert!(!production.contains("SOD_RAW_RULE_CONFLICT_SQL"));
        assert!(!production.contains("FROM permission_rule"));
        assert!(!production.contains("pub async fn check_sod_conflict("));
        assert!(!production.contains("pub async fn check_sod_conflict_with_org("));
        assert!(!production.contains("SodReadPath"));

        // Native pre-grant and post-ALLOW paths retain strict published evidence.
        assert!(production.contains("pub async fn check_grant_sod_conflict("));
        assert!(production.contains("check_published_sod_conflict("));
        // 新链数据通路在位（经指针对牌的进程内 evidence 缓存入口回源严格 reader）
        assert!(production.contains("cached_load_published_card_grant_evidence"));
        assert!(production.contains("sod_load_card_tenant"));
        assert!(production.contains("sod_resource_type_from_scoped_key"));
    }

    // ===== DYNAMIC 策略内存过滤（谓词对齐原 SQL） =====

    /// `(resource_type IS NULL OR resource_type = ?) AND (action_code IS NULL
    /// OR action_code = ?)` 的内存等价谓词：NULL 维度恒匹配；非 NULL 维度按
    /// ASCII 大小写不敏感精确比较（规范小写标识符下与 ci collation 一致）。
    #[test]
    fn dynamic_condition_requires_exact_grammar_and_known_operator() {
        assert!(
            validate_dynamic_sod_condition_script(" resourceOwnerId   == currentUserId ").is_ok()
        );
        for rejected in [
            "resourceOwnerId != currentUserId",
            "resourceOwnerId === currentUserId",
            "resourceOwnerId == currentUserId || true",
            "resourceOwnerId == currentUserId == 1",
            "other == currentUserId",
            "resourceOwnerId == unknown",
            "resourceOwnerId currentUserId",
            "resourceOwnerId == currentUserId trailing",
            "",
        ] {
            assert!(
                validate_dynamic_sod_condition_script(rejected).is_err(),
                "expression must be rejected: {rejected:?}"
            );
            assert!(
                evaluate_dynamic_condition(rejected, Some(7), Some(7)).is_err(),
                "unsupported runtime expression must fail closed: {rejected:?}"
            );
        }
    }

    #[test]
    fn dynamic_policy_filter_matches_sql_predicate() {
        let policy = |resource_type: Option<&str>, action_code: Option<&str>| DynamicPolicy {
            policy_name: "p".into(),
            condition_script: Some("resourceOwnerId == currentUserId".into()),
            resource_type: resource_type.map(str::to_owned),
            action_code: action_code.map(str::to_owned),
        };

        // 双 NULL → 恒匹配。
        assert!(dynamic_policy_matches_request(
            &policy(None, None),
            "approval",
            "submit"
        ));
        // 单边 NULL → 另一边决定。
        assert!(dynamic_policy_matches_request(
            &policy(Some("approval"), None),
            "approval",
            "submit"
        ));
        assert!(!dynamic_policy_matches_request(
            &policy(Some("approval"), None),
            "audit",
            "submit"
        ));
        assert!(dynamic_policy_matches_request(
            &policy(None, Some("submit")),
            "approval",
            "submit"
        ));
        assert!(!dynamic_policy_matches_request(
            &policy(None, Some("review")),
            "approval",
            "submit"
        ));
        // 双边精确匹配 / 任一边不匹配。
        assert!(dynamic_policy_matches_request(
            &policy(Some("approval"), Some("submit")),
            "approval",
            "submit"
        ));
        assert!(!dynamic_policy_matches_request(
            &policy(Some("approval"), Some("submit")),
            "approval",
            "review"
        ));
        assert!(!dynamic_policy_matches_request(
            &policy(Some("approval"), Some("submit")),
            "audit",
            "submit"
        ));
        // ASCII 大小写不敏感（对齐 ci collation 的常规标识符行为）。
        assert!(dynamic_policy_matches_request(
            &policy(Some("Approval"), Some("Submit")),
            "approval",
            "submit"
        ));
    }

    // ===== sod_policy 进程缓存 =====

    /// TTL 边界（纯逻辑，对齐 cache_epoch 的新鲜度边界语义）：恰好到达 TTL
    /// 即不新鲜。
    #[test]
    fn sod_policy_cache_freshness_honors_ttl_boundary() {
        let cached_at = Instant::now();
        assert!(sod_policy_cache_is_fresh(cached_at, cached_at));
        assert!(sod_policy_cache_is_fresh(
            cached_at,
            cached_at + SOD_POLICY_CACHE_TTL - Duration::from_secs(1)
        ));
        assert!(!sod_policy_cache_is_fresh(
            cached_at,
            cached_at + SOD_POLICY_CACHE_TTL
        ));
        assert!(!sod_policy_cache_is_fresh(
            cached_at,
            cached_at + SOD_POLICY_CACHE_TTL + Duration::from_secs(1)
        ));
    }

    /// TTL 常量钉死（30s，不超过 60s 上限）——配置不回退。
    #[test]
    fn sod_policy_cache_ttl_stays_bounded() {
        assert_eq!(SOD_POLICY_CACHE_TTL, Duration::from_secs(30));
        assert!(SOD_POLICY_CACHE_TTL <= Duration::from_secs(60));
    }

    /// 进程缓存往返 + evict：写入后 TTL 内命中同一快照；evict 后立即 miss
    /// （写路径钩子的失效语义）。
    #[test]
    fn sod_policy_cache_roundtrip_then_evict() {
        let snapshot = SodPolicySnapshot {
            static_policies: vec![StaticPolicy {
                policy_name: "approval-submit".into(),
                permission_a: Some("approval:submit".into()),
                permission_b: Some("approval:approve".into()),
            }],
            dynamic_policies: vec![DynamicPolicy {
                policy_name: "owner-only".into(),
                condition_script: Some("resourceOwnerId == currentUserId".into()),
                resource_type: Some("doc".into()),
                action_code: None,
            }],
        };

        // 独占本测试的全局缓存状态：先清空，再验证 store → fresh → evict。
        *sod_policy_cache().write().unwrap() = None;
        assert!(fresh_sod_policy_snapshot().is_none());

        store_sod_policy_snapshot(snapshot.clone());
        let cached = fresh_sod_policy_snapshot().expect("fresh snapshot");
        assert_eq!(cached.static_policies.len(), 1);
        assert_eq!(cached.dynamic_policies.len(), 1);
        assert_eq!(
            cached.static_policies[0].policy_name,
            snapshot.static_policies[0].policy_name
        );

        evict_sod_policy_cache();
        assert!(
            fresh_sod_policy_snapshot().is_none(),
            "evict must invalidate the process cache immediately"
        );
    }

    /// 既有 TTL 语义读取（测试专用等价路径；生产走 `serve_sod_policy_snapshot`
    /// 的矩阵判定，本 helper 直接钉 TTL 行为，不触碰任何 hub 全局态）。
    fn fresh_sod_policy_snapshot() -> Option<SodPolicySnapshot> {
        let cached = sod_policy_cache().read().ok()?;
        let entry = cached.as_ref()?;
        if sod_policy_cache_is_fresh(entry.cached_at, Instant::now()) {
            return Some(entry.snapshot.clone());
        }
        None
    }

    /// 源文本守卫助手：取 `start_marker` 之后到下一个函数声明（任意
    /// pub/async 组合）之间的函数体片段，保证形状断言不越界。
    fn fn_body_after<'a>(source: &'a str, start_marker: &str) -> &'a str {
        let after = source
            .split(start_marker)
            .nth(1)
            .expect("marker must exist");
        let end = ["\nfn ", "\nasync fn ", "\npub fn ", "\npub async fn "]
            .iter()
            .filter_map(|marker| after.find(marker))
            .min()
            .unwrap_or(after.len());
        &after[..end]
    }

    // ===== composite 模式切换：服务/回源判定矩阵（纯逻辑） =====

    /// 服务矩阵：composite 只认 token 绑定 + TTL 新鲜的条目（TTL 是既有
    /// 缓存/失效合同的条目寿命上界，过期即回填，绝不因 token 未变信任过期
    /// 条目）；模式错位一律 miss；非 composite 沿用 TTL。
    #[test]
    fn sod_policy_serve_matrix_pins_mode_binding() {
        // composite + 绑定条目：token 一致 **且** TTL 新鲜才服务。
        assert!(sod_policy_entry_serves(true, true, true, true));
        // token 未变但 TTL 过期 → miss（过期触发回填，不信任过期条目）。
        assert!(!sod_policy_entry_serves(true, true, true, false));
        // token 漂移（哪怕 TTL 新鲜）→ miss。
        assert!(!sod_policy_entry_serves(true, true, false, true));
        // composite + 未绑定条目（模式错位）：绝不服务（TTL 新鲜也不行）。
        assert!(!sod_policy_entry_serves(true, false, false, true));
        // 非 composite + 绑定条目（模式错位）：绝不服务。
        assert!(!sod_policy_entry_serves(false, true, true, true));
        // 非 composite + 未绑定条目：既有 TTL 语义。
        assert!(sod_policy_entry_serves(false, false, false, true));
        assert!(!sod_policy_entry_serves(false, false, false, false));
    }

    /// 回源矩阵：composite 回源前 hub 严格读 token 必须可读；writer-active/
    /// unknown → `Blocked`（fail-closed，绝不以并发/未知 source 状态回源或
    /// 放行）；非 composite → `Legacy`（既有行为，不触碰 token）。
    #[test]
    fn sod_policy_refill_outcome_blocks_writer_active_and_unknown() {
        assert_eq!(
            sod_policy_refill_outcome(true, true),
            SodPolicyRefillOutcome::Bound
        );
        assert_eq!(
            sod_policy_refill_outcome(true, false),
            SodPolicyRefillOutcome::Blocked
        );
        assert_eq!(
            sod_policy_refill_outcome(false, false),
            SodPolicyRefillOutcome::Legacy
        );
    }

    // ===== 有界回填：cap+1 探针 + 字节预算（纯逻辑） =====

    fn sod_policy_row(name: &str) -> StaticPolicy {
        StaticPolicy {
            policy_name: name.to_owned(),
            permission_a: Some("approval:submit".to_owned()),
            permission_b: Some("approval:approve".to_owned()),
        }
    }

    #[test]
    fn bounded_sod_policy_snapshot_rejects_over_cap_and_over_budget() {
        // cap+1 探针：读满 cap+1 行即超限 fail-closed（截断快照 = 放行方向）。
        let over_cap = vec![sod_policy_row("p"); SOD_POLICY_SNAPSHOT_ROW_CAP + 1];
        let error = bounded_sod_policy_snapshot(over_cap, Vec::new())
            .expect_err("over-cap static rows must fail closed");
        assert!(
            error
                .to_string()
                .contains("sod_policy_snapshot_capacity_exceeded"),
            "unexpected error: {error}"
        );

        let over_cap_dynamic = vec![
            DynamicPolicy {
                policy_name: "p".into(),
                condition_script: Some("resourceOwnerId == currentUserId".into()),
                resource_type: None,
                action_code: None,
            };
            SOD_POLICY_SNAPSHOT_ROW_CAP + 1
        ];
        let error = bounded_sod_policy_snapshot(Vec::new(), over_cap_dynamic)
            .expect_err("over-cap dynamic rows must fail closed");
        assert!(error
            .to_string()
            .contains("sod_policy_snapshot_capacity_exceeded"));

        // 字节预算：异常膨胀行超预算 fail-closed。
        let bloated = vec![sod_policy_row(&"x".repeat(SOD_POLICY_SNAPSHOT_MAX_BYTES / 2 + 1)); 2];
        let error = bounded_sod_policy_snapshot(bloated, Vec::new())
            .expect_err("over-budget snapshot must fail closed");
        assert!(
            error
                .to_string()
                .contains("sod_policy_snapshot_byte_budget_exceeded"),
            "unexpected error: {error}"
        );

        // 正常规模照常装配。
        let ok = bounded_sod_policy_snapshot(vec![sod_policy_row("p")], Vec::new())
            .expect("bounded snapshot must assemble");
        assert_eq!(ok.static_policies.len(), 1);
    }

    #[test]
    fn sod_policy_snapshot_bytes_counts_string_fields() {
        let snapshot = SodPolicySnapshot {
            static_policies: vec![StaticPolicy {
                policy_name: "ab".into(),
                permission_a: Some("cd".into()),
                permission_b: None,
            }],
            dynamic_policies: vec![DynamicPolicy {
                policy_name: "e".into(),
                condition_script: Some("fgh".into()),
                resource_type: Some("ij".into()),
                action_code: None,
            }],
        };
        assert_eq!(sod_policy_snapshot_bytes(&snapshot), 2 + 2 + 1 + 3 + 2);
    }

    // ===== 形状守卫：composite warm 零 SQL + 有界 single-flight 回源 =====

    /// 形状守卫：warm 记忆路径（`try_check_sod_conflict_from_memory`）必须是
    /// 零 SQL 读面——只允许 hub 记忆证据 + token 绑定策略缓存 + 纯评估；
    /// 任何 defer 必须返回 `Ok(None)` 回落 durable 链，绝不折算"无冲突"。
    #[test]
    fn memory_warm_path_is_zero_sql_and_defers_to_durable() {
        let source = include_str!("sod_check.rs");
        let body = fn_body_after(source, "async fn try_check_sod_conflict_from_memory");

        assert!(
            body.contains("hub: &crate::memory_projection_hub::MemoryProjectionHub"),
            "the memory path receives the hub from the context entry (composite-only)"
        );
        assert!(body.contains("MemoryEvidenceOutcome::Serve"));
        assert!(
            body.contains("MemoryEvidenceOutcome::DeferToDurable => return Ok(None)"),
            "defer must fall back to the durable path, never to a no-conflict result"
        );
        assert!(body.contains("load_sod_policy_snapshot(pool)"));
        assert!(body.contains("evaluate_sod_conflicts("));
        assert!(body.contains("&evidence"));
        assert!(body.contains("evidence.validate()"));
        // 栅栏由 context 入口捕获一次并传入（本函数零采样）；返回前只比较
        // 传入栅栏（绝不重采 token 覆盖旧读）。
        assert!(
            body.contains("fence: AuxiliaryReadToken"),
            "the memory path must receive the single-captured fence from the context entry"
        );
        assert!(
            body.contains("if evidence.tenant_id != tenant_id || evidence.card_id != card_id"),
            "card evidence returned by the memory index must match the requested scope"
        );
        assert!(
            !body.contains("strict_read_token()"),
            "the memory path must not sample tokens itself"
        );
        assert!(
            body.contains("sod_memory_source_mutation_raced_read"),
            "post-eval drift must fail closed"
        );
        for sql_marker in [
            "query_scalar",
            "query_as",
            "fetch_one",
            "fetch_all",
            "FROM ",
        ] {
            assert!(
                !body.contains(sql_marker),
                "warm memory path must stay zero-SQL, found {sql_marker}"
            );
        }
    }

    /// SoD source contract guard: scoring uses published-only evidence;
    /// removed raw-source APIs and SQL must stay absent.
    #[test]
    fn sod_paths_are_published_only_and_legacy_raw_api_is_absent() {
        let source = include_str!("sod_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let evaluator = fn_body_after(production, "fn evaluate_sod_conflicts(");
        let evaluator = evaluator
            .split_once('{')
            .expect("evaluator must have a body")
            .1
            .split("\n}")
            .next()
            .unwrap();
        assert!(evaluator.contains("sod_partner_matches_grant"));
        assert!(!evaluator.contains("FROM permission_rule"));
        assert!(!evaluator.contains("sqlx::"));
        assert!(!production.contains("SOD_RAW_RULE_CONFLICT_SQL"));
        assert!(!production.contains("FROM permission_rule"));
        assert!(!production.contains("SodReadPath"));
        assert!(!production.contains("pub async fn check_sod_conflict("));
        assert!(!production.contains("pub async fn check_sod_conflict_with_org("));
        assert!(production.contains("pub async fn check_grant_sod_conflict("));
        assert!(production.contains("check_published_sod_conflict("));
    }

    /// 形状守卫：策略快照回源必须有界——`LIMIT cap+1` 探针、3s 查询
    /// deadline、single-flight 有界锁等待、composite 回填前后 strict token
    /// 对牌且绑定安装（竞争产物绝不入缓存）。
    #[test]
    fn sod_policy_refill_is_bounded_single_flight_and_token_fenced() {
        let source = include_str!("sod_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let refill = fn_body_after(production, "async fn refill_sod_policy_snapshot");

        assert!(
            refill.contains("sod_policy_refill_outcome("),
            "refill must decide composite blocking via the pure outcome matrix"
        );
        assert!(
            refill.contains("sod_policy_source_state_unavailable"),
            "writer-active/unknown must fail closed before any query"
        );
        assert!(
            refill.contains("SOD_POLICY_REFILL_LOCK_WAIT, sod_policy_refill_lock().lock()"),
            "refill must single-flight on a bounded lock wait"
        );
        assert!(refill.contains("SOD_POLICY_QUERY_DEADLINE"));
        assert!(
            refill.contains("SOD_POLICY_SNAPSHOT_ROW_CAP + 1"),
            "both ACTIVE queries must use the cap+1 probe"
        );
        assert_eq!(refill.matches("LIMIT {}").count(), 2, "no unlimited list");
        assert!(refill.contains("bounded_sod_policy_snapshot("));
        // composite：回填后复核 token 未漂移才允许绑定安装；安装后终检
        // 同样只比较（绝不重采新 token 覆盖旧读）；全程无二次采样 expect。
        let verify = refill
            .find("strict_read_matches(token)")
            .expect("post-read token recheck must exist");
        let store = refill
            .find("store_sod_policy_snapshot_bound(")
            .expect("composite refill must bind the cache entry to the hub token");
        let final_check = refill[store..]
            .find("strict_read_matches(token)")
            .map(|index| store + index)
            .expect("a post-install final token comparison must exist");
        assert!(
            verify < store && store < final_check,
            "order must be after-read recheck -> bound install -> after-install final check"
        );
        assert!(
            refill.contains("sod_policy_source_mutation_raced_install"),
            "post-install drift must fail closed (safe-pending, retryable)"
        );
        assert!(
            !refill.contains(".expect("),
            "the token must be captured exactly once; no second-sample expect may exist"
        );
        // deadline/锁等待常量钉死（与镜像 strict refill 同域 3s）。
        assert_eq!(SOD_POLICY_QUERY_DEADLINE, Duration::from_secs(3));
        assert_eq!(SOD_POLICY_REFILL_LOCK_WAIT, Duration::from_secs(3));
        // 容量上界钉死（const 块消除恒真断言告警）。
        const {
            assert!(SOD_POLICY_SNAPSHOT_ROW_CAP >= 1);
            assert!(SOD_POLICY_SNAPSHOT_MAX_BYTES <= 16 * 1024 * 1024);
        }
    }

    /// 形状守卫：mirrored org 准入装配必须复用辅助镜像的
    /// `load_org_authorization`（与引擎 evaluate 同一 strict read contract），
    /// Ready 走同一 provenance 解析器；Pending/Unavailable fail-closed；
    /// StrictRequired/Disabled/Unmanaged 回落既有 fresh DB 读。
    #[test]
    fn mirrored_org_admission_reuses_aux_mirror_and_maps_fail_closed() {
        let source = include_str!("sod_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let body = fn_body_after(production, "pub async fn load_org_sod_admission_mirrored");

        let mirror = body
            .find("auxiliary_authorization_mirror()")
            .expect("must reuse the global auxiliary mirror");
        let read = body
            .find("load_org_authorization(hub, ctx)")
            .expect("must reuse the aux mirror org port (same strict read contract)");
        assert!(mirror < read);
        assert!(body.contains("OrgAuthorityRead::Ready(evidence)"));
        assert!(body.contains("org_scope_sod_evidence_pending;"));
        assert!(body.contains("org_scope_sod_evidence_unavailable;"));
        // Ready 读面必须 fenced：before-await 单次采样 + after-await 比较；
        // 采样缺失或漂移一律 fail-closed。
        assert!(
            body.contains("Some(hub) => Some(hub.strict_read_token().ok_or_else(||"),
            "the mirrored org read must sample the strict token once before the await"
        );
        assert!(
            body.contains("org_scope_sod_source_mutation_raced_read"),
            "a fenced Ready read that drifted must fail closed"
        );
        // 回落 fresh DB 读在镜像 match 之后（权威路径裁决罕见状态）。
        let fallback = body
            .find("SqlxOrgScopeRepository::new(pool.clone())")
            .expect("fallback must keep the fresh durable read");
        assert!(
            read < fallback,
            "the durable fallback must follow the mirror attempt"
        );
        let deadline = body[fallback..]
            .find("tokio::time::timeout(")
            .expect("the fresh fallback must have a query deadline");
        let final_recheck = body[fallback..]
            .find("hub.strict_read_matches(token)")
            .expect("the fresh fallback must compare the original fence");
        assert!(deadline < final_recheck);
        assert_eq!(body.matches("strict_read_token()").count(), 1);
        assert!(body.contains("org_scope_sod_source_state_unavailable"));
    }

    /// Context-aware host and grant-time entries share fail-closed strict
    /// published-evidence semantics; each composite read uses its original token.
    #[test]
    fn context_and_grant_entries_retain_original_token_fences() {
        let source = include_str!("sod_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let entry = fn_body_after(production, "async fn check_sod_conflict_with_context_inner");
        let capture = entry
            .find("let Some(fence) = hub.strict_read_token()")
            .expect("the context entry must capture the fence exactly once");
        let blocked = entry
            .find("sod_context_source_state_unavailable")
            .expect("an installed hub with an unreadable token must fail closed, not fall back");
        let memory = entry
            .find("try_check_sod_conflict_from_memory(")
            .expect("context entry must try the warm memory path first");
        let durable = entry
            .find("check_published_sod_conflict(")
            .expect("context entry must keep the durable strict fallback");
        let cold_guard = entry
            .find("sod_context_source_mutation_raced_read")
            .expect("the cold durable fallback must end inside the same fence");
        assert!(
            capture < blocked && blocked < memory && memory < durable && durable < cold_guard,
            "order must be capture -> unreadable-token reject -> memory -> durable fallback -> fence recheck"
        );
        assert_eq!(
            entry.matches("strict_read_token").count(),
            1,
            "exactly one token sample; all checks are comparisons of the captured fence"
        );

        // The native pre-grant API captures and rechecks exactly one original token.
        let grant_entry = fn_body_after(production, "pub async fn check_grant_sod_conflict(");
        assert_eq!(grant_entry.matches("strict_read_token()").count(), 1);
        let capture = grant_entry
            .find("strict_read_token()")
            .expect("grant check must capture its source token");
        let read = grant_entry
            .find("check_published_sod_conflict(")
            .expect("grant check must use the published-only strict reader");
        let verify = grant_entry
            .rfind("strict_read_matches(fence)")
            .expect("grant check must recheck its original fence");
        assert!(capture < read && read < verify);
        assert!(grant_entry.contains("writer_active_or_unknown"));
        assert!(grant_entry.contains("sod_grant_source_mutation_raced_read"));
    }

    #[test]
    fn transactional_grant_sod_blocks_unpublished_adds_without_pool_or_cache_reads() {
        let source = include_str!("sod_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let body = fn_body_after(production, "pub async fn check_grant_sod_conflict_in_tx(");
        let card = body.find("FROM user_card").unwrap();
        let pending = body
            .find("sqlx::query_scalar(GRANT_SOD_PENDING_SQL)")
            .unwrap();
        let published = body
            .find("load_published_card_grant_evidence_in_tx(tx, &scope)")
            .unwrap();
        let policy = body
            .find("SELECT policy_name, permission_a, permission_b")
            .unwrap();
        let evaluate = body.find("evaluate_sod_conflicts(").unwrap();
        assert!(card < pending && pending < published && published < policy && policy < evaluate);
        assert!(GRANT_SOD_PENDING_SQL.contains("(card_id = ? OR card_id IS NULL)"));
        assert!(GRANT_SOD_PENDING_SQL.contains("status <> 'SUCCEEDED'"));
        assert!(GRANT_SOD_PENDING_SQL.contains("('ADD', 'UPDATE', 'REMOVE', 'REVOKE')"));
        assert!(GRANT_SOD_PENDING_SQL.contains("LIMIT 1 FOR UPDATE"));
        assert!(body.contains("FOR SHARE"));
        assert!(body.contains("bounded_sod_policy_snapshot"));
        assert!(!body.contains("fetch_all(pool)"));
        assert!(!body.contains("cached_load_published"));
        assert!(!body.contains("strict_read_token"));
        assert!(!body.contains("permission_rule"));
    }

    // ===== ORG_SCOPE 复核：权威 target-resource 事实（跨租户贡献/provenance） =====
    //
    // 覆盖点：TenantScoped 当前请求只认 resolver 写入的
    // `ctx.resource_tenant_id` / `ctx.resource_domain_id`；只有 Internal typed
    // calls 保留 actor 侧兼容 fallback（与组织准入同一合同）。每条贡献的持有判定
    // 按贡献自身的权威 resource tenant（已发布、合同校验过的事实）；actor/card
    // 租户只用于定位，不再滤掉发布事实，也无任何客户端头入口。

    /// 复核 fixture 的 publication/membership/card 租户（actor/card 侧）。
    const ORG_SOD_TENANT: i64 = 200;
    /// 已发布贡献的权威 resource tenant（跨租户资源事实）。
    const ORG_SOD_RESOURCE_TENANT: i64 = 300;

    fn org_sod_uuid(seed: u8) -> String {
        uuid::Uuid::from_u128(0xA57A_0000_0000_0000_0000_0000_0000_0000u128 | seed as u128)
            .to_string()
    }

    /// 单元共享分支贡献：scope 携带自身的权威 resource tenant / domain 事实。
    fn org_sod_shared_contribution(
        resource_tenant_id: i64,
        domain_id: Option<i64>,
    ) -> OrgContribution {
        OrgContribution {
            grant_ref: OrgGrantRef {
                tenant_id: ORG_SOD_TENANT,
                grant_id: org_sod_uuid(1),
                revision: 1,
            },
            scope: OrgScope {
                resource_tenant_id,
                domain_id,
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
                validity: ValidityWindow::between(1_000, 2_000),
            },
            delegable: true,
            subject: None,
            provenance: OrgProvenance {
                origin_tenant_id: ORG_SOD_TENANT,
                parent_chain: vec![],
                operation_id: "op-org-sod-grant".to_owned(),
            },
        }
    }

    fn org_sod_personal_contribution() -> OrgContribution {
        let mut contribution = org_sod_shared_contribution(ORG_SOD_RESOURCE_TENANT, None);
        contribution.subject = Some(OrgSubject {
            user_id: 11,
            card_id: 222,
        });
        contribution
    }

    /// 合法准入证据：行政根单元 + 单段单贡献（段 digest 与 manifest digest 均按
    /// 合同计算，可整体通过 `OrgAdmissionEvidence::validate`）。
    fn org_sod_evidence(contribution: OrgContribution) -> OrgAdmissionEvidence {
        let content = OrgSegmentContent {
            key: OrgScopeKey {
                resource: contribution.scope.resource.clone(),
                action: contribution.scope.action.clone(),
            },
            contributions: vec![contribution],
        };
        let segment = org_build_segment(0, content).unwrap();
        let no_dependencies: Vec<OrgDependency> = Vec::new();
        let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: ORG_SOD_TENANT,
            root_tenant_id: ORG_SOD_TENANT,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: &no_dependencies,
            segments: std::slice::from_ref(&segment),
            compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION,
            operation_id: "op-org-sod-publication",
        })
        .unwrap();
        let publication = OrgPublication {
            tenant_id: ORG_SOD_TENANT,
            root_tenant_id: ORG_SOD_TENANT,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: no_dependencies,
            manifest_digest_hex,
            compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.to_owned(),
            segments: vec![segment],
            operation_id: "op-org-sod-publication".to_owned(),
        };
        let node = OrgNode {
            tenant_id: ORG_SOD_TENANT,
            root_tenant_id: ORG_SOD_TENANT,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active: true,
            operation_id: "op-org-sod-node".to_owned(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-org-sod-root".to_owned(),
            }),
        };
        let membership = OrgMembership {
            membership_id: org_sod_uuid(9),
            tenant_id: ORG_SOD_TENANT,
            root_tenant_id: ORG_SOD_TENANT,
            user_id: 11,
            identity_card_id: 111,
            card_id: 222,
            revision: 1,
            active: true,
            validity: ValidityWindow::between(0, 9_999),
            operation_id: "op-org-sod-member".to_owned(),
        };
        OrgAdmissionEvidence {
            publication,
            node,
            membership,
            checked_at_unix: 1_500,
        }
    }

    /// 与发布贡献逐项对牌的 provenance（复刻组织准入的构造）。
    fn org_sod_admission_fixture(
        resource_tenant_id: i64,
        domain_id: Option<i64>,
    ) -> OrgSodAdmission {
        let contribution = org_sod_shared_contribution(resource_tenant_id, domain_id);
        let evidence = org_sod_evidence(contribution.clone());
        let provenance = OrgBranchProvenance {
            receiving_tenant_id: evidence.publication.tenant_id,
            source_tenant_id: contribution.provenance.origin_tenant_id,
            resource_tenant_id: contribution.scope.resource_tenant_id,
            root_tenant_id: evidence.publication.root_tenant_id,
            membership_id: evidence.membership.membership_id.clone(),
            membership_revision: evidence.membership.revision,
            branch_kind: OrgBranchKind::Shared,
            grant_ref: contribution.grant_ref.clone(),
            publication_generation: evidence.publication.generation,
            manifest_digest_hex: evidence.publication.manifest_digest_hex.clone(),
            approval_operation_id: contribution.provenance.operation_id.clone(),
        };
        OrgSodAdmission {
            evidence,
            provenance,
        }
    }

    /// 复核上下文：actor/card 租户 200，权威 target-resource 事实由用例给定。
    fn org_sod_context(
        scope: ResourceOwnershipScope,
        resource_tenant_id: Option<i64>,
        resource_domain_id: Option<i64>,
        domain_id: Option<i64>,
    ) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(11))
            .card_id(Some(222))
            .identity_card_id(Some(111))
            .tenant_id(Some(ORG_SOD_TENANT))
            .resource_tenant_id(resource_tenant_id)
            .resource_domain_id(resource_domain_id)
            .resource_ownership_scope(scope)
            .domain_id(domain_id)
            .resource(Some("doc".to_owned()))
            .target_id(Some(42))
            .action("read".to_owned())
            .build()
    }

    fn org_sod_recheck(
        context: &PolicyContext,
        admission: &OrgSodAdmission,
    ) -> Result<Vec<OrgContribution>, sqlx::Error> {
        let input = OrgSodInput { context, admission };
        org_sod_contributions(ORG_SOD_TENANT, 222, 11, "doc", "read", &input)
    }

    /// 跨租户组织贡献必须被 STATIC 持有复核看见：贡献按自身权威 resource
    /// tenant（300）参与持有判定，当前请求按 `ctx.resource_tenant_id`（300）
    /// 对牌 provenance 稳定通过；actor/card 租户（200）不再滤掉发布事实，
    /// 且返回的贡献能直接命中 STATIC 互斥伙伴匹配。
    #[test]
    fn org_sod_cross_tenant_contribution_passes_recheck_via_authoritative_facts() {
        let admission = org_sod_admission_fixture(ORG_SOD_RESOURCE_TENANT, None);
        let context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_RESOURCE_TENANT),
            None,
            None,
        );
        let contributions = org_sod_recheck(&context, &admission)
            .expect("cross-tenant published contribution must pass the recheck");
        assert_eq!(contributions.len(), 1);
        assert_eq!(
            contributions[0].scope.resource_tenant_id,
            ORG_SOD_RESOURCE_TENANT
        );
        // 返回的贡献进入 STATIC 冲突判定时必须可命中伙伴（doc:42 → doc + read）。
        assert!(org_sod_contribution_matches_partner(
            &contributions[0],
            "doc",
            "read"
        ));
    }

    #[test]
    fn org_sod_personal_subject_and_provenance_are_exact() {
        let contribution = org_sod_personal_contribution();
        let evidence = org_sod_evidence(contribution.clone());
        let mut provenance = OrgBranchProvenance {
            receiving_tenant_id: evidence.publication.tenant_id,
            source_tenant_id: contribution.provenance.origin_tenant_id,
            resource_tenant_id: contribution.scope.resource_tenant_id,
            root_tenant_id: evidence.publication.root_tenant_id,
            membership_id: evidence.membership.membership_id.clone(),
            membership_revision: evidence.membership.revision,
            branch_kind: OrgBranchKind::Personal,
            grant_ref: contribution.grant_ref.clone(),
            publication_generation: evidence.publication.generation,
            manifest_digest_hex: evidence.publication.manifest_digest_hex.clone(),
            approval_operation_id: contribution.provenance.operation_id.clone(),
        };
        let admission = OrgSodAdmission {
            evidence,
            provenance: provenance.clone(),
        };
        let context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_RESOURCE_TENANT),
            None,
            None,
        );
        assert_eq!(org_sod_recheck(&context, &admission).unwrap().len(), 1);

        provenance.branch_kind = OrgBranchKind::Shared;
        let stale = OrgSodAdmission {
            evidence: admission.evidence.clone(),
            provenance,
        };
        let error = org_sod_recheck(&context, &stale)
            .expect_err("PERSONAL branch provenance mismatch must fail closed");
        assert!(error.to_string().contains("org_scope_sod_provenance_stale"));

        let mut wrong_subject = org_sod_personal_contribution();
        wrong_subject.subject = Some(OrgSubject {
            user_id: 99,
            card_id: 222,
        });
        let wrong_evidence = org_sod_evidence(wrong_subject);
        let wrong_admission = OrgSodAdmission {
            evidence: wrong_evidence,
            provenance: admission.provenance.clone(),
        };
        let error = org_sod_recheck(&context, &wrong_admission)
            .expect_err("PERSONAL subject mismatch must fail closed");
        assert!(error.to_string().contains("org_scope_sod_provenance_stale"));
    }

    /// 当前请求只对牌权威 target-resource tenant: `ctx.resource_tenant_id` 与
    /// 获胜贡献的 resource tenant 不一致 → provenance 不稳定 → Err
    /// （fail-closed），绝不退回 actor/card 租户静默通过。
    #[test]
    fn org_sod_authoritative_tenant_mismatch_fails_closed() {
        let admission = org_sod_admission_fixture(ORG_SOD_RESOURCE_TENANT, None);
        let context = org_sod_context(ResourceOwnershipScope::TenantScoped, Some(999), None, None);
        let error = org_sod_recheck(&context, &admission)
            .expect_err("authoritative tenant mismatch must fail closed");
        assert!(
            error.to_string().contains("org_scope_sod_provenance_stale"),
            "unexpected gate error: {error}"
        );
    }

    /// TenantScoped domain facts come only from the resolver: an authoritative
    /// target domain matches when equal and never falls back to actor domain.
    #[test]
    fn org_sod_tenant_scoped_request_uses_only_authoritative_domain_facts() {
        // Resolver domain（50）胜过 actor domain（60）。
        let admission = org_sod_admission_fixture(ORG_SOD_TENANT, Some(50));
        let context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_TENANT),
            Some(50),
            Some(60),
        );
        let contributions =
            org_sod_recheck(&context, &admission).expect("authoritative domain must win");
        assert_eq!(contributions.len(), 1);

        // A missing resolved target domain must not borrow matching actor domain.
        let context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_TENANT),
            None,
            Some(50),
        );
        let error = org_sod_recheck(&context, &admission)
            .expect_err("tenant-scoped request must not fall back to actor domain");
        assert!(
            error.to_string().contains("org_scope_sod_provenance_stale"),
            "unexpected gate error: {error}"
        );

        // Resolver domain（51）与贡献 domain（50）不一致 → fail-closed。
        let context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_TENANT),
            Some(51),
            Some(50),
        );
        let error = org_sod_recheck(&context, &admission)
            .expect_err("authoritative domain mismatch must fail closed");
        assert!(
            error.to_string().contains("org_scope_sod_provenance_stale"),
            "unexpected gate error: {error}"
        );
    }

    #[test]
    fn org_sod_internal_context_retains_compatibility_domain_fallback() {
        let admission = org_sod_admission_fixture(ORG_SOD_TENANT, Some(50));
        let context = org_sod_context(ResourceOwnershipScope::Internal, None, None, Some(50));
        let contributions = org_sod_recheck(&context, &admission)
            .expect("internal typed context may use actor domain fallback");
        assert_eq!(contributions.len(), 1);
    }

    #[test]
    fn org_sod_non_target_scopes_and_missing_tenant_scope_fail_closed() {
        let admission = org_sod_admission_fixture(ORG_SOD_RESOURCE_TENANT, None);
        for scope in [
            ResourceOwnershipScope::Global,
            ResourceOwnershipScope::Unresolved,
            ResourceOwnershipScope::Unavailable,
        ] {
            let context = org_sod_context(scope, Some(ORG_SOD_RESOURCE_TENANT), None, None);
            let error = org_sod_recheck(&context, &admission)
                .expect_err("{scope:?} must not enter ORG SoD recheck");
            assert!(
                error.to_string().contains("org_scope_sod_request_invalid"),
                "unexpected gate error: {error}"
            );
        }

        let context = org_sod_context(ResourceOwnershipScope::TenantScoped, None, None, None);
        let error = org_sod_recheck(&context, &admission)
            .expect_err("tenant-scoped request without resolver tenant must fail closed");
        assert!(
            error.to_string().contains("org_scope_sod_request_invalid"),
            "unexpected gate error: {error}"
        );
    }

    /// 无任何租户事实（`ctx.tenant_id` 缺失）→ context 对牌失败 fail-closed
    /// （与 `sod_load_card_tenant` 的租户缺失报错共同构成"无租户不放行"）。
    #[test]
    fn org_sod_missing_tenant_fact_fails_closed() {
        let admission = org_sod_admission_fixture(ORG_SOD_RESOURCE_TENANT, None);
        let mut context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_RESOURCE_TENANT),
            None,
            None,
        );
        context.tenant_id = None;
        let error = org_sod_recheck(&context, &admission)
            .expect_err("missing tenant fact must fail closed");
        assert!(
            error.to_string().contains("org_scope_sod_context_mismatch"),
            "unexpected gate error: {error}"
        );
    }

    // ===== load_org_sod_admission（shared 宿主接线 helper） =====

    /// ORG 判定 fixture：allowed + 合同校验通过的 provenance。
    fn org_sod_decision(provenance: Option<OrgBranchProvenance>) -> PolicyDecision {
        PolicyDecision {
            allowed: true,
            reason: "org_scope_allow".into(),
            matched_rule: None,
            audit_required: false,
            evaluation_path: vec![],
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: provenance,
        }
    }

    /// 懒连接池：本组用例只覆盖不触达 DB 的确定性分支（与 repository.rs 单测同型）。
    fn org_sod_lazy_pool() -> MySqlPool {
        MySqlPool::connect_lazy("mysql://localhost:1/astral_test")
            .expect("lazy pool construction must not require a live database")
    }

    #[tokio::test]
    async fn load_org_sod_admission_short_circuits_without_provenance() {
        // 非 ORG 判定（无 provenance）→ Ok(None)：即使 context 事实缺失也先
        // 短路，调用方对本次请求走普通 context-aware 宿主 SoD 纯 deny-only 路径。
        let pool = org_sod_lazy_pool();
        let context = org_sod_context(
            ResourceOwnershipScope::TenantScoped,
            Some(ORG_SOD_RESOURCE_TENANT),
            None,
            None,
        );
        let admission = load_org_sod_admission(&pool, &context, &org_sod_decision(None))
            .await
            .expect("non-org decision must not fail the host SoD wiring");
        assert!(admission.is_none());
    }

    #[tokio::test]
    async fn load_org_sod_admission_requires_every_context_fact_for_org_decisions() {
        // ORG 判定但租户/用户/卡/身份卡任一事实缺失 → 同一稳定错误码
        // fail-closed（调用方 503），绝不降级为普通 SoD 检查。
        let pool = org_sod_lazy_pool();
        let provenance = org_sod_admission_fixture(ORG_SOD_RESOURCE_TENANT, None).provenance;
        let decision = org_sod_decision(Some(provenance));
        let context = || {
            org_sod_context(
                ResourceOwnershipScope::TenantScoped,
                Some(ORG_SOD_RESOURCE_TENANT),
                None,
                None,
            )
        };

        let mut partial = context();
        partial.tenant_id = None;
        let error = load_org_sod_admission(&pool, &partial, &decision)
            .await
            .expect_err("missing tenant fact must fail closed");
        assert!(error.to_string().contains("org_scope_sod_context_missing"));

        let mut partial = context();
        partial.user_id = None;
        let error = load_org_sod_admission(&pool, &partial, &decision)
            .await
            .expect_err("missing user fact must fail closed");
        assert!(error.to_string().contains("org_scope_sod_context_missing"));

        let mut partial = context();
        partial.card_id = None;
        let error = load_org_sod_admission(&pool, &partial, &decision)
            .await
            .expect_err("missing card fact must fail closed");
        assert!(error.to_string().contains("org_scope_sod_context_missing"));

        let mut partial = context();
        partial.identity_card_id = None;
        let error = load_org_sod_admission(&pool, &partial, &decision)
            .await
            .expect_err("missing identity card fact must fail closed");
        assert!(error.to_string().contains("org_scope_sod_context_missing"));
    }

    /// EVIDENCE 读取结果与 provenance 原样装配（逐字段一致），无 DB 也能验证
    /// 装配面；装配产物可进入 `org_sod_contributions` 的 provenance 对牌。
    #[test]
    fn org_sod_admission_outcome_assembles_evidence_with_provenance() {
        let fixture = org_sod_admission_fixture(ORG_SOD_RESOURCE_TENANT, None);
        let admission = org_sod_admission_outcome(
            Ok(OrgAdmissionResult::Evidence(Box::new(
                fixture.evidence.clone(),
            ))),
            fixture.provenance.clone(),
        )
        .expect("evidence outcome must assemble the admission")
        .expect("evidence outcome must be Some");
        assert_eq!(
            admission.evidence.publication.manifest_digest_hex,
            fixture.evidence.publication.manifest_digest_hex
        );
        assert_eq!(
            admission.provenance.membership_id,
            fixture.provenance.membership_id
        );
        assert_eq!(
            admission.provenance.manifest_digest_hex,
            admission.evidence.publication.manifest_digest_hex
        );
    }

    /// 业务 Pending → 稳定前缀 + machine code 的 fail-closed 错误。
    #[test]
    fn org_sod_admission_outcome_maps_pending_to_stable_gate_error() {
        let error = org_sod_admission_outcome(
            Ok(OrgAdmissionResult::Pending {
                code: OrgPendingCode::PublicationMissing,
                detail: "publication missing".into(),
            }),
            org_sod_admission_fixture(ORG_SOD_TENANT, None).provenance,
        )
        .expect_err("pending admission evidence must fail closed");
        let message = error.to_string();
        assert!(message.contains("org_scope_sod_evidence_pending;"));
        assert!(message.contains("org_scope.pending.publication_missing"));
    }

    /// 基础设施错误 → unavailable 稳定前缀（fail-closed，绝不折算成"无冲突"）。
    #[test]
    fn org_sod_admission_outcome_maps_infra_error_to_unavailable_gate_error() {
        let error = org_sod_admission_outcome(
            Err(astral_types::AstralError::Database(
                "org_scope repository query failed: pool closed".into(),
            )),
            org_sod_admission_fixture(ORG_SOD_TENANT, None).provenance,
        )
        .expect_err("infrastructure failure must fail closed");
        let message = error.to_string();
        assert!(message.contains("org_scope_sod_evidence_unavailable;"));
        assert!(message.contains("pool closed"));
    }
}
