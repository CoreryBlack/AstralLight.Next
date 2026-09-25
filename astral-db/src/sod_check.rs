//! SoD 冲突检查（供权限中间件集成）
//!
//! 在权限检查通过后调用，防止持有互斥权限的卡访问敏感资源。
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
//! FOR UPDATE + 指针一致性校验天然接管，本模块不再读取旧链 CARD head 表，
//! 也不存在任何 legacy 快照 / raw source 回退。
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

use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use astral_types::org_scope::{
    org_action_matches, org_contribution_matches_request, org_decode_segment_content,
    org_resource_matches, OrgAdmissionEvidence, OrgAdmissionResult, OrgBranchKind,
    OrgBranchProvenance, OrgContribution, OrgReadRequest, OrgSubjectFilter,
};
use astral_types::{
    build_resource_key, DomainScopeRequirement, PolicyContext, PolicyDecision,
    PublishedCardEvidenceScope, ResourceOwnershipScope,
};
use sqlx::MySqlPool;

use crate::authorization_projection_repository::AuthorizationEvidenceError;
use crate::evidence_cache::cached_load_published_card_grant_evidence;
use crate::org_scope_repository::{OrgAdmissionQuery, OrgScopeRepository, SqlxOrgScopeRepository};

/// SoD 冲突检查结果
#[derive(Debug)]
pub struct SodCheckResult {
    pub has_conflict: bool,
    pub conflict_policy: Option<String>,
    pub conflict_permission: Option<String>,
    pub conflict_type: Option<String>, // "STATIC" | "DYNAMIC"
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
/// `check_sod_conflict` 的 STATIC 分支与 `sod_repository::card_has_permission`
/// 共用本函数，保证两条读路径的归一化语义一致。
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
/// 绝不让其参与冲突判定）。`check_sod_conflict` 与
/// `sod_repository::load_card_evidence` 共用，保证两条读路径的 Corrupt
/// 错误形状一致。
pub fn sod_evidence_contract_message(
    card_id: i64,
    contract_error: impl std::fmt::Display,
) -> String {
    format!("sod_card_evidence_corrupt;card_id={card_id};detail={contract_error}")
}

// ─────────────────────────────────────────────────────────────────────────────
// sod_policy 进程级缓存（读链规模化：每请求 2 次 sod_policy 全量读收敛）
// ─────────────────────────────────────────────────────────────────────────────

/// SoD 策略进程缓存 TTL（30s）：失效窗口与方向性取舍见模块文档
/// "sod_policy 进程缓存"节（本进程写路径 evict 立即生效；跨实例 ≤TTL）。
const SOD_POLICY_CACHE_TTL: Duration = Duration::from_secs(30);

/// SoD 策略快照（单条目全量缓存）：全量 ACTIVE STATIC 策略 + 全量 ACTIVE
/// DYNAMIC 策略。DYNAMIC 的 resource_type/action_code 过滤在读取侧内存执行
/// （谓词与原 SQL 等价，见 [`dynamic_policy_matches_request`]），一次缓存
/// 同时消除两条每请求 sod_policy 读。
#[derive(Debug, Clone, Default)]
struct SodPolicySnapshot {
    static_policies: Vec<StaticPolicy>,
    dynamic_policies: Vec<DynamicPolicy>,
}

static SOD_POLICY_CACHE: OnceLock<RwLock<Option<(SodPolicySnapshot, Instant)>>> = OnceLock::new();

fn sod_policy_cache() -> &'static RwLock<Option<(SodPolicySnapshot, Instant)>> {
    SOD_POLICY_CACHE.get_or_init(|| RwLock::new(None))
}

/// 缓存条目新鲜度（纯逻辑；`duration_since` 对未来时刻饱和为 0，恰好到达
/// TTL 即不新鲜，对齐 `cache_epoch` 的边界语义）。
fn sod_policy_cache_is_fresh(cached_at: Instant, now: Instant) -> bool {
    now.duration_since(cached_at) < SOD_POLICY_CACHE_TTL
}

/// TTL 内的进程缓存快照（未命中/过期/锁中毒 → `None`，调用方回源直查）。
fn fresh_sod_policy_snapshot() -> Option<SodPolicySnapshot> {
    let cached = sod_policy_cache().read().ok()?;
    let (snapshot, cached_at) = cached.as_ref()?;
    if sod_policy_cache_is_fresh(*cached_at, Instant::now()) {
        return Some(snapshot.clone());
    }
    None
}

/// 写入进程缓存（全量查询成功后调用；错误结果绝不缓存）。锁中毒时静默跳过
/// （缓存侧任何异常只意味着下一次读回源直查，绝不影响 fail-closed 语义）。
fn store_sod_policy_snapshot(snapshot: SodPolicySnapshot) {
    if let Ok(mut cached) = sod_policy_cache().write() {
        *cached = Some((snapshot, Instant::now()));
    }
}

/// 主动失效 SoD 策略进程缓存（sod_policy 写路径 evict 钩子：本进程内立即
/// 生效；其它实例由 TTL 兜底，见模块文档失效窗口记录）。
pub fn evict_sod_policy_cache() {
    if let Ok(mut cached) = sod_policy_cache().write() {
        *cached = None;
    }
}

/// 读取 SoD 策略全量快照（进程缓存优先，miss 回源直查；DB 错误原样上抛，
/// 绝不折算成"无冲突"，错误结果绝不入缓存）。
async fn load_sod_policy_snapshot(pool: &MySqlPool) -> Result<SodPolicySnapshot, sqlx::Error> {
    if let Some(snapshot) = fresh_sod_policy_snapshot() {
        return Ok(snapshot);
    }
    let static_policies = sqlx::query_as::<_, StaticPolicy>(
        "SELECT policy_name, permission_a, permission_b \
         FROM sod_policy WHERE conflict_type='STATIC' AND status='ACTIVE'",
    )
    .fetch_all(pool)
    .await?;
    let dynamic_policies = sqlx::query_as::<_, DynamicPolicy>(
        "SELECT policy_name, condition_script, resource_type, action_code \
         FROM sod_policy WHERE conflict_type='DYNAMIC' AND status='ACTIVE'",
    )
    .fetch_all(pool)
    .await?;
    let snapshot = SodPolicySnapshot {
        static_policies,
        dynamic_policies,
    };
    store_sod_policy_snapshot(snapshot.clone());
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

/// 检查当前请求是否触发 SoD 冲突（STATIC + DYNAMIC）。
///
/// - 前置：卡级 published evidence 必须可读（严格 reader 单短事务内锁定当前
///   指针并整链校验全部已发布聚合），否则返回错误——调用方必须拒绝请求，
///   绝不返回"无冲突"放行；tenant 缺失/非正同样报错。
/// - STATIC: 查询预定义互斥权限对；持有判定来自已发布 evidence 的
///   `effective_grants`（全部来源的生效 ALLOW，resource_key 归一化后匹配）；
///   raw `permission_rule` 分支仅为 deny-biased 诊断，见
///   [`SOD_RAW_RULE_CONFLICT_SQL`] 注释
/// - 不支持的脚本或缺失 owner fact → 返回错误，调用方必须拒绝请求
/// - "读取后复核"由 reader 事务 + FOR UPDATE + 指针一致性校验接管
///   （`pointer_moved_under_read` → `Corrupt` → Err）
///
/// # 参数
/// - `pool`: 数据库连接池
/// - `card_id`: 请求卡片的 ID
/// - `user_id`: 当前用户 ID（用于 DYNAMIC 脚本求值）
/// - `resource_type`: 请求的资源类型
/// - `action_code`: 请求的动作
/// - `resource_owner_id`: 由受保护资源 loader 派生的资源所有者 ID；不能来自客户端请求头
pub async fn check_sod_conflict(
    pool: &MySqlPool,
    card_id: i64,
    user_id: Option<i64>,
    resource_type: &str,
    action_code: &str,
    resource_owner_id: Option<i64>,
) -> Result<SodCheckResult, sqlx::Error> {
    check_sod_conflict_inner(
        pool,
        card_id,
        user_id,
        resource_type,
        action_code,
        resource_owner_id,
        None,
    )
    .await
}

/// Run the normal deny-only SoD check after a successful ORG_SCOPE decision.
///
/// The caller supplies a fresh organization read plus the `PolicyDecision`
/// provenance that was returned by `PolicyEngine`. The function requires both
/// to describe the same winner before it lets any organization contribution
/// participate in conflict detection. It never grants access and never bypasses
/// the card-level published-evidence gate.
///
/// Target-resource facts on `ctx` (`resource_tenant_id`/`resource_domain_id`)
/// are authoritative — resolved by the resource-owner loader, never accepted
/// from client headers. `TenantScoped` requests consume only those resolver
/// facts; `Internal` typed calls retain the legacy actor-scope fallback. Holding
/// validation evaluates each contribution under its own published resource
/// tenant. Missing tenant facts and provenance/publication mismatches stay
/// fail-closed (Err → the caller must reject the request).
pub async fn check_sod_conflict_with_org(
    pool: &MySqlPool,
    ctx: &PolicyContext,
    admission: &OrgSodAdmission,
    resource_owner_id: Option<i64>,
) -> Result<SodCheckResult, sqlx::Error> {
    let (Some(card_id), Some(user_id), Some(resource_type)) =
        (ctx.card_id, ctx.user_id, ctx.resource.as_deref())
    else {
        return Err(sod_gate_error("org_scope_sod_context_missing"));
    };
    check_sod_conflict_inner(
        pool,
        card_id,
        Some(user_id),
        resource_type,
        &ctx.action,
        resource_owner_id,
        Some(OrgSodInput {
            context: ctx,
            admission,
        }),
    )
    .await
}

/// 从已确认的 `PolicyDecision` 装配宿主 SoD 复核输入（shared，供
/// TrustGraph/Identity/Monitor 宿主中间件统一接线，消除本地重复实现）。
///
/// - 决策未携带 org provenance（非 ORG 判定）→ `Ok(None)`：调用方对本次请求
///   走既有 [`check_sod_conflict`] 纯 deny-only 路径，行为不变；
/// - ORG 判定但 `PolicyContext` 缺失租户/用户/卡/身份卡任一事实 →
///   `sod_gate_error("org_scope_sod_context_missing")`（fail-closed）；
/// - fresh 准入证据读取返回业务 Pending → `sod_gate_error`（稳定前缀
///   `org_scope_sod_evidence_pending;`，携带 pending machine code）；
/// - 基础设施错误 → `sod_gate_error`（稳定前缀
///   `org_scope_sod_evidence_unavailable;`）。
///
/// 语义与组织准入一致：本函数不产生任何授权事实，只把 `PolicyEngine` 已确认
/// ALLOW 的 provenance 与 fresh publication/membership evidence 重新装配，交给
/// [`check_sod_conflict_with_org`] 做 deny-only 的 STATIC 互斥复核；provenance
/// 或 publication 对牌失败沿错误返回，由调用方拒绝请求（503/fail-closed）。
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

async fn check_sod_conflict_inner(
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
    // - raw `permission_rule` 分支原样保留（deny-biased 诊断，见
    //   [`SOD_RAW_RULE_CONFLICT_SQL`] 注释）：命中只会把 has_conflict 变为
    //   true（→ 拒绝），永不参与放行语义。
    // 全量 ACTIVE 策略快照（进程级缓存，TTL 30s，失效窗口取舍见
    // SOD_POLICY_CACHE_TTL/模块文档；miss/DB 错误回源直查，fail-closed
    // 不变，错误绝不入缓存）。STATIC 与 DYNAMIC 两个检查段共用同一快照。
    let snapshot = load_sod_policy_snapshot(pool).await?;

    let mut conflict: Option<SodCheckResult> = None;
    {
        for policy in &snapshot.static_policies {
            let is_a = policy.permission_a.as_deref() == Some(&perm_key);
            let is_b = policy.permission_b.as_deref() == Some(&perm_key);
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
                sod_partner_matches_grant(&grant.resource, &grant.action, parts[0], parts[1])
            });
            if !has_conflict {
                has_conflict = org_contributions.as_ref().is_some_and(|contributions| {
                    contributions.iter().any(|contribution| {
                        org_sod_contribution_matches_partner(contribution, parts[0], parts[1])
                    })
                });
            }
            if !has_conflict {
                // raw 分支：deny-biased 诊断，命中同样只增冲突（→ 拒绝）。
                has_conflict = sqlx::query_scalar(SOD_RAW_RULE_CONFLICT_SQL)
                    .bind(card_id)
                    .bind(parts[0])
                    .bind(parts[1])
                    .fetch_one(pool)
                    .await?;
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
    // 不读授权证据；但入口 evidence 门禁已保证该卡的已发布授权证据可读，
    // "无冲突"不会被不可读投影伪装成放行。
    // 全量 ACTIVE DYNAMIC 策略来自同一进程缓存快照；resource_type/action_code
    // 过滤在内存执行（谓词与原 SQL `(resource_type IS NULL OR resource_type
    // = ?) AND (action_code IS NULL OR action_code = ?)` 对齐，见
    // `dynamic_policy_matches_request`）。
    if conflict.is_none() {
        for policy in snapshot
            .dynamic_policies
            .iter()
            .filter(|policy| dynamic_policy_matches_request(policy, resource_type, action_code))
        {
            let script = policy.condition_script.as_deref().ok_or_else(|| {
                sod_condition_error("active dynamic SoD policy has no condition script")
            })?;

            // 评估条件脚本（支持 resourceOwnerId == currentUserId 模式）。
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

/// STATIC 冲突判定的 raw `permission_rule` 诊断 SQL。
///
/// **仅作为 deny-biased 诊断保留**（旧 UNION 的 raw 分支原样提取）：它命中只会
/// 把 `has_conflict` 变为 true（→ 拒绝），永不参与放行语义；正式授权事实只来自
/// 上方的已发布 evidence 匹配。raw 表存 plain `resource_type`，与 partner 绑定
/// 形状一致（legacy 快照分支的形状错位不存在于此）。入口 evidence 门禁失败时
/// 本 SQL 不会被执行（先 Err 上抛）。
const SOD_RAW_RULE_CONFLICT_SQL: &str = "SELECT EXISTS ( \
 SELECT 1 FROM permission_rule WHERE card_id=? AND enabled=1 \
   AND (valid_from IS NULL OR valid_from <= UTC_TIMESTAMP()) \
   AND (valid_to IS NULL OR valid_to >= UTC_TIMESTAMP()) \
   AND resource_type=? AND action_code=? \
 LIMIT 1)";

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

/// 评估 DYNAMIC SoD 条件脚本
///
/// 当前支持的脚本模式：
/// - `resourceOwnerId == currentUserId` — 操作者即资源所有者时触发
/// - 不支持的脚本或缺失 owner fact → 返回错误
fn evaluate_dynamic_condition(
    script: &str,
    user_id: Option<i64>,
    resource_owner_id: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let script_trimmed = script.trim();
    if script_trimmed.is_empty() {
        return Err(sod_condition_error("active dynamic SoD condition is empty"));
    }

    // 模式: resourceOwnerId == currentUserId
    if script_trimmed.contains("resourceOwnerId") && script_trimmed.contains("currentUserId") {
        let (Some(uid), Some(oid)) = (user_id, resource_owner_id) else {
            return Err(sod_condition_error(
                "dynamic SoD owner condition requires authoritative owner fact",
            ));
        };
        if uid == oid {
            tracing::info!(
                user_id = uid,
                resource_owner_id = oid,
                condition = script_trimmed,
                "dynamic SoD triggered: resourceOwnerId == currentUserId"
            );
            return Ok(true);
        }
        return Ok(false);
    }

    tracing::error!(
        script = script_trimmed,
        "unrecognized active dynamic SoD condition script"
    );
    Err(sod_condition_error(
        "unrecognized active dynamic SoD condition script",
    ))
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
    use astral_types::ValidityWindow;

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

    /// 形状守卫：`check_sod_conflict` 必须先解析租户并构造卡级 evidence scope，
    /// 经严格 reader 读取已发布证据后才允许做冲突判定（归一匹配 → raw 诊断）；
    /// evidence 之前不得构造任何检查结果，也不得触碰 legacy 快照/旧链 head——
    /// 不可读只能报错，绝不能以"无冲突"（放行）收场。
    ///
    /// 读取调用必须是缓存感知入口（进程内 evidence 缓存 + 指针对牌，miss 回源
    /// 严格 reader；见 `crate::evidence_cache`）——对牌失败同样只能报错回源，
    /// 不会把旧缓存伪装成可读证据。
    #[test]
    fn check_sod_conflict_reads_evidence_before_any_conflict_decision() {
        let source = include_str!("sod_check.rs");
        // 锚定 check_sod_conflict_inner 的完整流程体（check_sod_conflict 与
        // check_sod_conflict_with_org 都收敛到它；此前锚定
        // "pub async fn check_sod_conflict" 会因 with_org 变体落在两个签名
        // 之间的窄段上而失明）。
        let body = source
            .split("async fn check_sod_conflict_inner")
            .nth(1)
            .expect("check_sod_conflict_inner flow must exist");

        let tenant = body
            .find("sod_load_card_tenant(pool, card_id)")
            .expect("tenant resolution must exist");
        let scope = body
            .find("PublishedCardEvidenceScope {")
            .expect("card-level evidence scope construction must exist");
        let reader = body
            .find("load_published_card_grant_evidence(pool, &scope)")
            .expect("strict evidence reader call must exist");
        let cached_reader = body
            .find("cached_load_published_card_grant_evidence(pool, &scope)")
            .expect("evidence reads must go through the pointer-fenced cache entry");
        assert_eq!(
            reader,
            cached_reader + "cached_".len(),
            "the evidence reader call must be the cache-aware wrapper"
        );
        let matcher = body
            .find("sod_partner_matches_grant")
            .expect("normalized partner matching must exist");
        let raw = body
            .find("SOD_RAW_RULE_CONFLICT_SQL")
            .expect("raw deny-biased diagnostic must exist");

        assert!(
            tenant < scope && scope < reader && reader < matcher && matcher < raw,
            "order must be tenant -> scope -> reader -> normalized match -> raw diagnostic"
        );

        let prefix = &body[..reader];
        assert!(
            !prefix.contains("permission_rule_snapshot"),
            "no legacy snapshot read may happen before the evidence reader"
        );
        assert!(
            !prefix.contains("has_conflict"),
            "no check result may be produced before the evidence reader"
        );
    }

    /// 全文件守卫（生产代码段）：旧链 CARD head 门禁函数与 legacy 快照读取
    /// 已从本模块清除；raw `permission_rule` 仅作为 deny-biased 诊断保留。
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

        // raw permission_rule 诊断保留（deny-biased）
        assert!(production.contains("FROM permission_rule WHERE"));
        assert!(production.contains("enabled=1"));
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
            compiler_version: "sod-check-test",
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
            compiler_version: "sod-check-test".to_owned(),
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
        // 短路，调用方对本次请求走既有 check_sod_conflict 纯 deny-only 路径。
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
