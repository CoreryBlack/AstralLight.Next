//! 委托数据访问 — DelegationRepository
//!
//! 对齐 Java `DelegationService` 的持久化边界：委托行与 DELEGATION 规则
//! 属于同一聚合，创建/撤销/更新各自在**单一事务**内完成（对齐 Java
//! `@Transactional` + 同事务写 `permission_rule` 的语义）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{
    get_alias_sources, parse_resource_key, AstralError, DomainScopeRequirement, GrantState,
    PolicyContext, PublishedCardAuthorization, PublishedCardEvidenceScope, EVENT_TYPE_REVOKE,
    SYSTEM_ACTOR_ID,
};

use crate::repository::authorization_source_transaction::AuthorizationSourceTransaction;
use crate::repository::grant_ledger_adapter::{
    append_delegation_grant_delta_in_tx, build_delegation_add_draft, build_delegation_revoke_draft,
    build_delegation_update_draft, delegation_update_authorization_content_changed,
    derive_delegation_contribution_event_id, derive_delegation_identity,
    derive_delegation_operation_id, map_grant_repository_error, DelegationContributionKind,
    DelegationLedgerFacts, DelegationMutationKind,
};
use crate::repository::projection_repository::append_card_projection_with_metadata_in_tx;

/// 委托行（permission_delegation，含规则生命周期所需字段）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DelegationRecord {
    pub delegation_id: i64,
    pub delegator_card_id: i64,
    pub delegate_card_id: i64,
    pub resource_type: String,
    pub action_code: String,
    /// effective_from 的 UNIX 秒（canonical validity 下界推算用）
    pub effective_from_ts: i64,
    /// effective_until 的 UNIX 秒（规则 valid_to 推算用）
    pub effective_until_ts: Option<i64>,
    pub is_revokable: i8,
    pub status: String,
}

/// Gateway/PolicyEngine 提供的委托写入可信上下文。
///
/// API 层只能从 Gateway 注入的 PolicyContext 构造该值；repository 仍会在
/// source transaction 内锁定并复核 caller card，不能把上下文当作数据库事实。
///
/// operation_id 不在此处生成：durable 业务身份必须由每次 mutation 从
/// delegation 主键 + mutation kind +（可选的）安全 x-request-id 头确定性派生，
/// 绝不允许随机 fallback。这里只保存已验证的可信 actor/scope 与原始头部。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationMutationContext {
    user_id: i64,
    caller_card_id: i64,
    tenant_id: i64,
    domain_id: i64,
    request_id_header: Option<String>,
}

impl DelegationMutationContext {
    pub fn from_policy_context(
        context: &PolicyContext,
        operation_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "delegation mutation requires a platform user context".into(),
            ));
        }
        let user_id = positive_context_id(context.user_id, "user_id")?;
        let caller_card_id = positive_context_id(context.card_id, "card_id")?;
        let tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let domain_id = positive_context_id(context.domain_id, "domain_id")?;
        // 显式安全 x-request-id 原样复用为 durable operation id；空白视同缺失，
        // 非法字符 fail-closed，不做静默替换或随机补位。
        let header = operation_id
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(header) = header {
            let usable = header.len()
                <= crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH
                && header.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
                });
            if !usable {
                return Err(AstralError::Validation(format!(
                    "delegation x-request-id header is not reusable as a durable operation id: {header:?}"
                )));
            }
        }
        let request_id_header = header.map(str::to_owned);

        Ok(Self {
            user_id,
            caller_card_id,
            tenant_id,
            domain_id,
            request_id_header,
        })
    }

    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    pub fn caller_card_id(&self) -> i64 {
        self.caller_card_id
    }

    pub fn tenant_id(&self) -> i64 {
        self.tenant_id
    }

    pub fn domain_id(&self) -> i64 {
        self.domain_id
    }

    /// 原始 x-request-id 头（None = 由 repository 按委托主键确定性派生）。
    pub fn request_id_header(&self) -> Option<&str> {
        self.request_id_header.as_deref()
    }
}

fn positive_context_id(value: Option<i64>, name: &str) -> Result<i64, AstralError> {
    value
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Auth(format!("delegation mutation requires a positive {name}")))
}

/// 新建委托参数（service 层完成过期时间推算）
#[derive(Debug, Clone)]
pub struct NewDelegation {
    pub delegator_card_id: i64,
    pub delegate_card_id: i64,
    pub resource_type: String,
    pub action_code: String,
    /// effective_until 的 UNIX 秒
    pub effective_until_ts: i64,
}

/// 原子创建结果；created=false 表示命中 ACTIVE 幂等记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationCreateResult {
    pub delegation_id: i64,
    pub created: bool,
}

/// 原子更新/撤销结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationMutationResult {
    pub changed: bool,
    pub delegate_card_id: Option<i64>,
}

/// 到期对账的显式结论：重复执行（已非 ACTIVE / 未到期）是幂等 no-op 而非失败，
/// 绝不产生第二条 tombstone 或普通 DENY。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationExpiryOutcome {
    /// 本事务完成收敛：REVOKE tombstone + CARD 投影 + 审计已在同一 source
    /// transaction 落库并提交。
    Reconciled { delegate_card_id: i64 },
    /// 委托行缺失或已非 ACTIVE：幂等 no-op，不写任何状态。
    AlreadyTerminal,
    /// 仍 ACTIVE 但锁定有效期尚未过去（相对事务内 DB 时钟）：不满足到期资格，
    /// 本次不执行任何写入。
    NotYetDue,
}

/// 到期对账候选批量的显式上限：候选发现永远是 LIMIT 绑定参数的有界查询，
/// 不提供任何无界扫描入口。
pub const MAX_EXPIRY_RECONCILIATION_BATCH: i64 = 500;

/// permission_delegation 行的别名映射列清单（全局唯一事实源；卡级联删除路径
/// 复用同一列形状，避免两处 SQL 漂移）。
pub(crate) const DELEGATION_SELECT: &str = "delegation_id, delegator_card_id, delegate_card_id, \
     resource_type, action_code, \
     UNIX_TIMESTAMP(effective_from) as effective_from_ts, \
     UNIX_TIMESTAMP(effective_until) as effective_until_ts, \
     COALESCE(is_revokable, 1) as is_revokable, status";
/// DELEGATION 规则写 SQL（创建/更新共用；有效期两侧均以绑定参数写入，
/// 保证 SQL 与 canonical grant 的 UTC 秒一致，不再依赖 NOW() 的双写漂移）。
const DELEGATION_RULE_INSERT: &str = "INSERT INTO permission_rule \
     (card_id, tenant_id, effect, resource_type, action_code, priority, source_type, source_id, enabled, valid_from, valid_to) \
     VALUES (?, ?, 'ALLOW', ?, ?, 500, 'DELEGATION', ?, 1, FROM_UNIXTIME(?), FROM_UNIXTIME(?))";

/// 委托列表查询的 caller scope：
/// - caller_card 必须由 Gateway context 指定、属于 caller user、ACTIVE 且在 caller tenant/domain；
/// - 委托两端都必须与 caller card 位于同一 tenant/domain；
/// - 全量列表也只返回 caller card 作为 delegator 或 delegate 的行。
///
/// 这些 SQL 使用静态字符串，避免把 query 参数拼入 SQL；每个列表请求只执行一条
/// 带双卡 JOIN 的查询，不通过逐行查询补充 scope。
const DELEGATION_LIST_ALL_SQL: &str = "SELECT d.delegation_id as id, d.delegator_card_id as delegator_id, \
     d.delegate_card_id as delegate_id, d.resource_type as resource, d.action_code as action, \
     UNIX_TIMESTAMP(d.effective_until) as expires_ts, \
     CASE WHEN d.status = 'ACTIVE' AND d.effective_until IS NOT NULL AND d.effective_until <= NOW() \
          THEN 'EXPIRED' ELSE d.status END AS status \
     FROM permission_delegation AS d \
     INNER JOIN user_card AS caller_card \
       ON caller_card.card_id = ? AND caller_card.user_id = ? \
      AND caller_card.card_status = 'ACTIVE' \
      AND caller_card.tenant_id = ? AND caller_card.domain_id = ? \
     INNER JOIN user_card AS delegator_card ON delegator_card.card_id = d.delegator_card_id \
     INNER JOIN user_card AS delegate_card ON delegate_card.card_id = d.delegate_card_id \
     WHERE (d.delegator_card_id = caller_card.card_id OR d.delegate_card_id = caller_card.card_id) \
       AND delegator_card.tenant_id = caller_card.tenant_id \
       AND delegator_card.domain_id = caller_card.domain_id \
       AND delegate_card.tenant_id = caller_card.tenant_id \
       AND delegate_card.domain_id = caller_card.domain_id \
     ORDER BY d.delegation_id";

const DELEGATION_LIST_BY_DELEGATOR_SQL: &str = "SELECT d.delegation_id as id, d.delegator_card_id as delegator_id, \
     d.delegate_card_id as delegate_id, d.resource_type as resource, d.action_code as action, \
     UNIX_TIMESTAMP(d.effective_until) as expires_ts, \
     CASE WHEN d.status = 'ACTIVE' AND d.effective_until IS NOT NULL AND d.effective_until <= NOW() \
          THEN 'EXPIRED' ELSE d.status END AS status \
     FROM permission_delegation AS d \
     INNER JOIN user_card AS caller_card \
       ON caller_card.card_id = ? AND caller_card.user_id = ? \
      AND caller_card.card_status = 'ACTIVE' \
      AND caller_card.tenant_id = ? AND caller_card.domain_id = ? \
     INNER JOIN user_card AS delegator_card ON delegator_card.card_id = d.delegator_card_id \
     INNER JOIN user_card AS delegate_card ON delegate_card.card_id = d.delegate_card_id \
     WHERE d.delegator_card_id = caller_card.card_id AND d.delegator_card_id = ? \
       AND delegator_card.tenant_id = caller_card.tenant_id \
       AND delegator_card.domain_id = caller_card.domain_id \
       AND delegate_card.tenant_id = caller_card.tenant_id \
       AND delegate_card.domain_id = caller_card.domain_id \
     ORDER BY d.delegation_id";

const DELEGATION_LIST_BY_DELEGATE_SQL: &str = "SELECT d.delegation_id as id, d.delegator_card_id as delegator_id, \
     d.delegate_card_id as delegate_id, d.resource_type as resource, d.action_code as action, \
     UNIX_TIMESTAMP(d.effective_until) as expires_ts, \
     CASE WHEN d.status = 'ACTIVE' AND d.effective_until IS NOT NULL AND d.effective_until <= NOW() \
          THEN 'EXPIRED' ELSE d.status END AS status \
     FROM permission_delegation AS d \
     INNER JOIN user_card AS caller_card \
       ON caller_card.card_id = ? AND caller_card.user_id = ? \
      AND caller_card.card_status = 'ACTIVE' \
      AND caller_card.tenant_id = ? AND caller_card.domain_id = ? \
     INNER JOIN user_card AS delegator_card ON delegator_card.card_id = d.delegator_card_id \
     INNER JOIN user_card AS delegate_card ON delegate_card.card_id = d.delegate_card_id \
     WHERE d.delegate_card_id = caller_card.card_id AND d.delegate_card_id = ? \
       AND delegator_card.tenant_id = caller_card.tenant_id \
       AND delegator_card.domain_id = caller_card.domain_id \
       AND delegate_card.tenant_id = caller_card.tenant_id \
       AND delegate_card.domain_id = caller_card.domain_id \
     ORDER BY d.delegation_id";

#[async_trait]
pub trait DelegationRepository: Send + Sync {
    /// 新建委托 + DELEGATION ALLOW 规则（同一事务），返回原子创建结果
    async fn create_with_rule(
        &self,
        new: &NewDelegation,
        context: &DelegationMutationContext,
    ) -> Result<DelegationCreateResult, AstralError>;
    /// 撤销：置 REVOKED + 删除该委托的 DELEGATION 规则（同一事务）
    async fn revoke_with_rules(
        &self,
        delegation_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<DelegationMutationResult, AstralError>;
    /// 更新委托行 + 重建 DELEGATION 规则（删旧插新，同一事务）
    async fn update_with_rule(
        &self,
        delegation_id: i64,
        resource_type: &str,
        action_code: &str,
        effective_until_ts: i64,
        context: &DelegationMutationContext,
    ) -> Result<DelegationMutationResult, AstralError>;
    /// 查询当前可信 caller card 参与的全部委托。
    ///
    /// 当前 route contract 没有 platform-admin/system scope；结果始终限定为
    /// caller 自己的 delegator/delegate 卡片，且两端都必须落在 caller tenant/domain。
    async fn list_all(
        &self,
        context: &DelegationMutationContext,
    ) -> Result<Vec<DelegationViewRecord>, AstralError>;
    /// 按委托方卡片查询；card_id 必须是可信 caller card。
    async fn list_by_delegator(
        &self,
        card_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<Vec<DelegationViewRecord>, AstralError>;
    /// 按被委托方卡片查询；card_id 必须是可信 caller card。
    async fn list_by_delegate(
        &self,
        card_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<Vec<DelegationViewRecord>, AstralError>;
    /// 到期对账（系统生命周期收敛，显式幂等）：对 ACTIVE 且 `effective_until`
    /// 已过（事务内 DB 时钟证明）的委托，按全局升序锁序锁定两端卡与委托行，
    /// 证明 source/rule/grant 身份与到期事实后，在同一 source transaction 内
    /// 追加既有 REVOKE tombstone + CARD 投影 + 审计并置 `EXPIRED` 终态。
    /// 事务内不触碰 Redis/MQ/网络；重复执行幂等 no-op。
    ///
    /// 这是 worker/运维显式调用的 durable 方法：不读 `is_revokable`（自然到期
    /// 不是提前撤销），也不创建普通 DENY。
    async fn reconcile_expired_delegation(
        &self,
        delegation_id: i64,
    ) -> Result<DelegationExpiryOutcome, AstralError>;
    /// 有界批量候选发现：ACTIVE 且 `effective_until <= NOW()` 的委托主键，按
    /// `delegation_id` 升序，`LIMIT ?` 绑定参数封顶（`batch_limit` 必须为正且
    /// 不超过 [`MAX_EXPIRY_RECONCILIATION_BATCH`]）。只读，不做任何写入。
    async fn list_expired_active_delegation_ids(
        &self,
        batch_limit: i64,
    ) -> Result<Vec<i64>, AstralError>;
    /// source mutation 事务是否已追加卡片投影。
    fn writes_projection_in_transaction(&self) -> bool {
        false
    }
}

/// 委托展示行（list_delegations 用；platform_v4 列名别名映射）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DelegationViewRecord {
    pub id: i64,
    pub delegator_id: i64,
    pub delegate_id: i64,
    pub resource: String,
    pub action: String,
    /// effective_until 的 UNIX 秒（None = 永不过期）
    pub expires_ts: Option<i64>,
    pub status: String,
}

pub struct SqlxDelegationRepository {
    db: MySqlPool,
}

impl SqlxDelegationRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct CardScope {
    card_id: i64,
    user_id: i64,
    card_status: String,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

fn permission_error(message: impl Into<String>) -> AstralError {
    AstralError::Permission(message.into())
}

fn validate_caller_card(
    context: &DelegationMutationContext,
    card: &CardScope,
    delegator_card_id: i64,
) -> Result<(), AstralError> {
    if context.caller_card_id() != delegator_card_id || card.card_id != delegator_card_id {
        return Err(permission_error(
            "delegation caller card does not own the delegator card",
        ));
    }
    if card.user_id != context.user_id() {
        return Err(permission_error(
            "delegation caller card does not belong to the verified user",
        ));
    }
    if card.card_status != "ACTIVE" {
        return Err(permission_error(
            "delegation mutation requires an active caller card",
        ));
    }
    validate_card_scope(context, card, "caller")
}

fn validate_card_scope(
    context: &DelegationMutationContext,
    card: &CardScope,
    role: &str,
) -> Result<(), AstralError> {
    if card.tenant_id != Some(context.tenant_id()) {
        return Err(permission_error(format!(
            "delegation {role} card is outside the caller tenant scope"
        )));
    }
    if card.domain_id != Some(context.domain_id()) {
        return Err(permission_error(format!(
            "delegation {role} card is outside the caller domain scope"
        )));
    }
    Ok(())
}

fn validate_delegate_card(
    context: &DelegationMutationContext,
    caller: &CardScope,
    delegate: &CardScope,
    require_active: bool,
) -> Result<(), AstralError> {
    if require_active && delegate.card_status != "ACTIVE" {
        return Err(permission_error(
            "delegation target requires an active delegate card",
        ));
    }
    if delegate.tenant_id != caller.tenant_id || delegate.domain_id != caller.domain_id {
        return Err(permission_error(
            "delegation target must remain in the caller tenant and domain scope",
        ));
    }
    validate_card_scope(context, delegate, "delegate")
}

async fn lock_card_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
) -> Result<CardScope, AstralError> {
    sqlx::query_as::<_, CardScope>(
        "SELECT card_id, user_id, card_status, tenant_id, domain_id \
         FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or_else(|| permission_error("delegation card scope could not be proven"))
}

/// 计算一次 mutation 参与的全部 user_card 行锁集合：去重、升序、非正 id 一律
/// Validation fail-closed。
///
/// 全局锁序契约（对齐 user_card_repository::delete_with_cascade 家族注释）：
/// **所有**涉及本事务的 user_card 行必须先于任何 permission_delegation /
/// permission_rule / 投影 head / 授权账本锁按 card_id 升序取得。这样同一对
/// delegator/delegate 的并发创建/更新/撤销被串行化，且跨方法族之间不存在 ABBA
/// 环 —— 卡级联删除同样先持卡锁再碰 delegation 行，方向一致。
fn ordered_unique_positive_card_ids(
    cards: impl IntoIterator<Item = i64>,
) -> Result<Vec<i64>, AstralError> {
    let mut seen = std::collections::BTreeSet::new();
    for card_id in cards {
        if card_id <= 0 {
            return Err(AstralError::Validation(format!(
                "delegation mutation requires positive user_card ids, got {card_id}"
            )));
        }
        seen.insert(card_id);
    }
    Ok(seen.into_iter().collect())
}

/// 从按升序锁定取得的卡行集合中取出指定卡行；锁定集合与请求集合不一致属于
/// 持久层不变式破坏，Internal fail-closed。
fn locked_card_of(cards: &[CardScope], card_id: i64) -> Result<&CardScope, AstralError> {
    cards
        .iter()
        .find(|card| card.card_id == card_id)
        .ok_or_else(|| {
            AstralError::Internal(format!(
                "locked delegation card set drift: expected card {card_id} inside the acquired lock set"
            ))
        })
}

/// self-delegation（同卡自委）显式拒绝：delegator 与 delegate 必须是两张不同
/// 卡片。纯判定，先于任何锁/durable 写入执行。
fn reject_self_delegation(new: &NewDelegation) -> Result<(), AstralError> {
    if new.delegator_card_id == new.delegate_card_id {
        return Err(AstralError::Validation(format!(
            "self delegation on card {} is rejected: delegator and delegate must differ",
            new.delegator_card_id
        )));
    }
    Ok(())
}

/// 数据库当前 UTC 秒（与 FROM_UNIXTIME/UNIX_TIMESTAMP 同一会话时区自洽，
/// 不在 Agent 侧引入第二时钟）。非正结果视为持久层不变式破坏。
async fn db_now_in_tx(tx: &mut sqlx::Transaction<'_, sqlx::MySql>) -> Result<i64, AstralError> {
    let (now_ts,): (i64,) = sqlx::query_as("SELECT UNIX_TIMESTAMP()")
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?;
    if now_ts <= 0 {
        return Err(AstralError::Internal(format!(
            "database clock returned an unusable unix timestamp: {now_ts}"
        )));
    }
    Ok(now_ts)
}

/// 纯有效期校验：正数、严格未来（相对事务内数据库时钟）。
fn require_future_expiry(now_ts: i64, effective_until_ts: i64) -> Result<(), AstralError> {
    if effective_until_ts <= 0 {
        return Err(AstralError::Validation(
            "delegation expiry must be a positive UNIX timestamp".into(),
        ));
    }
    if effective_until_ts <= now_ts {
        return Err(AstralError::Validation(
            "delegation expiry must be in the future".into(),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 委托人持有权证明（delegator hold proof，V2 修复核心）
//
// 契约：创建/变更委托前，必须在同一 source 事务内用 astral-db 严格 reader
// 返回的已发布 canonical evidence（`PublishedCardAuthorization`）证明委托人
// （delegator card）实际持有覆盖被委托 `resource_type:action_code` 的有效
// ALLOW。禁止读取 raw permission_rule / permission_delegation / 旧快照 /
// 缓存作为放行依据；evidence 读取失败（NotReady/Corrupt/InvalidRequest/Query）
// 一律按 Permission 拒绝（fail-closed，PENDING/DENY 家族），绝不降级放行。
// ─────────────────────────────────────────────────────────────────────────────

/// 已发布 canonical evidence 中一条候选授权的最小匹配视图（纯数据，可单测）。
///
/// `conditioned` 是面向未来 evidence 合同演进的 fail-closed 钩子：当前
/// `CanonicalGrant` 合同不含 condition 字段（对齐 policy-engine 匹配器注释：
/// 所有 effective grant 均为无条件 ALLOW，带运行时条件的条目在投影阶段即被
/// 跳过），适配层 [`delegator_evidence_grants`] 恒填 `false`；一旦未来
/// evidence 合同携带条件语义，本证明默认拒绝 —— 条件化的授权绝不允许被
/// 委托成无条件类型级 ALLOW（保守优先）。
pub(crate) struct DelegatorEvidenceGrant<'a> {
    pub resource: &'a str,
    pub action: &'a str,
    /// grant 有效期上界（UTC Unix 秒，排他上界；`None` = 永续）。
    pub expires_at: Option<i64>,
    pub conditioned: bool,
}

/// 委托人持有权证明的纯判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DelegatorHoldProof {
    /// 命中授权集合中最晚的有效期上界；`None` = 委托人持有永续授权，
    /// evidence 侧不存在可约束委托 `effective_until` 的上界。
    pub evidence_expires_at: Option<i64>,
}

/// 类型级委托请求的单条 evidence 匹配判定（纯函数）。
///
/// 语义与 policy-engine `match_published_effective_grant` 的类型级分支逐条
/// 对齐（委托写入的规则恒为 resource_id=NULL 的类型级 ALLOW，因此委托人
/// 必须在“类型级请求”语义下有效持有该权限）：
/// - 资源（`parse_resource_key` 语义）：grant 的资源类型等于被委托类型，
///   或 grant 为全局 `*`；且 grant 本身必须是类型级（`type:*`/裸 `type`/`*`）
///   —— 对象级 grant 绝不支撑类型级委托，否则被委托方将获得委托人从未
///   有效持有的类型级权限；
/// - 动作：exact → `write` 别名来源（write→create/update/delete，与引擎
///   同一张反向别名表）→ `'*'`；持有 `create` 不能反向委托出聚合动作
///   `write`（引擎语义下持有者同样无法直接通过 `write` 评估）。
fn evidence_grant_covers(
    grant: &DelegatorEvidenceGrant<'_>,
    resource_type: &str,
    action_code: &str,
) -> bool {
    if grant.conditioned {
        // 条件化授权：无 prove-safe 的继承语义，默认拒绝（保守优先）。
        return false;
    }
    let (grant_type, grant_object_id) = parse_resource_key(grant.resource);
    if grant_type != resource_type && grant_type != "*" {
        return false;
    }
    if grant_object_id.is_some() {
        return false;
    }
    grant.action == action_code
        || grant.action == "*"
        || get_alias_sources(action_code).contains(&grant.action)
}

/// 委托人持有权证明的纯判定（无 I/O，可单测）。
///
/// - 命中要求：候选集合中存在至少一条 [`evidence_grant_covers`] 通过的授权；
///   多条命中时取最晚的有效期上界（永续优先），这是委托人可证明持有的
///   真实上界，不放大也不缩小其授权。
/// - 有效期约束：委托 `effective_until`（排他上界）不得超过该上界 —— 两侧
///   均为排他上界，相等即窗口完全一致；越界即委托会越过委托人自身授权的
///   可证明有效期，Permission 拒绝。
/// - evidence 无上界（命中授权永续）时放行任意正数有效期：已发布 evidence
///   即是“持有该权限”的 canonical 证明，永续授权不存在 evidence 侧上界；
///   若强行引入固定时长上限，会以未登记的策略破坏既有委托有效期契约。
///   委托仍受撤销/到期对账等既有生命周期控制。
fn prove_delegator_hold(
    grants: &[DelegatorEvidenceGrant<'_>],
    resource_type: &str,
    action_code: &str,
    effective_until_ts: i64,
) -> Result<DelegatorHoldProof, AstralError> {
    // 外层 None = 未命中；Some(None) = 命中且永续；Some(Some(x)) = 命中且上界 x。
    let mut best_bound: Option<Option<i64>> = None;
    for grant in grants {
        if !evidence_grant_covers(grant, resource_type, action_code) {
            continue;
        }
        best_bound = match (best_bound, grant.expires_at) {
            (None, bound) => Some(bound),
            (Some(Some(current)), Some(candidate)) if candidate > current => Some(Some(candidate)),
            (Some(Some(_)), None) => Some(None),
            (current, _) => current,
        };
    }
    match best_bound {
        None => Err(permission_error(format!(
            "delegation rejected: the delegator does not hold a proven published ALLOW covering \
             {resource_type}:{action_code}; delegations may only be granted from published \
             canonical grant evidence"
        ))),
        Some(None) => Ok(DelegatorHoldProof {
            evidence_expires_at: None,
        }),
        Some(Some(expires_at)) => {
            if effective_until_ts > expires_at {
                return Err(permission_error(format!(
                    "delegation rejected: effective_until ({effective_until_ts}) exceeds the \
                     delegator's proven grant expiry ({expires_at}) for \
                     {resource_type}:{action_code}"
                )));
            }
            Ok(DelegatorHoldProof {
                evidence_expires_at: Some(expires_at),
            })
        }
    }
}

/// 构造 delegator 卡的已发布 evidence 读取范围：lens 与 PolicyEngine 读侧
/// 一致 —— tenant/card/user/domain 全部取自本事务内已锁定并通过归属/scope/
/// ACTIVE 校验的 delegator 卡行，不以请求输入为事实来源。
fn delegator_evidence_scope(caller: &CardScope) -> Result<PublishedCardEvidenceScope, AstralError> {
    let tenant_id = caller.tenant_id.ok_or_else(|| {
        permission_error(
            "delegator card has no tenant scope; published authorization evidence cannot be addressed",
        )
    })?;
    let domain_id = caller.domain_id.ok_or_else(|| {
        permission_error(
            "delegator card has no domain scope; published authorization evidence cannot be addressed",
        )
    })?;
    Ok(PublishedCardEvidenceScope {
        tenant_id,
        card_id: caller.card_id,
        user_filter: Some(caller.user_id),
        domain: DomainScopeRequirement::ExactlySome(domain_id),
    })
}

/// 把严格 reader 返回的 `Ready` evidence 适配为持有权证明输入。
///
/// fail-closed：gate 非 `Ready`、合同校验失败或 evidence 身份与锁定 delegator
/// 卡不一致时一律 Permission 拒绝；`effective_grants` 只包含 ACTIVE+ALLOW+
/// 窗口内+user/domain lens 通过的已验证记录，被排除记录不参与证明。
fn delegator_evidence_grants<'a>(
    evidence: &'a PublishedCardAuthorization,
    scope: &PublishedCardEvidenceScope,
) -> Result<Vec<DelegatorEvidenceGrant<'a>>, AstralError> {
    if !evidence.gate.status.is_authorization_usable() {
        return Err(permission_error(format!(
            "delegation rejected: delegator published evidence gate is {}",
            evidence.gate.status
        )));
    }
    if let Err(error) = evidence.validate() {
        return Err(permission_error(format!(
            "delegation rejected: delegator published evidence failed contract validation ({error})"
        )));
    }
    if evidence.tenant_id != scope.tenant_id || evidence.card_id != scope.card_id {
        return Err(permission_error(
            "delegation rejected: published evidence identity does not match the locked delegator card",
        ));
    }
    Ok(evidence
        .effective_grants
        .iter()
        .map(|grant| DelegatorEvidenceGrant {
            resource: &grant.resource,
            action: &grant.action,
            expires_at: grant.validity.expires_at,
            // `CanonicalGrant` 合同当前不含 condition 字段（见类型注释）；
            // 若未来合同引入条件语义，此处必须带出条件事实并保持 fail-closed。
            conditioned: false,
        })
        .collect())
}

/// `AuthorizationEvidenceError` → `AstralError`：NotReady（指针缺失/非
/// COMMITTED/超扇出上限）/ Corrupt / InvalidRequest / Query 全部映射为
/// Permission 拒绝。委托路径的契约是“无法证明即拒绝”——绝不回退 raw
/// source、旧快照或缓存，也绝不把基础设施未知当成放行依据。
fn map_delegator_evidence_error(error: astral_db::AuthorizationEvidenceError) -> AstralError {
    permission_error(format!(
        "delegation rejected: delegator published authorization evidence is not usable ({error}); \
         refusing to prove the delegated grant from anything but published canonical evidence"
    ))
}

/// 委托人持有权证明的事务内完整入口：构造锁定 delegator 卡的 evidence 范围
/// → 同事务严格读取已发布 canonical evidence（FOR UPDATE 指针行，锁序遵循
/// 全局契约：全部 user_card 行锁先行）→ 适配候选授权 → 纯判定匹配与有效期
/// 上界校验。任何一步无法证明一律 Permission/Validation 拒绝，调用方所在
/// source 事务整体回滚，source 保持不变。
async fn prove_delegator_hold_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    caller: &CardScope,
    resource_type: &str,
    action_code: &str,
    effective_until_ts: i64,
) -> Result<DelegatorHoldProof, AstralError> {
    let scope = delegator_evidence_scope(caller)?;
    let evidence = astral_db::load_published_card_grant_evidence_in_tx(tx, &scope)
        .await
        .map_err(map_delegator_evidence_error)?;
    let candidates = delegator_evidence_grants(&evidence, &scope)?;
    prove_delegator_hold(&candidates, resource_type, action_code, effective_until_ts)
}

/// 新建委托参数的 registry 校验 + trim 规范化副本（单一事实源）。
///
/// 契约：resource_type/action_code 必须已注册于 `ResourceRegistry`（复用
/// `personal_permission_service::validate_registry_resource_action`，不得
/// 移动或复制该函数）；未注册/空白一律 Validation fail-closed。返回副本中的
/// resource/action 是 trim 后的规范化值，调用方必须把该副本（而非原始输入）
/// 写入 permission_delegation、permission_rule 与授权账本 facts，保证三处
/// 写入零漂移。
pub(crate) fn normalize_new_delegation(new: &NewDelegation) -> Result<NewDelegation, AstralError> {
    let (resource_type, action_code) =
        crate::service::personal_permission_service::validate_registry_resource_action(
            &new.resource_type,
            &new.action_code,
        )?;
    Ok(NewDelegation {
        delegator_card_id: new.delegator_card_id,
        delegate_card_id: new.delegate_card_id,
        resource_type,
        action_code,
        effective_until_ts: new.effective_until_ts,
    })
}

async fn lock_delegation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    delegation_id: i64,
) -> Result<Option<DelegationRecord>, AstralError> {
    sqlx::query_as::<_, DelegationRecord>(&format!(
        "SELECT {DELEGATION_SELECT} FROM permission_delegation \
         WHERE delegation_id = ? FOR UPDATE"
    ))
    .bind(delegation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)
}

/// 委托行的**无锁预读**：仅用于在取得卡行锁前发现 delegator/delegate 端点
/// （全局锁序要求 user_card 全部先于 permission_delegation 锁）。
/// 预读结果不是事实来源 —— 最终判定一律以随后的 FOR UPDATE 复读为准，
/// 端点与预读集合漂移时整体 fail-closed。
async fn probe_delegation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    delegation_id: i64,
) -> Result<Option<DelegationRecord>, AstralError> {
    sqlx::query_as::<_, DelegationRecord>(&format!(
        "SELECT {DELEGATION_SELECT} FROM permission_delegation \
         WHERE delegation_id = ?"
    ))
    .bind(delegation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)
}

/// 锁定中 permission_rule 完整 before-image 行（DELEGATION 聚合的一条子句）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct LockedDelegationRuleRow {
    rule_id: i64,
    card_id: i64,
    resource_type: String,
    action_code: String,
    effect: String,
    /// UNIX_TIMESTAMP(valid_from)；NULL 即无下界。
    valid_from_ts: Option<i64>,
    /// UNIX_TIMESTAMP(valid_to)；NULL 即无上界。
    valid_to_ts: Option<i64>,
    enabled: i8,
}

/// 锁定（FOR UPDATE）某委托聚合当前的全部 DELEGATION 规则行并捕获 before-image。
/// 当前模型一条委托恰好产出一条规则；返回数量 != 1 视为 source/ledger 不一致，
/// 由调用方 fail-closed 拒绝 mutation 并保持 source 不变。
async fn lock_delegation_rules_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    delegation_id: i64,
) -> Result<Vec<LockedDelegationRuleRow>, AstralError> {
    sqlx::query_as::<_, LockedDelegationRuleRow>(
        "SELECT rule_id, card_id, resource_type, action_code, effect, \
         UNIX_TIMESTAMP(valid_from) as valid_from_ts, \
         UNIX_TIMESTAMP(valid_to) as valid_to_ts, enabled \
         FROM permission_rule \
         WHERE source_type = 'DELEGATION' AND source_id = ? \
         ORDER BY rule_id FOR UPDATE",
    )
    .bind(delegation_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)
}

/// 组装授权账本事实（tenant/domain/user/card 全部来自锁定的 ACTIVE 被委托卡，
/// 授权承载语义不被 delegator 卡混淆）；tenant 缺失即 fail-closed。
#[allow(clippy::too_many_arguments)]
fn delegation_facts<'a>(
    delegation_id: i64,
    not_before_unix: i64,
    resource: &'a str,
    action: &'a str,
    delegate_tenant_id: Option<i64>,
    delegate_domain_id: Option<i64>,
    delegate_user_id: i64,
    delegate_card_id: i64,
    expires_at_unix: i64,
) -> Result<DelegationLedgerFacts<'a>, AstralError> {
    let tenant_id = delegate_tenant_id.ok_or_else(|| {
        permission_error("delegation grant carrier (delegate) card has no tenant scope")
    })?;
    Ok(DelegationLedgerFacts {
        tenant_id,
        domain_id: delegate_domain_id,
        card_id: delegate_card_id,
        user_id: delegate_user_id,
        delegation_id,
        resource,
        action,
        not_before_unix: Some(not_before_unix),
        expires_at_unix,
    })
}

/// ACTIVE 委托行的可证明有效期；缺失/非正视为 source 不一致。
/// 卡级联删除路径复用同一判定（单一事实源，避免两处语义漂移）。
pub(crate) fn require_provable_expiry(record: &DelegationRecord) -> Result<i64, AstralError> {
    record
        .effective_until_ts
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "ACTIVE delegation {} carries no provable positive expiry; repair required",
                record.delegation_id
            ))
        })
}

/// 锁定行与无锁预读端点的一致性门禁：delegator/delegate 归属列在已落库的
/// permission_delegation 行上不可变；任何漂移都代表持久层被带外修改，整体
/// fail-closed，绝不基于部分锁定的端点继续。
fn assert_locked_endpoints_match_probe(
    locked: &DelegationRecord,
    probe: &DelegationRecord,
) -> Result<(), AstralError> {
    if locked.delegator_card_id != probe.delegator_card_id
        || locked.delegate_card_id != probe.delegate_card_id
    {
        return Err(AstralError::Internal(format!(
            "permission_delegation {} endpoint drift between the unlocked probe ({}, {}) and its FOR UPDATE read ({}, {}); refusing to mutate",
            locked.delegation_id,
            probe.delegator_card_id,
            probe.delegate_card_id,
            locked.delegator_card_id,
            locked.delegate_card_id
        )));
    }
    Ok(())
}

/// 校验锁定委托行的两个端点全部位于本次事务升序取得的 user_card 行锁集合内
/// （全局锁序契约的收敛断言）。
fn assert_endpoints_within_locked_cards(
    record: &DelegationRecord,
    cards: &[CardScope],
) -> Result<(), AstralError> {
    for endpoint in [record.delegator_card_id, record.delegate_card_id] {
        locked_card_of(cards, endpoint)?;
    }
    Ok(())
}

/// 在事务内读取委托账本 head（FOR UPDATE）；None = 未版本化，由调用方裁决。
async fn read_delegation_head_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    tenant_id: i64,
    delegation_id: i64,
    grant_id: astral_types::GrantId,
) -> Result<Option<astral_db::GrantHeadSnapshot>, AstralError> {
    astral_db::read_grant_head_for_update_in_tx(
        tx,
        tenant_id,
        crate::repository::grant_ledger_adapter::DELEGATION_AGGREGATE_TYPE,
        delegation_id,
        grant_id,
    )
    .await
    .map_err(map_grant_repository_error)
}

/// 锁定并要求委托账本 head 存在：missing/stale/gap 一律 fail-closed，
/// 绝不允许只改 source/旧链而留下无账本状态。
async fn expect_delegation_head_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    tenant_id: i64,
    delegation_id: i64,
    grant_id: astral_types::GrantId,
    delegate_card_id: i64,
) -> Result<astral_db::GrantHeadSnapshot, AstralError> {
    read_delegation_head_in_tx(tx, tenant_id, delegation_id, grant_id)
        .await?
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "delegation grant ledger entry missing for delegation {delegation_id} under delegate card {delegate_card_id}; refusing to mutate an un-versioned authorization"
            ))
        })
}

/// 幂等 ACTIVE 分支的账本 head 状态输入（纯判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdempotentHead {
    Active,
    NotActive,
    Missing,
}

/// 幂等 ACTIVE 分支的一致性结论（纯函数，可单测）：任何维度无法证明即
/// 要求显式修复，绝不把不可证明的重复当成功返回。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdempotentConsistency {
    Consistent,
    RepairRequired(&'static str),
}

fn classify_idempotent_consistency(
    rule_row_count: usize,
    rules_allow_enabled: bool,
    head: IdempotentHead,
    expiry_provable: bool,
) -> IdempotentConsistency {
    if rule_row_count != 1 {
        return IdempotentConsistency::RepairRequired("rule rows");
    }
    if !rules_allow_enabled {
        return IdempotentConsistency::RepairRequired("rule effect or enabled flag");
    }
    if !expiry_provable {
        return IdempotentConsistency::RepairRequired("delegation expiry");
    }
    match head {
        IdempotentHead::Missing => IdempotentConsistency::RepairRequired("grant ledger head"),
        IdempotentHead::NotActive => IdempotentConsistency::RepairRequired("grant ledger state"),
        IdempotentHead::Active => IdempotentConsistency::Consistent,
    }
}

/// 到期对账资格的纯判定（输入全部来自锁定的 source 行 + 事务内 DB 时钟；
/// 可单测）。锁定行不是 ACTIVE 即幂等 no-op；有效期缺失/非正是 source 漂移，
/// 显式要求修复而不是当作 no-op 或错误地收敛。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpiryReconciliationEligibility {
    /// ACTIVE 且锁定有效期已过 → 允许单事务收敛。
    Due,
    /// 非 ACTIVE → 已收敛或带外终结，幂等 no-op。
    AlreadyTerminal,
    /// 仍 ACTIVE 但锁定有效期尚未过去 → 显式不满足，不写任何状态。
    NotYetDue,
    /// ACTIVE 但无可证明的正数有效期 → source 漂移，要求显式修复。
    RepairRequired,
}

fn classify_expiry_reconciliation(
    status: &str,
    now_ts: i64,
    effective_until_ts: Option<i64>,
) -> ExpiryReconciliationEligibility {
    if status != "ACTIVE" {
        return ExpiryReconciliationEligibility::AlreadyTerminal;
    }
    match effective_until_ts {
        Some(expires_at) if expires_at > 0 && expires_at <= now_ts => {
            ExpiryReconciliationEligibility::Due
        }
        Some(expires_at) if expires_at > 0 => ExpiryReconciliationEligibility::NotYetDue,
        _ => ExpiryReconciliationEligibility::RepairRequired,
    }
}

/// 到期对账的稳定业务 operation id：纯派生自锁定委托主键 + 锁定有效期
/// （`delegation:expire:{id}:e{expires_at}`），无请求头依赖、无随机 fallback，
/// 恒 <64 字节（与 `audit_log.request_id VARCHAR(64)` 同一 canonical 上限）。
///
/// 唯一性论证：一次成功的到期收敛把行置为非 ACTIVE 终态，此后同一 id 的任何
/// 重放都会在 ACTIVE/到期门禁处幂等短路，不再产生第二组 durable 写入；因此
/// 该 id 与其派生的 contribution event id 全局唯一且重放稳定（uk_ade_event 安全）。
fn derive_delegation_expiry_operation_id(
    delegation_id: i64,
    expires_at_unix: i64,
) -> Result<String, AstralError> {
    if delegation_id <= 0 {
        return Err(AstralError::Validation(
            "delegation expiry reconciliation requires a positive delegation id".into(),
        ));
    }
    if expires_at_unix <= 0 {
        return Err(AstralError::Validation(
            "delegation expiry reconciliation requires a positive locked expiry".into(),
        ));
    }
    let derived = format!("delegation:expire:{delegation_id}:e{expires_at_unix}");
    if derived.len() >= crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH {
        return Err(AstralError::Internal(format!(
            "derived delegation expiry operation id exceeds the {}-byte audit column width",
            crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH
        )));
    }
    Ok(derived)
}

/// 到期对账候选批量的显式边界：正数且不超过
/// [`MAX_EXPIRY_RECONCILIATION_BATCH`]；非法输入 Validation fail-closed，
/// 不静默截断（避免无界扫描伪装成小批量）。测试 Fake 复用同一判定，保证
/// service 契约测试与真实仓库边界一致。
pub(crate) fn validated_expiry_batch_limit(batch_limit: i64) -> Result<i64, AstralError> {
    if batch_limit <= 0 {
        return Err(AstralError::Validation(format!(
            "delegation expiry reconciliation batch limit must be positive, got {batch_limit}"
        )));
    }
    if batch_limit > MAX_EXPIRY_RECONCILIATION_BATCH {
        return Err(AstralError::Validation(format!(
            "delegation expiry reconciliation batch limit {batch_limit} exceeds the explicit bound {MAX_EXPIRY_RECONCILIATION_BATCH}"
        )));
    }
    Ok(batch_limit)
}

/// 校验锁定规则行与锁定委托行一致：card 归属、恒 ALLOW、enabled、
/// resource/action 与有效期必须同源。任一漂移 fail-closed。
fn assert_rule_row_matches_locked_delegation(
    row: &LockedDelegationRuleRow,
    record: &DelegationRecord,
) -> Result<(), AstralError> {
    if row.card_id != record.delegate_card_id {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} does not belong to the locked delegate card {}; delegator/delegate scope drift detected",
            row.rule_id, record.delegate_card_id
        )));
    }
    if row.effect != "ALLOW" {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} effect must remain ALLOW; refusing to transform legacy DENY rows on the delegation path",
            row.rule_id
        )));
    }
    if row.enabled != 1 {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} is disabled; repair required before mutating the delegation aggregate",
            row.rule_id
        )));
    }
    if row.resource_type != record.resource_type || row.action_code != record.action_code {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} resource/action drifted from the locked permission_delegation row",
            row.rule_id
        )));
    }
    if row.valid_to_ts != record.effective_until_ts {
        return Err(AstralError::Validation(format!(
            "DELEGATION rule {} valid_to drifted from the locked permission_delegation effective_until",
            row.rule_id
        )));
    }
    Ok(())
}

/// 校验账本 head 快照与锁定的 source 状态一致（更新/撤销前的 continuity 门禁）：
/// 头部 payload 的 resource/action/有效期必须仍反映锁定 source 的变更前事实。
fn assert_head_matches_locked_source(
    head: &astral_db::GrantHeadSnapshot,
    old_rule: &LockedDelegationRuleRow,
    record: &DelegationRecord,
) -> Result<(), AstralError> {
    if head.payload.resource != record.resource_type || head.payload.action != record.action_code {
        return Err(AstralError::Validation(
            "grant ledger head resource/action drifted from the locked permission_delegation row"
                .into(),
        ));
    }
    if head.payload.validity.expires_at != old_rule.valid_to_ts {
        return Err(AstralError::Validation(
            "grant ledger head expiry drifted from the locked DELEGATION rule window".into(),
        ));
    }
    if head.payload.validity.not_before != old_rule.valid_from_ts {
        return Err(AstralError::Validation(
            "grant ledger head lower bound drifted from the locked DELEGATION rule window".into(),
        ));
    }
    Ok(())
}

fn rule_ids_of(rows: &[LockedDelegationRuleRow]) -> Vec<i64> {
    rows.iter().map(|row| row.rule_id).collect()
}

#[derive(Debug, Clone, Copy)]
struct DelegationAudit<'a> {
    delegation_id: i64,
    delegator_card_id: i64,
    delegate_card_id: i64,
    resource_type: &'a str,
    action_code: &'a str,
    effective_until_ts: Option<i64>,
    event_type: &'a str,
    /// 稳定业务 operation id（贯穿 source/head/outbox/audit/revision/delta）。
    operation_id: &'a str,
    /// CARD parent 投影事件号（幂等分支/无投影路径为 None）。
    parent_event_id: Option<&'a str>,
    /// 本贡献自身的独立账本事件号（幂等分支为 None）。
    contribution_event_id: Option<&'a str>,
    /// 本 mutation 覆盖的 permission_rule 主键（存在时至少一条）。
    rule_ids: &'a [i64],
    /// 账本 grant 身份（确定性派生，证明与 revision/delta 同一 identity）。
    grant_id: Option<&'a str>,
    /// before-image digest（update/revoke 与成对 before_image_json 关联）。
    before_image_digest_hex: Option<&'a str>,
    /// 账本 head revision（append 后的目标 revision；幂等分支为现有 head）。
    ledger_revision: Option<u64>,
}

/// 审计写入 actor：常规 mutation 携带已验证 caller 身份；系统到期对账使用
/// `SYSTEM_ACTOR_ID` 且不虚构 caller 卡与请求头（`audit_log.card_id` 允许
/// NULL，tenant/domain 取锁定 delegate 卡的可证明 scope，缺失允许 NULL）。
#[derive(Debug, Clone, Copy)]
struct DelegationAuditActor<'a> {
    user_id: i64,
    card_id: Option<i64>,
    request_id_header: Option<&'a str>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

impl<'a> From<&'a DelegationMutationContext> for DelegationAuditActor<'a> {
    fn from(context: &'a DelegationMutationContext) -> Self {
        Self {
            user_id: context.user_id(),
            card_id: Some(context.caller_card_id()),
            request_id_header: context.request_id_header(),
            tenant_id: Some(context.tenant_id()),
            domain_id: Some(context.domain_id()),
        }
    }
}

impl<'a> DelegationAuditActor<'a> {
    /// 系统到期对账 actor：无 caller 卡、无请求头；scope 来自锁定的 delegate 卡。
    fn system_expiry_reconciliation(tenant_id: Option<i64>, domain_id: Option<i64>) -> Self {
        Self {
            user_id: SYSTEM_ACTOR_ID,
            card_id: None,
            request_id_header: None,
            tenant_id,
            domain_id,
        }
    }
}

/// Source mutation audit and its operation correlation share the source tx.
async fn insert_delegation_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    actor: &DelegationAuditActor<'_>,
    audit: DelegationAudit<'_>,
) -> Result<(), AstralError> {
    let detail = serde_json::to_string(&serde_json::json!({
        "operationId": audit.operation_id,
        "requestIdHeader": actor.request_id_header,
        "delegationId": audit.delegation_id,
        "delegatorCardId": audit.delegator_card_id,
        "delegateCardId": audit.delegate_card_id,
        "resourceType": audit.resource_type,
        "actionCode": audit.action_code,
        "effectiveUntil": audit.effective_until_ts,
        "parentEventId": audit.parent_event_id,
        "contributionEventIds": audit
            .contribution_event_id
            .map(|event_id| [event_id])
            .unwrap_or_default(),
        "ruleIds": audit.rule_ids,
        "grantId": audit.grant_id,
        "beforeImageDigest": audit.before_image_digest_hex,
        "ledgerRevision": audit.ledger_revision,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("delegation audit serialization failed: {error}"))
    })?;

    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
          domain_id, tenant_id, detail) \
         VALUES (?, ?, ?, 'permission_delegation', 'ALLOW', ?, ?, ?, ?, ?, ?)",
    )
    .bind(actor.user_id)
    .bind(actor.card_id)
    .bind(audit.event_type)
    .bind("delegation source mutation")
    .bind(audit.event_type)
    .bind(audit.operation_id)
    .bind(actor.domain_id)
    .bind(actor.tenant_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

#[async_trait]
impl DelegationRepository for SqlxDelegationRepository {
    fn writes_projection_in_transaction(&self) -> bool {
        true
    }

    async fn create_with_rule(
        &self,
        new: &NewDelegation,
        context: &DelegationMutationContext,
    ) -> Result<DelegationCreateResult, AstralError> {
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        let now_ts = db_now_in_tx(&mut tx).await?;
        require_future_expiry(now_ts, new.effective_until_ts)?;
        // 同卡自委显式拒绝：先于任何锁/durable 写入的纯判定。
        reject_self_delegation(new)?;

        // ── V2 修复①：registry 校验 + trim 规范化（纯判定，先于任何锁）──────
        // 被委托 resource/action 必须已注册于 ResourceRegistry；未注册/空白
        // Validation fail-closed。规范化副本向下游遮蔽原始参数：duplicate 探测、
        // permission_delegation / permission_rule 写入、授权账本 facts 与审计
        // 全部使用 trim 后的值，消除 raw/trim 漂移。
        let normalized = normalize_new_delegation(new)?;
        let new = &normalized;

        // ── V1 修复：duplicate ACTIVE 查询必须发生在确定性卡行锁之后 ──────────
        //
        // 固定锁序第 1 步：本事务涉及的全部 user_card 行按 card_id **升序**
        // FOR UPDATE（delegator=caller 与 delegate 两张卡；跨并发方向也保持
        // 同一 asc 序，杜绝 ABBA）。不依赖隔离级别的隐式 gap lock：两端卡锁
        // 把"同 pair/resource/action 的并发创建"完全串行化，随后的锁定重复查询
        // 必然看到对手事务刚提交的行，从而无 schema 改动地消除双插。
        //
        // 锁后再验证 caller/delegate 归属、scope、ACTIVE 状态与有效期。
        let card_ids =
            ordered_unique_positive_card_ids([new.delegator_card_id, new.delegate_card_id])?;
        let mut cards: Vec<CardScope> = Vec::with_capacity(card_ids.len());
        for card_id in &card_ids {
            cards.push(lock_card_in_tx(&mut tx, *card_id).await?);
        }
        let caller = locked_card_of(&cards, context.caller_card_id())?;
        validate_caller_card(context, caller, new.delegator_card_id)?;
        let delegate = locked_card_of(&cards, new.delegate_card_id)?;
        validate_delegate_card(context, caller, delegate, true)?;

        // ── V2 修复②：委托人持有权证明（锁定 delegator 卡之后、任何
        // delegation/rule/ledger 写入与 duplicate 幂等复用之前）───────────────
        //
        // 只消费同事务内严格 reader 返回的已发布 canonical evidence；证明失败
        // （委托人未持有匹配 ALLOW / 条件化 evidence / 委托有效期越过委托人
        // 授权上界 / evidence 不可用）一律 Permission 拒绝并整体回滚。幂等
        // 命中路径同样先证明：重复创建是对“委托权”的再次主张，无法证明时
        // 绝不把既有 ACTIVE 委托当成功复用（保守优先）。
        prove_delegator_hold_in_tx(
            &mut tx,
            caller,
            &new.resource_type,
            &new.action_code,
            new.effective_until_ts,
        )
        .await?;

        // 锁序第 2 步：候选 ACTIVE 委托行（幂等检查现已受双卡行锁保护）。
        // 锁定读会看到其他事务刚提交的行，因此不会产生重复 ACTIVE 委托。
        let existing_delegation: Option<DelegationRecord> =
            sqlx::query_as::<_, DelegationRecord>(&format!(
                "SELECT {DELEGATION_SELECT} FROM permission_delegation \
                 WHERE delegator_card_id = ? AND delegate_card_id = ? AND resource_type = ? \
                   AND action_code = ? AND status = 'ACTIVE' \
                 ORDER BY delegation_id LIMIT 1 FOR UPDATE"
            ))
            .bind(new.delegator_card_id)
            .bind(new.delegate_card_id)
            .bind(&new.resource_type)
            .bind(&new.action_code)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;

        if let Some(record) = existing_delegation {
            // 幂等命中：卡片身份/一致性事实已由上方锁+校验证明；这里继续复核
            // 账本/规则投影一致，只有锁+校验，不写任何 source/ledger 状态；
            // 无法证明时显式冲突回滚，绝不把不可证明的重复当成功返回。
            let rules = lock_delegation_rules_in_tx(&mut tx, record.delegation_id).await?;
            for row in &rules {
                assert_rule_row_matches_locked_delegation(row, &record)?;
            }
            let expires_at_unix = match require_provable_expiry(&record) {
                Ok(value) => value,
                Err(_) => {
                    return Err(AstralError::Validation(format!(
                        "idempotent ACTIVE delegation {} carries no provable positive expiry; repair required, refusing to return it as a duplicate success",
                        record.delegation_id
                    )));
                }
            };
            let facts = delegation_facts(
                record.delegation_id,
                record.effective_from_ts,
                &record.resource_type,
                &record.action_code,
                delegate.tenant_id,
                delegate.domain_id,
                delegate.user_id,
                record.delegate_card_id,
                expires_at_unix,
            )?;
            let grant_id = derive_delegation_identity(&facts)?;
            let head =
                read_delegation_head_in_tx(&mut tx, facts.tenant_id, facts.delegation_id, grant_id)
                    .await?;
            if let Some(snapshot) = &head {
                if let Some(first_rule) = rules.first() {
                    assert_head_matches_locked_source(snapshot, first_rule, &record)?;
                }
            }
            let verdict = classify_idempotent_consistency(
                rules.len(),
                rules
                    .iter()
                    .all(|row| row.effect == "ALLOW" && row.enabled == 1),
                match &head {
                    None => IdempotentHead::Missing,
                    Some(snapshot)
                        if snapshot.entry.state == GrantState::Active
                            && snapshot.entry.status_active =>
                    {
                        IdempotentHead::Active
                    }
                    Some(_) => IdempotentHead::NotActive,
                },
                true,
            );
            let IdempotentConsistency::Consistent = verdict else {
                let IdempotentConsistency::RepairRequired(reason) = verdict else {
                    unreachable!("non-consistent verdict must carry a repair reason");
                };
                return Err(AstralError::Validation(format!(
                    "idempotent ACTIVE delegation {} cannot be proven consistent ({reason}); repair required, refusing to return it as a duplicate success",
                    record.delegation_id
                )));
            };
            let head_revision = head
                .as_ref()
                .map(|snapshot| snapshot.entry.revision.value());
            let rule_ids_vec = rule_ids_of(&rules);
            insert_delegation_audit_in_tx(
                &mut tx,
                &DelegationAuditActor::from(context),
                DelegationAudit {
                    delegation_id: record.delegation_id,
                    delegator_card_id: record.delegator_card_id,
                    delegate_card_id: record.delegate_card_id,
                    resource_type: &record.resource_type,
                    action_code: &record.action_code,
                    effective_until_ts: record.effective_until_ts,
                    event_type: "DELEGATION_IDEMPOTENT",
                    operation_id: &derive_delegation_operation_id(
                        DelegationMutationKind::Create,
                        record.delegation_id,
                        context.request_id_header(),
                        None,
                    )?,
                    parent_event_id: None,
                    contribution_event_id: None,
                    rule_ids: &rule_ids_vec,
                    grant_id: Some(&grant_id.as_str()),
                    before_image_digest_hex: None,
                    ledger_revision: head_revision,
                },
            )
            .await?;
            tx.commit_consuming().await?;
            return Ok(DelegationCreateResult {
                delegation_id: record.delegation_id,
                created: false,
            });
        }

        // 锁序第 3 步：INSERT permission_delegation（双卡锁下不会与并发创建交错）。
        let result = sqlx::query(
            "INSERT INTO permission_delegation \
             (delegator_card_id, delegate_card_id, resource_type, action_code, \
              effective_from, effective_until, max_duration_hours, is_revokable, delegated_at, status) \
             VALUES (?, ?, ?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?), 24, 1, NOW(), 'ACTIVE')",
        )
        .bind(new.delegator_card_id)
        .bind(new.delegate_card_id)
        .bind(&new.resource_type)
        .bind(&new.action_code)
        .bind(now_ts)
        .bind(new.effective_until_ts)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "permission_delegation insert did not apply exactly one row".into(),
            ));
        }
        let delegation_id = i64::try_from(result.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Internal("permission_delegation insert returned an unusable id".into())
            })?;

        // 锁序第 4 步：permission_rule ALLOW 写入（恒 ALLOW，不转换旧 DENY）。
        // rule_id 只作审计/source 记录；账本身份以稳定 delegation 主键为粒度。
        let rule_result = sqlx::query(DELEGATION_RULE_INSERT)
            .bind(new.delegate_card_id)
            .bind(
                delegate
                    .tenant_id
                    .ok_or_else(|| permission_error("delegation target tenant scope is missing"))?,
            )
            .bind(&new.resource_type)
            .bind(&new.action_code)
            .bind(delegation_id)
            .bind(now_ts)
            .bind(new.effective_until_ts)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        if rule_result.rows_affected() != 1 || rule_result.last_insert_id() == 0 {
            return Err(AstralError::Internal(
                "delegation permission_rule insert did not apply exactly one identified row".into(),
            ));
        }
        let rule_id = rule_result.last_insert_id() as i64;

        // 稳定业务 operation id：安全 x-request-id 复用，否则从 kind + 全新委托
        // 主键确定性派生；禁止随机 fallback。定型点就在此处 —— 位于
        // permission_delegation / permission_rule source 插入之后（派生输入需要
        // 全新委托主键），先于 CARD outbox 投影、授权账本 delta 与 audit 等
        // durable 写入，并贯穿 projection/outbox/ledger/delta/audit。
        let operation_id = derive_delegation_operation_id(
            DelegationMutationKind::Create,
            delegation_id,
            context.request_id_header(),
            None,
        )?;

        // 锁序第 5 步：CARD head/outbox（带 metadata 的 DELEGATION_CREATED，
        // 返回的 durable ProjectionEventIdentity 绑定进授权账本）。
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            new.delegate_card_id,
            "DELEGATION_CREATED",
            astral_db::ProjectionEventMetadata {
                actor_id: context.user_id(),
                operation_id: &operation_id,
            },
        )
        .await?;

        // 授权账本 ADD rev1 / delta base0→target1（同事务）。delegation_id 为
        // 新鲜自增 id，同 grant 并发首发结构性不可能；理论残余竞争由
        // uk_ade_target_version 唯一键串行化（败者整体回滚，重试幂等收敛）。
        let facts = delegation_facts(
            delegation_id,
            now_ts,
            &new.resource_type,
            &new.action_code,
            delegate.tenant_id,
            delegate.domain_id,
            delegate.user_id,
            new.delegate_card_id,
            new.effective_until_ts,
        )?;
        let contribution_event_id = derive_delegation_contribution_event_id(
            &operation_id,
            &facts,
            DelegationContributionKind::Add,
        )?;
        let draft = build_delegation_add_draft(
            &facts,
            &operation_id,
            context.user_id(),
            &projection,
            &contribution_event_id,
        )?;
        let (base_version, target_version) =
            astral_db::next_delta_version(None).map_err(map_grant_repository_error)?;
        append_delegation_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;
        insert_delegation_audit_in_tx(
            &mut tx,
            &DelegationAuditActor::from(context),
            DelegationAudit {
                delegation_id,
                delegator_card_id: new.delegator_card_id,
                delegate_card_id: new.delegate_card_id,
                resource_type: &new.resource_type,
                action_code: &new.action_code,
                effective_until_ts: Some(new.effective_until_ts),
                event_type: "DELEGATION_CREATED",
                operation_id: &operation_id,
                parent_event_id: Some(projection.event_id.as_str()),
                contribution_event_id: Some(draft.event_id()),
                rule_ids: &[rule_id],
                grant_id: Some(&draft.grant_id().as_str()),
                before_image_digest_hex: draft.before_digest_hex(),
                ledger_revision: Some(draft.resulting_revision_value()),
            },
        )
        .await?;

        tx.commit_consuming().await?;
        Ok(DelegationCreateResult {
            delegation_id,
            created: true,
        })
    }

    async fn revoke_with_rules(
        &self,
        delegation_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<DelegationMutationResult, AstralError> {
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        // 无锁预读：仅为在卡锁之前发现 delegator/delegate 端点；最终事实以
        // FOR UPDATE 复读为准，端点漂移整体 fail-closed。
        let Some(probe) = probe_delegation_in_tx(&mut tx, delegation_id).await? else {
            tx.commit_consuming().await?;
            return Ok(DelegationMutationResult {
                changed: false,
                delegate_card_id: None,
            });
        };
        // 锁序第 1 步：本事务涉及的全部 user_card 行按 card_id 升序 FOR UPDATE
        // （caller/delegator 与 delegate 两端点，去重升序），先于 delegation 行锁，
        // 与 create/卡级联家族保持同一全局方向。
        let card_ids = ordered_unique_positive_card_ids([
            context.caller_card_id(),
            probe.delegator_card_id,
            probe.delegate_card_id,
        ])?;
        let mut cards: Vec<CardScope> = Vec::with_capacity(card_ids.len());
        for card_id in &card_ids {
            cards.push(lock_card_in_tx(&mut tx, *card_id).await?);
        }
        // 锁序第 2 步：delegation 行。缺失或非 ACTIVE 一律显式 no-op（重复撤销
        // 不生成新身份、不追加第二条 tombstone）。
        let Some(record) = lock_delegation_in_tx(&mut tx, delegation_id).await? else {
            tx.commit_consuming().await?;
            return Ok(DelegationMutationResult {
                changed: false,
                delegate_card_id: None,
            });
        };
        if record.status != "ACTIVE" {
            tx.commit_consuming().await?;
            return Ok(DelegationMutationResult {
                changed: false,
                delegate_card_id: None,
            });
        }
        assert_locked_endpoints_match_probe(&record, &probe)?;
        assert_endpoints_within_locked_cards(&record, &cards)?;
        if record.is_revokable == 0 {
            return Err(permission_error(
                "delegation is marked non-revocable; refusing to revoke",
            ));
        }

        // 锁序第 3 步：端点校验（caller 归属 + scope + 被委托卡状态）。
        let caller = locked_card_of(&cards, context.caller_card_id())?;
        validate_caller_card(context, caller, record.delegator_card_id)?;
        let delegate = locked_card_of(&cards, record.delegate_card_id)?;
        validate_delegate_card(context, caller, delegate, false)?;

        // 锁序第 4 步：锁定并校验旧规则行（before-image；数量必须恰为一条）。
        let rules = lock_delegation_rules_in_tx(&mut tx, delegation_id).await?;
        if rules.len() != 1 {
            return Err(AstralError::Validation(format!(
                "ACTIVE delegation {delegation_id} must own exactly one DELEGATION rule row before revocation, found {}; repair required and source left unchanged",
                rules.len()
            )));
        }
        let old_rule = &rules[0];
        assert_rule_row_matches_locked_delegation(old_rule, &record)?;

        let expires_at_unix = require_provable_expiry(&record)?;
        let facts = delegation_facts(
            record.delegation_id,
            record.effective_from_ts,
            &record.resource_type,
            &record.action_code,
            delegate.tenant_id,
            delegate.domain_id,
            delegate.user_id,
            record.delegate_card_id,
            expires_at_unix,
        )?;

        // 锁序第 5 步：grant head FOR UPDATE 先于 operation id 定型 —— 撤销
        // continuity 门禁（payload 必须仍反映锁定 source 事实）在此闭合；缺失/
        // stale 一律 fail-closed，不写裸 source 链。
        let grant_id = derive_delegation_identity(&facts)?;
        let head = expect_delegation_head_in_tx(
            &mut tx,
            facts.tenant_id,
            facts.delegation_id,
            grant_id,
            record.delegate_card_id,
        )
        .await?;
        assert_head_matches_locked_source(&head, old_rule, &record)?;

        // 稳定业务 operation id：显式安全 header 原样复用；缺失头部把锁定的
        // durable revision 折入身份 —— 同一业务重试（head 未推进）得到相同
        // id/event，撤销落库后 head 终结，绝不与后续任何 mutation 复用事件号。
        let operation_id = derive_delegation_operation_id(
            DelegationMutationKind::Revoke,
            delegation_id,
            context.request_id_header(),
            Some(head.entry.revision.value()),
        )?;

        // 锁序第 6 步：CARD REVOKE head/outbox（metadata 版，revoke_fence 递增），
        // parent 投影事件与贡献事件号分离。
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            record.delegate_card_id,
            "REVOKE",
            astral_db::ProjectionEventMetadata {
                actor_id: context.user_id(),
                operation_id: &operation_id,
            },
        )
        .await?;
        let contribution_event_id = derive_delegation_contribution_event_id(
            &operation_id,
            &facts,
            DelegationContributionKind::Revoke,
        )?;

        // 锁序第 7 步：last delta target version FOR UPDATE → REVOKE tombstone。
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            &mut tx,
            facts.tenant_id,
            crate::repository::grant_ledger_adapter::DELEGATION_AGGREGATE_TYPE,
            facts.delegation_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;

        // REVOKE tombstone（生命周期撤权；旧 canonical grant 成对 before-image）。
        let draft = build_delegation_revoke_draft(
            &facts,
            &head,
            &operation_id,
            &projection,
            &contribution_event_id,
        )?;
        append_delegation_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;

        // Tombstone 落库后按锁定集精确删除旧规则并置 REVOKED。
        let delete_result = sqlx::query("DELETE FROM permission_rule WHERE rule_id = ?")
            .bind(old_rule.rule_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        if delete_result.rows_affected() != 1 {
            return Err(AstralError::Internal(format!(
                "permission_rule delete missed locked rule {} for delegation {}",
                old_rule.rule_id, delegation_id
            )));
        }
        let revoke_result = sqlx::query(
            "UPDATE permission_delegation SET status = 'REVOKED', revoked_at = NOW() \
             WHERE delegation_id = ? AND status = 'ACTIVE'",
        )
        .bind(delegation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if revoke_result.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "permission_delegation revoke did not apply exactly one row".into(),
            ));
        }

        insert_delegation_audit_in_tx(
            &mut tx,
            &DelegationAuditActor::from(context),
            DelegationAudit {
                delegation_id: record.delegation_id,
                delegator_card_id: record.delegator_card_id,
                delegate_card_id: record.delegate_card_id,
                resource_type: &record.resource_type,
                action_code: &record.action_code,
                effective_until_ts: record.effective_until_ts,
                event_type: "DELEGATION_REVOKED",
                operation_id: &operation_id,
                parent_event_id: Some(projection.event_id.as_str()),
                contribution_event_id: Some(draft.event_id()),
                rule_ids: &[old_rule.rule_id],
                grant_id: Some(&head.grant_id.as_str()),
                before_image_digest_hex: draft.before_digest_hex(),
                ledger_revision: Some(draft.resulting_revision_value()),
            },
        )
        .await?;

        tx.commit_consuming().await?;
        Ok(DelegationMutationResult {
            changed: true,
            delegate_card_id: Some(record.delegate_card_id),
        })
    }

    async fn update_with_rule(
        &self,
        delegation_id: i64,
        resource_type: &str,
        action_code: &str,
        effective_until_ts: i64,
        context: &DelegationMutationContext,
    ) -> Result<DelegationMutationResult, AstralError> {
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        let now_ts = db_now_in_tx(&mut tx).await?;
        require_future_expiry(now_ts, effective_until_ts)?;

        // ── V2 修复①：registry 校验 + trim 规范化（纯判定，先于任何锁/预读）──
        // 新 resource/action 必须已注册于 ResourceRegistry；未注册/空白
        // Validation fail-closed。规范化值贯穿 delegation 行 UPDATE、规则重写、
        // 授权账本 facts 与审计；与既有行的 trim 漂移会被视为变更并触发按新
        // 组合的重新证明（顺带把历史 raw 写法收敛为规范化值）。
        let (normalized_resource, normalized_action) =
            crate::service::personal_permission_service::validate_registry_resource_action(
                resource_type,
                action_code,
            )?;
        let resource = normalized_resource.as_str();
        let action = normalized_action.as_str();

        // 无锁预读：仅为在卡锁之前发现 delegator/delegate 端点；事实以 FOR UPDATE
        // 复读为准，端点漂移整体 fail-closed。
        let Some(probe) = probe_delegation_in_tx(&mut tx, delegation_id).await? else {
            tx.commit_consuming().await?;
            return Ok(DelegationMutationResult {
                changed: false,
                delegate_card_id: None,
            });
        };
        // 锁序第 1 步：全部 user_card 行按 card_id 升序 FOR UPDATE（先于 delegation
        // 行锁；与 create/revoke/卡级联同一全局方向）。
        let card_ids = ordered_unique_positive_card_ids([
            context.caller_card_id(),
            probe.delegator_card_id,
            probe.delegate_card_id,
        ])?;
        let mut cards: Vec<CardScope> = Vec::with_capacity(card_ids.len());
        for card_id in &card_ids {
            cards.push(lock_card_in_tx(&mut tx, *card_id).await?);
        }
        // 锁序第 2 步：delegation 行；缺失或非 ACTIVE 显式 no-op。
        let Some(record) = lock_delegation_in_tx(&mut tx, delegation_id).await? else {
            tx.commit_consuming().await?;
            return Ok(DelegationMutationResult {
                changed: false,
                delegate_card_id: None,
            });
        };
        if record.status != "ACTIVE" {
            tx.commit_consuming().await?;
            return Ok(DelegationMutationResult {
                changed: false,
                delegate_card_id: None,
            });
        }
        assert_locked_endpoints_match_probe(&record, &probe)?;
        assert_endpoints_within_locked_cards(&record, &cards)?;

        // 锁序第 3 步：端点校验（caller 归属 + scope + 被委托卡 ACTIVE）。
        let caller = locked_card_of(&cards, context.caller_card_id())?;
        validate_caller_card(context, caller, record.delegator_card_id)?;
        let delegate = locked_card_of(&cards, record.delegate_card_id)?;
        validate_delegate_card(context, caller, delegate, true)?;

        // ── V2 修复②：委托人持有权证明（resource/action 变更时按新组合重新
        // 证明；未变更时不重读 evidence，保持既有幂等语义）───────────────────
        //
        // 契约：规范化后的新组合与锁定委托行不一致 → 在任何 durable 写入前
        // 以新组合重新证明委托人持有权，并校验新有效期不超过委托人授权上界；
        // 组合一致（含纯有效期更新/幂等重放）→ 不要求重新证明，沿用创建时的
        // 既有证明事实。重新证明只消费同事务内已发布 canonical evidence，
        // 失败一律 Permission/Validation 拒绝，事务回滚，source 保持不变。
        if resource != record.resource_type || action != record.action_code {
            prove_delegator_hold_in_tx(&mut tx, caller, resource, action, effective_until_ts)
                .await?;
        }

        // 锁序第 4 步：锁定旧规则行并捕获完整 before-image（先于任何 source 修改；
        // 数量/归属/effect/有效期任一漂移 fail-closed，source 保持不变）。
        let rules = lock_delegation_rules_in_tx(&mut tx, delegation_id).await?;
        if rules.len() != 1 {
            return Err(AstralError::Validation(format!(
                "ACTIVE delegation {delegation_id} must own exactly one DELEGATION rule row before update, found {}; repair required and source left unchanged",
                rules.len()
            )));
        }
        let old_rule = &rules[0];
        assert_rule_row_matches_locked_delegation(old_rule, &record)?;

        // 身份/continuity facts 使用锁定 source 的变更前事实（resource/action/
        // 有效期不进入 grant identity，但 head 对齐校验必须锚定旧窗口）。
        let identity_facts = delegation_facts(
            record.delegation_id,
            record.effective_from_ts,
            &record.resource_type,
            &record.action_code,
            delegate.tenant_id,
            delegate.domain_id,
            delegate.user_id,
            record.delegate_card_id,
            require_provable_expiry(&record)?,
        )?;

        // 锁序第 5 步：grant head FOR UPDATE 先于 operation id 定型 —— 同一 JWT
        // 会话的连续更新复用 `delegation:update:{id}` fallback 时曾把 delta 事件号
        // 撞到 uk_ade_event（M1）；现在 fallback 绑定锁定的 durable revision：
        // 同代重试相同、提交推进后必然分叉。head 缺失/stale 一律 fail-closed。
        let grant_id = derive_delegation_identity(&identity_facts)?;
        let head = expect_delegation_head_in_tx(
            &mut tx,
            identity_facts.tenant_id,
            identity_facts.delegation_id,
            grant_id,
            record.delegate_card_id,
        )
        .await?;
        assert_head_matches_locked_source(&head, old_rule, &record)?;

        let operation_id = derive_delegation_operation_id(
            DelegationMutationKind::Update,
            delegation_id,
            context.request_id_header(),
            Some(head.entry.revision.value()),
        )?;

        // 先更新 source 聚合行（单事务内后续失败仍整体回滚，不存在"只改 source"的
        // 提交态）；delegator/delegate 归属与 delegation identity 不变。
        // resource/action 绑定规范化值（V2：写入即规范化）。
        let update_result = sqlx::query(
            "UPDATE permission_delegation SET resource_type = ?, action_code = ?, \
             effective_until = FROM_UNIXTIME(?) WHERE delegation_id = ? AND status = 'ACTIVE'",
        )
        .bind(resource)
        .bind(action)
        .bind(effective_until_ts)
        .bind(delegation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if update_result.rows_affected() > 1 {
            return Err(AstralError::Internal(
                "permission_delegation update touched more than one row".into(),
            ));
        }

        // 更新规则：删旧插新为既有模型语义。grant identity 以稳定 delegation 粒度
        // 派生，rule_id churn 不影响账本身份；新规则下界沿用旧 effective_from。
        let delete_result = sqlx::query("DELETE FROM permission_rule WHERE rule_id = ?")
            .bind(old_rule.rule_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        if delete_result.rows_affected() != 1 {
            return Err(AstralError::Internal(format!(
                "permission_rule delete missed locked rule {} for delegation {}",
                old_rule.rule_id, delegation_id
            )));
        }
        let new_valid_from = old_rule.valid_from_ts.or(Some(record.effective_from_ts));
        let rule_result = sqlx::query(DELEGATION_RULE_INSERT)
            .bind(record.delegate_card_id)
            .bind(
                delegate
                    .tenant_id
                    .ok_or_else(|| permission_error("delegation target tenant scope is missing"))?,
            )
            .bind(resource)
            .bind(action)
            .bind(delegation_id)
            .bind(new_valid_from)
            .bind(effective_until_ts)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        if rule_result.rows_affected() != 1 || rule_result.last_insert_id() == 0 {
            return Err(AstralError::Internal(
                "replacement permission_rule insert did not apply exactly one identified row"
                    .into(),
            ));
        }
        let new_rule_id = rule_result.last_insert_id() as i64;

        // 新值 facts：UPDATE payload 承载新的可变属性（resource/action 使用
        // 规范化值，与 delegation 行/rule 行零漂移）；identity 维度与
        // identity_facts 完全一致（tenant/card/user/delegation），事件号不因
        // 可变属性变化而分叉。
        let facts = delegation_facts(
            record.delegation_id,
            record.effective_from_ts,
            resource,
            action,
            delegate.tenant_id,
            delegate.domain_id,
            delegate.user_id,
            record.delegate_card_id,
            effective_until_ts,
        )?;

        // 收窄 UPDATE 的 stale-ALLOW 闭合（2026-09-04）：比较 before-image
        // （head.payload，锁序第 5 步已锁定）与新 grant 的 authorization-content
        // 字段（resource/action/effect/validity，与 build_delegation_update_draft
        // 同源）。任何可能移除旧授权的内容变化/移动 → CARD 父投影事件改用
        // REVOKE 语义抬 fence，delta 未发布期间严格 reader 的 source-freshness
        // 门命中（PENDING）；纯 provenance-only/no-op UPDATE 保持
        // DELEGATION_UPDATED（fence 不变，写突发不得自饥饿——P3 风暴实测教训）。
        let card_event_type = if delegation_update_authorization_content_changed(&facts, &head)? {
            EVENT_TYPE_REVOKE
        } else {
            "DELEGATION_UPDATED"
        };

        // 锁序第 6 步：CARD head/outbox（metadata 版 DELEGATION_UPDATED；
        // authorization-content 变化时为 REVOKE 语义抬 fence）。
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            record.delegate_card_id,
            card_event_type,
            astral_db::ProjectionEventMetadata {
                actor_id: context.user_id(),
                operation_id: &operation_id,
            },
        )
        .await?;
        let contribution_event_id = derive_delegation_contribution_event_id(
            &operation_id,
            &facts,
            DelegationContributionKind::Update,
        )?;

        // 锁序第 7 步：last target version FOR UPDATE → Append Update rev=head+1。
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            &mut tx,
            identity_facts.tenant_id,
            crate::repository::grant_ledger_adapter::DELEGATION_AGGREGATE_TYPE,
            identity_facts.delegation_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;

        let draft = build_delegation_update_draft(
            &facts,
            &head,
            &operation_id,
            context.user_id(),
            &projection,
            &contribution_event_id,
        )?;
        append_delegation_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;

        insert_delegation_audit_in_tx(
            &mut tx,
            &DelegationAuditActor::from(context),
            DelegationAudit {
                delegation_id: record.delegation_id,
                delegator_card_id: record.delegator_card_id,
                delegate_card_id: record.delegate_card_id,
                resource_type: resource,
                action_code: action,
                effective_until_ts: Some(effective_until_ts),
                event_type: "DELEGATION_UPDATED",
                operation_id: &operation_id,
                parent_event_id: Some(projection.event_id.as_str()),
                contribution_event_id: Some(draft.event_id()),
                rule_ids: &[old_rule.rule_id, new_rule_id],
                grant_id: Some(&head.grant_id.as_str()),
                before_image_digest_hex: draft.before_digest_hex(),
                ledger_revision: Some(draft.resulting_revision_value()),
            },
        )
        .await?;

        tx.commit_consuming().await?;
        Ok(DelegationMutationResult {
            changed: true,
            delegate_card_id: Some(record.delegate_card_id),
        })
    }

    async fn list_by_delegator(
        &self,
        card_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<Vec<DelegationViewRecord>, AstralError> {
        ensure_requested_card(context, card_id, "delegator")?;
        sqlx::query_as::<_, DelegationViewRecord>(DELEGATION_LIST_BY_DELEGATOR_SQL)
            .bind(context.caller_card_id())
            .bind(context.user_id())
            .bind(context.tenant_id())
            .bind(context.domain_id())
            .bind(card_id)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_by_delegate(
        &self,
        card_id: i64,
        context: &DelegationMutationContext,
    ) -> Result<Vec<DelegationViewRecord>, AstralError> {
        ensure_requested_card(context, card_id, "delegate")?;
        sqlx::query_as::<_, DelegationViewRecord>(DELEGATION_LIST_BY_DELEGATE_SQL)
            .bind(context.caller_card_id())
            .bind(context.user_id())
            .bind(context.tenant_id())
            .bind(context.domain_id())
            .bind(card_id)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(
        &self,
        context: &DelegationMutationContext,
    ) -> Result<Vec<DelegationViewRecord>, AstralError> {
        sqlx::query_as::<_, DelegationViewRecord>(DELEGATION_LIST_ALL_SQL)
            .bind(context.caller_card_id())
            .bind(context.user_id())
            .bind(context.tenant_id())
            .bind(context.domain_id())
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn reconcile_expired_delegation(
        &self,
        delegation_id: i64,
    ) -> Result<DelegationExpiryOutcome, AstralError> {
        if delegation_id <= 0 {
            return Err(AstralError::Validation(format!(
                "delegation expiry reconciliation requires a positive delegation id, got {delegation_id}"
            )));
        }
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        // 无锁预读：仅为在卡锁之前发现 delegator/delegate 端点（全局锁序要求
        // user_card 先于 permission_delegation 锁）；事实以 FOR UPDATE 复读为准，
        // 端点漂移整体 fail-closed。
        let Some(probe) = probe_delegation_in_tx(&mut tx, delegation_id).await? else {
            tx.commit_consuming().await?;
            return Ok(DelegationExpiryOutcome::AlreadyTerminal);
        };
        // 锁序第 1 步：本事务涉及的全部 user_card 行按 card_id 升序 FOR UPDATE
        // （系统对账没有 caller 卡，只锁两端点；去重升序与 create/revoke/update/
        // 卡级联家族保持同一全局方向，杜绝 ABBA）。
        let card_ids =
            ordered_unique_positive_card_ids([probe.delegator_card_id, probe.delegate_card_id])?;
        let mut cards: Vec<CardScope> = Vec::with_capacity(card_ids.len());
        for card_id in &card_ids {
            cards.push(lock_card_in_tx(&mut tx, *card_id).await?);
        }
        // 锁序第 2 步：delegation 行 FOR UPDATE；缺失或已非 ACTIVE 一律显式幂等
        // no-op（重复对账不生成新身份、不追加第二条 tombstone）。
        let Some(record) = lock_delegation_in_tx(&mut tx, delegation_id).await? else {
            tx.commit_consuming().await?;
            return Ok(DelegationExpiryOutcome::AlreadyTerminal);
        };
        // 锁序第 3 步：端点一致性收敛断言 + 事务内 DB 时钟的到期资格纯判定。
        assert_locked_endpoints_match_probe(&record, &probe)?;
        assert_endpoints_within_locked_cards(&record, &cards)?;
        let now_ts = db_now_in_tx(&mut tx).await?;
        match classify_expiry_reconciliation(&record.status, now_ts, record.effective_until_ts) {
            ExpiryReconciliationEligibility::AlreadyTerminal => {
                tx.commit_consuming().await?;
                return Ok(DelegationExpiryOutcome::AlreadyTerminal);
            }
            ExpiryReconciliationEligibility::NotYetDue => {
                tx.commit_consuming().await?;
                return Ok(DelegationExpiryOutcome::NotYetDue);
            }
            ExpiryReconciliationEligibility::RepairRequired => {
                return Err(AstralError::Validation(format!(
                    "ACTIVE delegation {delegation_id} carries no provable positive expiry; repair required and source left unchanged"
                )));
            }
            ExpiryReconciliationEligibility::Due => {}
        }

        // 锁序第 4 步：端点 scope 事实（授权承载 = 被委托卡）。与撤销路径一致，
        // 不要求被委托卡仍 ACTIVE —— tombstone 移除的是已失效授权本身；
        // tenant 缺失由 facts 组装期 fail-closed。
        let delegate = locked_card_of(&cards, record.delegate_card_id)?;

        // 锁序第 5 步：锁定并校验唯一规则行 before-image；数量/归属/effect/
        // enabled/资源/有效期任一漂移 fail-closed，source 保持不变。
        let rules = lock_delegation_rules_in_tx(&mut tx, delegation_id).await?;
        if rules.len() != 1 {
            return Err(AstralError::Validation(format!(
                "ACTIVE delegation {delegation_id} must own exactly one DELEGATION rule row before expiry reconciliation, found {}; repair required and source left unchanged",
                rules.len()
            )));
        }
        let old_rule = &rules[0];
        assert_rule_row_matches_locked_delegation(old_rule, &record)?;

        let expires_at_unix = require_provable_expiry(&record)?;
        let facts = delegation_facts(
            record.delegation_id,
            record.effective_from_ts,
            &record.resource_type,
            &record.action_code,
            delegate.tenant_id,
            delegate.domain_id,
            delegate.user_id,
            record.delegate_card_id,
            expires_at_unix,
        )?;

        // 锁序第 6 步：grant head FOR UPDATE + 身份/continuity 门禁；head 非
        // ACTIVE 即 source/ledger 漂移，要求修复，绝不追加第二条 tombstone。
        let grant_id = derive_delegation_identity(&facts)?;
        let head = expect_delegation_head_in_tx(
            &mut tx,
            facts.tenant_id,
            facts.delegation_id,
            grant_id,
            record.delegate_card_id,
        )
        .await?;
        assert_head_matches_locked_source(&head, old_rule, &record)?;
        if head.entry.state != GrantState::Active || !head.entry.status_active {
            return Err(AstralError::Validation(format!(
                "grant ledger head for delegation {delegation_id} is not ACTIVE; repair required and source left unchanged"
            )));
        }

        // 稳定 operation id：delegation:expire:{id}:e{锁定有效期}（纯派生，
        // 无请求头依赖、无随机 fallback；定型先于任何 durable 投影/账本写入）。
        let operation_id = derive_delegation_expiry_operation_id(delegation_id, expires_at_unix)?;

        // 锁序第 7 步：CARD REVOKE head/outbox（既有 REVOKE 事件类型 →
        // revoke_fence 递增；metadata 绑定 SYSTEM actor 与稳定 operation id）。
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            record.delegate_card_id,
            "REVOKE",
            astral_db::ProjectionEventMetadata {
                actor_id: SYSTEM_ACTOR_ID,
                operation_id: &operation_id,
            },
        )
        .await?;
        let contribution_event_id = derive_delegation_contribution_event_id(
            &operation_id,
            &facts,
            DelegationContributionKind::Revoke,
        )?;

        // 锁序第 8 步：last delta target FOR UPDATE → REVOKE tombstone。
        let last_target = astral_db::read_latest_delta_target_version_for_update_in_tx(
            &mut tx,
            facts.tenant_id,
            crate::repository::grant_ledger_adapter::DELEGATION_AGGREGATE_TYPE,
            facts.delegation_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            astral_db::next_delta_version(last_target).map_err(map_grant_repository_error)?;

        let draft = build_delegation_revoke_draft(
            &facts,
            &head,
            &operation_id,
            &projection,
            &contribution_event_id,
        )?;
        append_delegation_grant_delta_in_tx(&mut tx, &draft, base_version, target_version).await?;

        // Tombstone 落库后按锁定集精确删除旧规则并置 EXPIRED 终态（区别于人工
        // REVOKE 的审计语义；revoked_at 复用为终态时间戳列）。
        let delete_result = sqlx::query("DELETE FROM permission_rule WHERE rule_id = ?")
            .bind(old_rule.rule_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        if delete_result.rows_affected() != 1 {
            return Err(AstralError::Internal(format!(
                "permission_rule delete missed locked rule {} for delegation {}",
                old_rule.rule_id, delegation_id
            )));
        }
        let expire_result = sqlx::query(
            "UPDATE permission_delegation SET status = 'EXPIRED', revoked_at = NOW() \
             WHERE delegation_id = ? AND status = 'ACTIVE'",
        )
        .bind(delegation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if expire_result.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "permission_delegation expiry reconciliation did not apply exactly one row".into(),
            ));
        }

        insert_delegation_audit_in_tx(
            &mut tx,
            &DelegationAuditActor::system_expiry_reconciliation(
                delegate.tenant_id,
                delegate.domain_id,
            ),
            DelegationAudit {
                delegation_id: record.delegation_id,
                delegator_card_id: record.delegator_card_id,
                delegate_card_id: record.delegate_card_id,
                resource_type: &record.resource_type,
                action_code: &record.action_code,
                effective_until_ts: Some(expires_at_unix),
                event_type: "DELEGATION_EXPIRED",
                operation_id: &operation_id,
                parent_event_id: Some(projection.event_id.as_str()),
                contribution_event_id: Some(draft.event_id()),
                rule_ids: &[old_rule.rule_id],
                grant_id: Some(&head.grant_id.as_str()),
                before_image_digest_hex: draft.before_digest_hex(),
                ledger_revision: Some(draft.resulting_revision_value()),
            },
        )
        .await?;

        tx.commit_consuming().await?;
        Ok(DelegationExpiryOutcome::Reconciled {
            delegate_card_id: record.delegate_card_id,
        })
    }

    async fn list_expired_active_delegation_ids(
        &self,
        batch_limit: i64,
    ) -> Result<Vec<i64>, AstralError> {
        let limit = validated_expiry_batch_limit(batch_limit)?;
        // 只读候选发现：绑定参数 LIMIT 封顶，绝不无界扫描；候选只是提示，逐条
        // 的到期事实在各自事务内以锁定行 + DB 时钟重新证明（NotYetDue 幂等短路）。
        sqlx::query_scalar::<_, i64>(
            "SELECT delegation_id FROM permission_delegation \
             WHERE status = 'ACTIVE' AND effective_until IS NOT NULL \
               AND effective_until <= NOW() \
             ORDER BY delegation_id LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn ensure_requested_card(
    context: &DelegationMutationContext,
    requested_card_id: i64,
    role: &str,
) -> Result<(), AstralError> {
    if requested_card_id != context.caller_card_id() {
        return Err(permission_error(format!(
            "delegation {role} query must use the verified caller card"
        )));
    }
    Ok(())
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Delegation repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(card_id: i64, tenant_id: i64, domain_id: i64) -> DelegationMutationContext {
        let policy_context = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(card_id))
            .tenant_id(Some(tenant_id))
            .domain_id(Some(domain_id))
            .action("read".into())
            .build();
        DelegationMutationContext::from_policy_context(&policy_context, Some("list-test"))
            .expect("test context must be valid")
    }

    #[test]
    fn foreign_delegator_card_is_rejected_before_repository_query() {
        let context = context(101, 20, 30);
        let error = ensure_requested_card(&context, 202, "delegator").unwrap_err();
        assert!(
            matches!(error, AstralError::Permission(message) if message.contains("verified caller card"))
        );
    }

    #[test]
    fn foreign_delegate_card_is_rejected_before_repository_query() {
        let context = context(101, 20, 30);
        let error = ensure_requested_card(&context, 202, "delegate").unwrap_err();
        assert!(
            matches!(error, AstralError::Permission(message) if message.contains("verified caller card"))
        );
    }

    #[test]
    fn caller_scope_values_are_not_replaceable_by_foreign_tenant_or_domain() {
        let context = context(101, 20, 30);
        assert_eq!(context.caller_card_id(), 101);
        assert_eq!(context.tenant_id(), 20);
        assert_eq!(context.domain_id(), 30);
        assert!(ensure_requested_card(&context, 101, "delegator").is_ok());
    }

    fn record() -> DelegationRecord {
        DelegationRecord {
            delegation_id: 7001,
            delegator_card_id: 101,
            delegate_card_id: 310,
            resource_type: "learn_course".into(),
            action_code: "read".into(),
            effective_from_ts: 1_760_000_000,
            effective_until_ts: Some(1_770_000_000),
            is_revokable: 1,
            status: "ACTIVE".into(),
        }
    }

    fn rule_row() -> LockedDelegationRuleRow {
        LockedDelegationRuleRow {
            rule_id: 9001,
            card_id: 310,
            resource_type: "learn_course".into(),
            action_code: "read".into(),
            effect: "ALLOW".into(),
            valid_from_ts: Some(1_760_000_000),
            valid_to_ts: Some(1_770_000_000),
            enabled: 1,
        }
    }

    #[test]
    fn unsafe_x_request_id_header_fails_closed_at_context_construction() {
        let policy_context = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(101))
            .tenant_id(Some(20))
            .domain_id(Some(30))
            .action("create".into())
            .build();
        // 非法字符必须显式拒绝，绝不静默替换或随机补位。
        for unsafe_header in [
            "a b",
            "x\ny",
            "控制",
            &"z".repeat(
                crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH + 1,
            ),
        ] {
            let error = DelegationMutationContext::from_policy_context(
                &policy_context,
                Some(unsafe_header),
            )
            .expect_err("unsafe header must fail closed");
            assert!(matches!(error, AstralError::Validation(_)));
        }
        // 显式 header 边界：恰好 64 字节接受，65 字节 Validation 拒绝（M2 canonical
        // 上限与 audit_log.request_id VARCHAR(64) 对齐；绝不截断）。
        let boundary =
            "h".repeat(crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH);
        assert_eq!(boundary.len(), 64);
        let accepted =
            DelegationMutationContext::from_policy_context(&policy_context, Some(&boundary))
                .expect("exactly-64-byte safe header must be reusable");
        assert_eq!(accepted.request_id_header(), Some(boundary.as_str()));
        let over_boundary = DelegationMutationContext::from_policy_context(
            &policy_context,
            Some(&format!("{boundary}h")),
        )
        .expect_err("65-byte header must fail closed");
        assert!(matches!(over_boundary, AstralError::Validation(_)));
        // 空白视同缺失，成功构造且不留头部。
        let clean = DelegationMutationContext::from_policy_context(&policy_context, Some("   "))
            .expect("blank header is treated as absent");
        assert_eq!(clean.request_id_header(), None);
        let reused = DelegationMutationContext::from_policy_context(&policy_context, Some("req-7"))
            .expect("safe header must be reusable");
        assert_eq!(reused.request_id_header(), Some("req-7"));
    }

    #[test]
    fn expiry_validation_rejects_non_positive_and_past_boundaries() {
        assert!(require_future_expiry(100, 0).is_err());
        assert!(require_future_expiry(100, -5).is_err());
        assert!(require_future_expiry(100, 100).is_err());
        assert!(require_future_expiry(100, 101).is_ok());
    }

    #[test]
    fn ordered_card_ids_are_deduplicated_sorted_and_fail_closed_on_non_positive() {
        // 去重 + 升序：跨并发方向也取得同一把锁序（防 ABBA 的纯函数保证）。
        assert_eq!(
            ordered_unique_positive_card_ids([7, 3, 3, 11]).unwrap(),
            vec![3, 7, 11]
        );
        assert_eq!(
            ordered_unique_positive_card_ids([]).unwrap(),
            Vec::<i64>::new()
        );
        for bad in [vec![0], vec![-1], vec![5, 0]] {
            let error = ordered_unique_positive_card_ids(bad).unwrap_err();
            assert!(matches!(error, AstralError::Validation(_)));
        }
    }

    #[test]
    fn locked_card_lookup_fails_closed_when_the_acquired_set_drifts() {
        let cards = vec![card_scope(3), card_scope(9)];
        assert_eq!(locked_card_of(&cards, 3).unwrap().card_id, 3);
        let error = locked_card_of(&cards, 4).unwrap_err();
        assert!(matches!(error, AstralError::Internal(message) if message.contains("set drift")));
    }

    #[test]
    fn self_delegation_is_explicitly_rejected() {
        let mut new = NewDelegation {
            delegator_card_id: 101,
            delegate_card_id: 310,
            resource_type: "learn_course".into(),
            action_code: "read".into(),
            effective_until_ts: 1_770_000_000,
        };
        assert!(reject_self_delegation(&new).is_ok());
        new.delegate_card_id = 101;
        let error = reject_self_delegation(&new).unwrap_err();
        assert!(
            matches!(error, AstralError::Validation(message) if message.contains("self delegation"))
        );
    }

    fn card_scope(card_id: i64) -> CardScope {
        CardScope {
            card_id,
            user_id: 10,
            card_status: "ACTIVE".into(),
            tenant_id: Some(20),
            domain_id: Some(30),
        }
    }

    #[test]
    fn endpoint_drift_between_probe_and_locked_row_fails_closed() {
        let probe = record();
        let locked = record();
        assert!(assert_locked_endpoints_match_probe(&locked, &probe).is_ok());

        let mut drifted_delegator = record();
        drifted_delegator.delegator_card_id += 1;
        let error = assert_locked_endpoints_match_probe(&drifted_delegator, &probe).unwrap_err();
        assert!(
            matches!(error, AstralError::Internal(message) if message.contains("endpoint drift"))
        );

        let mut drifted_delegate = record();
        drifted_delegate.delegate_card_id += 5;
        assert!(matches!(
            assert_locked_endpoints_match_probe(&drifted_delegate, &record()),
            Err(AstralError::Internal(_))
        ));
    }

    #[test]
    fn endpoints_must_sit_inside_the_acquired_card_lock_set() {
        let record = record();
        let covering = vec![
            card_scope(record.delegator_card_id),
            card_scope(record.delegate_card_id),
        ];
        assert!(assert_endpoints_within_locked_cards(&record, &covering).is_ok());

        let partial = vec![card_scope(record.delegator_card_id)];
        let error = assert_endpoints_within_locked_cards(&record, &partial).unwrap_err();
        assert!(matches!(error, AstralError::Internal(message) if message.contains("set drift")));
    }

    #[test]
    fn idempotent_consistency_requires_single_allow_rule_active_ledger_and_expiry() {
        use IdempotentConsistency::{Consistent, RepairRequired};
        // 一致路径：单条 ALLOW/enabled 规则 + ACTIVE 账本 + 可证明有效期。
        assert_eq!(
            classify_idempotent_consistency(1, true, IdempotentHead::Active, true),
            Consistent
        );
        // 规则数量漂移。
        assert_eq!(
            classify_idempotent_consistency(0, true, IdempotentHead::Active, true),
            RepairRequired("rule rows")
        );
        assert_eq!(
            classify_idempotent_consistency(2, true, IdempotentHead::Active, true),
            RepairRequired("rule rows")
        );
        // effect/enabled 漂移。
        assert_eq!(
            classify_idempotent_consistency(1, false, IdempotentHead::Active, true),
            RepairRequired("rule effect or enabled flag")
        );
        // 账本缺失或非 ACTIVE 都不得当作幂等成功返回。
        assert_eq!(
            classify_idempotent_consistency(1, true, IdempotentHead::Missing, true),
            RepairRequired("grant ledger head")
        );
        assert_eq!(
            classify_idempotent_consistency(1, true, IdempotentHead::NotActive, true),
            RepairRequired("grant ledger state")
        );
        // 有效期不可证明（None/非正）同样要求修复。
        assert_eq!(
            classify_idempotent_consistency(1, true, IdempotentHead::Active, false),
            RepairRequired("delegation expiry")
        );
    }

    #[test]
    fn locked_rule_row_must_match_delegation_source_or_fail_closed() {
        let record = record();
        assert!(assert_rule_row_matches_locked_delegation(&rule_row(), &record).is_ok());

        let mut drifted = rule_row();
        drifted.card_id = 999;
        let error = assert_rule_row_matches_locked_delegation(&drifted, &record).unwrap_err();
        assert!(error.to_string().contains("scope drift"));

        let mut denied = rule_row();
        denied.effect = "DENY".into();
        let error = assert_rule_row_matches_locked_delegation(&denied, &record).unwrap_err();
        assert!(error.to_string().contains("ALLOW"));

        let mut disabled = rule_row();
        disabled.enabled = 0;
        assert!(assert_rule_row_matches_locked_delegation(&disabled, &record).is_err());

        let mut resources = rule_row();
        resources.resource_type = "learn_quiz".into();
        assert!(assert_rule_row_matches_locked_delegation(&resources, &record).is_err());

        let mut window = rule_row();
        window.valid_to_ts = None;
        assert!(assert_rule_row_matches_locked_delegation(&window, &record).is_err());
    }

    #[test]
    fn mutable_context_shape_guards_for_the_three_mutations() {
        let source = include_str!("delegation_repository.rs");
        // 只扫描非测试代码，避免断言文本自匹配。
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section must exist");

        // 禁止随机业务身份 fallback：生产代码内不允许再出现 uuid 生成调用。
        assert!(
            !production.contains("Uuid::new_v4"),
            "delegation mutations must not generate random business identity"
        );

        // 规则写 SQL 必须以绑定参数承载有效期（UTC 秒），不再用 NOW() 双写。
        assert!(DELEGATION_RULE_INSERT.contains("FROM_UNIXTIME(?), FROM_UNIXTIME(?)"));
        assert!(!DELEGATION_RULE_INSERT.contains("NOW()"));

        // 锁序守卫：revoke 中账本 REVOKE tombstone 先于旧规则删除与置 REVOKED。
        let revoke_body = split_mutation(source, "async fn revoke_with_rules");
        let tombstone = revoke_body
            .find("build_delegation_revoke_draft")
            .expect("revoke must append a ledger tombstone");
        let rule_delete = revoke_body
            .find("DELETE FROM permission_rule WHERE rule_id")
            .expect("revoke must delete the old rule");
        let status_flip = revoke_body
            .find("SET status = 'REVOKED'")
            .expect("revoke must flip delegation status");
        assert!(
            tombstone < rule_delete && rule_delete < status_flip,
            "ledger tombstone must precede source deletes/marks"
        );
        // M1 锁序守卫：revoke 先锁 grant head（FOR UPDATE + continuity 门禁），
        // 再定型 operation id，随后才允许第一个 durable CARD outbox 写入。
        let revoke_head = revoke_body
            .find("expect_delegation_head_in_tx")
            .expect("revoke must lock the grant head before deriving identity");
        let revoke_op = revoke_body
            .find("derive_delegation_operation_id")
            .expect("revoke must derive its operation id");
        let revoke_projection = revoke_body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("revoke must anchor its parent CARD event");
        assert!(
            revoke_head < revoke_op && revoke_op < revoke_projection,
            "locked head revision must be bound into the operation id before any durable write"
        );

        // 锁序守卫：update 中 CARD head/outbox（metadata 投影）先于 grant 版本锁。
        let update_body = split_mutation(source, "async fn update_with_rule");
        let projection_lock = update_body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("update must append a metadata CARD projection");
        let head_read = update_body
            .find("read_latest_delta_target_version_for_update_in_tx")
            .expect("update must lock last delta target version");
        assert!(
            projection_lock < head_read,
            "CARD head/outbox must be locked before the grant delta version"
        );
        // 2026-09-04 收窄 UPDATE 闭合守卫：authorization-content gate 先于 CARD
        // 父投影事件落库 —— 内容变化 ⟹ REVOKE 语义抬 fence；no-op/provenance-only
        // ⟹ 保持 DELEGATION_UPDATED。
        let content_gate = update_body
            .find("delegation_update_authorization_content_changed")
            .expect("update must gate the CARD parent event on authorization content");
        assert!(
            content_gate < projection_lock,
            "the authorization-content gate must decide the CARD parent event type before it is appended"
        );
        assert!(update_body.contains("EVENT_TYPE_REVOKE"));
        assert!(update_body.contains("\"DELEGATION_UPDATED\""));
        // 更新前必须先捕获并校验旧规则 before-image（先于规则删除）。
        let before_image_check = update_body
            .find("assert_rule_row_matches_locked_delegation")
            .expect("update must verify the locked rule row first");
        assert!(
            before_image_check
                < update_body
                    .find("DELETE FROM permission_rule WHERE rule_id")
                    .expect("update rebuilds the rule"),
        );
        // M1 锁序守卫：update 同样先锁 head 并绑定 revision，再写任何 source 行。
        let update_head = update_body
            .find("expect_delegation_head_in_tx")
            .expect("update must lock the grant head before deriving identity");
        let update_op = update_body
            .find("derive_delegation_operation_id")
            .expect("update must derive its operation id");
        let source_update = update_body
            .find("UPDATE permission_delegation SET resource_type")
            .expect("update must mutate the delegation row");
        assert!(
            update_head < update_op && update_op < source_update,
            "operation id (bound to the locked revision) must be fixed before source writes"
        );

        // V1 锁序守卫：create 中 self-delegation 拒绝 → 全部卡行升序 FOR UPDATE →
        // duplicate ACTIVE 探测 → INSERT。幂等检查必须受双卡行锁保护，串行化
        // 同 pair 的并发创建。
        let create_body = split_mutation(source, "async fn create_with_rule");
        let self_reject = create_body
            .find("reject_self_delegation(new)?")
            .expect("create must reject self delegations");
        let card_locks = create_body
            .find("ordered_unique_positive_card_ids([new.delegator_card_id, new.delegate_card_id])")
            .expect("create must acquire both card row locks up front");
        let duplicate_probe = create_body
            .find("AND action_code = ? AND status = 'ACTIVE'")
            .expect("duplicate ACTIVE probe must exist");
        let insert_marker = create_body
            .find("INSERT INTO permission_delegation")
            .expect("create must insert the delegation row");
        assert!(
            self_reject < card_locks && card_locks < duplicate_probe,
            "duplicate probe must run after the ascending card locks (V1)"
        );
        assert!(
            duplicate_probe < insert_marker,
            "idempotent branch must short-circuit before the insert"
        );

        // 幂等分支必须在证明一致后才允许复用既有委托；否则显式要求修复。
        assert!(create_body.contains("classify_idempotent_consistency"));
        assert!(create_body.contains("repair required"));
        assert!(create_body.contains("next_delta_version(None)"));
    }

    // ── 委托人持有权证明（V2 修复）纯判定测试 ──────────────────────────────

    fn evidence_grant<'a>(
        resource: &'a str,
        action: &'a str,
        expires_at: Option<i64>,
    ) -> DelegatorEvidenceGrant<'a> {
        DelegatorEvidenceGrant {
            resource,
            action,
            expires_at,
            conditioned: false,
        }
    }

    fn hold_error(result: Result<DelegatorHoldProof, AstralError>) -> String {
        match result {
            Err(error) => error.to_string(),
            Ok(proof) => panic!("expected the delegation to be rejected, got {proof:?}"),
        }
    }

    #[test]
    fn hold_proof_passes_on_exact_type_level_grant_within_window() {
        let grants = [evidence_grant("learn_question", "read", Some(2_000))];
        // 两侧均为排他上界：相等即窗口完全一致，允许通过。
        let proof = prove_delegator_hold(&grants, "learn_question", "read", 2_000).unwrap();
        assert_eq!(proof.evidence_expires_at, Some(2_000));
        let proof = prove_delegator_hold(&grants, "learn_question", "read", 1_000).unwrap();
        assert_eq!(proof.evidence_expires_at, Some(2_000));
    }

    #[test]
    fn hold_proof_fails_closed_without_a_matching_published_allow() {
        let grants = [
            evidence_grant("learn_question", "read", Some(2_000)),
            evidence_grant("learn_course:*", "delete", Some(3_000)),
        ];
        for (resource, action) in [
            ("learn_question", "create"), // 动作不匹配
            ("learn_exam", "read"),       // 类型不匹配
        ] {
            let error = hold_error(prove_delegator_hold(&grants, resource, action, 1_000));
            assert!(
                error.contains("does not hold a proven published ALLOW"),
                "{error}"
            );
        }
        // 空证据集合（evidence Ready 但有效授权面为空）同样拒绝。
        let error = hold_error(prove_delegator_hold(&[], "learn_question", "read", 1_000));
        assert!(error.contains("does not hold"), "{error}");
    }

    #[test]
    fn hold_proof_honors_wildcard_semantics_of_published_evidence() {
        // 类型级通配资源（`type:*`）+ `*` 动作按引擎语义覆盖该类型全部动作。
        let type_wildcard = [evidence_grant("learn_question:*", "*", Some(2_000))];
        assert!(prove_delegator_hold(&type_wildcard, "learn_question", "read", 1_000).is_ok());
        assert!(prove_delegator_hold(&type_wildcard, "learn_question", "delete", 2_000).is_ok());
        // 裸类型（无冒号）同样是类型级 grant；永续授权允许任意委托有效期。
        let bare_type = [evidence_grant("learn_question", "read", None)];
        let proof = prove_delegator_hold(&bare_type, "learn_question", "read", 9_999).unwrap();
        assert_eq!(proof.evidence_expires_at, None);
        // 全局 `*` 资源通配覆盖任意被委托类型。
        let global = [evidence_grant("*", "read", Some(2_000))];
        assert!(prove_delegator_hold(&global, "learn_exam", "read", 1_000).is_ok());
    }

    #[test]
    fn hold_proof_never_lets_object_level_grants_back_type_level_delegations() {
        // 委托写入的规则恒为 resource_id=NULL 的类型级 ALLOW；对象级 grant
        // 绝不支撑类型级委托（否则被委托方获得委托人从未有效持有的权限面）。
        let grants = [evidence_grant("learn_question:42", "read", Some(2_000))];
        let error = hold_error(prove_delegator_hold(
            &grants,
            "learn_question",
            "read",
            1_000,
        ));
        assert!(error.contains("does not hold"), "{error}");
    }

    #[test]
    fn hold_proof_rejects_conditioned_evidence_fail_closed() {
        let mut grants = [evidence_grant("learn_question", "read", Some(2_000))];
        grants[0].conditioned = true;
        // 即使精确命中：条件化授权不得被委托成无条件类型级 ALLOW（默认拒绝，
        // 保守优先）。当前 CanonicalGrant 合同无 condition 字段，该钩子面向
        // 未来 evidence 合同演进保持 fail-closed。
        let error = hold_error(prove_delegator_hold(
            &grants,
            "learn_question",
            "read",
            1_000,
        ));
        assert!(error.contains("does not hold"), "{error}");
    }

    #[test]
    fn hold_proof_rejects_delegation_expiry_beyond_the_proven_bound() {
        let grants = [evidence_grant("learn_question", "read", Some(1_000))];
        let error = hold_error(prove_delegator_hold(
            &grants,
            "learn_question",
            "read",
            1_001,
        ));
        assert!(
            error.contains("exceeds the delegator's proven grant expiry"),
            "{error}"
        );
    }

    #[test]
    fn hold_proof_uses_the_latest_bound_and_prefers_perpetual_among_matching_grants() {
        let grants = [
            evidence_grant("learn_question", "read", Some(1_000)),
            evidence_grant("learn_question:*", "read", Some(5_000)),
        ];
        // 委托人真实可证明的持有上界是命中集合的最晚上界（5_000）。
        assert!(prove_delegator_hold(&grants, "learn_question", "read", 3_000).is_ok());
        let error = hold_error(prove_delegator_hold(
            &grants,
            "learn_question",
            "read",
            5_001,
        ));
        assert!(error.contains("exceeds"), "{error}");

        // 任一命中授权永续 → evidence 侧无上界（不因另一条较早到期而收紧）。
        let with_perpetual = [
            evidence_grant("learn_question", "read", Some(1_000)),
            evidence_grant("learn_question", "read", None),
        ];
        let proof =
            prove_delegator_hold(&with_perpetual, "learn_question", "read", i64::MAX).unwrap();
        assert_eq!(proof.evidence_expires_at, None);
    }

    #[test]
    fn hold_proof_matches_action_aliases_like_the_policy_engine() {
        // 持有聚合动作 `write` 可支撑其展开动作（create/update/delete）的委托，
        // 与引擎读侧别名语义一致。
        let writer = [evidence_grant("learn_question", "write", Some(2_000))];
        assert!(prove_delegator_hold(&writer, "learn_question", "create", 1_000).is_ok());
        assert!(prove_delegator_hold(&writer, "learn_question", "delete", 1_000).is_ok());
        // 反向不成立：仅持有 `create` 不能委托出聚合动作 `write`（持有者在
        // 引擎读侧同样无法直接通过 `write` 评估）。
        let creator = [evidence_grant("learn_question", "create", Some(2_000))];
        let error = hold_error(prove_delegator_hold(
            &creator,
            "learn_question",
            "write",
            1_000,
        ));
        assert!(error.contains("does not hold"), "{error}");
    }

    #[test]
    fn normalize_new_delegation_trims_registered_pairs_and_fails_closed_on_unregistered() {
        let mut new = NewDelegation {
            delegator_card_id: 1,
            delegate_card_id: 3,
            resource_type: "learn_question".into(),
            action_code: "read".into(),
            effective_until_ts: 1_700_000_000,
        };
        new.resource_type = " learn_question ".into();
        new.action_code = " read ".into();
        let normalized = normalize_new_delegation(&new).unwrap();
        assert_eq!(normalized.resource_type, "learn_question");
        assert_eq!(normalized.action_code, "read");
        assert_eq!(normalized.delegator_card_id, 1);
        assert_eq!(normalized.delegate_card_id, 3);
        assert_eq!(normalized.effective_until_ts, 1_700_000_000);

        // 未注册资源 / 未注册动作 / 空白一律 Validation fail-closed。
        for (resource, action) in [
            ("no_such_resource", "read"),
            ("learn_question", "no_such_action"),
            ("   ", "read"),
        ] {
            new.resource_type = resource.into();
            new.action_code = action.into();
            let error = normalize_new_delegation(&new).unwrap_err();
            assert!(matches!(error, AstralError::Validation(_)), "{error}");
        }
    }

    #[test]
    fn delegator_hold_proof_shape_guards() {
        let source = include_str!("delegation_repository.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section must exist");

        // 放行依据只允许是已发布 canonical evidence 严格 reader 与 registry
        // 规范化函数；生产段不得出现 raw source/快照读取作为委托放行依据。
        assert!(production.contains("load_published_card_grant_evidence_in_tx"));
        assert!(production.contains("validate_registry_resource_action"));

        // create：规范化（纯判定）→ 卡锁 → 持有权证明 → duplicate 探测 → INSERT。
        let create_body = split_mutation(source, "async fn create_with_rule");
        let normalized = create_body
            .find("normalize_new_delegation(new)?")
            .expect("create must normalize resource/action through the registry");
        let card_locks = create_body
            .find("ordered_unique_positive_card_ids")
            .expect("create must lock the involved cards");
        let hold_proof = create_body
            .find("prove_delegator_hold_in_tx")
            .expect("create must prove the delegator hold in tx");
        let duplicate_probe = create_body
            .find("AND action_code = ? AND status = 'ACTIVE'")
            .expect("duplicate ACTIVE probe must exist");
        let insert_marker = create_body
            .find("INSERT INTO permission_delegation")
            .expect("create must insert the delegation row");
        assert!(
            normalized < card_locks,
            "registry normalization is pure and must fail fast before any lock"
        );
        assert!(
            card_locks < hold_proof,
            "hold proof must run after the delegator card is locked and validated"
        );
        assert!(
            hold_proof < duplicate_probe && duplicate_probe < insert_marker,
            "hold proof must precede any reuse or write of delegation rows"
        );

        // update：规范化 → 仅变更组合重新证明 → 任何 source 写入之前。
        let update_body = split_mutation(source, "async fn update_with_rule");
        let update_normalized = update_body
            .find("validate_registry_resource_action")
            .expect("update must normalize resource/action through the registry");
        let update_proof = update_body
            .find("prove_delegator_hold_in_tx")
            .expect("update must re-prove changed resource/action combos");
        let source_update = update_body
            .find("UPDATE permission_delegation SET resource_type")
            .expect("update must mutate the delegation row");
        assert!(
            update_normalized < update_proof && update_proof < source_update,
            "changed combos must be re-proven before any durable write"
        );
        // 变更检测必须比较规范化值与锁定行（trim 漂移视为变更并触发重新证明）。
        assert!(update_body
            .contains("resource != record.resource_type || action != record.action_code"));
    }

    #[test]
    fn expiry_reconciliation_classification_is_pure_and_fail_closed() {
        use ExpiryReconciliationEligibility as E;
        // ACTIVE 且已到期 → 允许收敛（边界：恰好等于 DB 时钟即视为已到期）。
        assert_eq!(
            classify_expiry_reconciliation("ACTIVE", 1_800_000_000, Some(1_800_000_000)),
            E::Due
        );
        assert_eq!(
            classify_expiry_reconciliation("ACTIVE", 1_800_000_001, Some(1_800_000_000)),
            E::Due
        );
        // 仍 ACTIVE 但未到期 → 显式不满足，绝不提前收敛。
        assert_eq!(
            classify_expiry_reconciliation("ACTIVE", 1_799_999_999, Some(1_800_000_000)),
            E::NotYetDue
        );
        // 已非 ACTIVE → 幂等 no-op（REVOKED/EXPIRED 终态重放不产生第二条 tombstone）。
        assert_eq!(
            classify_expiry_reconciliation("REVOKED", 1_800_000_000, Some(1_700_000_000)),
            E::AlreadyTerminal
        );
        assert_eq!(
            classify_expiry_reconciliation("EXPIRED", 1_800_000_000, Some(1_700_000_000)),
            E::AlreadyTerminal
        );
        // ACTIVE 但有效期缺失/非正 → source 漂移，要求修复而非 no-op。
        assert_eq!(
            classify_expiry_reconciliation("ACTIVE", 1_800_000_000, None),
            E::RepairRequired
        );
        assert_eq!(
            classify_expiry_reconciliation("ACTIVE", 1_800_000_000, Some(0)),
            E::RepairRequired
        );
        assert_eq!(
            classify_expiry_reconciliation("ACTIVE", 1_800_000_000, Some(-7)),
            E::RepairRequired
        );
    }

    #[test]
    fn expiry_operation_id_is_stable_deterministic_and_bounded() {
        let id = derive_delegation_expiry_operation_id(7001, 1_770_000_000).unwrap();
        assert_eq!(id, "delegation:expire:7001:e1770000000");
        // 重放稳定：同一（锁定委托主键, 锁定有效期）必然派生同一 id —— 幂等重试
        // 的 durable 身份基础；绝不引入随机量。
        assert_eq!(
            derive_delegation_expiry_operation_id(7001, 1_770_000_000).unwrap(),
            id
        );
        // 不同委托/不同锁定有效期必然分叉。
        assert_ne!(
            derive_delegation_expiry_operation_id(7002, 1_770_000_000).unwrap(),
            id
        );
        assert_ne!(
            derive_delegation_expiry_operation_id(7001, 1_770_000_001).unwrap(),
            id
        );
        // 与人工撤销/更新的 operation id 命名空间隔离，避免 uk_ade_event 事件号交叉。
        assert!(!id.starts_with("delegation:revoke"));
        assert!(!id.starts_with("delegation:update"));
        // 恒在 audit_log.request_id 的 64 字节 canonical 上限内。
        let max_id = derive_delegation_expiry_operation_id(i64::MAX, i64::MAX).unwrap();
        assert!(
            max_id.len() < crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH
        );
        // 非正输入 fail-closed。
        assert!(matches!(
            derive_delegation_expiry_operation_id(0, 5),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            derive_delegation_expiry_operation_id(7001, 0),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            derive_delegation_expiry_operation_id(7001, -1),
            Err(AstralError::Validation(_))
        ));
    }

    #[test]
    fn expiry_batch_limit_is_explicitly_bounded() {
        assert!(validated_expiry_batch_limit(1).is_ok());
        assert_eq!(
            validated_expiry_batch_limit(MAX_EXPIRY_RECONCILIATION_BATCH).unwrap(),
            MAX_EXPIRY_RECONCILIATION_BATCH
        );
        for bad in [
            0,
            -1,
            i64::MIN,
            MAX_EXPIRY_RECONCILIATION_BATCH + 1,
            i64::MAX,
        ] {
            let error = validated_expiry_batch_limit(bad).unwrap_err();
            assert!(matches!(error, AstralError::Validation(_)));
        }
    }

    #[test]
    fn expiry_reconciliation_shape_guards() {
        let source = include_str!("delegation_repository.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section must exist");
        let body = split_mutation(source, "async fn reconcile_expired_delegation");
        assert!(!body.is_empty(), "impl body must be located");

        // 全局锁序 + 证明门禁 + durable 写入顺序：
        // 无锁预读 → 两端点卡升序 FOR UPDATE → delegation 行锁 → 到期资格判定
        // （锁定行 + 事务内 DB 时钟）→ 规则行 before-image 锁 → grant head 锁 →
        // operation id 定型（锁定有效期派生）→ CARD REVOKE 投影 → delta 版本锁 →
        // REVOKE tombstone → 规则删除/置 EXPIRED → 审计 → 提交。
        let probe = body
            .find("probe_delegation_in_tx")
            .expect("reconcile must probe endpoints before any lock");
        let card_locks = body
            .find("ordered_unique_positive_card_ids([probe.delegator_card_id, probe.delegate_card_id])")
            .expect("reconcile must lock both endpoint cards ascending");
        let delegation_lock = body
            .find("lock_delegation_in_tx")
            .expect("reconcile must lock the delegation row after the card locks");
        let classify = body
            .find("classify_expiry_reconciliation")
            .expect("reconcile must classify expiry eligibility on the locked row");
        let rules_lock = body
            .find("lock_delegation_rules_in_tx")
            .expect("reconcile must lock the rule before-image");
        let head_lock = body
            .find("expect_delegation_head_in_tx")
            .expect("reconcile must lock the grant head");
        let op_id = body
            .find("derive_delegation_expiry_operation_id")
            .expect("reconcile must derive its stable operation id");
        let projection = body
            .find("append_card_projection_with_metadata_in_tx")
            .expect("reconcile must append the CARD REVOKE projection");
        let version_lock = body
            .find("read_latest_delta_target_version_for_update_in_tx")
            .expect("reconcile must lock the ledger delta version");
        let tombstone = body
            .find("build_delegation_revoke_draft")
            .expect("reconcile must append the existing REVOKE tombstone");
        let rule_delete = body
            .find("DELETE FROM permission_rule WHERE rule_id")
            .expect("reconcile must delete the expired rule");
        let status_flip = body
            .find("SET status = 'EXPIRED'")
            .expect("reconcile must flip the delegation to the EXPIRED terminal status");
        let audit = body
            .find("insert_delegation_audit_in_tx")
            .expect("reconcile must append the DELEGATION_EXPIRED audit");

        assert!(
            probe < card_locks,
            "endpoint probe must precede the card row locks (global lock order)"
        );
        assert!(
            card_locks < delegation_lock,
            "user_card locks must precede the delegation row lock"
        );
        assert!(
            delegation_lock < classify,
            "expiry eligibility must be proven on the locked row with the tx clock"
        );
        assert!(
            classify < rules_lock && rules_lock < head_lock,
            "rule before-image and grant head must be locked and proven before any durable write"
        );
        assert!(
            head_lock < op_id && op_id < projection,
            "operation id must be fixed from the locked expiry before any durable write"
        );
        assert!(
            projection < version_lock && version_lock < tombstone,
            "CARD projection must precede the ledger tombstone"
        );
        assert!(
            tombstone < rule_delete && rule_delete < status_flip,
            "ledger tombstone must precede source deletes/status flips"
        );
        assert!(status_flip < audit, "audit must be appended before commit");

        // 幂等门禁：非 ACTIVE 显式 no-op；未到期显式 NotYetDue 短路。
        assert!(body.contains("AlreadyTerminal"));
        assert!(body.contains("NotYetDue"));
        // 绝不把生命周期收敛降级为普通 DENY，也绝不依赖 is_revokable 门禁
        // （自然到期不是提前撤销）。
        assert!(
            !body.contains("DENY"),
            "expiry reconciliation must not create ordinary DENY rows"
        );
        assert!(
            !body.contains("non-revocable"),
            "natural expiry must not be gated by is_revokable"
        );
        // source transaction 内禁止网络/MQ/Redis 副作用。
        for forbidden in ["redis", "Redis", "publish", "mq_", "MQ"] {
            assert!(
                !body.contains(forbidden),
                "expiry reconciliation tx must not touch {forbidden}"
            );
        }
        // CARD 投影沿用既有 REVOKE 事件类型（revoke_fence 递增；CARD 白名单不扩）。
        assert!(body.contains("\"REVOKE\""));
        // 审计事件类型与 SYSTEM actor 绑定。
        assert!(body.contains("DELEGATION_EXPIRED"));
        assert!(body.contains("SYSTEM_ACTOR_ID"));

        // 候选发现必须是绑定参数 LIMIT 的有界只读查询，禁止无界扫描。
        assert!(production.contains("ORDER BY delegation_id LIMIT ?"));
        assert!(production.contains("validated_expiry_batch_limit"));
    }

    /// 取 impl 实现体：marker 在文件中出现两次（trait 声明 + impl 实现），
    /// 取第二次出现之后、下一个同级方法之前的文本段。
    fn split_mutation<'a>(source: &'a str, marker: &str) -> &'a str {
        source
            .split(marker)
            .nth(2)
            .unwrap_or("")
            .split("\n    async fn ")
            .next()
            .unwrap_or("")
    }
}
