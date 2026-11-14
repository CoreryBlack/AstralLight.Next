//! 租户数据访问 — TenantRepository
//!
//! 对齐 Java `TenantMapper` / `TenantMemberMapper` / `TenantInvitationMapper` /
//! `TenantPurchaseMapper` / `TenantDomainMapMapper` / `TenantAuditLogMapper` 边界。
//! 事务性方法（create 双步写 path、use_invitation_code 接受邀请）收口为聚合方法。
//! 影响有效授权的租户/域 mutation 以 `AuthorizationSourceTransaction` 为宿主：
//! 租户状态变更与硬删除使用 eligibility owner 的同事务 opaque capture，完成后
//! 交付 parent `stage_eligibility_source`；域映射变更保留逐卡 ELIGIBILITY 投影
//! 事件与 durable `ELIGIBILITY_INVALIDATED` 失效意图的成对登记。所有路径均在
//! commit 证明后才投递；事务开始还必须携带 composition-root 注入的冻结 delivery
//! context。硬删除的 user_card FOR UPDATE 引用守卫保持不变：锁定读在守卫通过
//! 后阻止并发新增引用行，与 DELETE 原子成立。//! create_tenant 与 update_tenant_name 同宿主（保守同栅栏：前者是 owning-
//! binding 存在性 source，后者为 metadata-only 字段）。用户面 member/invitation
//! mutation（add/remove/字段更新、invitation create/cancel/accept）同样以
//! `AuthorizationSourceTransaction` 为宿主承接 proof-bound admission：
//! `begin_source_transaction_with_capability` 拒绝无 admission 的
//! `UserPending` 能力，commit 前对牌 durable authority frontier/proof 行并
//! `consume_once`；actor 卡片行锁定复核（`verify_tenant_mutation_actor_in_tx`）
//! 把 admission scope 绑定到锁定的 user_card。这些治理行仍是 INSERT/状态类
//! 行、无缓存负事实依赖，因此刻意不登记 ELIGIBILITY 失效事件（不追加投影
//! fanout），授权事实仍由 user_card/发布证据路径承载。遗留无 context 方法
//! 一律 fail-closed（`tenant_context_required`），无内部 system 旁路。

use std::sync::Arc;

use async_trait::async_trait;
mod purchase;
use sha2::{Digest, Sha256};
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::authority_eligibility_completion::{
    EligibilitySourceCapture, EligibilitySourceSubject,
};
use astral_db::grant_ledger::validated_request_operation_id;
use astral_db::invalidation_delivery::InvalidationDeliveryContext;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::repository::authorization_source_transaction::{
    append_eligibility_projection_with_invalidation_in_tx,
    append_eligibility_projection_with_invalidation_on_raw_tx,
    begin_source_transaction_with_capability_and_delivery_context, AuthorizationSourceTransaction,
    InvalidationReceipt, SourceMutationCapability, SourceProjectionReceipt,
};

// ===== Records =====

/// 租户记录（platform_v4.tenant，domain_id 用 0 占位——真实表无该列）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantRecord {
    pub id: i64,
    pub domain_id: i64,
    pub name: String,
    pub status: String,
    pub parent_tenant_id: Option<i64>,
    pub path: String,
    pub depth: i32,
}

/// 租户成员记录（platform_v4.tenant_members）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantMemberRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub user_id: i64,
    pub role: String,
    pub status: String,
    pub display_name: Option<String>,
    pub joined_at: Option<i64>,
    pub left_at: Option<i64>,
}

/// 租户邀请记录（platform_v4.tenant_invitation）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantInvitationRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub inviter_id: i64,
    pub invitee_email: Option<String>,
    pub invitee_user_id: Option<i64>,
    pub token: String,
    pub role: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub message: Option<String>,
    pub accepted_at: Option<i64>,
}

/// 租户购买记录（platform_v4.tenant_purchase，业务字段占位）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantPurchaseRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub plan_id: Option<i64>,
    pub plan_name: String,
    pub amount: i64,
    pub currency: String,
    pub billing_cycle: String,
    pub status: String,
    pub payment_method: Option<String>,
    pub payment_channel: Option<String>,
    pub transaction_id: Option<String>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub paid_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub remark: Option<String>,
}

/// 租户域映射记录（platform_v4.tenant_domain_map）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantDomainMapRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub is_primary: bool,
    pub mapping_type: String,
    pub status: String,
}

/// 租户审计日志记录（platform_v4.tenant_audit_log）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantAuditLogRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub actor_id: Option<i64>,
    pub actor_name: Option<String>,
    pub action: String,
    pub action_label: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub result: String,
    pub reason: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: Option<i64>,
}

// ===== 参数 =====

/// 列表过滤（keyword / status 可选）
#[derive(Debug, Default)]
pub struct TenantFilter {
    pub keyword: Option<String>,
    pub status: Option<String>,
}

/// 新建租户参数（service 完成 path/depth 推算）
#[derive(Debug, Clone)]
pub struct NewTenant {
    pub name: String,
    pub parent_tenant_id: Option<i64>,
    pub path: String,
    pub depth: i32,
}

/// Gateway-verified identity and scope carried into one TrustGraph tenant mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl TenantMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    /// Gateway headers alone are not an authority source and must match this signed context.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "tenant mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("tenant mutation requires a canonical request id".into())
        })?;
        Ok(Self {
            actor_id,
            actor_card_id,
            actor_tenant_id,
            actor_domain_id,
            request_id,
            source_capability: SourceMutationCapability::UserPending,
        })
    }

    pub fn with_admission(mut self, admission: AuthorizationAdmission) -> Self {
        self.source_capability = SourceMutationCapability::user(admission);
        self
    }

    fn validate_admission_operation_id(&self) -> Result<(), AstralError> {
        if let SourceMutationCapability::User(admission) = self.source_capability() {
            validate_admission_operation_id(self.request_id(), admission.operation_id())?;
        }
        Ok(())
    }

    pub(crate) fn source_capability(&self) -> &SourceMutationCapability {
        &self.source_capability
    }

    fn request_id(&self) -> &str {
        &self.request_id
    }
}

fn positive_context_id(value: Option<i64>, name: &str) -> Result<i64, AstralError> {
    value
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Auth(format!("tenant mutation requires a positive {name}")))
}

fn tenant_context_required() -> AstralError {
    AstralError::Auth("tenant business mutation requires Gateway-verified user-card context".into())
}

fn validate_admission_operation_id(
    request_id: &str,
    admission_operation_id: &str,
) -> Result<(), AstralError> {
    if request_id != admission_operation_id {
        return Err(AstralError::Pending(
            "tenant mutation request id differs from admission operation id".into(),
        ));
    }
    Ok(())
}

type TenantActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

async fn verify_tenant_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &TenantMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<TenantActorCardRow> = sqlx::query_as(TENANT_MUTATION_ACTOR_LOCK_SQL)
        .bind(context.actor_card_id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    match actor {
        Some((Some(user_id), Some(tenant_id), Some(domain_id), status))
            if user_id == context.actor_id
                && tenant_id == context.actor_tenant_id
                && domain_id == context.actor_domain_id
                && status == "ACTIVE" =>
        {
            if let SourceMutationCapability::User(admission) = context.source_capability() {
                let scope = &admission.proof().scope;
                let domain_matches = matches!(
                    scope.domain,
                    astral_types::AuthorizationDomainScope::Exact(value)
                        if value == domain_id
                );
                if scope.tenant_id != tenant_id
                    || scope.card_id != context.actor_card_id
                    || scope.user_id != Some(user_id)
                    || !domain_matches
                {
                    return Err(AstralError::Permission(
                        "authorization admission scope does not match the locked tenant mutation actor card".into(),
                    ));
                }
            }
            Ok(())
        }
        _ => Err(AstralError::Auth(
            "Gateway tenant mutation card context no longer matches an active user_card".into(),
        )),
    }
}

async fn insert_tenant_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &TenantMutationContext,
    tenant_id: i64,
    action: &str,
    target_type: &str,
    target_id: i64,
    details: serde_json::Value,
) -> Result<astral_db::TypedSourceAuditReceipt, AstralError> {
    if tenant_id <= 0 || target_id <= 0 || action.trim().is_empty() || target_type.trim().is_empty()
    {
        return Err(AstralError::Validation(
            "tenant mutation audit requires positive tenant/target and non-empty action/type"
                .into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": target_type,
        "targetId": target_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("tenant audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("tenant audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(TENANT_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(target_type)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("tenant mutation audit insert failed: {error}"))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "tenant audit insert did not affect exactly one durable row".into(),
        ));
    }
    let audit_id = i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("tenant audit insert returned invalid id".into()))?;
    astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(audit_id)
}

fn eligibility_admission(
    context: &TenantMutationContext,
) -> Result<&AuthorizationAdmission, AstralError> {
    match context.source_capability() {
        SourceMutationCapability::User(admission) => Ok(admission),
        SourceMutationCapability::UserPending => Err(AstralError::Pending(
            "tenant eligibility source capture requires authorization admission".into(),
        )),
        SourceMutationCapability::System(_) => Err(AstralError::Permission(
            "tenant eligibility source capture cannot use a system capability".into(),
        )),
    }
}

async fn insert_tenant_mutation_audit_on_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    context: &TenantMutationContext,
    tenant_id: i64,
    action: &str,
    target_type: &str,
    target_id: i64,
    details: serde_json::Value,
) -> Result<i64, AstralError> {
    let detail = serde_json::to_string(&serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": target_type,
        "targetId": target_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("tenant audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(TENANT_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(target_type)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(tenant_id)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("tenant mutation audit insert failed: {error}"))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "tenant audit insert did not affect exactly one durable row".into(),
        ));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("tenant audit insert returned invalid id".into()))
}

async fn lock_existing_tenant_scope_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &TenantMutationContext,
    tenant_id: i64,
) -> Result<bool, AstralError> {
    let row: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
        .bind(tenant_id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    if row.is_some() {
        if tenant_id != context.actor_tenant_id {
            return Err(AstralError::Permission(
                "tenant mutation target tenant does not match the locked actor scope".into(),
            ));
        }
        verify_tenant_mutation_actor_in_tx(tx, context).await?;
    }
    Ok(row.is_some())
}

/// 新建购买参数（service 完成到期推算）
#[derive(Debug, Clone)]
pub struct NewPurchase {
    pub tenant_id: i64,
    pub plan_id: i64,
    pub expired_secs: Option<i64>,
}

// ===== SQL 常量 =====

const TENANT_SELECT: &str = "tenant_id as id, 0 as domain_id, tenant_name as name, status, \
     parent_tenant_id, path, depth";
/// JOIN 场景（tenant 带前缀的版本，0 占位字面量不带前缀）
const TENANT_SELECT_T: &str =
    "t.tenant_id as id, 0 as domain_id, t.tenant_name as name, t.status, \
     t.parent_tenant_id, t.path, t.depth";
const MEMBER_SELECT: &str = "member_id as id, tenant_id, user_id, role_type as role, \
     member_status as status, NULL as display_name, UNIX_TIMESTAMP(joined_at) as joined_at, NULL as left_at";
const INVITATION_SELECT: &str = "invitation_id as id, tenant_id, invited_by as inviter_id, \
     NULL as invitee_email, NULL as invitee_user_id, invite_code as token, role, status, \
     UNIX_TIMESTAMP(expires_at) as expires_at, NULL as message, NULL as accepted_at";
const PURCHASE_SELECT: &str = "purchase_id as id, tenant_id, package_id as plan_id, \
     '' as plan_name, 0 as amount, 'CNY' as currency, 'MONTHLY' as billing_cycle, status, \
     NULL as payment_method, NULL as payment_channel, NULL as transaction_id, \
     UNIX_TIMESTAMP(purchased_at) as period_start, UNIX_TIMESTAMP(expired_at) as period_end, \
     UNIX_TIMESTAMP(purchased_at) as paid_at, NULL as refunded_at, NULL as remark";
const DOMAIN_MAP_SELECT: &str = "id, tenant_id, domain_id, false as is_primary, \
     'OWNED' as mapping_type, status";
const AUDIT_LOG_SELECT: &str = "log_id as id, tenant_id, operator_id as actor_id, \
     NULL as actor_name, action, NULL as action_label, target_type, \
     CAST(target_id AS CHAR) as target_id, CAST(detail_json AS CHAR) as detail, \
     'SUCCESS' as result, NULL as reason, ip as source_ip, NULL as user_agent, \
     UNIX_TIMESTAMP(created_at) as created_at";

const TENANT_STATUS_LOCK_SQL: &str = "SELECT status FROM tenant WHERE tenant_id = ? FOR UPDATE";
const TENANT_ID_LOCK_SQL: &str = "SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE";
/// 成员目标行锁：remove/字段更新前按 (tenant_id, user_id) 锁定目标成员行，
/// 序列化同一成员的并发治理 mutation（参数化、无动态列）。
const TENANT_MEMBER_LOCK_SQL: &str = "SELECT member_id, member_status FROM tenant_members \
     WHERE tenant_id = ? AND user_id = ? FOR UPDATE";
/// 邀请目标行锁：cancel/accept 前按 invitation_id 锁定邀请行，ACTIVE 守卫与
/// 并发使用同一行锁串行化（accept 的 current_uses 自增依赖该锁）。
const TENANT_INVITATION_LOCK_SQL: &str = "SELECT tenant_id, role, status, \
     UNIX_TIMESTAMP(expires_at) AS expires_at FROM tenant_invitation \
     WHERE invitation_id = ? FOR UPDATE";
const DOMAIN_ID_LOCK_SQL: &str =
    "SELECT domain_id FROM platform_domain WHERE domain_id = ? FOR UPDATE";
const TENANT_DOMAIN_STATUS_LOCK_SQL: &str =
    "SELECT status FROM tenant_domain_map WHERE tenant_id = ? AND domain_id = ? FOR UPDATE";
const TENANT_MUTATION_ACTOR_LOCK_SQL: &str =
    "SELECT user_id, tenant_id, domain_id, card_status FROM user_card WHERE card_id = ? FOR UPDATE";
const TENANT_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_TENANT_MUTATION', ?, ?, ?, ?)";
/// 硬删除前置守卫：统计仍引用该租户的 user_card 行数（锁定读，参数化 SQL）。
/// 锁定读在守卫通过后阻止并发为该租户新增 user_card 行，直到事务结束。
/// 不按 card_status 过滤：任何状态（含 DISABLED/PENDING/INACTIVE）的引用行
/// 都会被级联删除销毁，且非 ACTIVE 行不在 ELIGIBILITY 捕获范围内。
const TENANT_CARD_REFERENCES_LOCK_SQL: &str = "SELECT COUNT(*) FROM user_card \
     WHERE tenant_id = ? FOR UPDATE";
/// 租户级 ELIGIBILITY 批量捕获：按 card_id 序锁定该租户的 ACTIVE user_card 行
/// （与 astral-db `ELIGIBILITY_BY_TENANT_ID_QUERY` 同一谓词形状，额外以 LIMIT ?
/// 约束锁定读行数上界；绑定值为 cap+1，多取一行仅用于判定超限）。
/// 锁序沿用调用方 tenant 行 -> mapping 行 -> 本段 user_card 行的既有顺序。
#[cfg(test)]
const TENANT_CARDS_ELIGIBILITY_LOCK_SQL: &str = "SELECT card_id, tenant_id FROM user_card \
     WHERE tenant_id = ? AND card_status = 'ACTIVE' ORDER BY card_id LIMIT ? FOR UPDATE";
/// 租户+域维度的同一批量捕获（与 `ELIGIBILITY_BY_TENANT_AND_DOMAIN_QUERY` 同一
/// 谓词形状 + LIMIT 上界），并返回 tenant_id 供每行 ownership 复核。
const TENANT_DOMAIN_CARDS_ELIGIBILITY_LOCK_SQL: &str = "SELECT card_id, tenant_id FROM user_card \
     WHERE tenant_id = ? AND domain_id = ? AND card_status = 'ACTIVE' \
     ORDER BY card_id LIMIT ? FOR UPDATE";

/// 租户级 ELIGIBILITY 批量捕获的每事务卡片上限：锁定候选数超过上限即
/// Validation fail-closed、整体回滚（含已执行的 source mutation），绝不部分
/// 通知、绝不先提交再补通知。多取一行仅用于证明超限，绝不截断后继续处理。
const TENANT_ELIGIBILITY_CARD_CAP: usize = 256;

/// 合法租户状态字母表（与 API 层 `ACTIVE | SUSPENDED | TERMINATED` 校验同向）。
/// 进入 operation id 的状态一律先过此复核，随机/任意字符串绝不进入事件链。
const TENANT_STATUS_ALPHABET: &[&str] = &["ACTIVE", "SUSPENDED", "TERMINATED"];

/// 合法成员角色字母表（与 API 层 `OWNER | ADMIN | MEMBER | GUEST` 校验同向）。
/// 仅作输入规范化复核（fail-closed backstop），不是授权证明；授权由
/// admission proof 承担，绝不以角色检查放行。
const MEMBER_ROLE_ALPHABET: &[&str] = &["OWNER", "ADMIN", "MEMBER", "GUEST"];

/// `update_member_field` 动态列白名单：只有这三列可进入 UPDATE 的 SET 段；
/// 任何其他输入（含拼接注入）一律 Validation fail-closed。列名是编译期
/// 白名单而非用户输入，值仍走绑定参数。
const MEMBER_FIELD_COLUMNS: &[&str] = &["admin_level", "dept_id", "role_type"];

/// 邀请码长度上界（platform_v4.tenant_invitation.invite_code 为 varchar(64)）。
const INVITATION_TOKEN_MAX_LEN: usize = 64;

/// 锁定读的行数上界（cap + 1：多取一行仅用于在单次锁定读内判定超限）。
fn tenant_eligibility_lock_bound() -> i64 {
    TENANT_ELIGIBILITY_CARD_CAP as i64 + 1
}

#[async_trait]
pub trait TenantRepository: Send + Sync {
    // ---- Tenant ----
    async fn count_tenants(&self, filter: &TenantFilter) -> Result<i64, AstralError>;
    async fn list_tenants(
        &self,
        filter: &TenantFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TenantRecord>, AstralError>;
    async fn get_tenant(&self, tenant_id: i64) -> Result<Option<TenantRecord>, AstralError>;
    async fn get_tenant_path_depth(
        &self,
        tenant_id: i64,
    ) -> Result<Option<(String, i32)>, AstralError>;
    /// 新建租户（INSERT + path 更新在单事务内，修复崩溃中间态）
    async fn create_tenant(&self, new: &NewTenant) -> Result<i64, AstralError> {
        let _ = new;
        Err(tenant_context_required())
    }
    async fn create_tenant_with_context(
        &self,
        new: &NewTenant,
        context: &TenantMutationContext,
    ) -> Result<i64, AstralError> {
        let _ = (new, context);
        Err(tenant_context_required())
    }

    async fn update_tenant_name(&self, tenant_id: i64, name: &str) -> Result<(), AstralError> {
        let _ = (tenant_id, name);
        Err(tenant_context_required())
    }
    async fn update_tenant_name_with_context(
        &self,
        tenant_id: i64,
        name: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (tenant_id, name, context);
        Err(tenant_context_required())
    }

    async fn update_tenant_status(&self, tenant_id: i64, status: &str) -> Result<(), AstralError> {
        let _ = (tenant_id, status);
        Err(tenant_context_required())
    }
    async fn update_tenant_status_with_context(
        &self,
        tenant_id: i64,
        status: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (tenant_id, status, context);
        Err(tenant_context_required())
    }

    /// 硬删除租户，返回是否命中。fail-closed：事务内先锁租户行证明存在，
    /// 再以锁定读守卫统计仍引用该租户的 user_card 行；存在引用行时返回
    /// Validation 冲突错误并整体回滚（无部分删除）。完整级联（捕获并持久
    /// 吊销所有受影响的规范授权贡献）不在本仓库范围，须先回收/迁移全部卡片。
    async fn delete_tenant(&self, tenant_id: i64) -> Result<bool, AstralError> {
        let _ = tenant_id;
        Err(tenant_context_required())
    }
    async fn delete_tenant_with_context(
        &self,
        tenant_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, context);
        Err(tenant_context_required())
    }

    /// 状态迁移（ACTIVE→SUSPENDED / SUSPENDED→ACTIVE），返回是否命中
    async fn transition_tenant_status(
        &self,
        tenant_id: i64,
        from: &str,
        to: &str,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, from, to);
        Err(tenant_context_required())
    }
    async fn transition_tenant_status_with_context(
        &self,
        tenant_id: i64,
        from: &str,
        to: &str,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, from, to, context);
        Err(tenant_context_required())
    }

    async fn list_my_tenants(&self, user_id: i64) -> Result<Vec<TenantRecord>, AstralError>;
    async fn list_sub_tenants(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError>;
    async fn list_tenant_tree(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError>;

    // ---- Members ----
    async fn list_members(&self, tenant_id: i64) -> Result<Vec<TenantMemberRecord>, AstralError>;
    /// upsert 成员（ON DUPLICATE KEY UPDATE）。遗留无 context 入口一律
    /// fail-closed：用户面成员治理必须携带 proof-bound admission。
    async fn upsert_member(
        &self,
        tenant_id: i64,
        user_id: i64,
        role: &str,
    ) -> Result<(), AstralError> {
        let _ = (tenant_id, user_id, role);
        Err(tenant_context_required())
    }
    /// upsert 成员的 proof-bound 入口：授权源事务宿主 + 租户范围/actor 卡片
    /// 复核 + 业务审计；`UserPending`（无 admission）在 begin 即被拒绝。
    async fn upsert_member_with_context(
        &self,
        tenant_id: i64,
        user_id: i64,
        role: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (tenant_id, user_id, role, context);
        Err(tenant_context_required())
    }
    async fn get_member(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> Result<TenantMemberRecord, AstralError>;
    /// 移除成员（member_status → REMOVED），返回是否命中。遗留无 context
    /// 入口一律 fail-closed。
    async fn remove_member(&self, tenant_id: i64, user_id: i64) -> Result<bool, AstralError> {
        let _ = (tenant_id, user_id);
        Err(tenant_context_required())
    }
    /// 移除成员的 proof-bound 入口：先锁目标成员行再置 REMOVED。
    async fn remove_member_with_context(
        &self,
        tenant_id: i64,
        user_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, user_id, context);
        Err(tenant_context_required())
    }
    /// 更新成员字段（admin_level / dept_id / role_type），返回是否命中。
    /// 遗留无 context 入口一律 fail-closed。
    async fn update_member_field(
        &self,
        tenant_id: i64,
        user_id: i64,
        column: &str,
        value: String,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, user_id, column, value);
        Err(tenant_context_required())
    }
    /// 更新成员字段的 proof-bound 入口：动态列先过 `MEMBER_FIELD_COLUMNS`
    /// 白名单，目标成员行锁定后更新。
    async fn update_member_field_with_context(
        &self,
        tenant_id: i64,
        user_id: i64,
        column: &str,
        value: String,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, user_id, column, value, context);
        Err(tenant_context_required())
    }

    // ---- Invitations ----
    async fn list_invitations(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantInvitationRecord>, AstralError>;
    /// 创建邀请。遗留无 context 入口一律 fail-closed。
    async fn create_invitation(
        &self,
        tenant_id: i64,
        token: &str,
        role: &str,
        inviter_id: i64,
        expires_secs: i64,
    ) -> Result<TenantInvitationRecord, AstralError> {
        let _ = (tenant_id, token, role, inviter_id, expires_secs);
        Err(tenant_context_required())
    }
    /// 创建邀请的 proof-bound 入口：inviter 由锁定 actor 卡片派生
    /// （`context.actor_id`），不由调用方声明。
    async fn create_invitation_with_context(
        &self,
        tenant_id: i64,
        token: &str,
        role: &str,
        expires_secs: i64,
        context: &TenantMutationContext,
    ) -> Result<TenantInvitationRecord, AstralError> {
        let _ = (tenant_id, token, role, expires_secs, context);
        Err(tenant_context_required())
    }
    async fn get_invitation_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError>;
    /// 按邀请码查 ACTIVE 邀请（use_invitation_code 用）
    async fn get_invitation_by_code_active(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError>;
    /// 撤销邀请（ACTIVE → REVOKED），返回是否命中。遗留无 context 入口一律
    /// fail-closed。
    async fn cancel_invitation(
        &self,
        tenant_id: i64,
        invitation_id: i64,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, invitation_id);
        Err(tenant_context_required())
    }
    /// 撤销邀请的 proof-bound 入口：先锁目标邀请行，租户归属不匹配即
    /// fail-closed。
    async fn cancel_invitation_with_context(
        &self,
        tenant_id: i64,
        invitation_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, invitation_id, context);
        Err(tenant_context_required())
    }
    /// 标记过期（status → EXPIRED）。仅供邀请接受事务内的过期分支同语义
    /// 复用；独立调用点同样 fail-closed（过期标记不再走无 context 裸写）。
    async fn mark_invitation_expired(&self, invitation_id: i64) -> Result<(), AstralError> {
        let _ = invitation_id;
        Err(tenant_context_required())
    }
    /// 接受邀请：事务（置 ACCEPTED + current_uses+1 + 成员 upsert）。
    /// 遗留无 context 入口一律 fail-closed。
    async fn accept_invitation(
        &self,
        invitation_id: i64,
        tenant_id: i64,
        user_id: i64,
        role: &str,
    ) -> Result<(), AstralError> {
        let _ = (invitation_id, tenant_id, user_id, role);
        Err(tenant_context_required())
    }
    /// 接受邀请的 proof-bound 入口：入会成员即锁定 actor
    /// （`context.actor_id`），邀请行锁定后复核 ACTIVE/过期/归属/角色一致，
    /// 过期分支在同一事务内置 EXPIRED 后 fail-closed。
    async fn accept_invitation_with_context(
        &self,
        invitation_id: i64,
        tenant_id: i64,
        role: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (invitation_id, tenant_id, role, context);
        Err(tenant_context_required())
    }

    // ---- Purchases ----
    async fn list_purchases(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantPurchaseRecord>, AstralError>;
    async fn create_purchase(&self, new: &NewPurchase) -> Result<i64, AstralError>;
    async fn create_purchase_with_context(
        &self,
        new: &NewPurchase,
        billing_cycle: &str,
        context: &astral_db::ProtectedMutationContext,
    ) -> Result<i64, AstralError> {
        let _ = (new, billing_cycle, context);
        Err(tenant_context_required())
    }
    async fn get_purchase(&self, purchase_id: i64) -> Result<TenantPurchaseRecord, AstralError>;

    // ---- Domain map ----
    async fn list_tenant_domains(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantDomainMapRecord>, AstralError>;
    /// upsert 域映射（ON DUPLICATE KEY UPDATE）
    async fn upsert_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError> {
        let _ = (tenant_id, domain_id);
        Err(tenant_context_required())
    }
    async fn upsert_tenant_domain_with_context(
        &self,
        tenant_id: i64,
        domain_id: i64,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (tenant_id, domain_id, context);
        Err(tenant_context_required())
    }

    async fn get_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<TenantDomainMapRecord, AstralError>;
    async fn remove_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, domain_id);
        Err(tenant_context_required())
    }
    async fn remove_tenant_domain_with_context(
        &self,
        tenant_id: i64,
        domain_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let _ = (tenant_id, domain_id, context);
        Err(tenant_context_required())
    }

    // ---- Audit log ----
    async fn list_audit_log(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantAuditLogRecord>, AstralError>;
}

pub struct SqlxTenantRepository {
    db: MySqlPool,
    delivery_context: Option<Arc<InvalidationDeliveryContext>>,
}

impl SqlxTenantRepository {
    /// Legacy construction is retained for read-only/unit wiring only. Source
    /// mutations fail closed until the composition root injects the frozen
    /// delivery context through `new_with_delivery_context`.
    pub fn new(db: MySqlPool) -> Self {
        Self {
            db,
            delivery_context: None,
        }
    }

    pub fn new_with_delivery_context(
        db: MySqlPool,
        delivery_context: Arc<InvalidationDeliveryContext>,
    ) -> Self {
        Self {
            db,
            delivery_context: Some(delivery_context),
        }
    }

    async fn begin_source_transaction(
        &self,
        context: &TenantMutationContext,
    ) -> Result<AuthorizationSourceTransaction, AstralError> {
        context.validate_admission_operation_id()?;
        let delivery_context = self.invalidation_delivery_context()?;
        begin_source_transaction_with_capability_and_delivery_context(
            &self.db,
            context.source_capability(),
            Arc::clone(delivery_context),
        )
        .await
    }

    fn invalidation_delivery_context(
        &self,
    ) -> Result<&Arc<InvalidationDeliveryContext>, AstralError> {
        self.delivery_context.as_ref().ok_or_else(|| {
            AstralError::Pending(
                "tenant source mutation requires an injected invalidation delivery context".into(),
            )
        })
    }
}

/// 追加租户过滤（列表与总数共用）
fn push_tenant_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &TenantFilter,
) {
    if let Some(kw) = &filter.keyword {
        builder
            .push(" AND tenant_name LIKE ")
            .push_bind(format!("%{kw}%"));
    }
    if let Some(status) = &filter.status {
        builder.push(" AND status = ").push_bind(status.clone());
    }
}

// ===== 租户级 ELIGIBILITY 捕获（授权源事务接线） =====

/// 租户级 ELIGIBILITY 批量捕获的候选卡 scope（与 astral-db 选择器同一谓词形状）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantEligibilityScope {
    ByTenantAndDomain { tenant_id: i64, domain_id: i64 },
}

/// 域映射变更方向（决定 operation base 的 action 段，grant/revoke 不共享身份）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantDomainEligibilityAction {
    Grant,
    Revoke,
}

impl TenantDomainEligibilityAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }
}

/// Tenant code identity is derived only from the normalized durable tenant name
/// and parent identity. Caller/request ids, tenant type, and status are excluded.
fn derive_tenant_code(name: &str, parent_tenant_id: Option<i64>) -> Result<String, AstralError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(AstralError::Validation(
            "tenant code derivation requires a bounded tenant name".into(),
        ));
    }
    if parent_tenant_id.is_some_and(|id| id <= 0) {
        return Err(AstralError::Validation(
            "tenant code derivation requires a positive parent tenant id".into(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_TENANT_CODE_V7\0");
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    digest.update(parent_tenant_id.unwrap_or(0).to_be_bytes());
    let encoded = hex::encode(digest.finalize());
    Ok(format!("TENANT-{}", &encoded[..48]))
}

/// 租户域映射变更的稳定 operation base（纯派生，fail-closed，可单测）：
/// `tenant:domain:{grant|revoke}:{tenant_id}:{domain_id}`。同一域反复
/// grant/revoke 由每事件 messageId 保证 outbox 唯一性，本 id 只做关联。
fn derive_tenant_domain_operation_base(
    tenant_id: i64,
    domain_id: i64,
    action: TenantDomainEligibilityAction,
) -> Result<String, AstralError> {
    if tenant_id <= 0 || domain_id <= 0 {
        return Err(AstralError::Validation(format!(
            "tenant domain operation identity requires positive tenant and domain ids, \
             got tenant_id={tenant_id}, domain_id={domain_id}"
        )));
    }
    Ok(format!(
        "tenant:domain:{}:{tenant_id}:{domain_id}",
        action.as_str()
    ))
}

/// 租户级 ELIGIBILITY 批量捕获：在**授权源事务内**按 card_id 序锁定候选 ACTIVE
/// user_card 行，并逐卡登记 ELIGIBILITY 投影事件 + durable
/// `ELIGIBILITY_INVALIDATED` 失效意图（与 user_card owner 的每卡路径
/// [`append_eligibility_projection_with_invalidation_in_tx`] 同一接线）。
///
/// 与 astral-db `append_eligibility_events_for_cards_in_tx` 的差异：后者只落投影
/// head/outbox、无法逐事件登记 receipt —— 租户路径因此曾遗漏 durable 失效意图。
/// 本 helper 以 [`AuthorizationSourceTransaction`] 为宿主补齐成对接线；提交语义由
/// [`AuthorizationSourceTransaction::commit_consuming`] 统一保证：只有 commit 被
/// 证明成功才按序直投，commit 未知/失败或显式回滚一律不投递，durable outbox 行
/// 保持为 relay 恢复路径。
///
/// 身份合同：每张卡的 operation_id 为 `"{operation_base}:card:{card_id}"` ——
/// 同一 operation base（由 `derive_*_operation_base` 从 tenant/action/锁定状态
/// 派生）可携带多卡；每张卡的 ELIGIBILITY 投影事件与失效 envelope 使用事务内
/// 各自新生成的 durable 事件 id（messageId，承担 outbox 唯一性）。与 user_card
/// owner 的事件不重复：本 helper **取代**旧的仅投影 fanout，同一事务内每卡只
/// 产生一对（投影事件, 失效意图），绝不叠加两次追加。
///
/// 边界：锁序沿用调用方 tenant 行 -> mapping 行 -> 本段 user_card 行（FOR UPDATE
/// + card_id 序 + [`TENANT_ELIGIBILITY_CARD_CAP`] 上界，超限 Validation
///   fail-closed 整体回滚）；事务内不触碰 Redis/MQ，网络投递全部发生在 commit
///   证明之后。本函数不 commit，由调用方决定提交/回滚。
async fn capture_tenant_eligibility_cards_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    scope: TenantEligibilityScope,
    expected_tenant_id: i64,
) -> Result<Vec<i64>, AstralError> {
    if expected_tenant_id <= 0 {
        return Err(AstralError::Validation(
            "tenant eligibility capture requires a positive locked tenant id".into(),
        ));
    }
    let lock_bound = tenant_eligibility_lock_bound();
    let cards: Vec<(i64, i64)> = match scope {
        TenantEligibilityScope::ByTenantAndDomain {
            tenant_id,
            domain_id,
        } => {
            if tenant_id != expected_tenant_id || domain_id <= 0 {
                return Err(AstralError::Permission(
                    "tenant/domain eligibility scope differs from the locked source scope".into(),
                ));
            }
            sqlx::query_as(TENANT_DOMAIN_CARDS_ELIGIBILITY_LOCK_SQL)
                .bind(tenant_id)
                .bind(domain_id)
                .bind(lock_bound)
                .fetch_all(&mut ***tx)
                .await
                .map_err(db_error)?
        }
    };
    if cards.len() > TENANT_ELIGIBILITY_CARD_CAP {
        return Err(AstralError::Validation(format!(
            "tenant eligibility capture locked {} candidate cards, exceeding cap {}; failing closed without truncation",
            cards.len(), TENANT_ELIGIBILITY_CARD_CAP
        )));
    }
    let mut ids = Vec::with_capacity(cards.len());
    let mut previous_card_id = 0;
    for (card_id, row_tenant_id) in cards {
        if card_id <= previous_card_id || row_tenant_id != expected_tenant_id {
            return Err(AstralError::Pending(
                "tenant eligibility row identity is duplicate, unordered, or outside the locked tenant".into(),
            ));
        }
        previous_card_id = card_id;
        ids.push(card_id);
    }
    Ok(ids)
}

async fn append_tenant_eligibility_for_cards_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    cards: &[i64],
    operation_base: &str,
) -> Result<(), AstralError> {
    if operation_base.trim().is_empty() || operation_base.trim() != operation_base {
        return Err(AstralError::Validation(
            "tenant eligibility fanout requires a canonical, non-empty operation base".into(),
        ));
    }
    if cards.len() > TENANT_ELIGIBILITY_CARD_CAP || cards.iter().any(|id| *id <= 0) {
        return Err(AstralError::Validation(
            "tenant eligibility captured card set is invalid or exceeds its cap".into(),
        ));
    }
    for card_id in cards {
        let operation_id = format!("{operation_base}:card:{card_id}");
        append_eligibility_projection_with_invalidation_in_tx(&mut *tx, *card_id, &operation_id)
            .await?;
    }
    tracing::debug!(
        operation_base = %operation_base,
        cards = cards.len(),
        "tenant-level eligibility fanout materialized from the pre-mutation locked card set"
    );
    Ok(())
}

/// Append the exact per-card eligibility evidence while the closed source capture
/// owns the raw transaction borrow. The source capture reads these rows back in
/// `finish_in_tx`; the parent registers the same returned identities only after
/// the capture is sealed, so no receipt is synthesized or detached from durable IO.
async fn append_tenant_eligibility_for_capture_in_tx(
    capture: &mut EligibilitySourceCapture<'_, '_>,
    delivery_context: &InvalidationDeliveryContext,
    operation_id: &str,
) -> Result<(Vec<SourceProjectionReceipt>, Vec<InvalidationReceipt>), AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "tenant eligibility fanout requires a non-empty operation id".into(),
        ));
    }
    let cards = capture.selected_cards().to_vec();
    if cards.len() > TENANT_ELIGIBILITY_CARD_CAP || cards.iter().any(|(id, _)| *id <= 0) {
        return Err(AstralError::Validation(
            "tenant eligibility captured card set is invalid or exceeds its cap".into(),
        ));
    }
    let mut projections = Vec::with_capacity(cards.len());
    let mut invalidations = Vec::with_capacity(cards.len());
    for (card_id, _) in cards {
        let (projection, invalidation) = append_eligibility_projection_with_invalidation_on_raw_tx(
            &mut *capture.with_tx_mut(),
            delivery_context,
            card_id,
            operation_id,
        )
        .await?;
        projections.push(projection);
        invalidations.push(invalidation);
    }
    tracing::debug!(
        operation_id = %operation_id,
        cards = projections.len(),
        "tenant-level eligibility fanout materialized inside the closed source capture"
    );
    Ok((projections, invalidations))
}

async fn append_tenant_eligibility_invalidation_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    scope: TenantEligibilityScope,
    operation_base: &str,
) -> Result<(), AstralError> {
    let tenant_id = match scope {
        TenantEligibilityScope::ByTenantAndDomain { tenant_id, .. } => tenant_id,
    };
    let cards = capture_tenant_eligibility_cards_in_tx(tx, scope, tenant_id).await?;
    append_tenant_eligibility_for_cards_in_tx(tx, &cards, operation_base).await
}

#[async_trait]
impl TenantRepository for SqlxTenantRepository {
    async fn count_tenants(&self, filter: &TenantFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM tenant WHERE 1=1");
        push_tenant_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_tenants(
        &self,
        filter: &TenantFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TenantRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {TENANT_SELECT} FROM tenant WHERE 1=1"
        ));
        push_tenant_filter(&mut builder, filter);
        builder
            .push(" ORDER BY tenant_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<TenantRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_tenant(&self, tenant_id: i64) -> Result<Option<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT} FROM tenant WHERE tenant_id = ?"
        ))
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_tenant_path_depth(
        &self,
        tenant_id: i64,
    ) -> Result<Option<(String, i32)>, AstralError> {
        sqlx::query_as::<_, (String, i32)>("SELECT path, depth FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_tenant(&self, _new: &NewTenant) -> Result<i64, AstralError> {
        Err(tenant_context_required())
    }

    async fn create_tenant_with_context(
        &self,
        new: &NewTenant,
        context: &TenantMutationContext,
    ) -> Result<i64, AstralError> {
        let mut tx = self.begin_source_transaction(context).await?;
        let actor_tenant_exists: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(context.actor_tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if actor_tenant_exists.is_none() {
            return Err(tenant_context_required());
        }
        verify_tenant_mutation_actor_in_tx(&mut tx, context).await?;
        if let Some(parent_id) = new.parent_tenant_id {
            if parent_id != context.actor_tenant_id {
                return Err(AstralError::Permission(
                    "tenant parent does not match the locked actor scope".into(),
                ));
            }
            let parent: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
                .bind(parent_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_error)?;
            if parent.is_none() {
                return Err(AstralError::NotFound(format!("parent tenant {parent_id}")));
            }
        }
        let tenant_code = derive_tenant_code(&new.name, new.parent_tenant_id)?;
        let mut capture = tx.typed_row_capture(
            astral_db::TypedSourceTable::Tenant,
            astral_db::TypedRowOperation::Insert,
        );
        let tenant_id = capture
            .insert_tenant_and_capture_in_tx(
                tenant_code,
                new.name.clone(),
                new.parent_tenant_id,
                new.path.clone(),
                new.depth,
            )
            .await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_create",
            "tenant",
            tenant_id,
            serde_json::json!({ "name": new.name, "parentTenantId": new.parent_tenant_id, "path": new.path, "depth": new.depth }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(tenant_id)
    }

    async fn update_tenant_name(&self, _tenant_id: i64, _name: &str) -> Result<(), AstralError> {
        Err(tenant_context_required())
    }

    async fn update_tenant_name_with_context(
        &self,
        tenant_id: i64,
        name: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        let lookup = astral_db::TypedSourceRowLookup::PrimaryId { id: tenant_id };
        let mut capture = tx.typed_row_capture(
            astral_db::TypedSourceTable::Tenant,
            astral_db::TypedRowOperation::Update,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let owned_name = name.to_owned();
        let update_name = owned_name.clone();
        let result = capture
            .with_tx_mut(move |inner| {
                Box::pin(async move {
                    sqlx::query("UPDATE tenant SET tenant_name = ? WHERE tenant_id = ?")
                        .bind(update_name)
                        .bind(tenant_id)
                        .execute(&mut **inner)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() > 1 {
            return Err(AstralError::Pending(
                "locked tenant name update affected more than one row".into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        if image.before_image_digest() == image.after_image_digest() {
            tx.rollback_consuming().await?;
            return Ok(());
        }
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "tenant name changed its source image without exactly one affected row".into(),
            ));
        }
        let audit = insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_name_update",
            "tenant",
            tenant_id,
            serde_json::json!({ "name": owned_name }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await
    }

    async fn update_tenant_status(
        &self,
        _tenant_id: i64,
        _status: &str,
    ) -> Result<(), AstralError> {
        Err(tenant_context_required())
    }

    async fn update_tenant_status_with_context(
        &self,
        tenant_id: i64,
        status: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        if !TENANT_STATUS_ALPHABET.contains(&status) {
            return Err(AstralError::Validation("invalid tenant status".into()));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }

        let current: Option<(String,)> = sqlx::query_as(TENANT_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        let Some((current_status,)) = current else {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        };
        let changed = status_changed(&current_status, status);
        if changed {
            let mut capture = EligibilitySourceCapture::begin_in_tx(
                &mut tx,
                eligibility_admission(context)?,
                EligibilitySourceSubject::TenantStatus { tenant_id },
            )
            .await
            .map_err(AstralError::from)?;
            let update = sqlx::query("UPDATE tenant SET status = ? WHERE tenant_id = ?")
                .bind(status)
                .bind(tenant_id)
                .execute(&mut **capture.with_tx_mut())
                .await
                .map_err(db_error)?;
            if update.rows_affected() != 1 {
                return Err(AstralError::Pending(
                    "locked tenant status update did not affect exactly one row".into(),
                ));
            }

            let delivery_context = self.invalidation_delivery_context()?;
            let operation_id = eligibility_admission(context)?.operation_id().to_owned();
            let (projection_receipts, invalidation_receipts) =
                append_tenant_eligibility_for_capture_in_tx(
                    &mut capture,
                    delivery_context,
                    &operation_id,
                )
                .await?;
            insert_tenant_mutation_audit_on_tx(
                capture.with_tx_mut(),
                context,
                tenant_id,
                "tenant_status_update",
                "tenant",
                tenant_id,
                serde_json::json!({ "fromStatus": current_status, "toStatus": status }),
            )
            .await?;
            let receipt = capture.finish_in_tx().await.map_err(AstralError::from)?;
            for projection in projection_receipts {
                tx.record_source_projection_receipt(projection)?;
            }
            for invalidation in invalidation_receipts {
                tx.record_invalidation_receipt(invalidation);
            }
            tx.stage_eligibility_source(receipt)?;
        } else {
            tx.rollback_consuming().await?;
            return Ok(());
        }
        tx.commit_consuming().await?;
        Ok(())
    }

    async fn delete_tenant(&self, _tenant_id: i64) -> Result<bool, AstralError> {
        Err(tenant_context_required())
    }

    async fn delete_tenant_with_context(
        &self,
        tenant_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx = self.begin_source_transaction(context).await?;
        let tenant: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if tenant.is_none() {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        verify_tenant_mutation_actor_in_tx(&mut tx, context).await?;

        // Locking the reference count before capture prevents a concurrent card
        // insertion from racing the hard delete. Any reference fails closed.
        let (card_references,) = sqlx::query_as::<_, (i64,)>(TENANT_CARD_REFERENCES_LOCK_SQL)
            .bind(tenant_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?;
        guard_tenant_delete(card_references, tenant_id)?;

        let mut capture = EligibilitySourceCapture::begin_in_tx(
            &mut tx,
            eligibility_admission(context)?,
            EligibilitySourceSubject::TenantDelete { tenant_id },
        )
        .await
        .map_err(AstralError::from)?;
        let result = sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .execute(&mut **capture.with_tx_mut())
            .await
            .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "tenant {tenant_id} disappeared during locked delete"
            )));
        }
        let delivery_context = self.invalidation_delivery_context()?;
        let operation_id = eligibility_admission(context)?.operation_id().to_owned();
        let (projection_receipts, invalidation_receipts) =
            append_tenant_eligibility_for_capture_in_tx(
                &mut capture,
                delivery_context,
                &operation_id,
            )
            .await?;
        insert_tenant_mutation_audit_on_tx(
            capture.with_tx_mut(),
            context,
            tenant_id,
            "tenant_delete",
            "tenant",
            tenant_id,
            serde_json::json!({ "status": "deleted" }),
        )
        .await?;
        let receipt = capture.finish_in_tx().await.map_err(AstralError::from)?;
        for projection in projection_receipts {
            tx.record_source_projection_receipt(projection)?;
        }
        for invalidation in invalidation_receipts {
            tx.record_invalidation_receipt(invalidation);
        }
        tx.stage_eligibility_source(receipt)?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn transition_tenant_status(
        &self,
        _tenant_id: i64,
        _from: &str,
        _to: &str,
    ) -> Result<bool, AstralError> {
        Err(tenant_context_required())
    }

    async fn transition_tenant_status_with_context(
        &self,
        tenant_id: i64,
        from: &str,
        to: &str,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        if !TENANT_STATUS_ALPHABET.contains(&from) || !TENANT_STATUS_ALPHABET.contains(&to) {
            return Err(AstralError::Validation(
                "invalid tenant status transition".into(),
            ));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        let current: Option<(String,)> = sqlx::query_as(TENANT_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        let Some((current_status,)) = current else {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        };
        if !status_transition_changes(&current_status, from, to) {
            tx.rollback_consuming().await?;
            return Ok(false);
        }

        let mut capture = EligibilitySourceCapture::begin_in_tx(
            &mut tx,
            eligibility_admission(context)?,
            EligibilitySourceSubject::TenantStatus { tenant_id },
        )
        .await
        .map_err(AstralError::from)?;
        let result = sqlx::query("UPDATE tenant SET status = ? WHERE tenant_id = ? AND status = ?")
            .bind(to)
            .bind(tenant_id)
            .bind(from)
            .execute(&mut **capture.with_tx_mut())
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(AstralError::Pending(
                "tenant status transition lost its locked source row".into(),
            ));
        }
        let delivery_context = self.invalidation_delivery_context()?;
        let operation_id = eligibility_admission(context)?.operation_id().to_owned();
        let (projection_receipts, invalidation_receipts) =
            append_tenant_eligibility_for_capture_in_tx(
                &mut capture,
                delivery_context,
                &operation_id,
            )
            .await?;
        insert_tenant_mutation_audit_on_tx(
            capture.with_tx_mut(),
            context,
            tenant_id,
            "tenant_status_transition",
            "tenant",
            tenant_id,
            serde_json::json!({ "fromStatus": current_status, "toStatus": to }),
        )
        .await?;
        let receipt = capture.finish_in_tx().await.map_err(AstralError::from)?;
        for projection in projection_receipts {
            tx.record_source_projection_receipt(projection)?;
        }
        for invalidation in invalidation_receipts {
            tx.record_invalidation_receipt(invalidation);
        }
        tx.stage_eligibility_source(receipt)?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn list_my_tenants(&self, user_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT_T} FROM tenant t \
             JOIN tenant_members tm ON tm.tenant_id = t.tenant_id \
             WHERE tm.user_id = ? AND tm.member_status = 'ACTIVE' AND t.status = 'ACTIVE' \
             ORDER BY t.tenant_id"
        ))
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_sub_tenants(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT} FROM tenant WHERE parent_tenant_id = ? ORDER BY tenant_id"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_tenant_tree(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT} FROM tenant \
             WHERE path LIKE (SELECT CONCAT(path, '/%') FROM tenant WHERE tenant_id = ?) \
             ORDER BY path"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_members(&self, tenant_id: i64) -> Result<Vec<TenantMemberRecord>, AstralError> {
        sqlx::query_as::<_, TenantMemberRecord>(&format!(
            "SELECT {MEMBER_SELECT} FROM tenant_members WHERE tenant_id = ? ORDER BY role_type, joined_at"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_member(
        &self,
        _tenant_id: i64,
        _user_id: i64,
        _role: &str,
    ) -> Result<(), AstralError> {
        Err(tenant_context_required())
    }

    async fn upsert_member_with_context(
        &self,
        tenant_id: i64,
        user_id: i64,
        role: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        validate_member_target_ids(tenant_id, user_id)?;
        validate_member_role(role)?;
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        sqlx::query(
            "INSERT INTO tenant_members (tenant_id, user_id, role_type, member_status) \
             VALUES (?, ?, ?, 'ACTIVE') \
             ON DUPLICATE KEY UPDATE role_type = VALUES(role_type), member_status = 'ACTIVE'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(role)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_member_add",
            "tenant_members",
            user_id,
            serde_json::json!({ "memberUserId": user_id, "role": role }),
        )
        .await?;
        tx.commit_consuming().await
    }

    async fn get_member(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> Result<TenantMemberRecord, AstralError> {
        sqlx::query_as::<_, TenantMemberRecord>(&format!(
            "SELECT {MEMBER_SELECT} FROM tenant_members WHERE tenant_id = ? AND user_id = ?"
        ))
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn remove_member(&self, _tenant_id: i64, _user_id: i64) -> Result<bool, AstralError> {
        Err(tenant_context_required())
    }

    async fn remove_member_with_context(
        &self,
        tenant_id: i64,
        user_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        validate_member_target_ids(tenant_id, user_id)?;
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            tx.commit_consuming().await?;
            return Ok(false);
        }
        // 目标行锁：序列化同一成员的并发治理 mutation；移除不筛状态，与
        // 遗留 UPDATE 谓词一致（已 REMOVED 行不再变更，rows_affected == 0）。
        let target: Option<(i64, String)> = sqlx::query_as(TENANT_MEMBER_LOCK_SQL)
            .bind(tenant_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        let Some((_, member_status)) = target else {
            tx.commit_consuming().await?;
            return Ok(false);
        };
        let result = sqlx::query(
            "UPDATE tenant_members SET member_status = 'REMOVED' WHERE tenant_id = ? AND user_id = ?",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        let removed = result.rows_affected() > 0;
        if removed {
            insert_tenant_mutation_audit_in_tx(
                &mut tx,
                context,
                tenant_id,
                "tenant_member_remove",
                "tenant_members",
                user_id,
                serde_json::json!({ "memberUserId": user_id, "fromStatus": member_status }),
            )
            .await?;
        }
        tx.commit_consuming().await?;
        Ok(removed)
    }

    async fn update_member_field(
        &self,
        _tenant_id: i64,
        _user_id: i64,
        _column: &str,
        _value: String,
    ) -> Result<bool, AstralError> {
        Err(tenant_context_required())
    }

    async fn update_member_field_with_context(
        &self,
        tenant_id: i64,
        user_id: i64,
        column: &str,
        value: String,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        validate_member_target_ids(tenant_id, user_id)?;
        // 动态列只允许编译期白名单内的三个列；值始终绑定参数。
        validate_member_field_column(column)?;
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            tx.commit_consuming().await?;
            return Ok(false);
        }
        let target: Option<(i64, String)> = sqlx::query_as(TENANT_MEMBER_LOCK_SQL)
            .bind(tenant_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if target.is_none() {
            tx.commit_consuming().await?;
            return Ok(false);
        }
        let detail = serde_json::json!({
            "memberUserId": user_id,
            "column": column,
            "value": value,
        });
        let sql = format!(
            "UPDATE tenant_members SET {column} = ? WHERE tenant_id = ? AND user_id = ? AND member_status = 'ACTIVE'"
        );
        let result = sqlx::query(&sql)
            .bind(value)
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        let updated = result.rows_affected() > 0;
        if updated {
            insert_tenant_mutation_audit_in_tx(
                &mut tx,
                context,
                tenant_id,
                "tenant_member_field_update",
                "tenant_members",
                user_id,
                detail,
            )
            .await?;
        }
        tx.commit_consuming().await?;
        Ok(updated)
    }

    async fn list_invitations(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantInvitationRecord>, AstralError> {
        sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE tenant_id = ? ORDER BY created_at DESC"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_invitation(
        &self,
        _tenant_id: i64,
        _token: &str,
        _role: &str,
        _inviter_id: i64,
        _expires_secs: i64,
    ) -> Result<TenantInvitationRecord, AstralError> {
        Err(tenant_context_required())
    }

    async fn create_invitation_with_context(
        &self,
        tenant_id: i64,
        token: &str,
        role: &str,
        expires_secs: i64,
        context: &TenantMutationContext,
    ) -> Result<TenantInvitationRecord, AstralError> {
        if tenant_id <= 0 {
            return Err(AstralError::Validation(format!(
                "tenant invitation creation requires a positive tenant id, got {tenant_id}"
            )));
        }
        validate_invitation_token(token)?;
        validate_member_role(role)?;
        if expires_secs <= 0 {
            return Err(AstralError::Validation(format!(
                "tenant invitation expiry must be a positive unix timestamp, got {expires_secs}"
            )));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        // inviter 由锁定的 actor 卡片派生（context.actor_id），不接受调用方声明。
        let result = sqlx::query(
            "INSERT INTO tenant_invitation (tenant_id, invite_code, role, invited_by, status, expires_at) \
             VALUES (?, ?, ?, ?, 'ACTIVE', FROM_UNIXTIME(?))",
        )
        .bind(tenant_id)
        .bind(token)
        .bind(role)
        .bind(context.actor_id)
        .bind(expires_secs)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        let invitation_id = i64::try_from(result.last_insert_id())
            .map_err(|_| AstralError::Database("created invitation id exceeds i64".into()))?;
        let record = sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE invitation_id = ?"
        ))
        .bind(invitation_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?;
        insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_invitation_create",
            "tenant_invitation",
            invitation_id,
            serde_json::json!({
                "invitationId": invitation_id,
                "role": role,
                "inviterId": context.actor_id,
                "expiresAt": expires_secs
            }),
        )
        .await?;
        tx.commit_consuming().await?;
        Ok(record)
    }

    async fn get_invitation_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError> {
        sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE invite_code = ?"
        ))
        .bind(code)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_invitation_by_code_active(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError> {
        sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE invite_code = ? AND status = 'ACTIVE'"
        ))
        .bind(code)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn cancel_invitation(
        &self,
        _tenant_id: i64,
        _invitation_id: i64,
    ) -> Result<bool, AstralError> {
        Err(tenant_context_required())
    }

    async fn cancel_invitation_with_context(
        &self,
        tenant_id: i64,
        invitation_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        if tenant_id <= 0 || invitation_id <= 0 {
            return Err(AstralError::Validation(format!(
                "tenant invitation cancel requires positive tenant and invitation ids, \
                 got tenant_id={tenant_id}, invitation_id={invitation_id}"
            )));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            tx.commit_consuming().await?;
            return Ok(false);
        }
        // 目标行锁：与并发 accept/cancel 串行化；租户归属不匹配即 fail-closed。
        let invitation: Option<(i64, String, String, Option<i64>)> =
            sqlx::query_as(TENANT_INVITATION_LOCK_SQL)
                .bind(invitation_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_error)?;
        let Some((invitation_tenant, _, _, _)) = invitation else {
            tx.commit_consuming().await?;
            return Ok(false);
        };
        if invitation_tenant != tenant_id {
            return Err(AstralError::Permission(
                "invitation does not belong to the locked tenant scope".into(),
            ));
        }
        let result = sqlx::query(
            "UPDATE tenant_invitation SET status = 'REVOKED' \
             WHERE invitation_id = ? AND tenant_id = ? AND status = 'ACTIVE'",
        )
        .bind(invitation_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        let canceled = result.rows_affected() > 0;
        if canceled {
            insert_tenant_mutation_audit_in_tx(
                &mut tx,
                context,
                tenant_id,
                "tenant_invitation_cancel",
                "tenant_invitation",
                invitation_id,
                serde_json::json!({ "invitationId": invitation_id, "status": "REVOKED" }),
            )
            .await?;
        }
        tx.commit_consuming().await?;
        Ok(canceled)
    }

    async fn mark_invitation_expired(&self, _invitation_id: i64) -> Result<(), AstralError> {
        Err(tenant_context_required())
    }

    async fn accept_invitation(
        &self,
        _invitation_id: i64,
        _tenant_id: i64,
        _user_id: i64,
        _role: &str,
    ) -> Result<(), AstralError> {
        Err(tenant_context_required())
    }

    async fn accept_invitation_with_context(
        &self,
        invitation_id: i64,
        tenant_id: i64,
        role: &str,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        if tenant_id <= 0 || invitation_id <= 0 {
            return Err(AstralError::Validation(format!(
                "tenant invitation accept requires positive tenant and invitation ids, \
                 got tenant_id={tenant_id}, invitation_id={invitation_id}"
            )));
        }
        if role.trim().is_empty() || role.trim() != role {
            return Err(AstralError::Validation(
                "invitation accept requires a canonical, non-empty role".into(),
            ));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        // 锁序：目标租户行 -> 邀请行 -> actor 卡片行（与既有 tenant -> 治理行
        // -> user_card 偏序一致）。入会租户不是 actor 的当前租户，因此不走
        // `lock_existing_tenant_scope_in_tx` 的 actor 租户匹配，但仍锁目标租户
        // 行证明其存在，并独立执行 actor 卡片/admission scope 绑定复核。
        let tenant_exists: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if tenant_exists.is_none() {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        let invitation: Option<(i64, String, String, Option<i64>)> =
            sqlx::query_as(TENANT_INVITATION_LOCK_SQL)
                .bind(invitation_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_error)?;
        let Some((invitation_tenant, invitation_role, invitation_status, expires_at)) = invitation
        else {
            return Err(AstralError::Validation(
                "invitation is no longer active".into(),
            ));
        };
        if invitation_tenant != tenant_id {
            return Err(AstralError::Permission(
                "invitation does not belong to the locked tenant scope".into(),
            ));
        }
        if invitation_role != role {
            return Err(AstralError::Validation(
                "invitation role changed between lookup and accept; failing closed".into(),
            ));
        }
        // admission scope 绑定：锁定的 actor 卡片必须与 proof scope 一致，
        // 缺失/失配在任何写入前 fail-closed（consume_once 由 commit 前对牌执行）。
        verify_tenant_mutation_actor_in_tx(&mut tx, context).await?;
        if invitation_status != "ACTIVE" {
            return Err(AstralError::Validation(
                "invitation is no longer active".into(),
            ));
        }
        // 过期分支：锁定行证明过期事实，同一事务内置 EXPIRED 并提交（该
        // 治理写由同一 admission 承担），随后 fail-closed 返回过期错误。
        if expires_at.is_some_and(|expires| unix_now_secs() > expires) {
            sqlx::query(
                "UPDATE tenant_invitation SET status = 'EXPIRED' \
                 WHERE invitation_id = ? AND status = 'ACTIVE'",
            )
            .bind(invitation_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
            insert_tenant_mutation_audit_in_tx(
                &mut tx,
                context,
                tenant_id,
                "tenant_invitation_expire",
                "tenant_invitation",
                invitation_id,
                serde_json::json!({ "invitationId": invitation_id, "status": "EXPIRED" }),
            )
            .await?;
            tx.commit_consuming().await?;
            return Err(AstralError::Validation("invitation expired".into()));
        }
        // ACTIVE 守卫：并发使用同一邀请码时仅一次成功（行锁已串行化）。
        let result = sqlx::query(
            "UPDATE tenant_invitation SET status = 'ACCEPTED', current_uses = current_uses + 1 \
             WHERE invitation_id = ? AND status = 'ACTIVE'",
        )
        .bind(invitation_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(AstralError::Validation(
                "invitation is no longer active".into(),
            ));
        }
        // 入会成员即锁定 actor；角色取锁定邀请行，不接受调用方声明。
        sqlx::query(
            "INSERT INTO tenant_members (tenant_id, user_id, role_type, member_status) \
             VALUES (?, ?, ?, 'ACTIVE') \
             ON DUPLICATE KEY UPDATE role_type = VALUES(role_type), member_status = 'ACTIVE'",
        )
        .bind(tenant_id)
        .bind(context.actor_id)
        .bind(&invitation_role)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_invitation_accept",
            "tenant_invitation",
            invitation_id,
            serde_json::json!({ "memberUserId": context.actor_id, "role": invitation_role }),
        )
        .await?;
        tx.commit_consuming().await
    }

    async fn list_purchases(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantPurchaseRecord>, AstralError> {
        sqlx::query_as::<_, TenantPurchaseRecord>(&format!(
            "SELECT {PURCHASE_SELECT} FROM tenant_purchase WHERE tenant_id = ? ORDER BY purchased_at DESC"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_purchase(&self, _new: &NewPurchase) -> Result<i64, AstralError> {
        Err(tenant_context_required())
    }

    async fn create_purchase_with_context(
        &self,
        new: &NewPurchase,
        billing_cycle: &str,
        context: &astral_db::ProtectedMutationContext,
    ) -> Result<i64, AstralError> {
        purchase::create_purchase_with_context(&self.db, new, billing_cycle, context).await
    }

    async fn get_purchase(&self, purchase_id: i64) -> Result<TenantPurchaseRecord, AstralError> {
        sqlx::query_as::<_, TenantPurchaseRecord>(&format!(
            "SELECT {PURCHASE_SELECT} FROM tenant_purchase WHERE purchase_id = ?"
        ))
        .bind(purchase_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_tenant_domains(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantDomainMapRecord>, AstralError> {
        sqlx::query_as::<_, TenantDomainMapRecord>(&format!(
            "SELECT {DOMAIN_MAP_SELECT} FROM tenant_domain_map WHERE tenant_id = ? ORDER BY id"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_tenant_domain(
        &self,
        _tenant_id: i64,
        _domain_id: i64,
    ) -> Result<(), AstralError> {
        Err(tenant_context_required())
    }

    async fn upsert_tenant_domain_with_context(
        &self,
        tenant_id: i64,
        domain_id: i64,
        context: &TenantMutationContext,
    ) -> Result<(), AstralError> {
        if tenant_id <= 0 || domain_id <= 0 {
            return Err(AstralError::Validation(
                "tenant-domain mutation requires positive tenant and domain ids".into(),
            ));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
        }
        let domain_exists: Option<(i64,)> = sqlx::query_as(DOMAIN_ID_LOCK_SQL)
            .bind(domain_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if domain_exists.is_none() {
            return Err(AstralError::NotFound(format!("domain {domain_id}")));
        }

        let current: Option<(String,)> = sqlx::query_as(TENANT_DOMAIN_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .bind(domain_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;

        let changed = match current {
            Some((status,)) if status == "ACTIVE" => false,
            Some(_) => {
                sqlx::query(
                    "UPDATE tenant_domain_map SET status = 'ACTIVE' \
                     WHERE tenant_id = ? AND domain_id = ?",
                )
                .bind(tenant_id)
                .bind(domain_id)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?;
                true
            }
            None => {
                // The unique key serializes a concurrent insert after the absent-row lock.
                let result = sqlx::query(
                    "INSERT INTO tenant_domain_map (tenant_id, domain_id, granted_by, status) \
                     VALUES (?, ?, ?, 'ACTIVE') \
                     ON DUPLICATE KEY UPDATE status = 'ACTIVE'",
                )
                .bind(tenant_id)
                .bind(domain_id)
                .bind(context.actor_id)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?;
                result.rows_affected() > 0
            }
        };

        if changed {
            let operation_base = derive_tenant_domain_operation_base(
                tenant_id,
                domain_id,
                TenantDomainEligibilityAction::Grant,
            )?;
            append_tenant_eligibility_invalidation_in_tx(
                &mut tx,
                TenantEligibilityScope::ByTenantAndDomain {
                    tenant_id,
                    domain_id,
                },
                &operation_base,
            )
            .await?;
        }
        insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_domain_grant",
            "tenant_domain_map",
            domain_id,
            serde_json::json!({ "tenantId": tenant_id, "domainId": domain_id, "changed": changed }),
        )
        .await?;
        tx.commit_consuming().await?;
        Ok(())
    }

    async fn get_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<TenantDomainMapRecord, AstralError> {
        sqlx::query_as::<_, TenantDomainMapRecord>(&format!(
            "SELECT {DOMAIN_MAP_SELECT} FROM tenant_domain_map WHERE tenant_id = ? AND domain_id = ?"
        ))
        .bind(tenant_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn remove_tenant_domain(
        &self,
        _tenant_id: i64,
        _domain_id: i64,
    ) -> Result<bool, AstralError> {
        Err(tenant_context_required())
    }

    async fn remove_tenant_domain_with_context(
        &self,
        tenant_id: i64,
        domain_id: i64,
        context: &TenantMutationContext,
    ) -> Result<bool, AstralError> {
        if tenant_id <= 0 || domain_id <= 0 {
            return Err(AstralError::Validation(
                "tenant-domain mutation requires positive tenant and domain ids".into(),
            ));
        }
        let mut tx = self.begin_source_transaction(context).await?;
        if !lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id).await? {
            tx.commit_consuming().await?;
            return Ok(false);
        }
        let domain_exists: Option<(i64,)> = sqlx::query_as(DOMAIN_ID_LOCK_SQL)
            .bind(domain_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if domain_exists.is_none() {
            tx.commit_consuming().await?;
            return Ok(false);
        }

        let current: Option<(String,)> = sqlx::query_as(TENANT_DOMAIN_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .bind(domain_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if current.is_none() {
            tx.commit_consuming().await?;
            return Ok(false);
        }

        let result =
            sqlx::query("DELETE FROM tenant_domain_map WHERE tenant_id = ? AND domain_id = ?")
                .bind(tenant_id)
                .bind(domain_id)
                .execute(&mut **tx)
                .await
                .map_err(db_error)?;
        if result.rows_affected() == 0 {
            tx.commit_consuming().await?;
            return Ok(false);
        }

        let operation_base = derive_tenant_domain_operation_base(
            tenant_id,
            domain_id,
            TenantDomainEligibilityAction::Revoke,
        )?;
        append_tenant_eligibility_invalidation_in_tx(
            &mut tx,
            TenantEligibilityScope::ByTenantAndDomain {
                tenant_id,
                domain_id,
            },
            &operation_base,
        )
        .await?;
        insert_tenant_mutation_audit_in_tx(
            &mut tx,
            context,
            tenant_id,
            "tenant_domain_revoke",
            "tenant_domain_map",
            domain_id,
            serde_json::json!({ "tenantId": tenant_id, "domainId": domain_id, "status": "deleted" }),
        )
        .await?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn list_audit_log(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantAuditLogRecord>, AstralError> {
        sqlx::query_as::<_, TenantAuditLogRecord>(&format!(
            "SELECT {AUDIT_LOG_SELECT} FROM tenant_audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Tenant repository query failed: {error}"))
}

fn status_changed(current: &str, requested: &str) -> bool {
    current != requested
}

fn status_transition_changes(current: &str, from: &str, to: &str) -> bool {
    current == from && from != to
}

/// 当前 unix 秒（与 service 层同语义；时钟异常回退 0 仅使过期判定永不触发，
/// 真实过期事实仍由锁定行的 expires_at 与本次比较共同证明）。
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 硬删除前置守卫决策（纯函数，便于单元测试）：引用行数为 0 才放行；
/// 否则返回明确的 Validation 冲突错误（消息含租户与引用行数）。
/// COUNT(*) 恒为非负，正数一律视为仍有卡片引用，禁止删除。
fn guard_tenant_delete(referencing_cards: i64, tenant_id: i64) -> Result<(), AstralError> {
    if referencing_cards > 0 {
        return Err(AstralError::Validation(format!(
            "tenant {tenant_id} hard delete blocked: {referencing_cards} user_card row(s) \
             still reference it; revoke or reassign all cards before delete"
        )));
    }
    Ok(())
}

/// 成员/邀请 mutation 的目标 id 复核（纯函数，便于单元测试）：租户与目标
/// 成员用户 id 必须为正，负/零 id 一律 Validation fail-closed。
fn validate_member_target_ids(tenant_id: i64, user_id: i64) -> Result<(), AstralError> {
    if tenant_id <= 0 || user_id <= 0 {
        return Err(AstralError::Validation(format!(
            "tenant member mutation requires positive tenant and user ids, \
             got tenant_id={tenant_id}, user_id={user_id}"
        )));
    }
    Ok(())
}

/// 成员角色输入规范化复核（纯函数，便于单元测试）：必须精确命中字母表
/// （调用方先做大写规范化）。这是输入白名单，不是授权证明。
fn validate_member_role(role: &str) -> Result<(), AstralError> {
    if !MEMBER_ROLE_ALPHABET.contains(&role) {
        return Err(AstralError::Validation(format!(
            "tenant member role must be exactly one of {MEMBER_ROLE_ALPHABET:?}"
        )));
    }
    Ok(())
}

/// `update_member_field` 动态列白名单复核（纯函数，便于单元测试）。
fn validate_member_field_column(column: &str) -> Result<(), AstralError> {
    if !MEMBER_FIELD_COLUMNS.contains(&column) {
        return Err(AstralError::Validation(format!(
            "tenant member field update only allows columns {MEMBER_FIELD_COLUMNS:?}, got {column:?}"
        )));
    }
    Ok(())
}

/// 邀请码输入复核（纯函数，便于单元测试）：非空、无环绕空白且不超过
/// invite_code 列的 64 字符上界；内容不限定（由服务层密码学随机生成），
/// SQL 始终绑定参数。
fn validate_invitation_token(token: &str) -> Result<(), AstralError> {
    if token.is_empty() || token.trim() != token || token.len() > INVITATION_TOKEN_MAX_LEN {
        return Err(AstralError::Validation(format!(
            "tenant invitation token must be non-empty, trimmed, and at most \
             {INVITATION_TOKEN_MAX_LEN} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Execute;

    #[test]
    fn tenant_context_requires_verified_platform_identity_and_bounded_request_id() {
        let policy_context = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(20))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        let context = TenantMutationContext::from_policy_context(&policy_context, Some("req-7"))
            .expect("verified context and canonical request id must be accepted");
        assert_eq!(context.actor_id, 10);
        assert_eq!(context.actor_card_id, 20);
        assert_eq!(context.actor_tenant_id, 30);
        assert_eq!(context.actor_domain_id, 40);
        assert_eq!(context.request_id(), "req-7");
        assert!(matches!(
            context.source_capability(),
            SourceMutationCapability::UserPending
        ));

        assert!(TenantMutationContext::from_policy_context(&policy_context, None).is_err());
        let overlong_request_id = "x".repeat(65);
        for unsafe_request_id in ["has space", "line\nbreak", overlong_request_id.as_str()] {
            assert!(matches!(
                TenantMutationContext::from_policy_context(
                    &policy_context,
                    Some(unsafe_request_id)
                ),
                Err(AstralError::Validation(_))
            ));
        }

        let non_platform_context = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("END_USER".into()))
            .card_id(Some(20))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(matches!(
            TenantMutationContext::from_policy_context(&non_platform_context, Some("req-7")),
            Err(AstralError::Auth(_))
        ));
        for invalid_ids in [
            (Some(0), Some(20), Some(30), Some(40)),
            (Some(10), Some(-1), Some(30), Some(40)),
            (Some(10), Some(20), None, Some(40)),
            (Some(10), Some(20), Some(30), Some(0)),
        ] {
            let invalid_context = PolicyContext::builder()
                .user_id(invalid_ids.0)
                .principal_kind(Some("PLATFORM_USER".into()))
                .card_id(invalid_ids.1)
                .tenant_id(invalid_ids.2)
                .domain_id(invalid_ids.3)
                .action("manage".into())
                .build();
            assert!(matches!(
                TenantMutationContext::from_policy_context(&invalid_context, Some("req-7")),
                Err(AstralError::Auth(_))
            ));
        }
    }

    #[test]
    fn emitted_tenant_mutation_sql_has_no_backslashes() {
        for statement in [
            TENANT_ID_LOCK_SQL,
            TENANT_STATUS_LOCK_SQL,
            TENANT_DOMAIN_STATUS_LOCK_SQL,
            TENANT_MUTATION_ACTOR_LOCK_SQL,
            TENANT_MUTATION_AUDIT_INSERT_SQL,
            DOMAIN_ID_LOCK_SQL,
            TENANT_CARD_REFERENCES_LOCK_SQL,
            TENANT_CARDS_ELIGIBILITY_LOCK_SQL,
            TENANT_DOMAIN_CARDS_ELIGIBILITY_LOCK_SQL,
            TENANT_MEMBER_LOCK_SQL,
            TENANT_INVITATION_LOCK_SQL,
        ] {
            assert!(
                !statement.as_bytes().contains(&0x5c),
                "emitted TrustGraph SQL must not contain a backslash: {statement}"
            );
        }
        let emitted_actor_lock_sql =
            sqlx::query::<sqlx::MySql>(TENANT_MUTATION_ACTOR_LOCK_SQL).sql();
        let emitted_audit_sql = sqlx::query::<sqlx::MySql>(TENANT_MUTATION_AUDIT_INSERT_SQL).sql();
        let emitted_multiline_mutation_sql = sqlx::query::<sqlx::MySql>(
            "INSERT INTO tenant_domain_map (tenant_id, domain_id, granted_by, status) \
             VALUES (?, ?, ?, 'ACTIVE')",
        )
        .sql();
        for emitted_sql in [
            emitted_actor_lock_sql,
            emitted_audit_sql,
            emitted_multiline_mutation_sql,
        ] {
            assert!(
                !emitted_sql.as_bytes().contains(&0x5c),
                "sqlx-emitted mutation SQL must not contain a backslash: {emitted_sql}"
            );
        }
    }

    #[test]
    fn tenant_mutations_lock_source_rows_before_card_fanout() {
        assert!(TENANT_STATUS_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(TENANT_ID_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(TENANT_DOMAIN_STATUS_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(DOMAIN_ID_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(TENANT_STATUS_LOCK_SQL.contains("tenant_id = ?"));
        assert!(TENANT_DOMAIN_STATUS_LOCK_SQL.contains("tenant_id = ? AND domain_id = ?"));
    }

    #[test]
    fn domain_mutations_use_tenant_domain_mapping_then_cards_order() {
        let tenant_lock = TENANT_ID_LOCK_SQL;
        let domain_lock = DOMAIN_ID_LOCK_SQL;
        let mapping_lock = TENANT_DOMAIN_STATUS_LOCK_SQL;
        assert!(tenant_lock.contains("FROM tenant"));
        assert!(domain_lock.contains("FROM platform_domain"));
        assert!(mapping_lock.contains("FROM tenant_domain_map"));
        assert!(tenant_lock.ends_with("FOR UPDATE"));
        assert!(domain_lock.ends_with("FOR UPDATE"));
        assert!(mapping_lock.ends_with("FOR UPDATE"));
        let source = include_str!("tenant_repository.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source must precede the test module");
        for method in [
            "async fn upsert_tenant_domain_with_context(",
            "async fn remove_tenant_domain_with_context(",
        ] {
            let start = source.rfind(method).unwrap();
            let body = source[start..].split("\n    async fn ").next().unwrap();
            let tenant = body.find("lock_existing_tenant_scope_in_tx(").unwrap();
            let domain = body.find("sqlx::query_as(DOMAIN_ID_LOCK_SQL)").unwrap();
            let mapping = body
                .find("sqlx::query_as(TENANT_DOMAIN_STATUS_LOCK_SQL)")
                .unwrap();
            let cards = body
                .find("append_tenant_eligibility_invalidation_in_tx(")
                .unwrap();
            assert!(tenant < domain && domain < mapping && mapping < cards);
        }
    }

    #[test]
    fn unchanged_status_does_not_request_eligibility_fanout() {
        assert!(!status_changed("ACTIVE", "ACTIVE"));
        assert!(status_changed("ACTIVE", "SUSPENDED"));
        assert!(!status_transition_changes("ACTIVE", "ACTIVE", "ACTIVE"));
        assert!(status_transition_changes("ACTIVE", "ACTIVE", "SUSPENDED"));
        assert!(!status_transition_changes(
            "SUSPENDED",
            "ACTIVE",
            "SUSPENDED"
        ));
    }

    #[test]
    fn unchanged_tenant_status_rolls_back_without_staging_source_evidence() {
        let source = include_str!("tenant_repository.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production source must precede the test module");
        let implementation = source
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("SqlxTenantRepository implementation must exist");
        let update = implementation
            .split("async fn update_tenant_status_with_context(")
            .nth(1)
            .unwrap()
            .split("async fn delete_tenant(")
            .next()
            .unwrap();
        let unchanged = update.rsplit("} else {").next().unwrap();
        let rollback = unchanged.find("tx.rollback_consuming().await?").unwrap();
        let returned = unchanged.find("return Ok(())").unwrap();
        let commit = unchanged.find("tx.commit_consuming().await?").unwrap();
        assert!(rollback < returned && returned < commit);
        assert!(!unchanged[..returned].contains("sqlx::query"));
        assert!(!unchanged[..returned].contains("stage_eligibility_source"));

        let transition = implementation
            .split("async fn transition_tenant_status_with_context(")
            .nth(1)
            .unwrap()
            .split("async fn list_my_tenants(")
            .next()
            .unwrap();
        let unchanged = transition
            .split("if !status_transition_changes(&current_status, from, to) {")
            .nth(1)
            .unwrap()
            .split("let mut capture")
            .next()
            .unwrap();
        assert!(unchanged.contains("tx.rollback_consuming().await?"));
        assert!(unchanged.contains("return Ok(false)"));
        assert!(!unchanged.contains("commit_consuming"));
    }

    #[test]
    fn delete_guard_allows_only_when_no_card_references() {
        assert!(guard_tenant_delete(0, 42).is_ok());

        for referencing in [1, 3, 100] {
            let err = guard_tenant_delete(referencing, 42)
                .expect_err("guard must block while user_card rows reference the tenant");
            match err {
                AstralError::Validation(message) => {
                    assert!(
                        message.contains("42"),
                        "message must name the tenant: {message}"
                    );
                    assert!(
                        message.contains(&referencing.to_string()),
                        "message must state the reference count: {message}"
                    );
                    assert!(
                        message.contains("user_card"),
                        "message must name the referencing table: {message}"
                    );
                }
                other => panic!("expected Validation error, got {other:?}"),
            }
        }
    }

    #[test]
    fn delete_card_guard_sql_is_locked_and_parameterized() {
        assert!(TENANT_CARD_REFERENCES_LOCK_SQL.contains("FROM user_card"));
        assert!(TENANT_CARD_REFERENCES_LOCK_SQL.contains("tenant_id = ?"));
        assert!(TENANT_CARD_REFERENCES_LOCK_SQL.ends_with("FOR UPDATE"));
        let tenant_lock = TENANT_ID_LOCK_SQL;
        assert!(
            tenant_lock.find("tenant").unwrap()
                < TENANT_CARD_REFERENCES_LOCK_SQL.find("user_card").unwrap(),
            "guard must read cards after the tenant source row lock (tenant -> cards order)"
        );
    }

    #[test]
    fn tenant_eligibility_card_locks_are_bounded_locked_and_ordered() {
        for sql in [
            TENANT_CARDS_ELIGIBILITY_LOCK_SQL,
            TENANT_DOMAIN_CARDS_ELIGIBILITY_LOCK_SQL,
        ] {
            assert!(sql.contains("FROM user_card"));
            assert!(sql.contains("card_status = 'ACTIVE'"));
            assert!(sql.contains("ORDER BY card_id"));
            assert!(sql.contains("LIMIT ?"), "lock read must be row-bounded");
            assert!(sql.ends_with("FOR UPDATE"));
        }
        assert!(TENANT_CARDS_ELIGIBILITY_LOCK_SQL.contains("tenant_id = ?"));
        assert!(
            TENANT_DOMAIN_CARDS_ELIGIBILITY_LOCK_SQL.contains("tenant_id = ? AND domain_id = ?")
        );
        // 锁序哨兵：按语句锁定的表给秩，tenant(0) -> platform_domain(1) ->
        // tenant_domain_map(2) -> user_card(3)。跨语句的真实加锁顺序由调用方的
        // await 序列保证；此处静态断言各常量的表归属构成同一偏序。
        assert!(
            tenant_mutation_lock_rank(TENANT_ID_LOCK_SQL)
                < tenant_mutation_lock_rank(DOMAIN_ID_LOCK_SQL),
            "tenant source row lock must rank below the domain source row lock"
        );
        assert!(
            tenant_mutation_lock_rank(DOMAIN_ID_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_DOMAIN_STATUS_LOCK_SQL),
            "domain source row lock must rank below the mapping row lock"
        );
        assert!(
            tenant_mutation_lock_rank(TENANT_DOMAIN_STATUS_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_DOMAIN_CARDS_ELIGIBILITY_LOCK_SQL),
            "card fanout lock must rank above the mapping row lock"
        );
        assert!(
            tenant_mutation_lock_rank(TENANT_STATUS_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_CARDS_ELIGIBILITY_LOCK_SQL),
            "card fanout lock must rank above the tenant source row lock"
        );
    }

    /// 测试哨兵：把租户 mutation 相关锁定语句映射到锁序秩。
    /// `FROM tenant_domain_map` / `FROM tenant_members` / `FROM tenant_invitation`
    /// 均含前缀 `FROM tenant`，必须先判具体治理表再判 tenant 源行。
    fn tenant_mutation_lock_rank(sql: &str) -> u8 {
        if sql.contains("FROM user_card") {
            4
        } else if sql.contains("FROM tenant_members") || sql.contains("FROM tenant_invitation") {
            3
        } else if sql.contains("FROM tenant_domain_map") {
            2
        } else if sql.contains("FROM platform_domain") {
            1
        } else if sql.contains("FROM tenant") {
            0
        } else {
            panic!("statement locks no tenant-mutation table: {sql}");
        }
    }

    #[test]
    fn tenant_eligibility_cap_is_finite_with_detectable_overflow() {
        const { assert!(TENANT_ELIGIBILITY_CARD_CAP > 0) };
        assert_eq!(
            tenant_eligibility_lock_bound(),
            TENANT_ELIGIBILITY_CARD_CAP as i64 + 1,
            "lock bound must be cap + 1 so exceeding the cap is detectable in one locked read"
        );
    }

    #[test]
    fn tenant_code_is_stable_bounded_and_excludes_caller_identity() {
        let code = derive_tenant_code(" Acme ", Some(7)).expect("valid tenant identity");
        assert_eq!(code.len(), 55, "TENANT- plus 48 hex digest characters");
        assert!(code.starts_with("TENANT-"));
        assert_eq!(
            code,
            derive_tenant_code("Acme", Some(7)).expect("normalization must be stable")
        );
        assert_ne!(
            code,
            derive_tenant_code("Acme", Some(8)).expect("parent identity must bind code")
        );
        assert!(derive_tenant_code("", None).is_err());
        assert!(derive_tenant_code("   ", None).is_err());
        assert!(derive_tenant_code("Acme", Some(0)).is_err());
        assert!(derive_tenant_code("Acme", Some(-1)).is_err());
        assert!(derive_tenant_code(&"x".repeat(129), None).is_err());
    }

    #[test]
    fn tenant_code_uses_only_source_identity_inputs() {
        let source = include_str!("tenant_repository.rs");
        let helper = source
            .split("fn derive_tenant_code(")
            .nth(1)
            .and_then(|body| body.split("/// 租户域映射").next())
            .expect("tenant code helper must exist");
        assert!(!helper.contains("request_id"));
        assert!(!helper.contains("status"));
        assert!(!helper.contains("tenant_type"));
        assert!(!helper.contains("caller"));
    }

    #[test]
    fn tenant_domain_operation_base_binds_action_and_scope() {
        let grant = derive_tenant_domain_operation_base(7, 3, TenantDomainEligibilityAction::Grant)
            .expect("positive ids must derive");
        let revoke =
            derive_tenant_domain_operation_base(7, 3, TenantDomainEligibilityAction::Revoke)
                .expect("positive ids must derive");
        assert_eq!(grant, "tenant:domain:grant:7:3");
        assert_eq!(revoke, "tenant:domain:revoke:7:3");
        assert_ne!(
            grant, revoke,
            "grant and revoke must not share operation identity"
        );
        assert!(
            derive_tenant_domain_operation_base(0, 3, TenantDomainEligibilityAction::Grant)
                .is_err()
        );
        assert!(
            derive_tenant_domain_operation_base(7, 0, TenantDomainEligibilityAction::Revoke)
                .is_err()
        );
        assert!(
            derive_tenant_domain_operation_base(7, -3, TenantDomainEligibilityAction::Grant)
                .is_err()
        );
    }

    #[test]
    fn tenant_eligibility_callers_materialize_fanout_before_capture_finish() {
        let source = include_str!("tenant_repository.rs");
        let impl_source = source
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("tenant repository implementation must exist");
        for (method, finish_marker) in [
            (
                "async fn update_tenant_status_with_context(",
                "async fn delete_tenant(",
            ),
            (
                "async fn delete_tenant_with_context(",
                "async fn transition_tenant_status(",
            ),
            (
                "async fn transition_tenant_status_with_context(",
                "async fn list_my_tenants(",
            ),
        ] {
            let body = impl_source
                .split(method)
                .nth(1)
                .and_then(|body| body.split(finish_marker).next())
                .expect("eligibility caller body must be delimited");
            let capture = body
                .find("EligibilitySourceCapture::begin_in_tx")
                .expect("caller must begin the closed eligibility capture");
            let fanout = body
                .find("append_tenant_eligibility_for_capture_in_tx")
                .expect("caller must append exact fanout in the capture transaction");
            let audit = body
                .find("insert_tenant_mutation_audit_on_tx")
                .expect("caller must write audit in the capture transaction");
            let finish = body
                .find("capture.finish_in_tx()")
                .expect("caller must consume the capture after fanout and audit");
            let projection = body
                .find("tx.record_source_projection_receipt(projection)")
                .expect("caller must register returned projection identities on parent");
            let invalidation = body
                .find("tx.record_invalidation_receipt(invalidation)")
                .expect("caller must register returned invalidation identities on parent");
            let stage = body
                .find("tx.stage_eligibility_source(receipt)")
                .expect("caller must stage the opaque eligibility receipt");
            assert!(
                capture < fanout
                    && fanout < audit
                    && audit < finish
                    && finish < projection
                    && projection < invalidation
                    && invalidation < stage,
                "{method} must order capture -> fanout -> audit -> finish -> parent receipts -> stage"
            );
            assert!(
                body.contains("eligibility_admission(context)?.operation_id().to_owned()"),
                "{method} must bind fanout to the admission operation id"
            );
        }
    }

    #[test]
    fn tenant_source_transaction_rejects_request_admission_operation_mismatch() {
        assert!(validate_admission_operation_id("request-1", "request-1").is_ok());
        let error = validate_admission_operation_id("request-1", "admission-1")
            .expect_err("mismatched operation identity must fail closed");
        assert!(matches!(error, AstralError::Pending(_)));
    }
    #[test]
    fn tenant_target_scope_guard_precedes_actor_revalidation() {
        let source = include_str!("tenant_repository.rs");
        let helper = source
            .split("async fn lock_existing_tenant_scope_in_tx(")
            .nth(1)
            .and_then(|body| body.split("/// 新建购买参数").next())
            .expect("tenant target scope helper must exist");
        let target = helper
            .find("tenant_id != context.actor_tenant_id")
            .expect("existing target tenant must be compared with actor scope");
        let actor = helper
            .find("verify_tenant_mutation_actor_in_tx(tx, context)")
            .expect("actor card must be revalidated after target scope check");
        assert!(target < actor);
    }

    #[test]
    fn tenant_parent_scope_guard_binds_subtenant_creation_to_actor_scope() {
        let source = include_str!("tenant_repository.rs");
        let create = source
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .and_then(|body| body.split("async fn create_tenant_with_context(").nth(1))
            .and_then(|body| body.split("async fn update_tenant_name(").next())
            .expect("tenant create implementation must exist");
        let parent_branch = create
            .split("if let Some(parent_id) = new.parent_tenant_id {")
            .nth(1)
            .and_then(|body| body.split("        let result = sqlx::query(").next())
            .expect("parent scope branch must delimit before tenant insert");
        let parent = parent_branch
            .find("parent_id != context.actor_tenant_id")
            .expect("subtenant parent must match actor scope");
        let parent_lock = parent_branch
            .find("sqlx::query_as(TENANT_ID_LOCK_SQL)")
            .expect("parent tenant must be locked after scope check");
        assert!(parent < parent_lock);
    }

    #[test]
    fn delete_tx_uses_capture_guard_audit_and_opaque_receipt() {
        let source = include_str!("tenant_repository.rs");
        let impl_source = source
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("SqlxTenantRepository implementation must exist");
        let delete_body = impl_source
            .split("async fn delete_tenant_with_context(")
            .nth(1)
            .and_then(|body| body.split("async fn transition_tenant_status(").next())
            .expect("audited delete_tenant implementation must be delimited");
        let wrapper_begin = delete_body
            .find("self.begin_source_transaction(context).await?")
            .expect("delete must use the delivery-aware source wrapper");
        let tenant_lock = delete_body
            .find("TENANT_ID_LOCK_SQL")
            .expect("delete must lock the tenant source row first");
        let guard = delete_body
            .find("guard_tenant_delete(card_references, tenant_id)")
            .expect("delete must wire the user_card reference guard");
        let capture = delete_body
            .find("EligibilitySourceCapture::begin_in_tx")
            .expect("delete must begin the opaque eligibility capture");
        let delete = delete_body
            .find("DELETE FROM tenant WHERE tenant_id = ?")
            .expect("delete must remove the tenant row");
        let audit = delete_body
            .find("insert_tenant_mutation_audit_on_tx")
            .expect("delete must write its business audit in the source transaction");
        let finish = delete_body
            .find("capture.finish_in_tx()")
            .expect("delete must finish the eligibility capture after audit");
        let stage = delete_body
            .find("tx.stage_eligibility_source(receipt)")
            .expect("delete must hand the opaque receipt to the parent slot");
        let commit = delete_body
            .rfind("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            wrapper_begin < tenant_lock
                && tenant_lock < guard
                && guard < capture
                && capture < delete
                && delete < audit
                && audit < finish
                && finish < stage
                && stage < commit,
            "delete must order wrapper -> tenant lock -> guard -> capture -> DELETE -> audit -> finish -> stage -> commit"
        );
        assert!(!delete_body.contains("tx.commit()"));
        assert!(!delete_body.contains("append_tenant_eligibility_invalidation_in_tx"));
    }

    #[test]
    fn member_and_invitation_target_locks_are_locked_and_parameterized() {
        for sql in [TENANT_MEMBER_LOCK_SQL, TENANT_INVITATION_LOCK_SQL] {
            assert!(
                sql.contains("= ?"),
                "target lock must be parameterized: {sql}"
            );
            assert!(sql.ends_with("FOR UPDATE"), "target lock must lock: {sql}");
            assert!(
                !sql.as_bytes().contains(&0x5c),
                "target lock must not contain a backslash: {sql}"
            );
        }
        assert!(TENANT_MEMBER_LOCK_SQL.contains("FROM tenant_members"));
        assert!(TENANT_MEMBER_LOCK_SQL.contains("tenant_id = ? AND user_id = ?"));
        assert!(TENANT_INVITATION_LOCK_SQL.contains("FROM tenant_invitation"));
        assert!(TENANT_INVITATION_LOCK_SQL.contains("invitation_id = ?"));
        // 目标治理行锁的表秩：tenant 源行 < 成员/邀请行 < user_card actor 卡片行。
        assert!(
            tenant_mutation_lock_rank(TENANT_ID_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_MEMBER_LOCK_SQL)
        );
        assert!(
            tenant_mutation_lock_rank(TENANT_ID_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_INVITATION_LOCK_SQL)
        );
        assert!(
            tenant_mutation_lock_rank(TENANT_MEMBER_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_MUTATION_ACTOR_LOCK_SQL)
        );
        assert!(
            tenant_mutation_lock_rank(TENANT_INVITATION_LOCK_SQL)
                < tenant_mutation_lock_rank(TENANT_MUTATION_ACTOR_LOCK_SQL)
        );
    }

    #[test]
    fn member_mutation_inputs_are_whitelisted_and_fail_closed() {
        // 目标 id 必须为正。
        assert!(validate_member_target_ids(1, 2).is_ok());
        for (tenant_id, user_id) in [(0, 2), (-1, 2), (1, 0), (1, -7)] {
            assert!(
                validate_member_target_ids(tenant_id, user_id).is_err(),
                "non-positive target ids must be rejected: ({tenant_id}, {user_id})"
            );
        }
        // 成员角色必须精确命中大写字母表（输入白名单，非授权证明）。
        for role in MEMBER_ROLE_ALPHABET {
            assert!(validate_member_role(role).is_ok());
        }
        for role in [
            "owner",
            "admin ",
            " ADMIN",
            "",
            "MEMBER;",
            "ADMIN\x5c",
            "TENANT_OWNER",
        ] {
            assert!(
                validate_member_role(role).is_err(),
                "non-alphabet member role must be rejected: {role:?}"
            );
        }
        // update_member_field 动态列只允许白名单三列。
        for column in MEMBER_FIELD_COLUMNS {
            assert!(validate_member_field_column(column).is_ok());
        }
        for column in [
            "member_status",
            "role_type = 'OWNER'",
            "admin_level, role_type",
            "(SELECT 1)",
            "1; DROP TABLE tenant_members",
            "",
        ] {
            assert!(
                validate_member_field_column(column).is_err(),
                "non-whitelisted member column must be rejected: {column:?}"
            );
        }
        // 邀请码输入必须非空、规范且有界。
        assert!(validate_invitation_token("inv_0123456789abcdef_0123456789abcdef").is_ok());
        assert!(validate_invitation_token("").is_err());
        assert!(validate_invitation_token(" padded").is_err());
        assert!(validate_invitation_token("padded ").is_err());
        assert!(validate_invitation_token(&"x".repeat(INVITATION_TOKEN_MAX_LEN + 1)).is_err());
    }

    /// 遗留无 context 的成员/邀请入口必须整体 fail-closed：既不开源事务，
    /// 也不执行任何 SQL（用户面治理 mutation 无 admission 即拒绝）。
    #[test]
    fn legacy_member_invitation_entries_fail_closed_without_execution() {
        let impl_source = include_str!("tenant_repository.rs")
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("SqlxTenantRepository implementation must exist");
        for (method, next) in [
            (
                "async fn upsert_member(",
                "async fn upsert_member_with_context(",
            ),
            (
                "async fn remove_member(",
                "async fn remove_member_with_context(",
            ),
            (
                "async fn update_member_field(",
                "async fn update_member_field_with_context(",
            ),
            (
                "async fn create_invitation(",
                "async fn create_invitation_with_context(",
            ),
            (
                "async fn cancel_invitation(",
                "async fn cancel_invitation_with_context(",
            ),
            (
                "async fn mark_invitation_expired(",
                "async fn accept_invitation(",
            ),
            (
                "async fn accept_invitation(",
                "async fn accept_invitation_with_context(",
            ),
        ] {
            let body = impl_source
                .split(method)
                .nth(1)
                .and_then(|rest| rest.split(next).next())
                .unwrap_or_else(|| panic!("legacy method body must exist: {method}"));
            assert!(
                body.contains("Err(tenant_context_required())"),
                "legacy entry must fail closed: {method}"
            );
            assert!(
                !body.contains("begin_source_transaction"),
                "legacy entry must not open a source transaction: {method}"
            );
            assert!(
                !body.contains(".execute(") && !body.contains("query_as"),
                "legacy entry must not execute SQL: {method}"
            );
        }
    }

    /// proof-bound 成员/邀请 mutation 必须以 capability 开启授权源事务，
    /// `UserPending`（无 admission）在 begin 即被拒绝，且 commit 只能走
    /// commit_consuming 证明门。
    #[test]
    fn member_invitation_context_mutations_host_admission_wrapper_before_commit() {
        let impl_source = include_str!("tenant_repository.rs")
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("SqlxTenantRepository implementation must exist");
        for (method, next) in [
            (
                "async fn upsert_member_with_context(",
                "async fn get_member(",
            ),
            (
                "async fn remove_member_with_context(",
                "async fn update_member_field(",
            ),
            (
                "async fn update_member_field_with_context(",
                "async fn list_invitations(",
            ),
            (
                "async fn create_invitation_with_context(",
                "async fn get_invitation_by_code(",
            ),
            (
                "async fn cancel_invitation_with_context(",
                "async fn mark_invitation_expired(",
            ),
            (
                "async fn accept_invitation_with_context(",
                "async fn list_purchases(",
            ),
        ] {
            let body = impl_source
                .split(method)
                .nth(1)
                .and_then(|rest| rest.split(next).next())
                .unwrap_or_else(|| panic!("context method body must exist: {method}"));
            let begin = body
                .find("self.begin_source_transaction(context).await?")
                .unwrap_or_else(|| {
                    panic!("mutation must use the delivery-aware source wrapper: {method}")
                });
            let commit = body
                .rfind("tx.commit_consuming()")
                .unwrap_or_else(|| panic!("mutation must commit through the wrapper: {method}"));
            assert!(
                begin < commit,
                "admission begin must precede commit: {method}"
            );
            assert!(
                !body.contains("tx.commit()"),
                "mutation must not bypass the proven-commit gate with a raw commit: {method}"
            );
        }
    }

    /// 接受邀请的锁序与 admission 绑定：目标租户行 -> 邀请行 -> actor 卡片
    /// （admission scope 对牌）-> 状态/过期分支 -> ACCEPTED 更新 -> 成员
    /// upsert -> 审计 -> commit。入会租户不做 actor 租户匹配，但目标租户行
    /// 必须先锁、actor 复核必须先于任何写入。
    #[test]
    fn accept_invitation_locks_target_tenant_then_invitation_then_actor_card_before_mutation() {
        let impl_source = include_str!("tenant_repository.rs")
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("SqlxTenantRepository implementation must exist");
        let body = impl_source
            .split("async fn accept_invitation_with_context(")
            .nth(1)
            .and_then(|rest| rest.split("async fn list_purchases(").next())
            .expect("accept_invitation_with_context body must exist");
        let wrapper_begin = body
            .find("self.begin_source_transaction(context).await?")
            .expect("accept must open the delivery-aware source wrapper");
        let tenant_lock = body
            .find("sqlx::query_as(TENANT_ID_LOCK_SQL)")
            .expect("accept must lock the target tenant row first");
        let invitation_lock = body
            .find("sqlx::query_as(TENANT_INVITATION_LOCK_SQL)")
            .expect("accept must lock the invitation row");
        let tenant_mismatch = body
            .find("invitation_tenant != tenant_id")
            .expect("accept must fail closed on tenant mismatch");
        let role_match = body
            .find("invitation_role != role")
            .expect("accept must bind the service lookup to the locked invitation row");
        let actor_verify = body
            .find("verify_tenant_mutation_actor_in_tx(&mut tx, context)")
            .expect("accept must bind the admission scope to the locked actor card");
        let status_guard = body
            .find("invitation_status != \"ACTIVE\"")
            .expect("accept must re-check status under the row lock");
        let expired_branch = body
            .find("unix_now_secs() > expires")
            .expect("accept must re-check expiry under the row lock");
        let accepted_update = body
            .find("SET status = 'ACCEPTED', current_uses = current_uses + 1")
            .expect("accept must mark ACCEPTED with the ACTIVE guard");
        let member_upsert = body
            .find("INSERT INTO tenant_members")
            .expect("accept must upsert the locked actor as member");
        // 接受分支的审计是第二次 insert_tenant_mutation_audit_in_tx（第一次在
        // 过期分支），取最后一次对齐提交顺序。
        let audit = body
            .rfind("insert_tenant_mutation_audit_in_tx")
            .expect("accept must write its business audit in the source transaction");
        let commit = body
            .rfind("tx.commit_consuming()")
            .expect("accept must commit through the wrapper consuming commit");
        assert!(
            wrapper_begin < tenant_lock
                && tenant_lock < invitation_lock
                && invitation_lock < tenant_mismatch
                && tenant_mismatch < role_match
                && role_match < actor_verify
                && actor_verify < status_guard
                && status_guard < expired_branch
                && expired_branch < accepted_update
                && accepted_update < member_upsert
                && member_upsert < audit
                && audit < commit,
            "accept must order: wrapper begin -> tenant lock -> invitation lock -> \
             tenant/role match -> actor admission verify -> status/expiry -> ACCEPTED -> \
             member upsert -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id)"),
            "accept joins a foreign tenant; the actor-tenant equality helper must not be called"
        );
        assert!(
            body.contains(".bind(context.actor_id)"),
            "member upsert must bind the locked actor id, not a caller-declared user"
        );
    }

    /// 租户范围内的成员/邀请 mutation（add/remove/字段更新/创建/撤销）必须
    /// 先经 lock_existing_tenant_scope_in_tx（租户锁 + actor scope + admission
    /// 绑定）再触碰目标行，审计在提交前写入同一事务。
    #[test]
    fn scoped_member_invitation_mutations_lock_tenant_scope_before_mutation_and_audit() {
        let impl_source = include_str!("tenant_repository.rs")
            .split("impl TenantRepository for SqlxTenantRepository")
            .nth(1)
            .expect("SqlxTenantRepository implementation must exist");
        for (method, next) in [
            (
                "async fn upsert_member_with_context(",
                "async fn get_member(",
            ),
            (
                "async fn remove_member_with_context(",
                "async fn update_member_field(",
            ),
            (
                "async fn update_member_field_with_context(",
                "async fn list_invitations(",
            ),
            (
                "async fn create_invitation_with_context(",
                "async fn get_invitation_by_code(",
            ),
            (
                "async fn cancel_invitation_with_context(",
                "async fn mark_invitation_expired(",
            ),
        ] {
            let body = impl_source
                .split(method)
                .nth(1)
                .and_then(|rest| rest.split(next).next())
                .unwrap_or_else(|| panic!("context method body must exist: {method}"));
            let scope_lock = body
                .find("lock_existing_tenant_scope_in_tx(&mut tx, context, tenant_id)")
                .unwrap_or_else(|| panic!("mutation must assert actor tenant scope: {method}"));
            let mutation = body
                .find("sqlx::query(")
                .unwrap_or_else(|| panic!("mutation must issue SQL: {method}"));
            let audit = body
                .find("insert_tenant_mutation_audit_in_tx")
                .unwrap_or_else(|| panic!("mutation must write tenant audit: {method}"));
            assert!(
                scope_lock < mutation && mutation < audit,
                "mutation must order: tenant scope lock -> SQL -> audit: {method}"
            );
        }
        // cancel 必须在锁定行上复核邀请的租户归属（fail-closed）。
        let cancel_body = impl_source
            .split("async fn cancel_invitation_with_context(")
            .nth(1)
            .and_then(|rest| rest.split("async fn mark_invitation_expired(").next())
            .expect("cancel_invitation_with_context body must exist");
        let invitation_lock = cancel_body
            .find("sqlx::query_as(TENANT_INVITATION_LOCK_SQL)")
            .expect("cancel must lock the invitation row");
        let tenant_match = cancel_body
            .find("invitation_tenant != tenant_id")
            .expect("cancel must fail closed on invitation tenant mismatch");
        assert!(
            invitation_lock < tenant_match,
            "cancel must check invitation tenant ownership after the row lock"
        );
    }
}
