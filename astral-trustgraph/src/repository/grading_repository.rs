//! 用户分级数据访问 — GradingRepository
//!
//! 对齐 Java `IdentityUserGradingMapper` 边界（identity_user_grading 表）。
//! 创建走 `INSERT ... ON DUPLICATE KEY UPDATE` 幂等（uk_iug_user_domain）。
//!
//! ## 授权源事务（TG-A 批次：admission-hosted source mutation）
//!
//! `identity_user_grading` 是受保护资源 resolver（`TargetLookupKind::UserGrading`）
//! 的 ownership 事实面：本仓全部 mutation（upsert/delete）以
//! `AuthorizationSourceTransaction` 为宿主——复用 canonical
//! `begin_source_transaction_with_capability` / `commit_consuming`，不在本文件
//! 发明第二套事务/栅栏基础设施：
//! - `begin` 在 DB begin 之前取得 hub 源活动栅栏（hub 已安装而拒发证即在开启
//!   事务**之前** fail-closed，绝不留下无栅栏 writer）；`UserPending`（缺失
//!   admission）在 begin 即被拒绝；
//! - commit 前 canonical wrapper 完成 durable authority 对牌
//!   （`validate_authorization_admission_in_tx`）与 admission `consume_once`，
//!   之后才 arm 栅栏并 await COMMIT；只有 proven commit 返回成功；
//! - commit 未知/失败 → 栅栏 sticky uncertain、receipts 空集，绝不投递、绝不
//!   重放（UNKNOWN fail-closed）。
//!
//! 事务内按固定锁序先锁定 actor 卡行（user/tenant/domain/ACTIVE 复核 +
//! admission proof scope 对牌，与 departments 同一形状），再以锁定读（FOR
//! UPDATE）复核目标等级在指定域存在且 ACTIVE（原 handler 前置校验下沉进
//! 事务，消除与等级删除之间的 TOCTOU 窗口）。`level_exists_in_domain` 保留
//! 为遗留只读读取；mutation 路径的存在性证明一律走事务内行锁。
//!
//! ## 范围结论（不虚构 eligibility fanout）
//!
//! `identity_user_grading` 不是 CanonicalGrant 源：policy-engine 与 astral-db
//! 的 eligibility/投影消费路径均无本表引用（唯一消费方是 `resource_ownership`
//! 的 ownership resolver 只读查询，其读面一致性由上述 hub 源活动栅栏保证）。
//! 因此本文件刻意不登记 ELIGIBILITY 失效事件、不追加任何投影 delta/receipt；
//! 授权事实仍由 user_card/发布证据路径承载。同事务保留 `audit_log` 关联
//! （request_id/event_type 关联源 mutation）。遗留无 context mutation 方法
//! 一律 fail-closed（`grading_context_required`），无内部 system 旁路。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::{
    grant_ledger::validated_request_operation_id, TypedRowOperation, TypedSourceRowLookup,
    TypedSourceTable,
};
use astral_types::{
    AstralError, AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationDomainScope,
    PolicyContext,
};

use crate::repository::authorization_source_transaction::{
    begin_source_transaction_with_capability, AuthorizationSourceTransaction,
    SourceMutationCapability,
};

/// 用户分级记录（identity_user_grading）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GradingRecord {
    pub id: i64,
    pub user_id: i64,
    pub level_id: i64,
    pub domain_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（user_id / domain_id 可选）
#[derive(Debug, Default)]
pub struct GradingFilter {
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
}

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph user-grading mutation.
///
/// 与 departments 同一装配合同：身份只能来自 TrustGraph permission 中间件
/// 安装的已验证 `PolicyContext`；Gateway 头不是授权来源，只允许在 API 层与
/// 该 context 完全一致后使用。`request_id` 必须携带且通过统一持久化安全性
/// 校验（`validated_request_operation_id`）；缺失/纯空白/超长/非法字符一律
/// fail-closed，绝不静默替换、截断或随机补位。`source_capability` 初始为
/// `UserPending`，只有 `.with_admission(...)` 注入 proof-bound admission 后
/// 才允许开启用户 source 事务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradingMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl GradingMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "user grading mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("user grading mutation requires a canonical request id".into())
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

    pub(crate) fn source_capability(&self) -> &SourceMutationCapability {
        &self.source_capability
    }

    fn request_id(&self) -> &str {
        &self.request_id
    }
}

fn positive_context_id(value: Option<i64>, name: &str) -> Result<i64, AstralError> {
    value.filter(|value| *value > 0).ok_or_else(|| {
        AstralError::Auth(format!("user grading mutation requires a positive {name}"))
    })
}

fn grading_context_required() -> AstralError {
    AstralError::Auth(
        "user grading business mutation requires Gateway-verified user-card context".into(),
    )
}

// ===== SQL 常量 =====

const GRADING_SELECT_COLUMNS: &str = "id, user_id, level_id, domain_id, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与 departments 同一形状。所有分级
/// mutation 的第一把锁，跨 upsert/delete 保持同一锁序避免死锁。
const GRADING_MUTATION_ACTOR_LOCK_SQL: &str = "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 等级存在性锁定读（原 handler 前置校验下沉进事务）：谓词与遗留只读读取
/// 完全一致（level_id + domain_id + ACTIVE），加 FOR UPDATE 消除与等级删除
/// 之间的 TOCTOU 窗口。
const GRADING_LEVEL_DOMAIN_LOCK_SQL: &str = "SELECT level_id FROM user_card_level_definition \
     WHERE level_id = ? AND domain_id = ? AND status = 'ACTIVE' FOR UPDATE";
/// 目标分级行锁：锁定读证明存在性并捕获 user/level/domain 事实供审计关联；
/// 行锁与 DELETE 原子成立（参数化 SQL）。
const GRADING_ROW_LOCK_SQL: &str =
    "SELECT id, user_id, level_id, domain_id FROM identity_user_grading WHERE id = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const GRADING_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：用户分级 mutation 家族标记。
const GRADING_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_USER_GRADING_MUTATION";
/// `audit_log.resource`：用户分级聚合（identity_user_grading 表）。
const GRADING_AUDIT_RESOURCE: &str = "identity_user_grading";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_grading_actor_scope_matches(
    scope: &AuthorizationAuthorityScope,
    actor_card_id: i64,
    user_id: i64,
    tenant_id: i64,
    domain_id: i64,
) -> Result<(), AstralError> {
    let domain_matches = matches!(
        scope.domain,
        AuthorizationDomainScope::Exact(value) if value == domain_id
    );
    if scope.tenant_id != tenant_id
        || scope.card_id != actor_card_id
        || scope.user_id != Some(user_id)
        || !domain_matches
    {
        return Err(AstralError::Permission(
            "authorization admission scope does not match the locked user grading mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type GradingActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 第一把锁：锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_grading_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &GradingMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<GradingActorCardRow> = sqlx::query_as(GRADING_MUTATION_ACTOR_LOCK_SQL)
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
                ensure_grading_actor_scope_matches(
                    &admission.proof().scope,
                    context.actor_card_id,
                    user_id,
                    tenant_id,
                    domain_id,
                )?;
            }
            Ok(())
        }
        _ => Err(AstralError::Auth(
            "Gateway user grading mutation card context no longer matches an active user_card"
                .into(),
        )),
    }
}

/// 目标分级行锁：存在性 + 锁定读取的 user/level/domain 事实（None 由调用点
/// 决定 no-hit 语义）。
type GradingTargetRow = (i64, i64, i64, i64);

async fn lock_grading_row_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    id: i64,
) -> Result<Option<GradingTargetRow>, AstralError> {
    let row: Option<GradingTargetRow> = sqlx::query_as(GRADING_ROW_LOCK_SQL)
        .bind(id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    Ok(row)
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 departments/level 路径同一机制：不用
/// MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_grading_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &GradingMutationContext,
    grading_id: i64,
    action: &str,
    details: serde_json::Value,
) -> Result<i64, AstralError> {
    if grading_id <= 0 || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "user grading mutation audit requires a positive target id and a non-empty action"
                .into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "user_grading",
        "targetId": grading_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("user grading audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("user grading audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(GRADING_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(GRADING_AUDIT_RESOURCE)
        .bind(GRADING_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!(
                "user grading mutation audit insert failed: {error}"
            ))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "user grading mutation audit insert affected an unexpected row count".into(),
        ));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("user grading audit insert returned invalid id".into()))
}

#[async_trait]
pub trait GradingRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_gradings(&self, filter: &GradingFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY user_id, domain_id）
    async fn list_gradings(
        &self,
        filter: &GradingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GradingRecord>, AstralError>;
    /// 等级是否存在且 ACTIVE（遗留只读读取；mutation 路径的存在性证明一律
    /// 走事务内行锁，见 `upsert_grading_with_context`）
    async fn level_exists_in_domain(
        &self,
        level_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError>;
    /// 幂等 upsert 后查回（用户+域唯一，应存在）
    async fn get_grading(&self, user_id: i64, domain_id: i64)
        -> Result<GradingRecord, AstralError>;

    /// 遗留无 context upsert：一律 fail-closed（无 admission 旁路）。
    async fn upsert_grading(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError> {
        let _ = (user_id, level_id, domain_id);
        Err(grading_context_required())
    }
    /// 幂等 upsert（uk_iug_user_domain，单用户单域唯一；proof-bound admission
    /// source transaction）。
    ///
    /// 事务内锁序：actor 卡行 → 目标等级行（存在且 ACTIVE 的锁定读复核，
    /// 缺失/INACTIVE/跨域 Validation fail-closed，与既有 handler 前置校验同
    /// 一消息语义）→ `INSERT ... ON DUPLICATE KEY UPDATE`（SQL 原样保留），
    /// 但 no-op 不提交空 config completion。
    /// 只有 proven commit 返回成功。
    async fn upsert_grading_with_context(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
        context: &GradingMutationContext,
    ) -> Result<(), AstralError>;

    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn delete_grading(&self, id: i64) -> Result<bool, AstralError> {
        let _ = id;
        Err(grading_context_required())
    }
    /// 删除，返回是否命中（proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 卡行 → 目标分级行锁（未命中返回 false，事务随 drop
    /// 回滚；命中则锁定读取的 user/level/domain 事实进审计关联）。只有
    /// proven commit 返回命中。
    async fn delete_grading_with_context(
        &self,
        id: i64,
        context: &GradingMutationContext,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxGradingRepository {
    db: MySqlPool,
}

impl SqlxGradingRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 向 QueryBuilder 追加 user_id / domain_id 过滤（列表与总数共用同一条件）
fn push_grading_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &GradingFilter,
) {
    if let Some(user_id) = filter.user_id {
        builder.push(" AND user_id = ").push_bind(user_id);
    }
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
}

#[async_trait]
impl GradingRepository for SqlxGradingRepository {
    async fn count_gradings(&self, filter: &GradingFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(*) FROM identity_user_grading WHERE 1=1",
        );
        push_grading_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_gradings(
        &self,
        filter: &GradingFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GradingRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {GRADING_SELECT_COLUMNS} FROM identity_user_grading WHERE 1=1"
        ));
        push_grading_filter(&mut builder, filter);
        builder
            .push(" ORDER BY user_id, domain_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<GradingRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn level_exists_in_domain(
        &self,
        level_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_card_level_definition \
             WHERE level_id = ? AND domain_id = ? AND status = 'ACTIVE'",
        )
        .bind(level_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(count > 0)
    }

    async fn upsert_grading_with_context(
        &self,
        user_id: i64,
        level_id: i64,
        domain_id: i64,
        context: &GradingMutationContext,
    ) -> Result<(), AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_grading_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标等级存在性（锁定读）：原 handler 前置校验下沉进事务，谓词与
        // 遗留只读读取一致；校验错误先于任何写入返回，事务随 Err 整体回滚。
        let level_row: Option<(i64,)> = sqlx::query_as(GRADING_LEVEL_DOMAIN_LOCK_SQL)
            .bind(level_id)
            .bind(domain_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        if level_row.is_none() {
            return Err(AstralError::Validation(format!(
                "level_id {level_id} does not exist in domain {domain_id} or is inactive"
            )));
        }
        // INSERT ... ON DUPLICATE KEY UPDATE 幂等（uk_iug_user_domain）——
        // mutation SQL must run through the bound typed capture handle.
        let lookup = TypedSourceRowLookup::GradingUserDomain { user_id, domain_id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::Grading, TypedRowOperation::Upsert);
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO identity_user_grading (user_id, level_id, domain_id) \
                         VALUES (?, ?, ?) \
                         ON DUPLICATE KEY UPDATE level_id = VALUES(level_id)",
                    )
                    .bind(user_id)
                    .bind(level_id)
                    .bind(domain_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() == 0 {
            return Err(AstralError::Pending(
                "user grading upsert produced no durable change; refusing empty config completion"
                    .into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        // 同事务内回读本 upsert 的物理行 id（我们刚写的行，同事务可见），
        // 审计关联绑定真实物理 id，绝不伪造身份。
        let (grading_id,): (i64,) = sqlx::query_as(
            "SELECT id FROM identity_user_grading WHERE user_id = ? AND domain_id = ?",
        )
        .bind(user_id)
        .bind(domain_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?;
        let audit_id = insert_grading_mutation_audit_in_tx(
            &mut tx,
            context,
            grading_id,
            "user_grading_upsert",
            serde_json::json!({
                "userId": user_id,
                "levelId": level_id,
                "domainId": domain_id,
                "idempotentUpsert": "uk_iug_user_domain",
            }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await
    }

    async fn get_grading(
        &self,
        user_id: i64,
        domain_id: i64,
    ) -> Result<GradingRecord, AstralError> {
        sqlx::query_as::<_, GradingRecord>(&format!(
            "SELECT {GRADING_SELECT_COLUMNS} FROM identity_user_grading WHERE user_id = ? AND domain_id = ?"
        ))
        .bind(user_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn delete_grading_with_context(
        &self,
        id: i64,
        context: &GradingMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_grading_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标分级行锁：未命中返回 false（对齐既有 API 404 语义），事务随
        // drop 回滚；命中则锁定读取的 user/level/domain 事实进审计关联。
        let Some((_, user_id, level_id, domain_id)) = lock_grading_row_in_tx(&mut tx, id).await?
        else {
            return Ok(false);
        };
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::Grading, TypedRowOperation::Delete);
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM identity_user_grading WHERE id = ?")
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "user grading {id} disappeared during locked delete"
            )));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_grading_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "user_grading_delete",
            serde_json::json!({
                "userId": user_id,
                "levelId": level_id,
                "domainId": domain_id,
                "status": "deleted",
            }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(true)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Grading repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_context(user_id: i64, card_id: i64, tenant_id: i64, domain_id: i64) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(user_id))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(card_id))
            .tenant_id(Some(tenant_id))
            .domain_id(Some(domain_id))
            .action("manage".into())
            .build()
    }

    fn admission_scope(
        tenant_id: i64,
        card_id: i64,
        user_id: i64,
        domain: AuthorizationDomainScope,
    ) -> AuthorizationAuthorityScope {
        AuthorizationAuthorityScope {
            tenant_id,
            card_id,
            user_id: Some(user_id),
            domain,
        }
    }

    // ── context 构造：缺失/非法身份 fail-closed，admission 装载可见 ────────

    #[test]
    fn grading_mutation_context_requires_verified_identity() {
        // 非平台身份拒绝
        let end_user = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("END_USER".into()))
            .card_id(Some(20))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(matches!(
            GradingMutationContext::from_policy_context(&end_user, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失/非正 id 拒绝
        let incomplete = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("PLATFORM_USER".into()))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(matches!(
            GradingMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            GradingMutationContext::from_policy_context(&policy_context(10, 20, 30, 40), None),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            GradingMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            GradingMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = GradingMutationContext::from_policy_context(
            &policy_context(10, 20, 30, 40),
            Some("req-1"),
        )
        .unwrap();
        assert!(matches!(
            context.source_capability(),
            SourceMutationCapability::UserPending
        ));
        let admitted = context.with_admission(admission_for_test());
        assert!(matches!(
            admitted.source_capability(),
            SourceMutationCapability::User(_)
        ));
    }

    fn admission_for_test() -> AuthorizationAdmission {
        // 测试专用 admission 构造：走 from_verified_proof 合同入口，不手写内部
        // 状态。proof 本身只需通过结构校验即可（无签名验证；scope 对牌在锁定
        // 行复核时完成）。
        let proof = astral_types::AuthorizationFenceProof {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-test".into(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: admission_scope(30, 20, 10, AuthorizationDomainScope::Exact(40)),
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "a".repeat(64),
            parent_hash: None,
            operation_id: "op-grading-test".into(),
            event_id: "evt-grading-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-grading-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-grading-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = GradingMutationContext::from_policy_context(
            &policy_context(10, 20, 30, 40),
            Some("req-1"),
        )
        .unwrap();
        let error = match begin_source_transaction_with_capability(
            &pool,
            context.source_capability(),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("missing admission must not open a source transaction"),
        };
        assert!(
            matches!(error, AstralError::Pending(_)),
            "missing admission must fail closed as PENDING, got: {error:?}"
        );
    }

    // ── foreign scope：admission 与锁定 actor 卡行不一致一律 Permission ────

    #[test]
    fn actor_scope_mismatch_is_fail_closed_per_dimension() {
        const CARD: i64 = 20;
        const USER: i64 = 10;
        const TENANT: i64 = 30;
        const DOMAIN: i64 = 40;
        // 完全一致 → 放行
        assert!(ensure_grading_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_grading_actor_scope_matches(
                &admission_scope(31, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // foreign card → 拒绝
        assert!(matches!(
            ensure_grading_actor_scope_matches(
                &admission_scope(TENANT, 21, USER, AuthorizationDomainScope::Exact(DOMAIN)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // foreign user → 拒绝
        assert!(matches!(
            ensure_grading_actor_scope_matches(
                &admission_scope(TENANT, CARD, 11, AuthorizationDomainScope::Exact(DOMAIN)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // foreign domain → 拒绝
        assert!(matches!(
            ensure_grading_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(41)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // 非显式 Exact（Any/NoDomain）绝不匹配 —— 不放宽域要求
        assert!(matches!(
            ensure_grading_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_grading_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::NoDomain),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
    }

    // ── 审计关联：固定 event_type/resource 常量 + 全绑定参数 ──────────────

    #[test]
    fn audit_correlation_uses_bound_parameters_and_fixed_event_type() {
        assert_eq!(GRADING_AUDIT_EVENT_TYPE, "TRUSTGRAPH_USER_GRADING_MUTATION");
        assert!(
            GRADING_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(GRADING_AUDIT_RESOURCE, "identity_user_grading");
        assert!(
            GRADING_MUTATION_AUDIT_INSERT_SQL
                .contains("VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)"),
            "audit insert must bind every mutable input"
        );
        assert!(
            GRADING_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && GRADING_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
            "audit correlation must land in event_type/request_id columns"
        );
    }

    // ── 源序守卫：upsert/delete 事务内锁序与 commit 门 ────────────────────

    /// 自引用防呆：拼接构造 begin token，避免本测试模块源码字面量污染
    /// 全文件出现次数统计（include_str! 包含本测试自身）。
    fn wrapper_begin_token() -> &'static str {
        concat!(
            "begin_source_transaction_with_capability",
            "(&self.db, context.source_capability())"
        )
    }

    fn impl_segment(source: &'static str, start_marker: &str, end_marker: &str) -> &'static str {
        source
            .split(start_marker)
            .nth(2)
            .expect("implementation must exist")
            .split(end_marker)
            .next()
            .expect("body must be delimited")
    }

    #[test]
    fn upsert_tx_orders_actor_lock_level_check_insert_audit_and_commit() {
        let source = include_str!("grading_repository.rs");
        let body = impl_segment(
            source,
            "async fn upsert_grading_with_context",
            "async fn get_grading",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("upsert must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_grading_mutation_actor_in_tx(&mut tx, context)")
            .expect("upsert must bind the actor card facts first");
        let level_check = body
            .find("GRADING_LEVEL_DOMAIN_LOCK_SQL")
            .expect("upsert must re-check level/domain existence inside the tx");
        let insert = body
            .find("INSERT INTO identity_user_grading")
            .expect("upsert must upsert on the wrapper connection");
        let readback = body
            .find("SELECT id FROM identity_user_grading WHERE user_id = ? AND domain_id = ?")
            .expect("upsert must read back the physical grading id in the same tx");
        let audit = body
            .find("insert_grading_mutation_audit_in_tx")
            .expect("upsert must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("upsert must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < level_check
                && level_check < insert
                && insert < readback
                && readback < audit
                && audit < commit,
            "upsert must order: wrapper begin -> actor card lock -> locked level check -> upsert -> id readback -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "upsert must not bypass the wrapper's proven-commit gate with a raw commit"
        );
        // 等级存在性复核必须是锁定读（FOR UPDATE），且谓词与遗留只读读取一致。
        assert!(
            GRADING_LEVEL_DOMAIN_LOCK_SQL.contains("FOR UPDATE"),
            "the in-transaction level existence check must be a locked read"
        );
        assert!(
            GRADING_LEVEL_DOMAIN_LOCK_SQL
                .contains("WHERE level_id = ? AND domain_id = ? AND status = 'ACTIVE'"),
            "the in-transaction level check must keep the legacy predicate"
        );
    }

    #[test]
    fn delete_tx_orders_actor_lock_target_lock_delete_audit_and_commit() {
        let source = include_str!("grading_repository.rs");
        let body = impl_segment(
            source,
            "async fn delete_grading_with_context",
            "fn db_error",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("delete must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_grading_mutation_actor_in_tx(&mut tx, context)")
            .expect("delete must bind the actor card facts first");
        let target_lock = body
            .find("lock_grading_row_in_tx(&mut tx, id)")
            .expect("delete must lock the target grading row");
        let row_delete = body
            .find("DELETE FROM identity_user_grading WHERE id = ?")
            .expect("delete must remove the grading row");
        let audit = body
            .find("insert_grading_mutation_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < target_lock
                && target_lock < row_delete
                && row_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> actor card lock -> target lock -> DELETE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    // ── 范围结论：无 eligibility fanout、幂等 SQL 原样、遗留入口 fail-closed ─

    #[test]
    fn grading_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("grading_repository.rs");
        // 分级行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "user grading mutations must not invent eligibility/projection fanout"
        );
        // upsert/delete 全部以 proof-bound source transaction 为宿主。
        assert_eq!(
            source.matches(wrapper_begin_token()).count(),
            2,
            "upsert/delete must each use the proof-bound source wrapper"
        );
        // 遗留无 context mutation 入口一律 fail-closed（trait 默认实现）。
        let legacy = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        assert_eq!(
            legacy.matches("Err(grading_context_required())").count(),
            2,
            "legacy upsert/delete must fail closed without a mutation context"
        );
        // actor 卡行与目标行锁定读都是 FOR UPDATE 锁定读（原子守卫）。
        assert!(GRADING_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
        assert!(GRADING_ROW_LOCK_SQL.contains("FOR UPDATE"));
        // 幂等 upsert SQL 原样保留（uk_iug_user_domain 单用户单域唯一）。
        assert!(
            source.contains("ON DUPLICATE KEY UPDATE level_id = VALUES(level_id)"),
            "the idempotent upsert semantics must be preserved verbatim"
        );
    }
}
