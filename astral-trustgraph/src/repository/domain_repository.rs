//! 域数据访问 — DomainRepository
//!
//! 对齐 Java `DomainControlService` 域 CRUD 边界（platform_domain 表）。
//! 动态过滤统一使用 `QueryBuilder` 参数绑定，禁止裸字符串拼接。
//!
//! ## 授权源事务（TG 域 mutation：admission-hosted source mutation）
//!
//! create/update/delete 是平台域治理 mutation：以 `AuthorizationSourceTransaction`
//! 为宿主承接 proof-bound admission —— 复用 canonical
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
//! admission proof scope 对牌，域要求显式 `Exact`，与 departments/levels 同一
//! 形状），再锁定目标域行（存在性 + 行锁序列化并发 mutation）。
//! `platform_domain` 无租户列，域治理的租户边界由 actor 卡行锁定事实与
//! admission scope 对牌承载，不虚构目标租户列。
//!
//! ## 范围结论（不虚构 eligibility fanout）
//!
//! `platform_domain` 不是 CanonicalGrant 源：policy-engine 与 astral-db 的
//! eligibility/投影消费路径均无本表业务引用（仅 DDL 迁移），因此本文件刻意
//! 不登记 ELIGIBILITY 失效事件、不追加任何投影 delta/receipt；授权事实仍由
//! user_card/发布证据路径承载。同事务保留 `audit_log` 关联（request_id/
//! event_type 关联源 mutation）。遗留无 context mutation 方法一律 fail-closed
//! （`domain_context_required`），无内部 system 旁路。
//!
//! ## bootstrap/system 语义保留
//!
//! `sync_default_domain` 是平台引导（bootstrap）幂等同步：确保系统至少存在
//! 一个默认域。它保留既有直连 pool 写入与容错语义（并发同步失败仅告警），
//! 不要求用户 admission，也绝不作为普通用户 mutation 的旁路 —— 普通用户
//! create/update/delete 必须走 `_with_context` admission 路径。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::grant_ledger::validated_request_operation_id;
use astral_db::{TypedRowOperation, TypedSourceRowLookup, TypedSourceTable};
use astral_types::{
    AstralError, AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationDomainScope,
    PolicyContext,
};

use crate::repository::authorization_source_transaction::{
    begin_source_transaction_with_capability, AuthorizationSourceTransaction,
    SourceMutationCapability,
};

/// 域记录（platform_domain）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainRecord {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（status 可选）
#[derive(Debug, Default)]
pub struct DomainFilter {
    pub status: Option<String>,
}

/// 部分更新补丁（仅更新非 None 字段，对齐 Java Mapper.updateById 语义）
#[derive(Debug, Default)]
pub struct DomainPatch {
    pub name: Option<String>,
    pub code: Option<String>,
    pub status: Option<String>,
}

/// 新建域参数（status 由 API 白名单校验后传入，缺省 'ACTIVE'）
#[derive(Debug, Clone)]
pub struct NewDomain {
    pub name: String,
    pub code: Option<String>,
    pub status: String,
}

/// 默认域同步结果
#[derive(Debug, Clone)]
pub struct DefaultDomainSyncResult {
    pub existing: i64,
    pub created: i64,
}

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph domain mutation.
///
/// 与 departments/levels 同一装配合同：身份只能来自 TrustGraph permission
/// 中间件安装的已验证 `PolicyContext`；Gateway 头不是授权来源，只允许在 API
/// 层与该 context 完全一致后使用。`request_id` 必须携带且通过统一持久化安全
/// 性校验（`validated_request_operation_id`）；缺失/纯空白/超长/非法字符一律
/// fail-closed，绝不静默替换、截断或随机补位 —— 它是同事务 audit_log 关联
/// 与源 mutation 的可追溯 operation id。`source_capability` 初始为
/// `UserPending`，只有 `.with_admission(...)` 注入 proof-bound admission 后
/// 才允许开启用户 source 事务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl DomainMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "domain mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("domain mutation requires a canonical request id".into())
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
    value
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Auth(format!("domain mutation requires a positive {name}")))
}

fn domain_context_required() -> AstralError {
    AstralError::Auth("domain business mutation requires Gateway-verified user-card context".into())
}

// ===== SQL 常量 =====

/// platform_v4 真实列名映射（domain_id → id, domain_name → name 等）
const DOMAIN_SELECT_COLUMNS: &str = "domain_id as id, domain_name as name, domain_code as code, \
     domain_description as description, status, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与 departments/levels 同一形状。
/// 所有域 mutation 的第一把锁，跨 create/update/delete 保持同一锁序避免死锁。
const DOMAIN_MUTATION_ACTOR_LOCK_SQL: &str = "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 目标域行锁：锁定读证明存在性并序列化并发 update/soft-delete（参数化 SQL）。
const DOMAIN_ROW_LOCK_SQL: &str =
    "SELECT domain_id FROM platform_domain WHERE domain_id = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const DOMAIN_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：域 mutation 家族标记。
const DOMAIN_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_DOMAIN_MUTATION";
/// `audit_log.resource`：域聚合（platform_domain 表）。
const DOMAIN_AUDIT_RESOURCE: &str = "platform_domain";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_domain_actor_scope_matches(
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
            "authorization admission scope does not match the locked domain mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type DomainActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 第一把锁：锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_domain_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &DomainMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<DomainActorCardRow> = sqlx::query_as(DOMAIN_MUTATION_ACTOR_LOCK_SQL)
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
                ensure_domain_actor_scope_matches(
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
            "Gateway domain mutation card context no longer matches an active user_card".into(),
        )),
    }
}

/// 目标域行锁：存在性（None 由调用点决定 NotFound/no-hit 语义）+ 行锁。
async fn lock_domain_row_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    domain_id: i64,
) -> Result<bool, AstralError> {
    let row: Option<(i64,)> = sqlx::query_as(DOMAIN_ROW_LOCK_SQL)
        .bind(domain_id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    Ok(row.is_some())
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 departments/levels 路径同一机制：
/// 不用 MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_domain_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &DomainMutationContext,
    domain_id: i64,
    action: &str,
    details: serde_json::Value,
) -> Result<astral_db::TypedSourceAuditReceipt, AstralError> {
    if domain_id <= 0 || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "domain mutation audit requires a positive target id and a non-empty action".into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "domain",
        "targetId": domain_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("domain audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("domain audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(DOMAIN_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(DOMAIN_AUDIT_RESOURCE)
        .bind(DOMAIN_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("domain mutation audit insert failed: {error}"))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "domain audit insert did not affect exactly one durable row".into(),
        ));
    }
    let audit_id = i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("domain audit insert returned invalid id".into()))?;
    astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(audit_id)
}

#[async_trait]
pub trait DomainRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_domains(&self, filter: &DomainFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY domain_id）
    async fn list_domains(
        &self,
        filter: &DomainFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainRecord>, AstralError>;
    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError>;

    /// 遗留无 context create：一律 fail-closed（无 admission 旁路）。
    async fn create_domain(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<i64, AstralError> {
        let _ = (name, code, status);
        Err(domain_context_required())
    }
    /// 新建域（proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 卡行 → INSERT。status 由 API 白名单校验后传入。
    /// commit 前 canonical wrapper 完成 durable authority revalidation /
    /// consume_once，只有 proven commit 返回新 id。
    async fn create_domain_with_context(
        &self,
        new: &NewDomain,
        context: &DomainMutationContext,
    ) -> Result<i64, AstralError>;

    /// 遗留无 context update：一律 fail-closed（无 admission 旁路）。
    async fn update_domain(&self, id: i64, patch: &DomainPatch) -> Result<(), AstralError> {
        let _ = (id, patch);
        Err(domain_context_required())
    }
    /// 部分更新（仅应用非 None 字段；空补丁 no-op：无 source mutation，
    /// 不开启事务）。
    ///
    /// 事务内锁序：actor 卡行 → 目标域行锁（NotFound fail-closed）。
    /// 只有 proven commit 返回成功。
    async fn update_domain_with_context(
        &self,
        id: i64,
        patch: &DomainPatch,
        context: &DomainMutationContext,
    ) -> Result<(), AstralError>;

    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn soft_delete_domain(&self, id: i64) -> Result<bool, AstralError> {
        let _ = id;
        Err(domain_context_required())
    }
    /// 软删除（ACTIVE → INACTIVE，保留既有语义，不做行 DELETE），返回是否命中。
    ///
    /// 事务内锁序：actor 卡行 → 目标域行锁（未命中返回 false，事务随 drop
    /// 回滚；命中则行锁与 UPDATE 原子成立）。只有 proven commit 返回命中。
    async fn delete_domain_with_context(
        &self,
        id: i64,
        context: &DomainMutationContext,
    ) -> Result<bool, AstralError>;

    /// 幂等同步默认域（无域时插入「默认域」），返回现状与新建数量。
    ///
    /// bootstrap/system 语义：平台引导路径的幂等直连写入（并发同步失败仅
    /// 告警，不阻塞主链路），不要求用户 admission；绝不作为普通用户域
    /// mutation 的旁路。
    async fn sync_default_domain(&self) -> Result<DefaultDomainSyncResult, AstralError>;
}

pub struct SqlxDomainRepository {
    db: MySqlPool,
}

impl SqlxDomainRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 向 QueryBuilder 追加 status 过滤（列表与总数共用同一条件）
fn push_domain_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &DomainFilter,
) {
    if let Some(status) = &filter.status {
        builder
            .push(" AND status = ")
            .push_bind(status.to_uppercase());
    }
}

#[async_trait]
impl DomainRepository for SqlxDomainRepository {
    async fn count_domains(&self, filter: &DomainFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM platform_domain WHERE 1=1");
        push_domain_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_domains(
        &self,
        filter: &DomainFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {DOMAIN_SELECT_COLUMNS} FROM platform_domain WHERE 1=1"
        ));
        push_domain_filter(&mut builder, filter);
        builder
            .push(" ORDER BY domain_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<DomainRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError> {
        sqlx::query_as::<_, DomainRecord>(&format!(
            "SELECT {DOMAIN_SELECT_COLUMNS} FROM platform_domain WHERE domain_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_domain_with_context(
        &self,
        new: &NewDomain,
        context: &DomainMutationContext,
    ) -> Result<i64, AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_domain_mutation_actor_in_tx(&mut tx, context).await?;
        let mut capture = tx.typed_row_capture(TypedSourceTable::Domain, TypedRowOperation::Insert);
        let new_id = capture
            .insert_domain_and_capture_in_tx(
                new.code.clone(),
                new.name.clone(),
                None,
                new.status.clone(),
            )
            .await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_domain_mutation_audit_in_tx(
            &mut tx,
            context,
            new_id,
            "domain_create",
            serde_json::json!({
                "name": new.name,
                "code": new.code,
                "status": new.status,
            }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    async fn update_domain_with_context(
        &self,
        id: i64,
        patch: &DomainPatch,
        context: &DomainMutationContext,
    ) -> Result<(), AstralError> {
        // 先把补丁装配成绑定参数 UPDATE（列名是编译期常量，值全部 push_bind）；
        // 空补丁 no-op：无 source mutation，不开启事务。
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE platform_domain SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
            builder.push("domain_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.code {
            if !first {
                builder.push(", ");
            }
            builder.push("domain_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            builder.push("status = ").push_bind(status.clone());
            first = false;
        }
        if first {
            // 空补丁：无字段更新（对齐既有 handler 语义，直接返回）。零 SQL
            // 零副作用，不开启 source 事务。
            return Ok(());
        }
        builder.push(" WHERE domain_id = ").push_bind(id);

        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_domain_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标域行锁：存在性 NotFound fail-closed（错误先于任何写入返回，
        // 事务随 Err 整体回滚），行锁序列化并发 update/soft-delete。
        let target_exists = lock_domain_row_in_tx(&mut tx, id).await?;
        if !target_exists {
            return Err(AstralError::NotFound(format!("domain {id} not found")));
        }
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture = tx.typed_row_capture(TypedSourceTable::Domain, TypedRowOperation::Update);
        capture.capture_before_in_tx(&lookup).await?;
        let affected = capture
            .with_tx_mut(move |inner| {
                Box::pin(async move {
                    let result = builder
                        .build()
                        .execute(&mut **inner)
                        .await
                        .map_err(db_error)?;
                    if result.rows_affected() > 1 {
                        return Err(AstralError::Pending(
                            "locked domain update affected more than one row".into(),
                        ));
                    }
                    Ok(result.rows_affected())
                })
            })
            .await?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        if image.before_image_digest() == image.after_image_digest() {
            tx.rollback_consuming().await?;
            return Ok(());
        }
        if affected != 1 {
            return Err(AstralError::Pending(
                "domain update changed its source image without exactly one affected row".into(),
            ));
        }
        let audit = insert_domain_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "domain_update",
            serde_json::json!({
                "name": patch.name,
                "code": patch.code,
                "status": patch.status,
            }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await
    }

    async fn delete_domain_with_context(
        &self,
        id: i64,
        context: &DomainMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_domain_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标域行锁：未命中返回 false（对齐既有 API 404 语义），事务随 drop
        // 回滚；命中则行锁与软删除 UPDATE 原子成立。
        let target_exists = lock_domain_row_in_tx(&mut tx, id).await?;
        if !target_exists {
            return Ok(false);
        }
        // 既有软删除语义保持不变：ACTIVE → INACTIVE，不做行 DELETE、不改谓词。
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture = tx.typed_row_capture(TypedSourceTable::Domain, TypedRowOperation::Update);
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(|inner| {
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE platform_domain SET status = 'INACTIVE' WHERE domain_id = ? AND status = 'ACTIVE'",
                    )
                    .bind(id)
                    .execute(&mut **inner)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() == 0 {
            tx.rollback_consuming().await?;
            return Ok(false);
        }
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "locked domain soft-delete affected more than one row".into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_domain_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "domain_delete",
            serde_json::json!({ "status": "INACTIVE", "delete": "soft" }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn sync_default_domain(&self) -> Result<DefaultDomainSyncResult, AstralError> {
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM platform_domain")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;

        let mut created = 0i64;
        if existing == 0 {
            // 幂等语义：并发同步时容忍失败（对齐现有 handler，不阻塞主链路）。
            // bootstrap/system 路径：不走用户 admission source 事务。
            match sqlx::query(
                "INSERT INTO platform_domain (domain_name, domain_code, status) \
                 VALUES ('默认域', 'DEFAULT', 'ACTIVE')",
            )
            .execute(&self.db)
            .await
            {
                Ok(_) => created = 1,
                Err(e) => {
                    tracing::warn!(error = %e, "default domain insert failed (idempotent sync)");
                }
            }
        }

        Ok(DefaultDomainSyncResult { existing, created })
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Domain repository query failed: {error}"))
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
    fn domain_mutation_context_requires_verified_identity() {
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
            DomainMutationContext::from_policy_context(&end_user, Some("req-1")),
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
            DomainMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            DomainMutationContext::from_policy_context(&policy_context(10, 20, 30, 40), None),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            DomainMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            DomainMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = DomainMutationContext::from_policy_context(
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
            operation_id: "op-domain-test".into(),
            event_id: "evt-domain-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-domain-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-domain-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = DomainMutationContext::from_policy_context(
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
        assert!(ensure_domain_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_domain_actor_scope_matches(
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
            ensure_domain_actor_scope_matches(
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
            ensure_domain_actor_scope_matches(
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
            ensure_domain_actor_scope_matches(
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
            ensure_domain_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_domain_actor_scope_matches(
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
        assert_eq!(DOMAIN_AUDIT_EVENT_TYPE, "TRUSTGRAPH_DOMAIN_MUTATION");
        assert!(
            DOMAIN_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(DOMAIN_AUDIT_RESOURCE, "platform_domain");
        assert!(
            DOMAIN_MUTATION_AUDIT_INSERT_SQL
                .contains("VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)"),
            "audit insert must bind every mutable input"
        );
        assert!(
            DOMAIN_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && DOMAIN_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
            "audit correlation must land in event_type/request_id columns"
        );
    }

    // ── 源序守卫：create/update/delete 事务内锁序与 commit 门 ─────────────

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
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production must precede the test module")
            .split(start_marker)
            .nth(2)
            .expect("implementation must exist")
            .split(end_marker)
            .next()
            .expect("body must be delimited")
    }

    #[test]
    fn create_tx_orders_actor_lock_insert_audit_and_commit() {
        let source = include_str!("domain_repository.rs");
        let body = impl_segment(
            source,
            "async fn create_domain_with_context",
            "async fn get_domain",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("create must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_domain_mutation_actor_in_tx(&mut tx, context)")
            .expect("create must bind the actor card facts first");
        let insert = body
            .find(".insert_domain_and_capture_in_tx(")
            .expect("create must delegate the insert and locked readback to the capture child");
        let normalized: String = body.split_whitespace().collect();
        assert!(normalized.contains("capture.insert_domain_and_capture_in_tx("));
        let capture_child =
            include_str!("../../../astral-db/src/authority_config_source/tenant_domain.rs")
                .split("#[cfg(test)]")
                .next()
                .expect("domain capture child production source must exist");
        let insert_sql = capture_child
            .find(r#"const DOMAIN_INSERT_SQL: &str = "INSERT INTO platform_domain"#)
            .expect("domain capture child must own the actual INSERT statement");
        assert!(
            capture_child[insert_sql..].contains(".execute(&mut **tx)"),
            "domain capture child must execute the INSERT on its bound transaction"
        );
        let audit = body
            .find("insert_domain_mutation_audit_in_tx")
            .expect("create must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("create must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock && actor_lock < insert && insert < audit && audit < commit,
            "create must order: wrapper begin -> actor card lock -> INSERT -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "create must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    #[test]
    fn update_tx_orders_actor_lock_target_lock_update_audit_and_commit() {
        let source = include_str!("domain_repository.rs");
        let body = impl_segment(
            source,
            "async fn update_domain_with_context",
            "async fn delete_domain_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("update must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_domain_mutation_actor_in_tx(&mut tx, context)")
            .expect("update must bind the actor card facts first");
        let target_lock = body
            .find("lock_domain_row_in_tx(&mut tx, id)")
            .expect("update must lock the target domain row");
        let update = body
            .find(".execute(&mut **inner)")
            .expect("update must mutate the domain row through the capture child borrow");
        let normalized: String = body.split_whitespace().collect();
        assert!(normalized.contains("builder.build().execute(&mut**inner)"));
        let audit = body
            .find("insert_domain_mutation_audit_in_tx")
            .expect("update must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("update must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < target_lock
                && target_lock < update
                && update < audit
                && audit < commit,
            "update must order: wrapper begin -> actor card lock -> target lock -> UPDATE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "update must not bypass the wrapper's proven-commit gate with a raw commit"
        );
        // 空补丁 no-op 必须先于任何 source 事务（零 SQL 零副作用）。
        let empty_patch = body
            .find("return Ok(());")
            .expect("empty patch must stay a no-op");
        assert!(
            empty_patch < begin,
            "the empty-patch no-op must be decided before opening a source transaction"
        );
    }

    #[test]
    fn delete_tx_orders_actor_lock_target_lock_soft_delete_audit_and_commit() {
        let source = include_str!("domain_repository.rs");
        let body = impl_segment(
            source,
            "async fn delete_domain_with_context",
            "async fn sync_default_domain",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("delete must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_domain_mutation_actor_in_tx(&mut tx, context)")
            .expect("delete must bind the actor card facts first");
        let target_lock = body
            .find("lock_domain_row_in_tx(&mut tx, id)")
            .expect("delete must lock the target domain row");
        let soft_delete = body
            .find("UPDATE platform_domain SET status = 'INACTIVE' WHERE domain_id = ? AND status = 'ACTIVE'")
            .expect("delete must keep the exact parameterized soft-delete predicate");
        let audit = body
            .find("insert_domain_mutation_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < target_lock
                && target_lock < soft_delete
                && soft_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> actor card lock -> target lock -> soft delete -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    // ── 范围结论：无 eligibility fanout、sync 保持 bootstrap、遗留入口 fail-closed ─

    #[test]
    fn domain_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("domain_repository.rs");
        // 域行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "domain mutations must not invent eligibility/projection fanout"
        );
        // create/update/delete 全部以 proof-bound source transaction 为宿主；
        // sync_default_domain 保持 bootstrap 直连写入，不占用 wrapper。
        assert_eq!(
            source.matches(wrapper_begin_token()).count(),
            3,
            "create/update/delete must each use the proof-bound source wrapper"
        );
        // 遗留无 context mutation 入口一律 fail-closed（trait 默认实现）。
        let legacy = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        assert_eq!(
            legacy.matches("Err(domain_context_required())").count(),
            3,
            "legacy create/update/delete must fail closed without a mutation context"
        );
        // actor 卡行与目标域行锁定读都是 FOR UPDATE 锁定读（原子守卫）。
        assert!(DOMAIN_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
        assert!(DOMAIN_ROW_LOCK_SQL.contains("FOR UPDATE"));
    }

    /// `sync_default_domain` 保持 bootstrap/system 语义：幂等直连写入、容错
    /// 不阻塞、不要求 admission，也绝不借用用户 source wrapper。
    #[test]
    fn sync_default_domain_stays_a_bootstrap_system_semantics() {
        let source = include_str!("domain_repository.rs");
        let body = impl_segment(source, "async fn sync_default_domain", "fn db_error");
        assert!(
            body.find("INSERT INTO platform_domain").is_some(),
            "sync must keep its idempotent default-domain insert"
        );
        assert!(
            body.contains("'默认域', 'DEFAULT', 'ACTIVE'"),
            "sync must keep the exact default domain bootstrap row"
        );
        assert!(
            !body.contains(wrapper_begin_token()) && !body.contains("commit_consuming"),
            "bootstrap sync must not be forced onto the user admission source wrapper"
        );
        assert!(
            body.contains("tracing::warn!"),
            "sync must keep the tolerant concurrent-insert failure semantics"
        );
    }
}
