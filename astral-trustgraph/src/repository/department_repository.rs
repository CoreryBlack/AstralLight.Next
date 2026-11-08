//! 部门数据访问 — DepartmentRepository
//!
//! 对齐 Java `DepartmentMapper` 边界（departments 表）。
//! 动态过滤统一 `QueryBuilder` 参数绑定；删除前校验子部门数。
//!
//! 部门治理 mutation（create/update/delete）是影响组织归属的 source mutation：
//! 以 `AuthorizationSourceTransaction` 为宿主承接 proof-bound admission ——
//! `begin_source_transaction_with_capability` 拒绝无 admission 的 `UserPending`
//! 能力（缺失 admission 一律 fail-closed），commit 前由 canonical wrapper 对牌
//! durable authority frontier/proof 并 `consume_once`，只有 proven commit 返回
//! 成功。事务内按固定锁序锁定 actor 租户行 → 目标部门行 → 父部门行（如适用）
//! → admission caller 卡行，并校验 user/card/tenant/domain scope；目标不存在
//! （NotFound）或租户不匹配（Permission）一律 fail-closed。self-reference /
//! 父部门存在性 / 子部门删除守卫全部保留：子部门计数用锁定读（FOR UPDATE），
//! 与 DELETE 原子成立（并发 re-parent/新增子部门被行锁阻塞）。
//!
//! 范围结论（不虚构 eligibility fanout）：departments 行不是 CanonicalGrant
//! 源，`departments` 不参与投影/资格缓存（astral-db 投影查询与 policy-engine
//! 均无 dept 引用；`tenant_members.dept_id`/`tenant_invitation.dept_id` 为
//! SET NULL 元数据引用），因此本文件刻意不登记 ELIGIBILITY 失效事件、不追加
//! 任何投影 fanout；授权事实仍由 user_card/发布证据路径承载。同事务保留
//! `audit_log` 关联（request_id/event_type 关联源 mutation）。
//! 遗留无 context mutation 方法一律 fail-closed（`department_context_required`），
//! 无内部 system 旁路。

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

/// 部门记录（departments，通过别名映射）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DepartmentRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub status: String,
    pub description: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

/// 列表过滤（parent_id / tenant_id 可选）
#[derive(Debug, Default)]
pub struct DepartmentFilter {
    pub parent_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

/// 部分更新补丁
#[derive(Debug, Default)]
pub struct DepartmentPatch {
    pub name: Option<String>,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub description: Option<String>,
}

/// 新建部门参数（租户归属在事务内与锁定 actor scope 对牌）
#[derive(Debug, Clone)]
pub struct NewDepartment {
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: i32,
    pub description: Option<String>,
}

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph department mutation.
///
/// - 身份只能来自 TrustGraph permission 中间件安装的已验证 `PolicyContext`；
///   Gateway 头不是授权来源，只允许在 API 层与该 context 完全一致后使用。
/// - `request_id` 必须携带且通过统一持久化安全性校验
///   （`validated_request_operation_id`：长度 ≤ audit 列宽、ASCII 安全集、
///   无控制字符）；缺失、纯空白、超长或非法字符一律 fail-closed，绝不静默
///   替换、截断或随机补位 —— 它是同事务 audit_log 关联与源 mutation 的
///   可追溯 operation id。
/// - `source_capability` 初始为 `UserPending`；只有 `.with_admission(...)` 注入
///   proof-bound `AuthorizationAdmission` 后才允许开启用户 source 事务
///   （`begin_source_transaction_with_capability` 拒绝 `UserPending`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepartmentMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl DepartmentMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "department mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("department mutation requires a canonical request id".into())
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
        .ok_or_else(|| AstralError::Auth(format!("department mutation requires a positive {name}")))
}

fn department_context_required() -> AstralError {
    AstralError::Auth(
        "department business mutation requires Gateway-verified user-card context".into(),
    )
}

// ===== SQL 常量 =====

const DEPT_SELECT_COLUMNS: &str =
    "dept_id as id, tenant_id, dept_name as name, dept_code as code, \
     parent_dept_id as parent_id, sort_order, status, description, \
     UNIX_TIMESTAMP(created_at) as created_at, \
     UNIX_TIMESTAMP(updated_at) as updated_at";

/// actor 租户行锁：mutation 前按目标租户锁定 tenant 行，证明租户存在并
/// 序列化同租户治理 mutation（参数化、无动态列）。所有部门 mutation 的
/// 第一把锁，跨 create/update/delete 保持同一锁序避免死锁。
const DEPARTMENT_TENANT_LOCK_SQL: &str =
    "SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE";
/// 目标/父部门行锁（同一谓词，按调用点区分错误语义）：锁定读证明存在性并
/// 携带 tenant_id 供同租户校验。对目标行持有 X 锁后，并发为该部门新增子
/// 部门的 INSERT（需对父行取 S 锁）被阻塞至事务结束。
const DEPARTMENT_ROW_TENANT_LOCK_SQL: &str =
    "SELECT tenant_id FROM departments WHERE dept_id = ? FOR UPDATE";
/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与租户路径同一形状。
const DEPARTMENT_MUTATION_ACTOR_LOCK_SQL: &str =
    "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 子部门删除前置守卫：锁定读统计仍以该部门为父的子部门行数（参数化 SQL）。
/// 锁定读在守卫通过后阻止并发新增/re-parent 子部门行，直到事务结束 ——
/// 守卫计数与 DELETE 因此原子成立（ departments 自引用 FK 为 ON DELETE
/// RESTRICT，DB 层兜底不变）。
const DEPARTMENT_CHILDREN_LOCK_SQL: &str =
    "SELECT COUNT(*) FROM departments WHERE parent_dept_id = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const DEPARTMENT_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_DEPARTMENT_MUTATION', ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：部门 mutation 家族标记。
const DEPARTMENT_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_DEPARTMENT_MUTATION";
/// `audit_log.resource`：部门聚合（departments 表）。
const DEPARTMENT_AUDIT_RESOURCE: &str = "departments";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_department_actor_scope_matches(
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
            "authorization admission scope does not match the locked department mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type DepartmentActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_department_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &DepartmentMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<DepartmentActorCardRow> = sqlx::query_as(DEPARTMENT_MUTATION_ACTOR_LOCK_SQL)
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
                ensure_department_actor_scope_matches(
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
            "Gateway department mutation card context no longer matches an active user_card".into(),
        )),
    }
}

/// 第一把锁：锁定目标租户行（存在性证明）→ 租户不匹配 Permission fail-closed
/// （foreign scope）→ 锁定并复核 admission caller 卡。create 的目标租户来自
/// 请求体，update/delete 锁 actor 自己的租户；所有 mutation 共用同一首锁。
async fn lock_department_tenant_scope_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &DepartmentMutationContext,
    tenant_id: i64,
) -> Result<(), AstralError> {
    let row: Option<(i64,)> = sqlx::query_as(DEPARTMENT_TENANT_LOCK_SQL)
        .bind(tenant_id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    if row.is_none() {
        return Err(AstralError::NotFound(format!("tenant {tenant_id}")));
    }
    if tenant_id != context.actor_tenant_id {
        return Err(AstralError::Permission(
            "department mutation target tenant does not match the locked actor scope".into(),
        ));
    }
    verify_department_mutation_actor_in_tx(tx, context).await
}

/// 锁定目标/父部门行并校验同租户归属。行缺失返回 `false`（调用点决定
/// NotFound/Validation 语义），租户不匹配 Permission fail-closed。
async fn lock_department_row_tenant_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    dept_id: i64,
    tenant_id: i64,
) -> Result<bool, AstralError> {
    let row: Option<(i64,)> = sqlx::query_as(DEPARTMENT_ROW_TENANT_LOCK_SQL)
        .bind(dept_id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    match row {
        Some((row_tenant_id,)) if row_tenant_id == tenant_id => Ok(true),
        Some(_) => Err(AstralError::Permission(
            "department mutation target does not belong to the locked actor tenant".into(),
        )),
        None => Ok(false),
    }
}

/// 纯守卫：self-reference（部门不能是自己的父）。
fn guard_department_parent_reference(
    dept_id: i64,
    parent_id: Option<i64>,
) -> Result<(), AstralError> {
    if parent_id == Some(dept_id) {
        return Err(AstralError::Validation(
            "department cannot be its own parent".into(),
        ));
    }
    Ok(())
}

/// 纯守卫：子部门计数 > 0 禁止删除（消息对齐既有 API 语义）。
fn guard_department_delete(children: i64, dept_id: i64) -> Result<(), AstralError> {
    if children > 0 {
        return Err(AstralError::Validation(format!(
            "department {dept_id} has {children} child departments, cannot delete"
        )));
    }
    Ok(())
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 tenant/level-template 路径同一机制：
/// 不用 MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_department_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &DepartmentMutationContext,
    department_id: i64,
    action: &str,
    details: serde_json::Value,
) -> Result<astral_db::TypedSourceAuditReceipt, AstralError> {
    if department_id <= 0 || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "department mutation audit requires a positive target id and a non-empty action".into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "department",
        "targetId": department_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("department audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("department audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(DEPARTMENT_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(DEPARTMENT_AUDIT_RESOURCE)
        .bind(DEPARTMENT_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("department mutation audit insert failed: {error}"))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "department audit insert did not affect exactly one durable row".into(),
        ));
    }
    let audit_id = i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Pending("department audit insert returned invalid id".into())
        })?;
    astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(audit_id)
}

#[async_trait]
pub trait DepartmentRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_departments(&self, filter: &DepartmentFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY dept_id）
    async fn list_departments(
        &self,
        filter: &DepartmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DepartmentRecord>, AstralError>;
    /// 父部门是否存在（无租户边界的遗留读取；mutation 路径不再使用，
    /// 存在性证明一律走事务内行锁）
    async fn department_exists(&self, dept_id: i64) -> Result<bool, AstralError>;
    /// 按 id 查回
    async fn get_department(&self, id: i64) -> Result<Option<DepartmentRecord>, AstralError>;

    /// 遗留无 context create：一律 fail-closed（无 admission 旁路）。
    async fn create_department(
        &self,
        tenant_id: i64,
        name: &str,
        code: Option<&str>,
        parent_id: Option<i64>,
        sort_order: i32,
        description: Option<&str>,
    ) -> Result<i64, AstralError> {
        let _ = (tenant_id, name, code, parent_id, sort_order, description);
        Err(department_context_required())
    }
    /// 新建部门（proof-bound admission source transaction）。
    ///
    /// 事务内锁序：目标租户行 → （父部门行，如适用）→ admission caller 卡行。
    /// 请求租户与锁定 actor 租户不一致（foreign scope）或租户不存在时整体
    /// fail-closed；父部门必须存在且同租户。commit 前 canonical wrapper 完成
    /// durable authority revalidation/consume_once，只有 proven commit 返回新 id。
    async fn create_department_with_context(
        &self,
        new: &NewDepartment,
        context: &DepartmentMutationContext,
    ) -> Result<i64, AstralError>;

    /// 遗留无 context update：一律 fail-closed（无 admission 旁路）。
    async fn update_department(&self, id: i64, patch: &DepartmentPatch) -> Result<(), AstralError> {
        let _ = (id, patch);
        Err(department_context_required())
    }
    /// 部分更新（空补丁 no-op；proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 租户行 → 目标部门行 → （父部门行，如适用）。
    /// self-reference/父存在性/父租户守卫在事务内复核；目标不存在 NotFound、
    /// 租户不匹配 Permission，一律 fail-closed。只有 proven commit 返回成功。
    async fn update_department_with_context(
        &self,
        id: i64,
        patch: &DepartmentPatch,
        context: &DepartmentMutationContext,
    ) -> Result<(), AstralError>;

    /// 子部门数量（遗留读取；删除守卫走事务内锁定读）
    async fn count_children(&self, dept_id: i64) -> Result<i64, AstralError>;
    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn delete_department(&self, id: i64) -> Result<bool, AstralError> {
        let _ = id;
        Err(department_context_required())
    }
    /// 删除部门（proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 租户行 → 目标部门行 → 子部门行（锁定计数守卫）。
    /// 子部门守卫与 DELETE 原子成立；目标不存在 NotFound、租户不匹配
    /// Permission，一律 fail-closed。只有 proven commit 返回命中。
    async fn delete_department_with_context(
        &self,
        id: i64,
        context: &DepartmentMutationContext,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxDepartmentRepository {
    db: MySqlPool,
}

impl SqlxDepartmentRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 追加过滤条件（列表与总数共用）
fn push_filter<'args>(builder: &mut QueryBuilder<'args, sqlx::MySql>, filter: &DepartmentFilter) {
    if let Some(parent_id) = filter.parent_id {
        builder.push(" AND parent_dept_id = ").push_bind(parent_id);
    }
    if let Some(tenant_id) = filter.tenant_id {
        builder.push(" AND tenant_id = ").push_bind(tenant_id);
    }
}

#[async_trait]
impl DepartmentRepository for SqlxDepartmentRepository {
    async fn count_departments(&self, filter: &DepartmentFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM departments WHERE 1=1");
        push_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_departments(
        &self,
        filter: &DepartmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DepartmentRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {DEPT_SELECT_COLUMNS} FROM departments WHERE 1=1"
        ));
        push_filter(&mut builder, filter);
        builder
            .push(" ORDER BY dept_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<DepartmentRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn department_exists(&self, dept_id: i64) -> Result<bool, AstralError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT dept_id FROM departments WHERE dept_id = ?")
                .bind(dept_id)
                .fetch_optional(&self.db)
                .await
                .map_err(db_error)?;
        Ok(row.is_some())
    }

    async fn create_department_with_context(
        &self,
        new: &NewDepartment,
        context: &DepartmentMutationContext,
    ) -> Result<i64, AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：目标租户行（存在性 + foreign scope fail-closed）+ caller 卡。
        lock_department_tenant_scope_in_tx(&mut tx, context, new.tenant_id).await?;
        // 父部门守卫（如适用）：存在性 + 同租户，锁定读防并发移动/删除。
        if let Some(parent_id) = new.parent_id {
            let parent_exists =
                lock_department_row_tenant_in_tx(&mut tx, parent_id, new.tenant_id).await?;
            if !parent_exists {
                return Err(AstralError::Validation(format!(
                    "parent department {parent_id} not found"
                )));
            }
        }
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::Department, TypedRowOperation::Insert);
        let new_id = capture
            .insert_department_and_capture_in_tx(
                new.tenant_id,
                None,
                new.name.clone(),
                new.code.clone(),
                new.parent_id,
                new.sort_order,
                new.description.clone(),
            )
            .await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_department_mutation_audit_in_tx(
            &mut tx,
            context,
            new_id,
            "department_create",
            serde_json::json!({
                "name": new.name,
                "parentId": new.parent_id,
                "tenantId": new.tenant_id,
            }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    async fn get_department(&self, id: i64) -> Result<Option<DepartmentRecord>, AstralError> {
        sqlx::query_as::<_, DepartmentRecord>(&format!(
            "SELECT {DEPT_SELECT_COLUMNS} FROM departments WHERE dept_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn update_department_with_context(
        &self,
        id: i64,
        patch: &DepartmentPatch,
        context: &DepartmentMutationContext,
    ) -> Result<(), AstralError> {
        // 先把补丁装配成绑定参数 UPDATE（列名是编译期常量，值全部 push_bind）；
        // 空补丁 no-op：无 source mutation，不开启事务。
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE departments SET ");
        let mut first = true;
        if let Some(name) = &patch.name {
            if !first {
                builder.push(", ");
            }
            builder.push("dept_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.code {
            if !first {
                builder.push(", ");
            }
            builder.push("dept_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(parent_id) = patch.parent_id {
            if !first {
                builder.push(", ");
            }
            builder.push("parent_dept_id = ").push_bind(parent_id);
            first = false;
        }
        if let Some(sort_order) = patch.sort_order {
            if !first {
                builder.push(", ");
            }
            builder.push("sort_order = ").push_bind(sort_order);
            first = false;
        }
        if let Some(description) = &patch.description {
            if !first {
                builder.push(", ");
            }
            builder
                .push("description = ")
                .push_bind(description.clone());
            first = false;
        }
        if first {
            return Ok(());
        }
        builder.push(" WHERE dept_id = ").push_bind(id);

        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 租户行 + caller 卡（scope 校验）。
        lock_department_tenant_scope_in_tx(&mut tx, context, context.actor_tenant_id).await?;
        // 目标部门行锁：存在性（NotFound fail-closed）+ 租户归属
        // （foreign scope Permission fail-closed）。
        let target_exists =
            lock_department_row_tenant_in_tx(&mut tx, id, context.actor_tenant_id).await?;
        if !target_exists {
            return Err(AstralError::NotFound(format!("department {id} not found")));
        }
        // self-reference + 父部门守卫（如适用）：事务内复核，防 TOCTOU。
        // 目标租户已证明等于 actor 租户，父行按同一租户对牌。
        if let Some(parent_id) = patch.parent_id {
            guard_department_parent_reference(id, patch.parent_id)?;
            let parent_exists =
                lock_department_row_tenant_in_tx(&mut tx, parent_id, context.actor_tenant_id)
                    .await?;
            if !parent_exists {
                return Err(AstralError::Validation(format!(
                    "parent department {parent_id} not found"
                )));
            }
        }
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::Department, TypedRowOperation::Update);
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
                            "locked department update affected more than one row".into(),
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
                "department update changed its source image without exactly one affected row"
                    .into(),
            ));
        }
        let audit = insert_department_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "department_update",
            serde_json::json!({
                "name": patch.name,
                "code": patch.code,
                "parentId": patch.parent_id,
                "sortOrder": patch.sort_order,
                "description": patch.description,
            }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await
    }

    async fn count_children(&self, dept_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM departments WHERE parent_dept_id = ?")
            .bind(dept_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn delete_department_with_context(
        &self,
        id: i64,
        context: &DepartmentMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 租户行 + caller 卡（scope 校验）。
        lock_department_tenant_scope_in_tx(&mut tx, context, context.actor_tenant_id).await?;
        // 目标部门行锁：存在性（NotFound fail-closed）+ 租户归属
        // （foreign scope Permission fail-closed）。
        let target_exists =
            lock_department_row_tenant_in_tx(&mut tx, id, context.actor_tenant_id).await?;
        if !target_exists {
            return Err(AstralError::NotFound(format!("department {id} not found")));
        }
        // 子部门删除守卫：锁定读计数，与 DELETE 原子成立（守卫错误先于任何
        // 写入返回，事务随 Err 整体回滚，不产生部分删除）。
        let (children,) = sqlx::query_as::<_, (i64,)>(DEPARTMENT_CHILDREN_LOCK_SQL)
            .bind(id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db_error)?;
        guard_department_delete(children, id)?;
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::Department, TypedRowOperation::Delete);
        capture.capture_before_in_tx(&lookup).await?;
        capture
            .with_tx_mut(|inner| {
                Box::pin(async move {
                    let result = sqlx::query("DELETE FROM departments WHERE dept_id = ?")
                        .bind(id)
                        .execute(&mut **inner)
                        .await
                        .map_err(db_error)?;
                    if result.rows_affected() != 1 {
                        return Err(AstralError::Pending(format!(
                            "locked department {id} delete did not affect exactly one row"
                        )));
                    }
                    Ok(())
                })
            })
            .await?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_department_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "department_delete",
            serde_json::json!({ "status": "deleted" }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(true)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Department repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

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
    fn department_mutation_context_requires_verified_identity() {
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
            DepartmentMutationContext::from_policy_context(&end_user, Some("req-1")),
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
            DepartmentMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            DepartmentMutationContext::from_policy_context(&policy_context(10, 20, 30, 40), None),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            DepartmentMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            DepartmentMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = DepartmentMutationContext::from_policy_context(
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
            operation_id: "op-dept-test".into(),
            event_id: "evt-dept-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-dept-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-dept-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = DepartmentMutationContext::from_policy_context(
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
        assert!(ensure_department_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_department_actor_scope_matches(
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
            ensure_department_actor_scope_matches(
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
            ensure_department_actor_scope_matches(
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
            ensure_department_actor_scope_matches(
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
            ensure_department_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_department_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::NoDomain),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
    }

    // ── 纯守卫：self-reference 与子部门删除 ────────────────────────────────

    #[test]
    fn parent_reference_and_delete_guards_fail_closed() {
        // self-reference 拒绝；其他父引用放行；None 放行
        assert!(matches!(
            guard_department_parent_reference(7, Some(7)),
            Err(AstralError::Validation(message))
                if message.contains("own parent")
        ));
        assert!(guard_department_parent_reference(7, Some(8)).is_ok());
        assert!(guard_department_parent_reference(7, None).is_ok());

        // 有子部门拒绝（消息对齐既有 API 语义），无子部门放行
        assert!(matches!(
            guard_department_delete(2, 7),
            Err(AstralError::Validation(message))
                if message.contains("2 child departments")
        ));
        assert!(guard_department_delete(0, 7).is_ok());
    }

    // ── 审计关联：固定 event_type/resource 常量 + 全绑定参数 ──────────────

    #[test]
    fn audit_correlation_uses_bound_parameters_and_fixed_event_type() {
        assert_eq!(
            DEPARTMENT_AUDIT_EVENT_TYPE,
            "TRUSTGRAPH_DEPARTMENT_MUTATION"
        );
        assert!(
            DEPARTMENT_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(DEPARTMENT_AUDIT_RESOURCE, "departments");
        assert!(
            DEPARTMENT_MUTATION_AUDIT_INSERT_SQL
                .contains("VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_DEPARTMENT_MUTATION', ?, ?, ?, ?)"),
            "audit insert must bind every mutable input"
        );
        assert!(
            DEPARTMENT_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && DEPARTMENT_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
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
    fn create_tx_orders_tenant_parent_insert_audit_and_commit() {
        let source = include_str!("department_repository.rs");
        let body = impl_segment(
            source,
            "async fn create_department_with_context",
            "async fn get_department",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("create must host the mutation in the proof-bound source wrapper");
        let tenant_lock = body
            .find("lock_department_tenant_scope_in_tx(&mut tx, context, new.tenant_id)")
            .expect("create must lock the target tenant row first");
        let parent_lock = body
            .find("lock_department_row_tenant_in_tx(")
            .expect("create must lock the parent row (when present) after the tenant");
        let insert = body
            .find(".insert_department_and_capture_in_tx(")
            .expect("create must delegate the insert and locked readback to the capture child");
        let normalized: String = body.split_whitespace().collect();
        assert!(normalized.contains("capture.insert_department_and_capture_in_tx("));
        let capture_child =
            include_str!("../../../astral-db/src/authority_config_source/tenant_domain.rs")
                .split("#[cfg(test)]")
                .next()
                .expect("department capture child production source must exist");
        let insert_sql = capture_child
            .find(r#"const DEPARTMENT_INSERT_SQL: &str = "INSERT INTO departments"#)
            .expect("department capture child must own the actual INSERT statement");
        assert!(
            capture_child[insert_sql..].contains(".execute(&mut **tx)"),
            "department capture child must execute the INSERT on its bound transaction"
        );
        let audit = body
            .find("insert_department_mutation_audit_in_tx")
            .expect("create must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("create must commit through the wrapper consuming commit");
        assert!(
            begin < tenant_lock
                && tenant_lock < parent_lock
                && parent_lock < insert
                && insert < audit
                && audit < commit,
            "create must order: wrapper begin -> tenant lock -> parent lock -> INSERT -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "create must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    #[test]
    fn update_tx_orders_tenant_target_parent_update_audit_and_commit() {
        let source = include_str!("department_repository.rs");
        let body = impl_segment(
            source,
            "async fn update_department_with_context",
            "async fn count_children",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("update must host the mutation in the proof-bound source wrapper");
        let tenant_lock = body
            .find("lock_department_tenant_scope_in_tx(&mut tx, context, context.actor_tenant_id)")
            .expect("update must lock the actor tenant row first");
        let target_lock = body
            .find("lock_department_row_tenant_in_tx(&mut tx, id, context.actor_tenant_id)")
            .expect("update must lock the target department row");
        let parent_guard = body
            .find("guard_department_parent_reference(id, patch.parent_id)")
            .expect("update must re-check self-reference inside the tx");
        // 父行锁是同 helper 的第二次调用：锚定 target 锁之后的下一次出现，
        // 不绑定 rustfmt 的换行布局。
        let parent_lock = body[target_lock + "lock_department_row_tenant_in_tx".len()..]
            .find("lock_department_row_tenant_in_tx(")
            .map(|offset| target_lock + "lock_department_row_tenant_in_tx".len() + offset)
            .expect("update must lock the parent row (when present)");
        let update = body
            .find(".execute(&mut **inner)")
            .expect("update must mutate the department row through the capture child borrow");
        let normalized: String = body.split_whitespace().collect();
        assert!(normalized.contains("builder.build().execute(&mut**inner)"));
        let audit = body
            .find("insert_department_mutation_audit_in_tx")
            .expect("update must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("update must commit through the wrapper consuming commit");
        assert!(
            begin < tenant_lock
                && tenant_lock < target_lock
                && target_lock < parent_guard
                && parent_guard < parent_lock
                && parent_lock < update
                && update < audit
                && audit < commit,
            "update must order: wrapper begin -> tenant lock -> target lock -> parent guard/lock -> UPDATE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "update must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    #[test]
    fn delete_tx_orders_tenant_target_children_delete_audit_and_commit() {
        let source = include_str!("department_repository.rs");
        let body = impl_segment(
            source,
            "async fn delete_department_with_context",
            "fn db_error",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("delete must host the mutation in the proof-bound source wrapper");
        let tenant_lock = body
            .find("lock_department_tenant_scope_in_tx(&mut tx, context, context.actor_tenant_id)")
            .expect("delete must lock the actor tenant row first");
        let target_lock = body
            .find("lock_department_row_tenant_in_tx(&mut tx, id, context.actor_tenant_id)")
            .expect("delete must lock the target department row");
        let children_guard = body
            .find("DEPARTMENT_CHILDREN_LOCK_SQL")
            .expect("delete must count children with a locked read");
        let guard_check = body
            .find("guard_department_delete(children, id)?")
            .expect("delete must enforce the child-delete guard before any write");
        let row_delete = body
            .find("DELETE FROM departments WHERE dept_id = ?")
            .expect("delete must remove the department row");
        let audit = body
            .find("insert_department_mutation_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            begin < tenant_lock
                && tenant_lock < target_lock
                && target_lock < children_guard
                && children_guard < guard_check
                && guard_check < row_delete
                && row_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> tenant lock -> target lock -> locked child guard -> DELETE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    // ── 范围结论：无 eligibility fanout、无投影事件、遗留入口 fail-closed ──

    #[test]
    fn department_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("department_repository.rs");
        // 部门行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "department mutations must not invent eligibility/projection fanout"
        );
        // create/update/delete 全部以 proof-bound source transaction 为宿主。
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
            legacy.matches("Err(department_context_required())").count(),
            3,
            "legacy create/update/delete must fail closed without a mutation context"
        );
        // 目标行/父行锁定读与子部门守卫都是 FOR UPDATE 锁定读（原子守卫）。
        assert!(DEPARTMENT_ROW_TENANT_LOCK_SQL.contains("FOR UPDATE"));
        assert!(DEPARTMENT_TENANT_LOCK_SQL.contains("FOR UPDATE"));
        assert!(DEPARTMENT_CHILDREN_LOCK_SQL.contains("FOR UPDATE"));
        assert!(DEPARTMENT_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
    }

    // ── request id 校验复核（context 入参直通 validated_request_operation_id）─

    fn header_map_with_request_id(request_id: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(value) = request_id {
            map.insert(
                "x-request-id",
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        map
    }

    #[test]
    fn request_id_header_parsing_stays_within_durable_contract() {
        fn extract(map: &HeaderMap) -> Option<&str> {
            map.get("x-request-id")
                .and_then(|value| value.to_str().ok())
        }
        // 缺失 → context 构造拒绝
        let headers = header_map_with_request_id(None);
        let context = DepartmentMutationContext::from_policy_context(
            &policy_context(10, 20, 30, 40),
            extract(&headers),
        );
        assert!(matches!(context, Err(AstralError::Auth(_))));
        // 携带合法值 → 原样保留为 operation id
        let headers = header_map_with_request_id(Some("req-dept-42"));
        let context = DepartmentMutationContext::from_policy_context(
            &policy_context(10, 20, 30, 40),
            extract(&headers),
        )
        .unwrap();
        assert_eq!(context.request_id(), "req-dept-42");
    }
}
