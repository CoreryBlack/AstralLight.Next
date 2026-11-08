//! 权限动作数据访问 — PermissionActionRepository
//!
//! 对齐 Java `PermissionActionMapper` 边界（permission_action 表 + domain_resource_type 只读）。
//!
//! ## 授权源事务（admission-hosted source mutation）
//!
//! `permission_action` 是资源/动作注册事实面（与 `ResourceRegistry` 共同构成
//! 授权模型的对象/动作词汇表）：本文件的 CRUD mutation（create/update/delete）
//! 以 `AuthorizationSourceTransaction` 为宿主——复用 canonical
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
//! create 的 **insert 与查回在同一个 source 事务内原子完成**（INSERT IGNORE +
//! 同事务 reselect，行由 `(resource_type_id, action_code)` UNIQUE 定位），响应
//! 行绝不依赖第二连接的事务外读取。事务内按固定锁序先锁定 actor 卡行
//! （user/tenant/domain/ACTIVE 复核 + admission proof scope 对牌，与
//! departments/levels 同一形状），再锁定目标行。
//!
//! ## 范围结论（不虚构 eligibility fanout / scan 编排）
//!
//! `permission_action` 行不是 CanonicalGrant 源：policy-engine 与 astral-db 的
//! eligibility/投影消费路径均无本表引用（动作词汇在规则编译/评估侧静态使用）。
//! 因此本文件刻意不登记 ELIGIBILITY 失效事件、不追加任何投影 delta/receipt；
//! 卡片授权事实仍由 user_card/发布证据路径承载。`ResourceRegistry`/async
//! tracker 的 scan 编排保留在 HTTP handler（in-memory），scan 路径维持
//! `NotImplemented`，本文件只提供其遗留数据访问原语（`insert_ignore_action` /
//! `upsert_action_from_registry`），不在事务内编排注册表。同事务保留
//! `audit_log` 关联（request_id/event_type 关联源 mutation）。遗留无 context
//! CRUD 方法一律 fail-closed（`action_context_required`），无内部 system 旁路。

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

/// 权限动作记录（permission_action，通过别名映射）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PermissionActionRecord {
    pub id: i64,
    pub domain_id: Option<i64>,
    pub resource_type_id: i64,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
}

/// 列表过滤（domain_id / resource_type_ids 可选）
#[derive(Debug, Default)]
pub struct ActionFilter {
    pub domain_id: Option<i64>,
    pub resource_type_ids: Vec<i64>,
}

/// 部分更新补丁（name / description）
#[derive(Debug, Default)]
pub struct ActionPatch {
    pub name: Option<String>,
    pub description: Option<String>,
}

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph permission-action mutation.
///
/// 与 departments/levels 同一装配合同：身份只能来自 TrustGraph permission
/// 中间件安装的已验证 `PolicyContext`；Gateway 头不是授权来源，只允许在 API
/// 层与该 context 完全一致后使用。`request_id` 必须携带且通过统一持久化安全
/// 性校验（`validated_request_operation_id`）；缺失/纯空白/超长/非法字符一律
/// fail-closed，绝不静默替换、截断或随机补位。`source_capability` 初始为
/// `UserPending`，只有 `.with_admission(...)` 注入 proof-bound admission 后
/// 才允许开启用户 source 事务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionActionMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl PermissionActionMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "permission action mutation requires a Gateway-verified platform user context"
                    .into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("permission action mutation requires a canonical request id".into())
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
        AstralError::Auth(format!(
            "permission action mutation requires a positive {name}"
        ))
    })
}

fn action_context_required() -> AstralError {
    AstralError::Auth(
        "permission action business mutation requires Gateway-verified user-card context".into(),
    )
}

// ===== SQL 常量 =====

const ACTION_SELECT_COLUMNS: &str = "action_id as id, domain_id, resource_type_id, \
     action_code as code, action_name as name, action_description as description, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at";

/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与 departments/levels 同一形状。所有
/// 动作 mutation 的第一把锁，跨 create/update/delete 保持同一锁序避免死锁。
const ACTION_MUTATION_ACTOR_LOCK_SQL: &str = "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 目标动作行锁：锁定读证明存在性并序列化并发 update/delete（参数化 SQL）。
const ACTION_ROW_LOCK_SQL: &str =
    "SELECT action_id FROM permission_action WHERE action_id = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const ACTION_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_ACTION_MUTATION', ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：权限动作 mutation 家族标记。
const ACTION_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_ACTION_MUTATION";
/// `audit_log.resource`：权限动作聚合（permission_action 表）。
const ACTION_AUDIT_RESOURCE: &str = "permission_action";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_action_actor_scope_matches(
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
            "authorization admission scope does not match the locked permission action mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type ActionActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 第一把锁：锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_action_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &PermissionActionMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<ActionActorCardRow> = sqlx::query_as(ACTION_MUTATION_ACTOR_LOCK_SQL)
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
                ensure_action_actor_scope_matches(
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
            "Gateway permission action mutation card context no longer matches an active user_card"
                .into(),
        )),
    }
}

/// 目标动作行锁：存在性（None 由调用点决定 NotFound/no-hit 语义）+ 行锁。
async fn lock_action_row_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    action_id: i64,
) -> Result<bool, AstralError> {
    let row: Option<(i64,)> = sqlx::query_as(ACTION_ROW_LOCK_SQL)
        .bind(action_id)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    Ok(row.is_some())
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 departments/levels 路径同一机制：
/// 不用 MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_action_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &PermissionActionMutationContext,
    action_id: i64,
    action: &str,
    details: serde_json::Value,
) -> Result<i64, AstralError> {
    if action_id <= 0 || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "permission action mutation audit requires a positive target id and a non-empty action"
                .into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "permission_action",
        "targetId": action_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!(
            "permission action audit serialization failed: {error}"
        ))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!(
            "permission action audit serialization failed: {error}"
        ))
    })?;
    let result = sqlx::query(ACTION_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(ACTION_AUDIT_RESOURCE)
        .bind(ACTION_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!(
                "permission action mutation audit insert failed: {error}"
            ))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "permission action audit insert affected an unexpected row count".into(),
        ));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Pending("permission action audit insert returned invalid id".into())
        })
}

#[async_trait]
pub trait PermissionActionRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_actions(&self, filter: &ActionFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY action_id）
    async fn list_actions(
        &self,
        filter: &ActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionActionRecord>, AstralError>;
    /// 按 id 查回（只读路径；mutation 走 `_with_context`）
    async fn get_action(&self, id: i64) -> Result<Option<PermissionActionRecord>, AstralError>;

    /// 遗留无 context create：一律 fail-closed（无 admission 旁路）。
    async fn create_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<PermissionActionRecord, AstralError> {
        let _ = (domain_id, resource_type_id, code, name, description);
        Err(action_context_required())
    }
    /// 新建动作（proof-bound admission source transaction）。
    ///
    /// **insert 与查回在同一 source 事务内原子完成**：INSERT IGNORE 落行后，
    /// 同事务按 `(resource_type_id, action_code)` UNIQUE 锁定查回（行锁 +
    /// reselect），响应行绝不依赖第二连接的事务外读取。事务内锁序：actor 卡行
    /// → INSERT → 锁定 reselect → 审计关联。commit 前 canonical wrapper 完成
    /// durable authority revalidation / consume_once，只有 proven commit 返回行。
    async fn create_action_with_context(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
        description: Option<&str>,
        context: &PermissionActionMutationContext,
    ) -> Result<PermissionActionRecord, AstralError>;

    /// 遗留无 context update：一律 fail-closed（无 admission 旁路）。
    async fn update_action(&self, id: i64, patch: &ActionPatch) -> Result<bool, AstralError> {
        let _ = (id, patch);
        Err(action_context_required())
    }
    /// 部分更新（name/description + updated_at；空补丁 no-op 返回 false：
    /// 无 source mutation，不开启事务）。非空补丁必须产生真实 before/after
    /// typed image；受影响行数为 0 时 fail-closed。
    ///
    /// 事务内锁序：actor 卡行 → 目标行锁（未命中/空补丁返回 false，对齐既有
    /// API 404 语义）。只有 proven commit 返回命中。
    async fn update_action_with_context(
        &self,
        id: i64,
        patch: &ActionPatch,
        context: &PermissionActionMutationContext,
    ) -> Result<bool, AstralError>;

    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn delete_action(&self, id: i64) -> Result<bool, AstralError> {
        let _ = id;
        Err(action_context_required())
    }
    /// 删除动作（proof-bound admission source transaction），返回是否命中。
    ///
    /// 事务内锁序：actor 卡行 → 目标行锁（未命中返回 false，事务随 drop 回滚）
    /// → DELETE → 审计关联。只有 proven commit 返回命中。
    async fn delete_action_with_context(
        &self,
        id: i64,
        context: &PermissionActionMutationContext,
    ) -> Result<bool, AstralError>;

    /// 全量列表（scan 后重查；scan 编排保留在 handler，路径保持 NotImplemented）
    async fn list_all(&self) -> Result<Vec<PermissionActionRecord>, AstralError>;
    /// 同步扫描用：按 type_code 查 domain_resource_type_id（遗留数据访问原语）
    async fn resource_type_id_by_code(&self, type_code: &str) -> Result<Option<i64>, AstralError>;
    /// 同步扫描用：INSERT IGNORE（permission_action；遗留数据访问原语）
    async fn insert_ignore_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
    ) -> Result<(), AstralError>;
    /// 异步扫描用：INSERT ... SELECT（domain_resource_type JOIN）ON DUPLICATE KEY
    /// （遗留数据访问原语）
    async fn upsert_action_from_registry(
        &self,
        code: &str,
        name: &str,
        description: &str,
        resource_type: &str,
    ) -> Result<(), AstralError>;
}

pub struct SqlxPermissionActionRepository {
    db: MySqlPool,
}

impl SqlxPermissionActionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 追加过滤条件（列表与总数共用）
fn push_action_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &ActionFilter,
) {
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
    if !filter.resource_type_ids.is_empty() {
        builder.push(" AND resource_type_id IN (");
        let mut sep = "";
        for id in &filter.resource_type_ids {
            builder.push(sep).push_bind(*id);
            sep = ", ";
        }
        builder.push(")");
    }
}

#[async_trait]
impl PermissionActionRepository for SqlxPermissionActionRepository {
    async fn count_actions(&self, filter: &ActionFilter) -> Result<i64, AstralError> {
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM permission_action WHERE 1=1");
        push_action_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_actions(
        &self,
        filter: &ActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionActionRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action WHERE 1=1"
        ));
        push_action_filter(&mut builder, filter);
        builder
            .push(" ORDER BY action_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<PermissionActionRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_action(&self, id: i64) -> Result<Option<PermissionActionRecord>, AstralError> {
        sqlx::query_as::<_, PermissionActionRecord>(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action WHERE action_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_action_with_context(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
        description: Option<&str>,
        context: &PermissionActionMutationContext,
    ) -> Result<PermissionActionRecord, AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_action_mutation_actor_in_tx(&mut tx, context).await?;
        // INSERT IGNORE：唯一键冲突不作为成功的 config mutation；命中既有行
        // 的 no-op 直接回滚，避免提交 before==after 的空完成证据。
        let lookup = TypedSourceRowLookup::PermissionActionCode {
            resource_type_id,
            action_code: code.to_owned(),
        };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::PermissionAction,
            TypedRowOperation::Insert,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let code_owned = code.to_owned();
        let name_owned = name.to_owned();
        let description_owned = description.map(str::to_owned);
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT IGNORE INTO permission_action (domain_id, resource_type_id, action_code, action_name, action_description) \
                         VALUES (?, ?, ?, ?, ?)",
                    )
                    .bind(domain_id)
                    .bind(resource_type_id)
                    .bind(code_owned)
                    .bind(name_owned)
                    .bind(description_owned)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "permission action insert was a no-op; refusing empty config completion".into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        // 同事务锁定 reselect：与 INSERT 原子成立，响应行不依赖第二连接的
        // 事务外读取。
        let row = sqlx::query_as::<_, PermissionActionRecord>(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action \
             WHERE resource_type_id = ? AND action_code = ? FOR UPDATE"
        ))
        .bind(resource_type_id)
        .bind(code)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
        let record = row.ok_or_else(|| {
            AstralError::Database(format!(
                "permission action '{code}' for resource_type {resource_type_id} disappeared during locked insert"
            ))
        })?;
        let new_id = record.id;
        let audit_id = insert_action_mutation_audit_in_tx(
            &mut tx,
            context,
            new_id,
            "permission_action_create",
            serde_json::json!({
                "code": code,
                "name": name,
                "domainId": domain_id,
                "resourceTypeId": resource_type_id,
            }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(record)
    }

    async fn update_action_with_context(
        &self,
        id: i64,
        patch: &ActionPatch,
        context: &PermissionActionMutationContext,
    ) -> Result<bool, AstralError> {
        // 先把补丁装配成绑定参数 UPDATE；空补丁 no-op 不开启 source tx。
        if patch.name.is_none() && patch.description.is_none() {
            return Ok(false);
        }

        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        verify_action_mutation_actor_in_tx(&mut tx, context).await?;
        if !lock_action_row_in_tx(&mut tx, id).await? {
            return Ok(false);
        }
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::PermissionAction,
            TypedRowOperation::Update,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let name = patch.name.clone();
        let description = patch.description.clone();
        let result = match (name, description) {
            (Some(name), Some(description)) => capture
                .with_tx_mut(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE permission_action SET action_name = ?, action_description = ?, updated_at = NOW() WHERE action_id = ?",
                        )
                        .bind(name)
                        .bind(description)
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                    })
                })
                .await?,
            (Some(name), None) => capture
                .with_tx_mut(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE permission_action SET action_name = ?, updated_at = NOW() WHERE action_id = ?",
                        )
                        .bind(name)
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                    })
                })
                .await?,
            (None, Some(description)) => capture
                .with_tx_mut(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE permission_action SET action_description = ?, updated_at = NOW() WHERE action_id = ?",
                        )
                        .bind(description)
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                    })
                })
                .await?,
            (None, None) => unreachable!("empty action patch returned above"),
        };
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "permission action update affected no row; refusing empty config completion".into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_action_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "permission_action_update",
            serde_json::json!({
                "name": patch.name,
                "description": patch.description,
            }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn delete_action_with_context(
        &self,
        id: i64,
        context: &PermissionActionMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_action_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标行锁：未命中返回 false（对齐既有 API 404 语义），事务随 drop 回滚；
        // 命中则行锁与 DELETE 原子成立。
        let target_exists = lock_action_row_in_tx(&mut tx, id).await?;
        if !target_exists {
            return Ok(false);
        }
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::PermissionAction,
            TypedRowOperation::Delete,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM permission_action WHERE action_id = ?")
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "permission action {id} disappeared during locked delete"
            )));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_action_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "permission_action_delete",
            serde_json::json!({ "status": "deleted" }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn list_all(&self) -> Result<Vec<PermissionActionRecord>, AstralError> {
        sqlx::query_as::<_, PermissionActionRecord>(&format!(
            "SELECT {ACTION_SELECT_COLUMNS} FROM permission_action ORDER BY action_id"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn resource_type_id_by_code(&self, type_code: &str) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT resource_type_id FROM domain_resource_type WHERE type_code = ? LIMIT 1",
        )
        .bind(type_code)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn insert_ignore_action(
        &self,
        domain_id: Option<i64>,
        resource_type_id: i64,
        code: &str,
        name: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT IGNORE INTO permission_action (domain_id, resource_type_id, action_code, action_name) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(domain_id)
        .bind(resource_type_id)
        .bind(code)
        .bind(name)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn upsert_action_from_registry(
        &self,
        code: &str,
        name: &str,
        description: &str,
        resource_type: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO permission_action (domain_id, resource_type_id, action_code, action_name, action_description) \
             SELECT NULL, dt.resource_type_id, ?, ?, ? \
             FROM domain_resource_type dt WHERE dt.type_code = ? \
             ON DUPLICATE KEY UPDATE updated_at = NOW()",
        )
        .bind(code)
        .bind(name)
        .bind(description)
        .bind(resource_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!(
        "Permission action repository query failed: {error}"
    ))
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
    fn permission_action_mutation_context_requires_verified_identity() {
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
            PermissionActionMutationContext::from_policy_context(&end_user, Some("req-1")),
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
            PermissionActionMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            PermissionActionMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                None
            ),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            PermissionActionMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            PermissionActionMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = PermissionActionMutationContext::from_policy_context(
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
            operation_id: "op-action-test".into(),
            event_id: "evt-action-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-action-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-action-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = PermissionActionMutationContext::from_policy_context(
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
        assert!(ensure_action_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_action_actor_scope_matches(
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
            ensure_action_actor_scope_matches(
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
            ensure_action_actor_scope_matches(
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
            ensure_action_actor_scope_matches(
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
            ensure_action_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_action_actor_scope_matches(
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
        assert_eq!(ACTION_AUDIT_EVENT_TYPE, "TRUSTGRAPH_ACTION_MUTATION");
        assert!(
            ACTION_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(ACTION_AUDIT_RESOURCE, "permission_action");
        assert!(
            ACTION_MUTATION_AUDIT_INSERT_SQL.contains(
                "VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_ACTION_MUTATION', ?, ?, ?, ?)"
            ),
            "audit insert must bind every mutable input"
        );
        assert!(
            ACTION_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && ACTION_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
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
            .split(start_marker)
            .nth(2)
            .expect("implementation must exist")
            .split(end_marker)
            .next()
            .expect("body must be delimited")
    }

    /// include_str! 结构断言：create 的 insert 与查回必须在**同一个 source
    /// 事务**内原子完成（INSERT IGNORE → 同事务 FOR UPDATE reselect），响应行
    /// 绝不依赖第二连接的事务外读取。
    #[test]
    fn create_tx_orders_actor_lock_insert_atomic_reselect_audit_and_commit() {
        let source = include_str!("permission_action_repository.rs");
        let body = impl_segment(
            source,
            "async fn create_action_with_context",
            "async fn update_action_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("create must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_action_mutation_actor_in_tx(&mut tx, context)")
            .expect("create must lock the admission caller card first");
        let insert = body
            .find("INSERT IGNORE INTO permission_action")
            .expect("create must insert on the wrapper connection");
        let reselect = body
            .find("WHERE resource_type_id = ? AND action_code = ? FOR UPDATE")
            .expect("create must reselect the row with a locked read inside the same tx");
        let audit = body
            .find("insert_action_mutation_audit_in_tx")
            .expect("create must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("create must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < insert
                && insert < reselect
                && reselect < audit
                && audit < commit,
            "create must order: wrapper begin -> actor lock -> INSERT IGNORE -> locked reselect -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "create must not bypass the wrapper's proven-commit gate with a raw commit"
        );
        assert!(
            !body.contains("&self.db)"),
            "create must not read through a second pool connection inside the mutation"
        );
    }

    #[test]
    fn update_tx_orders_actor_lock_row_lock_update_audit_and_commit() {
        let source = include_str!("permission_action_repository.rs");
        let body = impl_segment(
            source,
            "async fn update_action_with_context",
            "async fn delete_action_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("update must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_action_mutation_actor_in_tx(&mut tx, context)")
            .expect("update must lock the admission caller card first");
        let row_lock = body
            .find("lock_action_row_in_tx(&mut tx, id)")
            .expect("update must lock the target action row");
        let update = body
            .find("UPDATE permission_action SET action_name")
            .expect("update must mutate the action row on the wrapper connection");
        let audit = body
            .find("insert_action_mutation_audit_in_tx")
            .expect("update must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("update must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < row_lock
                && row_lock < update
                && update < audit
                && audit < commit,
            "update must order: wrapper begin -> actor lock -> row lock -> UPDATE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "update must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    #[test]
    fn delete_tx_orders_actor_lock_row_lock_delete_audit_and_commit() {
        let source = include_str!("permission_action_repository.rs");
        let body = impl_segment(
            source,
            "async fn delete_action_with_context",
            "async fn list_all",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("delete must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_action_mutation_actor_in_tx(&mut tx, context)")
            .expect("delete must lock the admission caller card first");
        let row_lock = body
            .find("lock_action_row_in_tx(&mut tx, id)")
            .expect("delete must lock the target action row");
        let row_delete = body
            .find("DELETE FROM permission_action WHERE action_id = ?")
            .expect("delete must remove the action row");
        let audit = body
            .find("insert_action_mutation_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < row_lock
                && row_lock < row_delete
                && row_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> actor lock -> row lock -> DELETE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    // ── 范围结论：无 eligibility fanout、遗留入口 fail-closed、scan 原语保留 ──

    #[test]
    fn action_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("permission_action_repository.rs");
        // 动作词汇行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "permission action mutations must not invent eligibility/projection fanout"
        );
        // create/update/delete 全部以 proof-bound source transaction 为宿主。
        assert_eq!(
            source.matches(wrapper_begin_token()).count(),
            3,
            "create/update/delete must each use the proof-bound source wrapper"
        );
        // 遗留无 context CRUD 入口一律 fail-closed（trait 默认实现）。
        // 只统计生产区（include_str! 含本测试自身，避免测试字面量自引用假阳性）。
        let legacy = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        assert_eq!(
            legacy.matches("Err(action_context_required())").count(),
            3,
            "legacy create/update/delete must fail closed without a mutation context"
        );
        // scan 数据访问原语保留（编排归 handler，路径保持 NotImplemented）。
        assert!(source.contains("async fn insert_ignore_action"));
        assert!(source.contains("async fn upsert_action_from_registry"));
        // actor 卡行与目标行锁定读都是 FOR UPDATE（原子守卫）。
        assert!(ACTION_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
        assert!(ACTION_ROW_LOCK_SQL.contains("FOR UPDATE"));
    }
}
