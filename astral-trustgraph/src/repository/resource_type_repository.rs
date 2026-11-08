//! 资源类型数据访问 — ResourceTypeRepository
//!
//! 对齐 Java `DomainResourceTypeMapper` / `ResourceTypeRegistryMapper` 边界
//! （domain_resource_type + resource_type_registry 表）。
//!
//! ## 授权源事务（admission-hosted source mutation）
//!
//! `resource_type_registry` 是资源/动作词汇表的持久事实源（启动时经
//! `load_registry_rows` 装入运行时 `ResourceRegistry`，与规则编译/评估侧共享
//! 同一词汇）。本文件的 register/update mutation 以 `AuthorizationSourceTransaction`
//! 为宿主——复用 canonical `begin_source_transaction_with_capability` /
//! `commit_consuming`，不在本文件发明第二套事务/栅栏基础设施：
//! - `begin` 在 DB begin 之前取得 hub 源活动栅栏（hub 已安装而拒发证即在开启
//!   事务**之前** fail-closed，绝不留下无栅栏 writer）；`UserPending`（缺失
//!   admission）在 begin 即被拒绝；
//! - 事务内按固定锁序先锁定 actor 卡行（user/tenant/domain/ACTIVE 复核 +
//!   admission proof scope 对牌，与 domains/permission_actions 同一形状），再
//!   处理目标 registry 行；
//! - commit 前 canonical wrapper 完成 durable authority 对牌
//!   （`validate_authorization_admission_in_tx`）与 admission `consume_once`，
//!   之后才 arm 栅栏并 await COMMIT；只有 proven commit 返回成功；
//! - commit 未知/失败 → 栅栏 sticky uncertain、receipts 空集，绝不投递、绝不
//!   重放（UNKNOWN fail-closed）。
//!
//! persist-before-runtime 边界：本文件只落 durable registry 行，绝不在事务内
//! 触碰运行时 `ResourceRegistry`；post-commit 安装、`RESOURCE_REGISTRY_INSTALL_PENDING`
//! 语义与 restart reload 对账归 HTTP handler / 启动路径（`load_registry_rows`）。
//!
//! ## 范围结论（不虚构 eligibility fanout / scan 编排）
//!
//! `resource_type_registry` 行不是 CanonicalGrant 源：policy-engine 与 astral-db
//! 的 eligibility/投影消费路径均无本表引用（词汇在规则编译/评估侧静态使用）。
//! 因此本文件刻意不登记 ELIGIBILITY 失效事件、不追加任何投影 delta/receipt。
//! scan 路径维持 `NotImplemented`，本文件只提供其遗留数据访问原语
//! （`upsert_registry`），不在事务内编排注册表。同事务保留 `audit_log` 关联
//! （request_id/event_type 关联源 mutation）。遗留无 context register/update
//! 方法一律 fail-closed（`resource_type_context_required`），无内部 system 旁路。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::grant_ledger::validated_request_operation_id;
use astral_db::{TypedRowOperation, TypedSourceRowLookup, TypedSourceTable};
use astral_types::{
    AstralError, AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationDomainScope,
    CustomResourceRegistration, PolicyContext, RegistryRegistrationError, ResourceRegistry,
    MAX_CUSTOM_RESOURCE_REGISTRY_BYTES, MAX_CUSTOM_RESOURCE_TYPES,
};

use crate::repository::authorization_source_transaction::{
    begin_source_transaction_with_capability, AuthorizationSourceTransaction,
    SourceMutationCapability,
};

/// Bounded persisted registry read. One extra row detects oversized startup data.
pub const RESOURCE_TYPE_REGISTRY_READ_LIMIT: i64 = (MAX_CUSTOM_RESOURCE_TYPES + 1) as i64;

/// Load persisted rows into the shared registry through its validated additive API.
///
/// The input should come from the bounded `list_registry` reader below; cap+1 rows
/// are rejected before any registry mutation. JSON parse or registration errors
/// are surfaced and must abort startup rather than leave a partially loaded registry.
pub fn load_registry_rows(rows: &[ResourceTypeRegistryRecord]) -> Result<(), AstralError> {
    if rows.len() > MAX_CUSTOM_RESOURCE_TYPES {
        return Err(AstralError::Validation(
            "persisted resource registry exceeds configured resource limit".into(),
        ));
    }
    let mut registrations = Vec::with_capacity(rows.len());
    let mut total_bytes = 0usize;
    for row in rows {
        total_bytes = total_bytes
            .saturating_add(row.resource_type.len())
            .saturating_add(row.actions_json.len());
        if total_bytes > MAX_CUSTOM_RESOURCE_REGISTRY_BYTES {
            return Err(AstralError::Validation(
                "persisted resource registry exceeds configured byte limit".into(),
            ));
        }
        let actions: Vec<String> = serde_json::from_str(&row.actions_json).map_err(|error| {
            AstralError::Validation(format!(
                "invalid actions_json for resource '{}': {error}",
                row.resource_type
            ))
        })?;
        registrations.push(CustomResourceRegistration {
            resource_type: row.resource_type.clone(),
            actions,
        });
    }
    ResourceRegistry::global()
        .validate_custom_resources(registrations.clone())
        .map_err(registry_registration_error)?;
    ResourceRegistry::global()
        .register_custom_resources(registrations)
        .map_err(registry_registration_error)
}

fn registry_registration_error(error: RegistryRegistrationError) -> AstralError {
    AstralError::Validation(format!("invalid persisted resource registry: {error}"))
}

/// domain_resource_type 行（通过别名映射）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainResourceTypeRecord {
    pub id: i64,
    pub domain_id: Option<i64>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub sensitivity_level: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// resource_type_registry 行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceTypeRegistryRecord {
    pub id: i64,
    pub resource_type: String,
    pub actions_json: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph resource-type mutation.
///
/// 与 domains/permission_actions 同一装配合同：身份只能来自 TrustGraph permission
/// 中间件安装的已验证 `PolicyContext`；Gateway 头不是授权来源，只允许在 API
/// 层与该 context 完全一致后使用。`request_id` 必须携带且通过统一持久化安全
/// 性校验（`validated_request_operation_id`）；缺失/纯空白/超长/非法字符一律
/// fail-closed，绝不静默替换、截断或随机补位 —— 它是同事务 audit_log 关联
/// 与源 mutation 的可追溯 operation id。`source_capability` 初始为
/// `UserPending`，只有 `.with_admission(...)` 注入 proof-bound admission 后
/// 才允许开启用户 source 事务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceTypeMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl ResourceTypeMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "resource type mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("resource type mutation requires a canonical request id".into())
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
        AstralError::Auth(format!("resource type mutation requires a positive {name}"))
    })
}

fn resource_type_context_required() -> AstralError {
    AstralError::Auth(
        "resource type business mutation requires Gateway-verified user-card context".into(),
    )
}

// ===== SQL 常量 =====

/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与 domains/permission_actions 同一形状。
/// 所有资源类型 mutation 的第一把锁，跨 register/update 保持同一锁序避免死锁。
const RESOURCE_TYPE_MUTATION_ACTOR_LOCK_SQL: &str =
    "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 目标 registry 行锁（按自然键 resource_type 定位）：锁定读证明存在性并取回
/// 稳定 id，序列化并发 register/update（参数化 SQL）。
const RESOURCE_TYPE_ROW_LOCK_SQL: &str =
    "SELECT id FROM resource_type_registry WHERE resource_type = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const RESOURCE_TYPE_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：资源类型 mutation 家族标记。
const RESOURCE_TYPE_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_RESOURCE_MUTATION";
/// `audit_log.resource`：资源类型词汇聚合（resource_type_registry 表）。
const RESOURCE_TYPE_AUDIT_RESOURCE: &str = "resource_type_registry";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_resource_type_actor_scope_matches(
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
            "authorization admission scope does not match the locked resource type mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type ResourceTypeActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 第一把锁：锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_resource_type_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &ResourceTypeMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<ResourceTypeActorCardRow> =
        sqlx::query_as(RESOURCE_TYPE_MUTATION_ACTOR_LOCK_SQL)
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
                ensure_resource_type_actor_scope_matches(
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
            "Gateway resource type mutation card context no longer matches an active user_card"
                .into(),
        )),
    }
}

/// 目标 registry 行锁：取回稳定 id（None 由调用点决定 NotFound/no-hit 语义）
/// 并持有行锁序列化并发 mutation。
async fn lock_resource_type_row_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    resource_type: &str,
) -> Result<Option<i64>, AstralError> {
    let row: Option<(i64,)> = sqlx::query_as(RESOURCE_TYPE_ROW_LOCK_SQL)
        .bind(resource_type)
        .fetch_optional(&mut ***tx)
        .await
        .map_err(db_error)?;
    Ok(row.map(|(id,)| id))
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 domains/permission_actions 路径同一机制：
/// 不用 MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_resource_type_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &ResourceTypeMutationContext,
    registry_id: i64,
    resource_type_key: &str,
    action: &str,
    details: serde_json::Value,
) -> Result<i64, AstralError> {
    if registry_id <= 0 || action.trim().is_empty() || resource_type_key.trim().is_empty() {
        return Err(AstralError::Validation(
            "resource type mutation audit requires a positive target id, a non-empty key and a non-empty action"
                .into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "resource_type_registry",
        "targetId": registry_id,
        "targetKey": resource_type_key,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("resource type audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("resource type audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(RESOURCE_TYPE_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(RESOURCE_TYPE_AUDIT_RESOURCE)
        .bind(RESOURCE_TYPE_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!(
                "resource type mutation audit insert failed: {error}"
            ))
        })?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "resource type audit insert affected an unexpected row count".into(),
        ));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Pending("resource type audit insert returned invalid id".into())
        })
}

#[async_trait]
pub trait ResourceTypeRepository: Send + Sync {
    /// domain_resource_type 总数
    async fn count_domain_resource_types(&self) -> Result<i64, AstralError>;
    /// domain_resource_type 分页列表（ORDER BY resource_type_id）
    async fn list_domain_resource_types(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainResourceTypeRecord>, AstralError>;
    /// resource_type_registry 全量列表（ORDER BY resource_type）
    async fn list_registry(&self) -> Result<Vec<ResourceTypeRegistryRecord>, AstralError>;
    /// 遗留无 context register：一律 fail-closed（无 admission 旁路）。
    async fn insert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<(), AstralError> {
        let _ = (resource_type, actions_json, description);
        Err(resource_type_context_required())
    }
    /// 注册新资源（proof-bound admission source transaction）。
    ///
    /// resource_type 已存在时由 `uk_rtr_resource_type` 唯一键拒绝（返回错误，
    /// 不忽略冲突、不覆盖 built-in）。事务内锁序：actor 卡行 → INSERT → 同事务
    /// FOR UPDATE reselect（证明落行并取回 audit 关联 id）→ 审计关联。commit
    /// 前 canonical wrapper 完成 durable authority revalidation / consume_once，
    /// 只有 proven commit 返回成功。
    async fn insert_registry_with_context(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
        context: &ResourceTypeMutationContext,
    ) -> Result<(), AstralError>;
    /// 遗留无 context update：一律 fail-closed（无 admission 旁路）。
    async fn update_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<bool, AstralError> {
        let _ = (resource_type, actions_json, description);
        Err(resource_type_context_required())
    }
    /// 更新（actions_json + description），返回是否命中。
    ///
    /// 命中且实际产生 before/after typed image 才能提交；数据库报告 no-op
    /// 时 fail-closed，避免空 config completion。
    ///
    /// 事务内锁序：actor 卡行 → 目标行锁（未命中返回 false，事务随 drop 回滚）
    /// → UPDATE → 审计关联。只有 proven commit 返回命中。
    async fn update_registry_with_context(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
        context: &ResourceTypeMutationContext,
    ) -> Result<bool, AstralError>;
    /// 异步扫描用：INSERT ... ON DUPLICATE KEY UPDATE（遗留数据访问原语）
    async fn upsert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
    ) -> Result<(), AstralError>;
}

pub struct SqlxResourceTypeRepository {
    db: MySqlPool,
}

impl SqlxResourceTypeRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ResourceTypeRepository for SqlxResourceTypeRepository {
    async fn count_domain_resource_types(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM domain_resource_type")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_domain_resource_types(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainResourceTypeRecord>, AstralError> {
        sqlx::query_as::<_, DomainResourceTypeRecord>(
            "SELECT resource_type_id as id, domain_id, type_code as code, type_name as name, \
             type_description as description, sensitivity_level, status, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
             DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at \
             FROM domain_resource_type ORDER BY resource_type_id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_registry(&self) -> Result<Vec<ResourceTypeRegistryRecord>, AstralError> {
        sqlx::query_as::<_, ResourceTypeRegistryRecord>(
            "SELECT id, resource_type, actions_json, description, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
             DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at \
             FROM resource_type_registry ORDER BY resource_type LIMIT ?",
        )
        .bind(RESOURCE_TYPE_REGISTRY_READ_LIMIT)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn insert_registry_with_context(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
        context: &ResourceTypeMutationContext,
    ) -> Result<(), AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_resource_type_mutation_actor_in_tx(&mut tx, context).await?;
        let lookup = TypedSourceRowLookup::ResourceTypeCode {
            code: resource_type.to_owned(),
        };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::ResourceType, TypedRowOperation::Insert);
        capture.capture_before_in_tx(&lookup).await?;
        let resource_type_owned = resource_type.to_owned();
        let actions_owned = actions_json.to_owned();
        let description_owned = description.map(str::to_owned);
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO resource_type_registry (resource_type, actions_json, description) \
                         VALUES (?, ?, ?)",
                    )
                    .bind(resource_type_owned)
                    .bind(actions_owned)
                    .bind(description_owned)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "resource type insert did not create a row; refusing empty config completion"
                    .into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        // 同事务锁定 reselect：证明行已落库并取回稳定 id（audit 关联目标），
        // 绝不依赖第二连接的事务外读取。
        let registry_id = lock_resource_type_row_in_tx(&mut tx, resource_type)
            .await?
            .ok_or_else(|| {
                AstralError::Database(format!(
                    "resource type '{resource_type}' disappeared during locked insert"
                ))
            })?;
        let audit_id = insert_resource_type_mutation_audit_in_tx(
            &mut tx,
            context,
            registry_id,
            resource_type,
            "resource_type_register",
            serde_json::json!({
                "actionsJson": actions_json,
                "description": description,
            }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(())
    }

    async fn update_registry_with_context(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
        context: &ResourceTypeMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_resource_type_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标行锁：未命中返回 false（对齐既有 API 404 语义），事务随 drop 回滚；
        // 命中则行锁与 UPDATE 原子成立。行存在即"命中"——no-op 更新（值完全
        // 相同，MySQL rows_affected=0）也算命中，不需要事务外二次存在性复查。
        let Some(registry_id) = lock_resource_type_row_in_tx(&mut tx, resource_type).await? else {
            return Ok(false);
        };
        let lookup = TypedSourceRowLookup::ResourceTypeCode {
            code: resource_type.to_owned(),
        };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::ResourceType, TypedRowOperation::Update);
        capture.capture_before_in_tx(&lookup).await?;
        let resource_type_owned = resource_type.to_owned();
        let actions_owned = actions_json.to_owned();
        let description_owned = description.map(str::to_owned);
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE resource_type_registry SET actions_json = ?, description = ? WHERE resource_type = ?",
                    )
                    .bind(actions_owned)
                    .bind(description_owned)
                    .bind(resource_type_owned)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() == 0 {
            return Err(AstralError::Pending(
                "resource type update was a no-op; refusing empty config completion".into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_resource_type_mutation_audit_in_tx(
            &mut tx,
            context,
            registry_id,
            resource_type,
            "resource_type_update",
            serde_json::json!({
                "actionsJson": actions_json,
                "description": description,
            }),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(true)
    }

    async fn upsert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO resource_type_registry (resource_type, actions_json) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE actions_json = VALUES(actions_json), updated_at = NOW()",
        )
        .bind(resource_type)
        .bind(actions_json)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Resource type repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_resource_type_actor_scope_matches, load_registry_rows, ResourceTypeMutationContext,
        ResourceTypeRegistryRecord, RESOURCE_TYPE_AUDIT_EVENT_TYPE, RESOURCE_TYPE_AUDIT_RESOURCE,
        RESOURCE_TYPE_MUTATION_ACTOR_LOCK_SQL, RESOURCE_TYPE_MUTATION_AUDIT_INSERT_SQL,
        RESOURCE_TYPE_REGISTRY_READ_LIMIT, RESOURCE_TYPE_ROW_LOCK_SQL,
    };
    use crate::repository::authorization_source_transaction::{
        begin_source_transaction_with_capability, SourceMutationCapability,
    };
    use crate::service::rule_set_write_service::validate_entry_fields;
    use astral_types::{
        AstralError, AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationDomainScope,
        PolicyContext, ResourceRegistry, MAX_CUSTOM_RESOURCE_REGISTRY_BYTES,
        MAX_CUSTOM_RESOURCE_TYPES,
    };

    fn row(resource_type: String, actions_json: &str) -> ResourceTypeRegistryRecord {
        ResourceTypeRegistryRecord {
            id: 1,
            resource_type,
            actions_json: actions_json.into(),
            description: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn bounded_startup_loader_registers_custom_actions_that_grant_validation_accepts() {
        let resource = format!("test_loaded_{}", std::process::id());
        let rows = [row(resource.clone(), r#"["read","approve"]"#)];
        assert!(load_registry_rows(&rows).is_ok());
        assert!(ResourceRegistry::global()
            .validate(&resource, "approve")
            .is_ok());
        assert_eq!(
            validate_entry_fields("ALLOW", Some(&resource), Some("approve"), None)
                .expect("registered custom actions must be grantable"),
            "ALLOW"
        );
        assert!(
            load_registry_rows(&rows).is_ok(),
            "startup reload is idempotent"
        );
        assert_eq!(
            RESOURCE_TYPE_REGISTRY_READ_LIMIT,
            (MAX_CUSTOM_RESOURCE_TYPES + 1) as i64
        );
    }

    #[test]
    fn invalid_registry_batch_is_rejected_before_any_custom_resource_is_registered() {
        let resource = format!("test_atomic_{}", std::process::id());
        let rows = [
            row(resource.clone(), r#"["read"]"#),
            row("monitor".into(), r#"["read","unknown"]"#),
        ];
        let error = load_registry_rows(&rows).expect_err("incompatible built-in action must fail");
        assert!(matches!(error, AstralError::Validation(_)));
        assert!(ResourceRegistry::global()
            .validate(&resource, "read")
            .is_err());
    }

    #[test]
    fn startup_loader_rejects_malformed_actions_json() {
        let rows = [row(
            format!("test_malformed_{}", std::process::id()),
            r#"{"read":true}"#,
        )];
        assert!(matches!(
            load_registry_rows(&rows),
            Err(AstralError::Validation(_))
        ));
    }

    #[test]
    fn startup_loader_rejects_rows_over_the_registry_byte_budget_before_any_install() {
        let oversized_actions = format!("[\"{}\"]", "a".repeat(MAX_CUSTOM_RESOURCE_REGISTRY_BYTES));
        let rows = [row(
            format!("test_budget_{}", std::process::id()),
            &oversized_actions,
        )];
        assert!(matches!(
            load_registry_rows(&rows),
            Err(AstralError::Validation(message)) if message.contains("byte limit")
        ));
        assert!(
            ResourceRegistry::global()
                .validate(&rows[0].resource_type, "a")
                .is_err(),
            "byte-budget rejection must leave the runtime registry untouched"
        );
    }

    #[test]
    fn startup_loader_rejects_more_rows_than_the_configured_type_limit() {
        let rows: Vec<ResourceTypeRegistryRecord> = (0..=MAX_CUSTOM_RESOURCE_TYPES)
            .map(|index| {
                row(
                    format!("test_cap_{}_{}", index, std::process::id()),
                    r#"["read"]"#,
                )
            })
            .collect();
        assert!(matches!(
            load_registry_rows(&rows),
            Err(AstralError::Validation(message)) if message.contains("resource limit")
        ));
    }

    // ── context 构造：缺失/非法身份 fail-closed，admission 装载可见 ────────

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

    #[test]
    fn resource_type_mutation_context_requires_verified_identity() {
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
            ResourceTypeMutationContext::from_policy_context(&end_user, Some("req-1")),
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
            ResourceTypeMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            ResourceTypeMutationContext::from_policy_context(&policy_context(10, 20, 30, 40), None),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            ResourceTypeMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            ResourceTypeMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = ResourceTypeMutationContext::from_policy_context(
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
            operation_id: "op-resource-type-test".into(),
            event_id: "evt-resource-type-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-resource-type-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-resource-type-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = ResourceTypeMutationContext::from_policy_context(
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
        assert!(ensure_resource_type_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_resource_type_actor_scope_matches(
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
            ensure_resource_type_actor_scope_matches(
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
            ensure_resource_type_actor_scope_matches(
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
            ensure_resource_type_actor_scope_matches(
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
            ensure_resource_type_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_resource_type_actor_scope_matches(
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
        assert_eq!(
            RESOURCE_TYPE_AUDIT_EVENT_TYPE,
            "TRUSTGRAPH_RESOURCE_MUTATION"
        );
        assert!(
            RESOURCE_TYPE_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(RESOURCE_TYPE_AUDIT_RESOURCE, "resource_type_registry");
        assert!(
            RESOURCE_TYPE_MUTATION_AUDIT_INSERT_SQL
                .contains("VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)"),
            "audit insert must bind every mutable input"
        );
        assert!(
            RESOURCE_TYPE_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && RESOURCE_TYPE_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
            "audit correlation must land in event_type/request_id columns"
        );
    }

    // ── 源序守卫：register/update 事务内锁序与 commit 门 ─────────────────

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

    /// include_str! 结构断言：register 的 INSERT 与查回必须在**同一个 source
    /// 事务**内原子完成（INSERT → 同事务 FOR UPDATE reselect），audit 关联 id
    /// 绝不依赖第二连接的事务外读取。
    #[test]
    fn register_tx_orders_actor_lock_insert_atomic_reselect_audit_and_commit() {
        let source = include_str!("resource_type_repository.rs");
        let body = impl_segment(
            source,
            "async fn insert_registry_with_context",
            "async fn update_registry_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("register must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_resource_type_mutation_actor_in_tx(&mut tx, context)")
            .expect("register must lock the admission caller card first");
        let insert = body
            .find("INSERT INTO resource_type_registry")
            .expect("register must insert on the wrapper connection");
        let reselect = body
            .find("lock_resource_type_row_in_tx(&mut tx, resource_type)")
            .expect("register must reselect the row with a locked read inside the same tx");
        let audit = body
            .find("insert_resource_type_mutation_audit_in_tx")
            .expect("register must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("register must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < insert
                && insert < reselect
                && reselect < audit
                && audit < commit,
            "register must order: wrapper begin -> actor lock -> INSERT -> locked reselect -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "register must not bypass the wrapper's proven-commit gate with a raw commit"
        );
        assert!(
            !body.contains("&self.db)"),
            "register must not read through a second pool connection inside the mutation"
        );
    }

    #[test]
    fn update_tx_orders_actor_lock_row_lock_update_audit_and_commit() {
        let source = include_str!("resource_type_repository.rs");
        let body = impl_segment(
            source,
            "async fn update_registry_with_context",
            "async fn upsert_registry",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("update must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_resource_type_mutation_actor_in_tx(&mut tx, context)")
            .expect("update must lock the admission caller card first");
        let row_lock = body
            .find("lock_resource_type_row_in_tx(&mut tx, resource_type)")
            .expect("update must lock the target registry row");
        let update = body
            .find("UPDATE resource_type_registry SET actions_json")
            .expect("update must mutate the registry row on the wrapper connection");
        let audit = body
            .find("insert_resource_type_mutation_audit_in_tx")
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

    // ── 范围结论：无 eligibility fanout、遗留入口 fail-closed、锁序常量 ────

    #[test]
    fn resource_type_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("resource_type_repository.rs");
        // 资源类型词汇行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "resource type mutations must not invent eligibility/projection fanout"
        );
        // register/update 全部以 proof-bound source transaction 为宿主。
        assert_eq!(
            source.matches(wrapper_begin_token()).count(),
            2,
            "register/update must each use the proof-bound source wrapper"
        );
        // 遗留无 context register/update 入口一律 fail-closed（trait 默认实现）。
        // 只统计生产区（include_str! 含本测试自身，避免测试字面量自引用假阳性）。
        let legacy = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        assert_eq!(
            legacy
                .matches("Err(resource_type_context_required())")
                .count(),
            2,
            "legacy register/update must fail closed without a mutation context"
        );
        // scan 数据访问原语保留（编排归 handler，路径保持 NotImplemented）。
        assert!(source.contains("async fn upsert_registry"));
        assert!(source.contains("async fn load_registry_rows"));
        // actor 卡行与目标 registry 行锁定读都是 FOR UPDATE（原子守卫）。
        assert!(RESOURCE_TYPE_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
        assert!(RESOURCE_TYPE_ROW_LOCK_SQL.contains("FOR UPDATE"));
    }
}
